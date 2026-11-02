//! External audit export.
//!
//! The local chain is only as trustworthy as the machine that holds it. Pushing
//! signed batches to an external sink (HTTP JSONL, SIEM collector, WORM bucket
//! front-end) gives an anchor the database owner cannot rewrite.
//!
//! Delivery is at-least-once: the exporter resumes from the last acknowledged
//! sequence and the receiver deduplicates by `event_id`. Every batch carries an
//! HMAC over the exact body so the receiver can reject tampering in transit.

use serde::Serialize;

use crate::audit::signature::hmac_sha256_hex;
use crate::audit::AuditEvent;

pub const SIGNATURE_HEADER: &str = "x-dbx-audit-signature";

#[derive(Clone, Debug)]
pub struct AuditExporterConfig {
    pub url: String,
    pub hmac_key: Option<String>,
}

impl AuditExporterConfig {
    /// `DBX_AUDIT_EXPORT_URL` + `DBX_AUDIT_EXPORT_HMAC_KEY`.
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("DBX_AUDIT_EXPORT_URL").ok()?.trim().to_string();
        if url.is_empty() {
            return None;
        }
        let hmac_key = std::env::var("DBX_AUDIT_EXPORT_HMAC_KEY").ok().filter(|value| !value.trim().is_empty());
        Some(Self { url, hmac_key })
    }
}

/// One signed batch: the JSONL body and the signature header value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBatch {
    pub body: String,
    pub signature: Option<String>,
    pub last_seq: i64,
    pub count: usize,
}

#[derive(Serialize)]
struct Envelope<'a> {
    from_seq: i64,
    to_seq: i64,
    count: usize,
    events: &'a [AuditEvent],
}

/// Serializes a batch as a single JSON envelope (JSONL inside is not enough for
/// the receiver to verify the batch boundaries) and signs the exact bytes.
pub fn sign_batch(events: &[AuditEvent], hmac_key: Option<&str>) -> Result<SignedBatch, String> {
    let first = events.first().ok_or_else(|| "AUDIT_EXPORT_EMPTY".to_string())?;
    let last = events.last().ok_or_else(|| "AUDIT_EXPORT_EMPTY".to_string())?;
    let envelope = Envelope { from_seq: first.seq, to_seq: last.seq, count: events.len(), events };
    let body = serde_json::to_string(&envelope).map_err(|error| error.to_string())?;
    let signature = hmac_key.map(|key| format!("sha256={}", hmac_sha256_hex(key.as_bytes(), body.as_bytes())));
    Ok(SignedBatch { body, signature, last_seq: last.seq, count: events.len() })
}

/// Posts one batch. Returns only on a 2xx response; the caller advances the
/// export cursor after this call succeeds.
pub async fn post_batch(
    client: &reqwest::Client,
    config: &AuditExporterConfig,
    batch: &SignedBatch,
) -> Result<(), String> {
    let mut request = client.post(&config.url).header("content-type", "application/json").body(batch.body.clone());
    if let Some(signature) = &batch.signature {
        request = request.header(SIGNATURE_HEADER, signature);
    }
    let response = request.send().await.map_err(|error| format!("AUDIT_EXPORT_REQUEST: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("AUDIT_EXPORT_STATUS: {}", response.status()));
    }
    Ok(())
}

/// A PostgreSQL sink. The table stores one row per event, with the complete
/// signed event as JSONB; `ON CONFLICT DO NOTHING` makes at-least-once delivery
/// idempotent on `event_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditPostgresConfig {
    pub url: String,
    pub table: String,
}

impl AuditPostgresConfig {
    pub fn new(url: impl Into<String>, table: impl Into<String>) -> Result<Self, String> {
        let table = table.into();
        validate_table_name(&table)?;
        Ok(Self { url: url.into(), table })
    }
}

fn validate_table_name(table: &str) -> Result<(), String> {
    if table.is_empty() || table.len() > 128 {
        return Err("AUDIT_EXPORT_PG_TABLE: table name must be 1-128 characters".to_string());
    }
    let parts: Vec<&str> = table.split('.').collect();
    if parts.len() > 2 {
        return Err("AUDIT_EXPORT_PG_TABLE: expected `table` or `schema.table`".to_string());
    }
    for part in parts {
        let mut chars = part.chars();
        let valid = chars.next().is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !valid {
            return Err(format!("AUDIT_EXPORT_PG_TABLE: invalid identifier `{part}`"));
        }
    }
    Ok(())
}

/// Where exported batches go. PostgreSQL wins when both are configured, so a
/// deployment can migrate from HTTP to a database sink without editing the
/// old variables.
#[derive(Clone, Debug)]
pub enum AuditExporter {
    Http(AuditExporterConfig),
    Postgres(AuditPostgresConfig),
}

impl AuditExporter {
    /// `DBX_AUDIT_EXPORT_POSTGRES_URL` (+ `..._TABLE`, default
    /// `dbx_audit_events`), otherwise `DBX_AUDIT_EXPORT_URL`.
    pub fn from_env() -> Result<Option<Self>, String> {
        if let Some(url) = env_non_empty("DBX_AUDIT_EXPORT_POSTGRES_URL") {
            let table = std::env::var("DBX_AUDIT_EXPORT_POSTGRES_TABLE")
                .ok()
                .filter(|table| !table.trim().is_empty())
                .unwrap_or_else(|| "dbx_audit_events".to_string());
            return Ok(Some(Self::Postgres(AuditPostgresConfig::new(url, table)?)));
        }
        Ok(AuditExporterConfig::from_env().map(Self::Http))
    }

    pub fn sink_name(&self) -> &'static str {
        match self {
            Self::Http(_) => "http_jsonl",
            Self::Postgres(_) => "postgres",
        }
    }

    /// Signs the batch with this sink's key. PostgreSQL rows carry the same
    /// body, so the signature field is unused there but the envelope is kept
    /// for identical cursor accounting.
    pub fn sign_batch(&self, events: &[AuditEvent]) -> Result<SignedBatch, String> {
        match self {
            Self::Http(config) => sign_batch(events, config.hmac_key.as_deref()),
            Self::Postgres(_) => sign_batch(events, None),
        }
    }

    pub async fn deliver(
        &self,
        client: &reqwest::Client,
        events: &[AuditEvent],
        batch: &SignedBatch,
    ) -> Result<(), String> {
        match self {
            Self::Http(config) => post_batch(client, config, batch).await,
            Self::Postgres(config) => deliver_postgres(config, events).await,
        }
    }
}

fn env_non_empty(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn postgres_tls_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("AUDIT_EXPORT_PG_TLS: {error}"))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

async fn deliver_postgres(config: &AuditPostgresConfig, events: &[AuditEvent]) -> Result<(), String> {
    if events.is_empty() {
        return Ok(());
    }
    let pg_config: tokio_postgres::Config =
        config.url.parse().map_err(|error| format!("AUDIT_EXPORT_PG_CONFIG: {error}"))?;
    let (mut client, connection) = pg_config
        .connect(tokio_postgres_rustls::MakeRustlsConnect::new(postgres_tls_config()?))
        .await
        .map_err(|error| format!("AUDIT_EXPORT_PG_CONNECT: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS {} (
                seq BIGINT PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                occurred_at TIMESTAMPTZ NOT NULL,
                actor_id TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                body JSONB NOT NULL,
                exported_at TIMESTAMPTZ NOT NULL DEFAULT now()
             )",
            config.table
        ))
        .await
        .map_err(|error| format!("AUDIT_EXPORT_PG_SCHEMA: {error}"))?;
    let insert = format!(
        "INSERT INTO {} (seq, event_id, occurred_at, actor_id, event_hash, prev_hash, body) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        config.table
    );
    let transaction = client.transaction().await.map_err(|error| format!("AUDIT_EXPORT_PG_TX: {error}"))?;
    let statement = transaction.prepare(&insert).await.map_err(|error| format!("AUDIT_EXPORT_PG_TX: {error}"))?;
    for event in events {
        let occurred_at = chrono::DateTime::parse_from_rfc3339(&event.event.occurred_at)
            .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
            .map_err(|error| format!("AUDIT_EXPORT_PG_TIMESTAMP: {error}"))?;
        let body = serde_json::to_value(event).map_err(|error| format!("AUDIT_EXPORT_PG_BODY: {error}"))?;
        let params: [&(dyn tokio_postgres::types::ToSql + Sync); 7] = [
            &event.seq,
            &event.event.event_id,
            &occurred_at,
            &event.event.actor.id,
            &event.event_hash,
            &event.prev_hash,
            &body,
        ];
        transaction.execute(&statement, &params).await.map_err(|error| format!("AUDIT_EXPORT_PG_INSERT: {error}"))?;
    }
    transaction.commit().await.map_err(|error| format!("AUDIT_EXPORT_PG_TX: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        Actor, AuditContext, AuditDecision, AuditEventInsert, AuditOperation, AuditOutcome, AuditSource,
    };

    fn event(seq: i64, id: &str) -> AuditEvent {
        let context = AuditContext {
            actor: Actor::bootstrap(),
            source: AuditSource::Web,
            client_ip: None,
            user_agent: None,
            request_id: None,
            execution_id: None,
        };
        let mut insert =
            AuditEventInsert::new(&context, AuditOperation::Query, AuditDecision::Allowed, AuditOutcome::Success);
        insert.event_id = id.to_string();
        AuditEvent { seq, event: insert, prev_hash: "prev".to_string(), event_hash: "hash".to_string() }
    }

    #[test]
    fn a_batch_carries_its_range_and_count() {
        let batch = sign_batch(&[event(3, "a"), event(4, "b")], None).unwrap();
        assert_eq!(batch.last_seq, 4);
        assert_eq!(batch.count, 2);
        assert!(batch.signature.is_none());
        let parsed: serde_json::Value = serde_json::from_str(&batch.body).unwrap();
        assert_eq!(parsed["from_seq"], 3);
        assert_eq!(parsed["to_seq"], 4);
        assert_eq!(parsed["count"], 2);
        assert_eq!(parsed["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn the_signature_covers_the_exact_body() {
        let events = [event(1, "a")];
        let signed = sign_batch(&events, Some("secret")).unwrap();
        let expected = format!("sha256={}", hmac_sha256_hex(b"secret", signed.body.as_bytes()));
        assert_eq!(signed.signature.as_deref(), Some(expected.as_str()));

        let other = sign_batch(&[event(1, "b")], Some("secret")).unwrap();
        assert_ne!(signed.signature, other.signature);
    }

    #[test]
    fn an_empty_batch_is_rejected() {
        assert_eq!(sign_batch(&[], None).unwrap_err(), "AUDIT_EXPORT_EMPTY");
    }

    #[test]
    fn postgres_table_names_are_validated() {
        assert!(AuditPostgresConfig::new("postgres://host/db", "dbx_audit_events").is_ok());
        assert!(AuditPostgresConfig::new("postgres://host/db", "audit.dbx_events").is_ok());
        assert!(AuditPostgresConfig::new("postgres://host/db", "events; DROP TABLE x").is_err());
        assert!(AuditPostgresConfig::new("postgres://host/db", "1events").is_err());
        assert!(AuditPostgresConfig::new("postgres://host/db", "").is_err());
        assert!(AuditPostgresConfig::new("postgres://host/db", "a.b.c").is_err());
    }

    #[test]
    fn each_sink_has_a_stable_cursor_name() {
        let http = AuditExporter::Http(AuditExporterConfig { url: "https://collector".to_string(), hmac_key: None });
        let postgres =
            AuditExporter::Postgres(AuditPostgresConfig::new("postgres://host/db", "dbx_audit_events").unwrap());
        assert_eq!(http.sink_name(), "http_jsonl");
        assert_eq!(postgres.sink_name(), "postgres");
        assert!(http.sign_batch(&[event(1, "a")]).is_ok());
        assert!(postgres.sign_batch(&[event(1, "a")]).unwrap().signature.is_none());
    }
}
