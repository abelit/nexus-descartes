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
}
