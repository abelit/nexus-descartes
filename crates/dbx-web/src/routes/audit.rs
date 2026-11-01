use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dbx_core::audit::{
    Actor, AuditChainHead, AuditChainReport, AuditContext, AuditDecision, AuditEventInsert, AuditOperation,
    AuditOutcome, AuditPage, AuditQuery, AuditSource,
};
use serde::Deserialize;

use crate::error::AppError;
use crate::state::WebState;

/// `DBX_AUDIT_BOOTSTRAP_TOKEN`
const ENV_AUDIT_BOOTSTRAP_TOKEN: &str = "DBX_AUDIT_BOOTSTRAP_TOKEN";
/// Header carrying the bootstrap token.
const AUDIT_TOKEN_HEADER: &str = "x-dbx-audit-token";

/// Gate for the audit API.
///
/// A session whose roles include the required permission passes. Otherwise the
/// bootstrap token (or loopback when no token is configured) is the fallback
/// for automation and first-run access.
///
/// Deployments behind a reverse proxy on the same host see the peer as
/// loopback; such deployments **must** set `DBX_AUDIT_BOOTSTRAP_TOKEN`,
/// otherwise the proxy makes the audit log readable to every client.
pub async fn require_audit_access(
    State(state): State<Arc<WebState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
    let required = required_permission(req.uri().path(), req.method());

    if let Some(actor) = req.extensions().get::<Actor>() {
        if dbx_core::identity::has_permission(&actor.roles, required) {
            record_audit_read(&state, &req);
            return next.run(req).await;
        }
    }

    let expected = std::env::var(ENV_AUDIT_BOOTSTRAP_TOKEN)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match expected {
        Some(expected) => {
            let provided = req.headers().get(AUDIT_TOKEN_HEADER).and_then(|value| value.to_str().ok()).map(str::trim);
            if !provided.is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes())) {
                return denied("audit bootstrap token required");
            }
        }
        None => {
            let loopback = peer.is_some_and(|addr| addr.ip().is_loopback());
            if !loopback {
                return denied("audit permission required");
            }
        }
    }

    record_audit_read(&state, &req);
    next.run(req).await
}

/// Export is a separate permission, and verification is read-only but stronger
/// than browsing, so each endpoint maps to its own code.
fn required_permission(path: &str, method: &axum::http::Method) -> dbx_core::identity::Permission {
    use dbx_core::identity::Permission;
    let path = path.trim_end_matches('/');
    if path.ends_with("/audit/export") {
        return Permission::AuditExport;
    }
    if path.ends_with("/audit/verify") || path.ends_with("/audit/verify-checkpoint") {
        return Permission::AuditVerify;
    }
    if path.ends_with("/audit/checkpoints") && *method != axum::http::Method::GET {
        return Permission::AuditVerify;
    }
    Permission::AuditRead
}

fn denied(reason: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"))],
        format!("AUDIT_ACCESS_DENIED: {reason}"),
    )
        .into_response()
}

/// Reading the audit log is itself an audited action.
fn record_audit_read(state: &WebState, req: &Request<axum::body::Body>) {
    let actor = req.extensions().get::<Actor>().cloned().unwrap_or_else(Actor::bootstrap);
    let context = AuditContext {
        actor,
        source: AuditSource::Web,
        client_ip: None,
        user_agent: req.headers().get(header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_string),
        request_id: req.headers().get("x-request-id").and_then(|value| value.to_str().ok()).map(str::to_string),
        execution_id: None,
    };
    let mut event =
        AuditEventInsert::new(&context, AuditOperation::Admin, AuditDecision::Allowed, AuditOutcome::Success);
    event.resource_type = Some("audit".to_string());
    event.request_path = Some(req.uri().path().to_string());
    event.request_method = Some(req.method().as_str().to_string());
    event.details_json = Some(serde_json::json!({ "meta": true }).to_string());
    state.app.record_audit(event);
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditEventsQuery {
    pub actor_id: Option<String>,
    pub connection_id: Option<String>,
    pub database: Option<String>,
    pub operation: Option<String>,
    pub decision: Option<String>,
    pub outcome: Option<String>,
    pub sql_contains: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub cursor_seq: Option<i64>,
    pub limit: Option<usize>,
}

impl AuditEventsQuery {
    fn into_filter(&self) -> Result<AuditQuery, AppError> {
        Ok(AuditQuery {
            actor_id: self.actor_id.clone(),
            connection_id: self.connection_id.clone(),
            database: self.database.clone(),
            operation: self.operation.as_deref().map(parse_operation).transpose()?,
            decision: self.decision.as_deref().map(parse_decision).transpose()?,
            outcome: self.outcome.as_deref().map(parse_outcome).transpose()?,
            sql_contains: self.sql_contains.clone(),
            from_ms: self.from_ms,
            to_ms: self.to_ms,
            cursor_seq: self.cursor_seq,
            limit: self.limit,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditStatsQuery {
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditExportQuery {
    pub format: Option<String>,
    #[serde(flatten)]
    pub filter: AuditEventsQuery,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditVerifyQuery {
    pub from_seq: Option<i64>,
    pub to_seq: Option<i64>,
}

/// Read-only audit API. Reached only through [`require_audit_access`], which
/// enforces the bootstrap token / loopback gate until Phase B supplies roles.
pub async fn list_events(
    State(state): State<Arc<WebState>>,
    Query(query): Query<AuditEventsQuery>,
) -> Result<Json<AuditPage>, AppError> {
    let query = query.into_filter()?;
    state.app.storage.query_audit_events(query).await.map(Json).map_err(AppError::from)
}

pub async fn event_detail(
    State(state): State<Arc<WebState>>,
    axum::extract::Path(event_id): axum::extract::Path<String>,
) -> Result<Json<dbx_core::audit::AuditEvent>, AppError> {
    state
        .app
        .storage
        .audit_event_by_id(event_id.clone())
        .await
        .map_err(AppError::from)?
        .map(Json)
        .ok_or_else(|| AppError::not_found(format!("Audit event '{event_id}' not found")))
}

pub async fn stats(
    State(state): State<Arc<WebState>>,
    Query(query): Query<AuditStatsQuery>,
) -> Result<Json<dbx_core::audit::AuditStats>, AppError> {
    state.app.storage.audit_stats(query.from_ms, query.to_ms).await.map(Json).map_err(AppError::from)
}

/// Upper bound for one export; the audit log must not be exfiltrated in a
/// single unbounded request.
const EXPORT_PAGE_SIZE: usize = 500;
const EXPORT_MAX_EVENTS: usize = 500_000;

pub async fn export_events(
    State(state): State<Arc<WebState>>,
    Query(query): Query<AuditExportQuery>,
) -> Result<Response, AppError> {
    let format = match query.format.as_deref().unwrap_or("jsonl") {
        "jsonl" | "ndjson" => ExportFormat::Jsonl,
        "csv" => ExportFormat::Csv,
        other => return Err(AppError::bad_request(format!("Unsupported audit export format '{other}'"))),
    };
    let mut filter = query.filter.into_filter()?;
    filter.cursor_seq = None;
    filter.limit = Some(EXPORT_PAGE_SIZE);

    let storage = state.app.storage.clone();
    let stream = async_stream::stream! {
        let mut exported = 0usize;
        if format == ExportFormat::Csv {
            yield Ok::<String, std::io::Error>(csv_line(&[
                "seq", "occurred_at", "actor_id", "source", "connection_id", "database", "operation",
                "decision", "outcome", "risk_level", "rule_id", "sql_digest", "sql_text", "error_message",
            ]));
        }
        loop {
            let page_filter = filter.clone();
            let page = match storage.query_audit_events(page_filter).await {
                Ok(page) => page,
                Err(error) => {
                    yield Err(std::io::Error::other(error));
                    break;
                }
            };
            if page.events.is_empty() {
                break;
            }
            let next_cursor = page.next_cursor;
            for event in page.events {
                exported += 1;
                match format {
                    ExportFormat::Jsonl => {
                        match serde_json::to_string(&event) {
                            Ok(line) => yield Ok(format!("{line}\n")),
                            Err(error) => {
                                yield Err(std::io::Error::other(error.to_string()));
                                return;
                            }
                        }
                    }
                    ExportFormat::Csv => {
                        let inner = &event.event;
                        yield Ok(csv_line(&[
                            &event.seq.to_string(),
                            &inner.occurred_at,
                            &inner.actor.id,
                            inner.source.as_str(),
                            inner.connection_id.as_deref().unwrap_or_default(),
                            inner.database.as_deref().unwrap_or_default(),
                            inner.operation.as_str(),
                            inner.decision.as_str(),
                            inner.outcome.as_str(),
                            inner.risk_level.as_deref().unwrap_or_default(),
                            inner.rule_id.as_deref().unwrap_or_default(),
                            inner.sql_digest.as_deref().unwrap_or_default(),
                            inner.sql_text.as_deref().unwrap_or_default(),
                            inner.error_message.as_deref().unwrap_or_default(),
                        ]));
                    }
                }
                if exported >= EXPORT_MAX_EVENTS {
                    break;
                }
            }
            match next_cursor {
                Some(cursor) if exported < EXPORT_MAX_EVENTS => filter.cursor_seq = Some(cursor),
                _ => break,
            }
        }
    };

    let content_type = match format {
        ExportFormat::Jsonl => "application/x-ndjson; charset=utf-8",
        ExportFormat::Csv => "text/csv; charset=utf-8",
    };
    let filename = match format {
        ExportFormat::Jsonl => "audit-events.jsonl",
        ExportFormat::Csv => "audit-events.csv",
    };
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\""))
        .body(axum::body::Body::from_stream(stream))
        .map_err(|error| AppError::internal(error.to_string()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    Jsonl,
    Csv,
}

/// CSV cell escaping, including spreadsheet formula injection: a cell starting
/// with `=`, `+`, `-` or `@` is prefixed with a quote so Excel does not execute
/// it as a formula.
fn csv_line(fields: &[&str]) -> String {
    let mut line = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            line.push(',');
        }
        let escaped = field.replace('"', "\"\"");
        let needs_prefix = matches!(escaped.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'));
        if needs_prefix {
            line.push('\'');
        }
        line.push('"');
        line.push_str(&escaped);
        line.push('"');
    }
    line.push('\n');
    line
}

pub async fn chain_head(State(state): State<Arc<WebState>>) -> Result<Json<AuditChainHead>, AppError> {
    state.app.storage.audit_chain_head().await.map(Json).map_err(AppError::from)
}

pub async fn checkpoints(
    State(state): State<Arc<WebState>>,
) -> Result<Json<Vec<dbx_core::audit::AuditCheckpoint>>, AppError> {
    state.app.storage.audit_checkpoints(100).await.map(Json).map_err(AppError::from)
}

pub async fn create_checkpoint(
    State(state): State<Arc<WebState>>,
) -> Result<Json<dbx_core::audit::AuditCheckpoint>, AppError> {
    state.app.storage.create_audit_checkpoint().await.map(Json).map_err(AppError::from)
}

pub async fn verify_from_checkpoint(
    State(state): State<Arc<WebState>>,
) -> Result<Json<dbx_core::audit::AuditCheckpointReport>, AppError> {
    state.app.storage.verify_audit_chain_from_checkpoint().await.map(Json).map_err(AppError::from)
}

pub async fn verify_chain(
    State(state): State<Arc<WebState>>,
    Query(query): Query<AuditVerifyQuery>,
) -> Result<Json<AuditChainReport>, AppError> {
    state.app.storage.verify_audit_chain(query.from_seq, query.to_seq).await.map(Json).map_err(AppError::from)
}

fn parse_operation(value: &str) -> Result<AuditOperation, AppError> {
    match value {
        "query" => Ok(AuditOperation::Query),
        "dml" => Ok(AuditOperation::Dml),
        "ddl" => Ok(AuditOperation::Ddl),
        "transaction" => Ok(AuditOperation::Transaction),
        "export" => Ok(AuditOperation::Export),
        "import" => Ok(AuditOperation::Import),
        "backup" => Ok(AuditOperation::Backup),
        "config" => Ok(AuditOperation::Config),
        "connection" => Ok(AuditOperation::Connection),
        "auth" => Ok(AuditOperation::Auth),
        "policy" => Ok(AuditOperation::Policy),
        "approval" => Ok(AuditOperation::Approval),
        "admin" => Ok(AuditOperation::Admin),
        other => Err(AppError::bad_request(format!("Unknown audit operation '{other}'"))),
    }
}

fn parse_decision(value: &str) -> Result<AuditDecision, AppError> {
    match value {
        "allowed" => Ok(AuditDecision::Allowed),
        "denied" => Ok(AuditDecision::Denied),
        "warned" => Ok(AuditDecision::Warned),
        "approval_required" => Ok(AuditDecision::ApprovalRequired),
        "blocked" => Ok(AuditDecision::Blocked),
        "error" => Ok(AuditDecision::Error),
        other => Err(AppError::bad_request(format!("Unknown audit decision '{other}'"))),
    }
}

fn parse_outcome(value: &str) -> Result<AuditOutcome, AppError> {
    match value {
        "success" => Ok(AuditOutcome::Success),
        "error" => Ok(AuditOutcome::Error),
        "canceled" => Ok(AuditOutcome::Canceled),
        "unknown" => Ok(AuditOutcome::Unknown),
        "not_started" => Ok(AuditOutcome::NotStarted),
        other => Err(AppError::bad_request(format!("Unknown audit outcome '{other}'"))),
    }
}
