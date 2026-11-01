//! Request-level audit for non-SQL operations.
//!
//! Schema changes, imports, exports, plugin and settings changes do not all
//! pass through the SQL statement instrumentation — many reach the driver
//! directly. Recording one HTTP event per mutating API request closes that gap
//! without pretending each generated statement was observed.
//!
//! SQL endpoints keep their statement-level events; both carry the same
//! `request_id`, so a reader can correlate them instead of double-counting.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use dbx_core::audit::{
    current_audit_context, Actor, AuditContext, AuditDecision, AuditEventInsert, AuditOperation, AuditOutcome,
    AuditSource,
};

use crate::state::WebState;

/// Endpoints that write their own domain events. Recording them here as well
/// would create two unrelated rows for one action.
fn records_its_own_event(path: &str) -> bool {
    let suffix = path.rsplit("/api/").next().unwrap_or(path);
    suffix.starts_with("auth/") || suffix.starts_with("audit/")
}

/// Mutating requests are audited even when the handler fails: a rejected
/// attempt to drop a table is exactly what an audit trail must show.
pub async fn http_audit_middleware(
    State(state): State<Arc<WebState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let recordable = !(method == Method::GET || method == Method::HEAD || method == Method::OPTIONS);
    let path = req.uri().path().to_string();
    let should_record = recordable && !records_its_own_event(&path);
    let actor = req.extensions().get::<Actor>().cloned();
    let started = Instant::now();
    let response = next.run(req).await;
    if !should_record {
        return response;
    }
    let status = response.status().as_u16();
    let duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);

    let context = match current_audit_context() {
        Some(context) => context,
        None => AuditContext {
            actor: actor.unwrap_or_else(Actor::system),
            source: AuditSource::Web,
            client_ip: None,
            user_agent: None,
            request_id: None,
            execution_id: None,
        },
    };
    let (decision, outcome) = match status {
        401 | 403 => (AuditDecision::Denied, AuditOutcome::Error),
        500..=599 => (AuditDecision::Error, AuditOutcome::Error),
        _ => (AuditDecision::Allowed, AuditOutcome::Success),
    };
    let mut event = AuditEventInsert::new(&context, AuditOperation::Admin, decision, outcome);
    event.event_type = "http".to_string();
    event.resource_type = Some("http".to_string());
    event.resource_id = Some(path.clone());
    event.request_method = Some(method.as_str().to_string());
    event.request_path = Some(path);
    event.http_status = Some(i64::from(status));
    event.duration_ms = Some(duration_ms);
    event.details_json = Some(
        serde_json::json!({
            "http": true,
            "status": status,
        })
        .to_string(),
    );
    state.app.record_audit(event);
    response
}
