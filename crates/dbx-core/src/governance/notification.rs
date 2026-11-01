//! Approval notifications over a generic webhook.
//!
//! The payload deliberately omits SQL text: a webhook receiver is outside the
//! audit boundary and should learn that a request needs attention, not what the
//! statement contains. Delivery is best-effort from the request path; a durable
//! outbox with retries is a later step.

use serde_json::json;

use crate::audit::signature::hmac_sha256_hex;

pub const SIGNATURE_HEADER: &str = "x-dbx-approval-signature";

#[derive(Clone, Debug)]
pub struct ApprovalWebhook {
    url: String,
    hmac_key: Option<String>,
    client: reqwest::Client,
}

impl ApprovalWebhook {
    /// `DBX_APPROVAL_WEBHOOK_URL` (optional `DBX_APPROVAL_WEBHOOK_HMAC_KEY`).
    pub fn from_env() -> Option<Self> {
        let url = std::env::var("DBX_APPROVAL_WEBHOOK_URL").ok()?.trim().to_string();
        if url.is_empty() {
            return None;
        }
        let hmac_key = std::env::var("DBX_APPROVAL_WEBHOOK_HMAC_KEY").ok().filter(|key| !key.trim().is_empty());
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build().ok()?;
        Some(Self { url, hmac_key, client })
    }

    pub async fn send(&self, event: &str, payload: serde_json::Value) -> Result<(), String> {
        let body = json!({ "event": event, "sent_at_ms": chrono::Utc::now().timestamp_millis(), "approval": payload })
            .to_string();
        let mut request = self.client.post(&self.url).header("content-type", "application/json").body(body.clone());
        if let Some(key) = &self.hmac_key {
            request = request
                .header(SIGNATURE_HEADER, format!("sha256={}", hmac_sha256_hex(key.as_bytes(), body.as_bytes())));
        }
        let response = request.send().await.map_err(|error| format!("APPROVAL_WEBHOOK_REQUEST: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("APPROVAL_WEBHOOK_STATUS: {}", response.status()));
        }
        Ok(())
    }
}

/// Payload shared by every approval event.
pub fn approval_payload(
    request_id: &str,
    status: &str,
    requester_id: &str,
    connection_id: &str,
    database: &str,
    rule_ids: &[String],
    statement_count: i64,
) -> serde_json::Value {
    json!({
        "request_id": request_id,
        "status": status,
        "requester_id": requester_id,
        "connection_id": connection_id,
        "database": database,
        "rule_ids": rule_ids,
        "statement_count": statement_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_carries_context_but_not_sql() {
        let payload = approval_payload("r1", "pending", "alice", "conn", "app", &["prod.ddl.approval".to_string()], 2);
        assert_eq!(payload["request_id"], "r1");
        assert_eq!(payload["rule_ids"][0], "prod.ddl.approval");
        assert_eq!(payload["statement_count"], 2);
        assert!(payload.get("sql_text").is_none());
        assert!(payload.get("sql").is_none());
    }
}
