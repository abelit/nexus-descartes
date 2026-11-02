//! Approval notifications: generic webhook, DingTalk, and Feishu/Lark bots.
//!
//! Every payload deliberately omits SQL text: a receiver is outside the audit
//! boundary and should learn that a request needs attention, not what the
//! statement contains. Delivery is best-effort from the request path; a durable
//! outbox with retries remains a later step.

use base64::Engine;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde_json::json;

use crate::audit::signature::hmac_sha256_bytes;

pub const SIGNATURE_HEADER: &str = "x-dbx-approval-signature";

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct ApprovalWebhook {
    url: String,
    hmac_key: Option<String>,
    client: reqwest::Client,
}

impl ApprovalWebhook {
    fn from_env(client: &reqwest::Client) -> Option<Self> {
        let url = env_url("DBX_APPROVAL_WEBHOOK_URL")?;
        let hmac_key = std::env::var("DBX_APPROVAL_WEBHOOK_HMAC_KEY").ok().filter(|key| !key.trim().is_empty());
        Some(Self { url, hmac_key, client: client.clone() })
    }

    pub async fn send(&self, event: &str, payload: serde_json::Value) -> Result<(), String> {
        let body = envelope(event, &payload).to_string();
        let mut request = self.client.post(&self.url).header("content-type", "application/json").body(body.clone());
        if let Some(key) = &self.hmac_key {
            request = request.header(
                SIGNATURE_HEADER,
                format!("sha256={}", crate::audit::signature::hmac_sha256_hex(key.as_bytes(), body.as_bytes())),
            );
        }
        // `without_url` keeps the webhook token out of the log: the receiver URL
        // is a bearer secret.
        let response =
            request.send().await.map_err(|error| format!("APPROVAL_WEBHOOK_REQUEST: {}", error.without_url()))?;
        if !response.status().is_success() {
            return Err(format!("APPROVAL_WEBHOOK_STATUS: {}", response.status()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChatKind {
    DingTalk,
    Feishu,
}

#[derive(Clone, Debug)]
struct ChatChannel {
    kind: ChatKind,
    url: String,
    secret: Option<String>,
    client: reqwest::Client,
}

impl ChatChannel {
    fn from_env(client: &reqwest::Client, kind: ChatKind) -> Option<Self> {
        let (url_var, secret_var) = match kind {
            ChatKind::DingTalk => ("DBX_APPROVAL_DINGTALK_WEBHOOK_URL", "DBX_APPROVAL_DINGTALK_SECRET"),
            ChatKind::Feishu => ("DBX_APPROVAL_FEISHU_WEBHOOK_URL", "DBX_APPROVAL_FEISHU_SECRET"),
        };
        let url = env_url(url_var)?;
        let secret = std::env::var(secret_var).ok().filter(|secret| !secret.trim().is_empty());
        Some(Self { kind, url, secret, client: client.clone() })
    }

    async fn send(&self, event: &str, payload: &serde_json::Value) -> Result<(), String> {
        let text = summary_text(event, payload);
        let (url, body) = match self.kind {
            ChatKind::DingTalk => {
                let timestamp_ms = chrono::Utc::now().timestamp_millis();
                let url = match &self.secret {
                    Some(secret) => dingtalk_signed_url(&self.url, secret, timestamp_ms),
                    None => self.url.clone(),
                };
                (url, json!({ "msgtype": "text", "text": { "content": text } }))
            }
            ChatKind::Feishu => {
                let mut body = json!({ "msg_type": "text", "content": { "text": text } });
                if let Some(secret) = &self.secret {
                    let timestamp_secs = chrono::Utc::now().timestamp();
                    body["timestamp"] = json!(timestamp_secs.to_string());
                    body["sign"] = json!(feishu_sign(secret, timestamp_secs));
                }
                (self.url.clone(), body)
            }
        };
        let response = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|error| format!("APPROVAL_CHAT_REQUEST: {}", error.without_url()))?;
        if !response.status().is_success() {
            return Err(format!("APPROVAL_CHAT_STATUS: {}", response.status()));
        }
        let body = response.text().await.unwrap_or_default();
        check_chat_response(self.kind, &body)
    }
}

fn check_chat_response(kind: ChatKind, body: &str) -> Result<(), String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Ok(());
    };
    let code = match kind {
        ChatKind::DingTalk => value.get("errcode").and_then(serde_json::Value::as_i64),
        ChatKind::Feishu => value.get("code").or_else(|| value.get("StatusCode")).and_then(serde_json::Value::as_i64),
    };
    match code {
        Some(0) | None => Ok(()),
        Some(code) => {
            let message = value
                .get("errmsg")
                .or_else(|| value.get("msg"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error");
            Err(format!("APPROVAL_CHAT_REJECTED: {code} {message}"))
        }
    }
}

/// Fan-out over every configured channel. Each error is returned separately so
/// one failing receiver cannot hide another channel's result.
#[derive(Clone, Debug, Default)]
pub struct ApprovalNotifier {
    webhook: Option<ApprovalWebhook>,
    dingtalk: Option<ChatChannel>,
    feishu: Option<ChatChannel>,
}

impl ApprovalNotifier {
    pub fn from_env() -> Self {
        let Ok(client) = reqwest::Client::builder().timeout(REQUEST_TIMEOUT).build() else {
            return Self::default();
        };
        Self {
            webhook: ApprovalWebhook::from_env(&client),
            dingtalk: ChatChannel::from_env(&client, ChatKind::DingTalk),
            feishu: ChatChannel::from_env(&client, ChatKind::Feishu),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.webhook.is_some() || self.dingtalk.is_some() || self.feishu.is_some()
    }

    pub async fn send(&self, event: &str, payload: &serde_json::Value) -> Vec<String> {
        let mut errors = Vec::new();
        if let Some(webhook) = &self.webhook {
            if let Err(error) = webhook.send(event, payload.clone()).await {
                errors.push(format!("webhook: {error}"));
            }
        }
        if let Some(channel) = &self.dingtalk {
            if let Err(error) = channel.send(event, payload).await {
                errors.push(format!("dingtalk: {error}"));
            }
        }
        if let Some(channel) = &self.feishu {
            if let Err(error) = channel.send(event, payload).await {
                errors.push(format!("feishu: {error}"));
            }
        }
        errors
    }
}

fn env_url(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn envelope(event: &str, payload: &serde_json::Value) -> serde_json::Value {
    json!({ "event": event, "sent_at_ms": chrono::Utc::now().timestamp_millis(), "approval": payload })
}

/// Human-readable summary for chat bots. Mirrors the structured payload and
/// never includes SQL text.
fn summary_text(event: &str, payload: &serde_json::Value) -> String {
    let text = |key: &str| payload.get(key).and_then(serde_json::Value::as_str).unwrap_or("-").to_string();
    let rules = payload
        .get("rule_ids")
        .and_then(serde_json::Value::as_array)
        .map(|rules| rules.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let count = payload.get("statement_count").and_then(serde_json::Value::as_i64).unwrap_or(0);
    format!(
        "[DBX] {event}\nrequest: {}\nstatus: {}\nrequester: {}\nconnection: {} / {}\nstatements: {count}\nrules: {}",
        text("request_id"),
        text("status"),
        text("requester_id"),
        text("connection_id"),
        text("database"),
        if rules.is_empty() { "-".to_string() } else { rules },
    )
}

/// DingTalk custom-robot signing: `sign` is the URL-encoded base64 HMAC of
/// `timestamp\nsecret` keyed by the secret, appended to the webhook URL.
pub fn dingtalk_signed_url(base: &str, secret: &str, timestamp_ms: i64) -> String {
    let string_to_sign = format!("{timestamp_ms}\n{secret}");
    let sign = base64::engine::general_purpose::STANDARD
        .encode(hmac_sha256_bytes(secret.as_bytes(), string_to_sign.as_bytes()));
    let encoded = utf8_percent_encode(&sign, NON_ALPHANUMERIC).to_string();
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}timestamp={timestamp_ms}&sign={encoded}")
}

/// Feishu/Lark custom-bot signing: `base64(HMAC-SHA256(key = timestamp\nsecret,
/// message = ""))`, carried in the JSON body with the timestamp in seconds.
pub fn feishu_sign(secret: &str, timestamp_secs: i64) -> String {
    let key = format!("{timestamp_secs}\n{secret}");
    base64::engine::general_purpose::STANDARD.encode(hmac_sha256_bytes(key.as_bytes(), b""))
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

    #[test]
    fn the_chat_summary_contains_the_context_but_not_sql() {
        let payload = approval_payload("r1", "pending", "alice", "conn", "app", &["rule".to_string()], 1);
        let summary = summary_text("approval.created", &payload);
        assert!(summary.contains("approval.created"));
        assert!(summary.contains("request: r1"));
        assert!(summary.contains("rules: rule"));
        assert!(!summary.contains("SQL"));
    }

    #[test]
    fn dingtalk_signing_appends_an_encoded_signature() {
        let url =
            dingtalk_signed_url("https://oapi.dingtalk.com/robot/send?access_token=t", "secret", 1_700_000_000_000);
        assert!(url.starts_with("https://oapi.dingtalk.com/robot/send?access_token=t&timestamp=1700000000000&sign="));
        let sign = url.split("&sign=").nth(1).unwrap();
        assert!(!sign.contains('+') && !sign.contains('/') && !sign.contains('='));
        assert_eq!(feishu_sign("secret", 1_700_000_000), feishu_sign("secret", 1_700_000_000));
        assert_ne!(feishu_sign("secret", 1_700_000_000), feishu_sign("secret", 1_700_000_001));
    }
}
