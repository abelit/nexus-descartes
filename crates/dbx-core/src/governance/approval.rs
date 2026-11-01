//! Approval requests and one-time execution tokens.
//!
//! An approval is bound to exactly what was reviewed: the connection (including
//! its configuration), the schema, the full statement list, the policy bundle,
//! and the rule IDs that required approval. Editing any of them invalidates the
//! token, and a token only satisfies the rule it was issued for.

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
    Executed,
    ExecutionFailed,
}

impl ApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Executed => "executed",
            Self::ExecutionFailed => "execution_failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            "expired" => Some(Self::Expired),
            "cancelled" => Some(Self::Cancelled),
            "executed" => Some(Self::Executed),
            "execution_failed" => Some(Self::ExecutionFailed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub id: String,
    pub request_type: String,
    pub status: ApprovalStatus,
    pub requester_id: String,
    pub connection_id: String,
    pub database: String,
    pub schema_name: Option<String>,
    pub sql_text: String,
    pub sql_digest: String,
    pub statement_count: i64,
    pub risk_level: Option<String>,
    pub rule_ids: Vec<String>,
    pub policy_bundle_hash: Option<String>,
    pub justification: String,
    pub request_hash: String,
    pub expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub executed_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalToken {
    pub id: String,
    pub request_id: String,
    pub token_hash: String,
    pub actor_id: String,
    pub request_hash: String,
    pub expires_at_ms: i64,
    pub consumed_at_ms: Option<i64>,
}

/// Inputs an approval is bound to. All of them come from the server, never
/// from the request body alone.
pub struct ApprovalBinding<'a> {
    pub connection_id: &'a str,
    /// Stable hash of the connection configuration (host, port, user, TLS,
    /// read-only and production markers, ...).
    pub connection_config_hash: &'a str,
    pub database: &'a str,
    pub schema: Option<&'a str>,
    /// Digest of the complete, ordered statement list.
    pub statements_digest: &'a str,
    pub policy_bundle_hash: Option<&'a str>,
    /// The rules that required approval, sorted and deduplicated.
    pub rule_ids: &'a [String],
}

/// Stable hash of everything a connection's identity depends on, so editing
/// the connection (host, port, user, TLS, production marker, ...) invalidates
/// issued approvals. Used by both the approval API and the execution funnel so
/// the two sides can never disagree.
pub fn connection_config_hash(config: &crate::models::connection::ConnectionConfig) -> String {
    serde_json::to_string(config)
        .map(|json| sha256_hex(json.as_bytes()))
        .unwrap_or_else(|_| sha256_hex(config.id.as_bytes()))
}

/// Deterministic binding hash. Changing a character of SQL, the connection
/// configuration, or the policy bundle changes the hash and invalidates the
/// token.
pub fn request_hash(binding: &ApprovalBinding<'_>) -> String {
    let mut rule_ids = binding.rule_ids.to_vec();
    rule_ids.sort();
    rule_ids.dedup();
    let canonical = serde_json::json!({
        "v": 1,
        "connection_id": binding.connection_id,
        "connection_config_hash": binding.connection_config_hash,
        "database": binding.database,
        "schema": binding.schema,
        "statements_digest": binding.statements_digest,
        "policy_bundle_hash": binding.policy_bundle_hash,
        "rule_ids": rule_ids,
    });
    hex_sha256(canonical.to_string().as_bytes())
}

/// Digest of the ordered statement list that the approver reviewed.
pub fn statements_digest(statements: &[String]) -> String {
    let mut hasher = Sha256::new();
    for statement in statements {
        hasher.update(statement.trim().as_bytes());
        hasher.update(b"\n");
    }
    hex(&hasher.finalize())
}

pub fn new_approval_token() -> (String, String) {
    let raw = uuid::Uuid::new_v4().to_string();
    let hash = sha256_hex(raw.as_bytes());
    (raw, hash)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex_sha256(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Checks a token against the execution it is about to authorize.
pub fn token_authorizes(token: &ApprovalToken, actor_id: &str, request_hash: &str, now_ms: i64) -> Result<(), String> {
    if token.consumed_at_ms.is_some() {
        return Err("APPROVAL_TOKEN_ALREADY_USED".to_string());
    }
    if now_ms >= token.expires_at_ms {
        return Err("APPROVAL_TOKEN_EXPIRED".to_string());
    }
    if token.actor_id != actor_id {
        return Err("APPROVAL_TOKEN_WRONG_ACTOR".to_string());
    }
    if token.request_hash != request_hash {
        return Err("APPROVAL_TOKEN_BINDING_MISMATCH".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding<'a>(rules: &'a [String], digest: &'a str) -> ApprovalBinding<'a> {
        ApprovalBinding {
            connection_id: "conn-1",
            connection_config_hash: "cfg-hash",
            database: "app",
            schema: Some("public"),
            statements_digest: digest,
            policy_bundle_hash: Some("bundle-1"),
            rule_ids: rules,
        }
    }

    fn token(request_hash: &str, actor: &str) -> ApprovalToken {
        ApprovalToken {
            id: "t1".to_string(),
            request_id: "r1".to_string(),
            token_hash: "hash".to_string(),
            actor_id: actor.to_string(),
            request_hash: request_hash.to_string(),
            expires_at_ms: 10_000,
            consumed_at_ms: None,
        }
    }

    #[test]
    fn the_binding_hash_is_stable_and_order_insensitive_for_rules() {
        let rules = vec!["a".to_string(), "b".to_string()];
        let reversed = vec!["b".to_string(), "a".to_string(), "a".to_string()];
        let first = request_hash(&binding(&rules, "d1"));
        let second = request_hash(&binding(&reversed, "d1"));
        assert_eq!(first, second);
    }

    #[test]
    fn every_binding_field_changes_the_hash() {
        let rules = vec!["r1".to_string()];
        let base = request_hash(&binding(&rules, "d1"));
        assert_ne!(base, request_hash(&ApprovalBinding { database: "other", ..binding(&rules, "d1") }));
        assert_ne!(base, request_hash(&ApprovalBinding { schema: None, ..binding(&rules, "d1") }));
        assert_ne!(base, request_hash(&ApprovalBinding { connection_config_hash: "cfg-2", ..binding(&rules, "d1") }));
        assert_ne!(base, request_hash(&ApprovalBinding { policy_bundle_hash: None, ..binding(&rules, "d1") }));
        assert_ne!(base, request_hash(&binding(&rules, "d2")));
        assert_ne!(base, request_hash(&binding(&["r2".to_string()], "d1")));
    }

    #[test]
    fn the_statements_digest_tracks_content() {
        let statements = vec!["UPDATE users SET name = 'a' WHERE id = 1".to_string()];
        assert_eq!(statements_digest(&statements), statements_digest(&statements.clone()));
        let mut changed = statements.clone();
        changed[0] = "UPDATE users SET name = 'b' WHERE id = 1".to_string();
        assert_ne!(statements_digest(&statements), statements_digest(&changed));
    }

    #[test]
    fn a_token_only_authorizes_its_own_binding_and_actor() {
        let hash = request_hash(&binding(&["r1".to_string()], "d1"));
        let token = token(&hash, "alice");
        assert!(token_authorizes(&token, "alice", &hash, 5_000).is_ok());
        assert_eq!(token_authorizes(&token, "bob", &hash, 5_000).unwrap_err(), "APPROVAL_TOKEN_WRONG_ACTOR");
        assert_eq!(
            token_authorizes(&token, "alice", "other-hash", 5_000).unwrap_err(),
            "APPROVAL_TOKEN_BINDING_MISMATCH"
        );
    }

    #[test]
    fn a_token_expires_and_can_only_be_used_once() {
        let hash = request_hash(&binding(&["r1".to_string()], "d1"));
        let mut token = token(&hash, "alice");
        assert_eq!(token_authorizes(&token, "alice", &hash, 10_000).unwrap_err(), "APPROVAL_TOKEN_EXPIRED");
        token.consumed_at_ms = Some(1);
        assert_eq!(token_authorizes(&token, "alice", &hash, 5_000).unwrap_err(), "APPROVAL_TOKEN_ALREADY_USED");
    }

    #[test]
    fn a_new_token_returns_the_raw_secret_and_its_hash() {
        let (raw, hash) = new_approval_token();
        assert_ne!(raw, hash);
        assert_eq!(hash, sha256_hex(raw.as_bytes()));
        assert_eq!(hash.len(), 64);
    }
}
