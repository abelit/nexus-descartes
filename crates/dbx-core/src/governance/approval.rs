//! Approval requests and one-time execution tokens.
//!
//! An approval is bound to exactly what was reviewed: the connection (including
//! its configuration), the schema, the full statement list, the policy bundle,
//! and the rule IDs that required approval. Editing any of them invalidates the
//! token, and a token only satisfies the rule it was issued for.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Upper bound on template steps. Each step is one approval round; keeping the
/// number small stops a misconfigured template from producing an approval chain
/// nobody can finish.
pub const MAX_APPROVAL_STEPS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    /// An execution attempt owns the request. The CAS from `approved` makes an
    /// approval executable at most once.
    Executing,
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
            Self::Executing => "executing",
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
            "executing" => Some(Self::Executing),
            "rejected" => Some(Self::Rejected),
            "expired" => Some(Self::Expired),
            "cancelled" => Some(Self::Cancelled),
            "executed" => Some(Self::Executed),
            "execution_failed" => Some(Self::ExecutionFailed),
            _ => None,
        }
    }
}

/// Who triggers execution after the last approval, mirroring Alibaba Cloud
/// DMS's COMMITOR / LAST_AUDITOR / AUTO modes. The SQL itself always comes
/// from the stored request; the mode only decides who presses "execute" (or
/// whether the server does it immediately).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalExecutionMode {
    /// The requester triggers execution (DMS `COMMITOR`).
    #[default]
    Submitter,
    /// The approver who completed the last step triggers execution
    /// (DMS `LAST_AUDITOR`).
    LastApprover,
    /// The server executes immediately after the last approval (DMS `AUTO`).
    Auto,
}

impl ApprovalExecutionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitter => "submitter",
            Self::LastApprover => "last_approver",
            Self::Auto => "auto",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "submitter" | "commitor" => Some(Self::Submitter),
            "last_approver" | "last_auditor" => Some(Self::LastApprover),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    /// Default from `DBX_APPROVAL_EXECUTION_MODE`; invalid values fall back to
    /// `submitter` so a typo cannot silently auto-execute production changes.
    pub fn from_env_default() -> Self {
        std::env::var("DBX_APPROVAL_EXECUTION_MODE").ok().and_then(|value| Self::parse(&value)).unwrap_or_default()
    }

    /// Modes other than `submitter` run without the requester's session, so
    /// the connection password must be stored server-side.
    pub fn requires_saved_credential(&self) -> bool {
        !matches!(self, Self::Submitter)
    }
}

/// How one approval step is decided. `All` is a countersign: every approver
/// resolved for the step must approve; `Any` needs a single approval.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStepMode {
    #[default]
    Any,
    All,
}

impl ApprovalStepMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::All => "all",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "any" => Some(Self::Any),
            "all" => Some(Self::All),
            _ => None,
        }
    }
}

/// One step of a template document. `roles` and `users` are resolved to a
/// concrete user snapshot when a request is created.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalStepSpec {
    #[serde(default)]
    pub mode: ApprovalStepMode,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

/// A stored approval template. A request created without an explicit template
/// uses the most specific enabled one for its connection, falling back to the
/// built-in single-step behaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalTemplate {
    pub id: String,
    pub name: String,
    pub scope_type: String,
    pub scope_id: String,
    pub steps: Vec<ApprovalStepSpec>,
    pub sla_secs: Option<i64>,
    pub enabled: bool,
    pub created_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStepStatus {
    Pending,
    Approved,
    Rejected,
    Skipped,
}

impl ApprovalStepStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Skipped => "skipped",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            "skipped" => Some(Self::Skipped),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalStep {
    pub id: String,
    pub request_id: String,
    pub step_no: i64,
    pub mode: ApprovalStepMode,
    pub status: ApprovalStepStatus,
    pub approver_roles: Vec<String>,
    pub approver_users: Vec<String>,
    /// Users who could decide this step when the request was created. For an
    /// `all` step every one of them must approve; for `any` it is informational.
    pub required_user_ids: Vec<String>,
    pub decided_by: Option<String>,
    pub decided_at_ms: Option<i64>,
    pub comment: String,
}

impl ApprovalStep {
    /// Whether `actor` may decide this step. Roles and users are resolved to
    /// `required_user_ids` when the request is created, and only that snapshot
    /// may vote: granting someone a role later must not widen an approval that
    /// is already in flight. An empty approver list is the built-in single-step
    /// default, open to any holder of `approval:act`.
    pub fn allows(&self, actor_id: &str, _actor_roles: &[String]) -> bool {
        if self.approver_roles.is_empty() && self.approver_users.is_empty() {
            return true;
        }
        self.required_user_ids.iter().any(|user| user == actor_id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalVote {
    Approve,
    Reject,
}

impl ApprovalVote {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "approve" => Some(Self::Approve),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalStepDecision {
    pub id: String,
    pub request_id: String,
    pub step_id: String,
    pub step_no: i64,
    pub actor_id: String,
    pub decision: ApprovalVote,
    pub comment: String,
    pub created_at_ms: i64,
}

/// What one vote did to the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDecisionOutcome {
    pub step_no: i64,
    pub step_status: ApprovalStepStatus,
    /// `pending` while later steps remain, `approved` on the last step,
    /// `rejected` when the vote rejected the request.
    pub request_status: ApprovalStatus,
    pub step_completed: bool,
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
    /// Authoritative ordered statement list. Execution uses this list, never a
    /// client-supplied copy, so the approved artifact is exactly what runs.
    pub statements: Vec<String>,
    pub sql_digest: String,
    pub statement_count: i64,
    pub risk_level: Option<String>,
    pub rule_ids: Vec<String>,
    pub policy_bundle_hash: Option<String>,
    pub justification: String,
    pub request_hash: String,
    /// Template the request was created from, empty for the built-in default.
    pub template_id: String,
    /// 1-based position of the approval round that is currently open.
    pub current_step_no: i64,
    pub step_count: i64,
    pub execution_mode: ApprovalExecutionMode,
    /// Why execution failed, kept on the request for the UI and audit.
    pub execution_error: Option<String>,
    pub executed_by: Option<String>,
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

/// Parses a template document. Both the bare array and the `{"steps": [...]}`
/// wrapper are accepted so the API can store a small JSON object.
pub fn parse_steps_document(raw: &str) -> Result<Vec<ApprovalStepSpec>, String> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Document {
        List(Vec<ApprovalStepSpec>),
        Wrapped { steps: Vec<ApprovalStepSpec> },
    }
    let document: Document =
        serde_json::from_str(raw).map_err(|error| format!("APPROVAL_TEMPLATE_INVALID: {error}"))?;
    let steps = match document {
        Document::List(steps) => steps,
        Document::Wrapped { steps } => steps,
    };
    validate_steps(&steps)?;
    Ok(steps)
}

pub fn steps_document_json(steps: &[ApprovalStepSpec]) -> Result<String, String> {
    serde_json::to_string(&serde_json::json!({ "steps": steps })).map_err(|error| error.to_string())
}

pub fn validate_steps(steps: &[ApprovalStepSpec]) -> Result<(), String> {
    if steps.is_empty() {
        return Err("APPROVAL_TEMPLATE_EMPTY: at least one step is required".to_string());
    }
    if steps.len() > MAX_APPROVAL_STEPS {
        return Err(format!(
            "APPROVAL_TEMPLATE_INVALID: at most {MAX_APPROVAL_STEPS} steps are allowed, got {}",
            steps.len()
        ));
    }
    for (index, step) in steps.iter().enumerate() {
        let step_no = index + 1;
        if step.roles.iter().any(|role| role.trim().is_empty()) || step.users.iter().any(|user| user.trim().is_empty())
        {
            return Err(format!("APPROVAL_TEMPLATE_INVALID: step {step_no} has a blank approver"));
        }
        let has_role = step.roles.iter().any(|role| !role.trim().is_empty());
        let has_user = step.users.iter().any(|user| !user.trim().is_empty());
        if !has_role && !has_user {
            return Err(format!("APPROVAL_TEMPLATE_INVALID: step {step_no} has no approvers"));
        }
    }
    Ok(())
}

/// Turns template steps into the concrete steps of one request. Role
/// membership is snapshotted here so later role edits cannot silently widen or
/// deadlock an approval that is already in flight.
pub fn materialize_approval_steps(
    request_id: &str,
    requester_id: &str,
    specs: &[ApprovalStepSpec],
    role_members: &std::collections::HashMap<String, Vec<String>>,
) -> Result<Vec<ApprovalStep>, String> {
    let mut steps = Vec::with_capacity(specs.len());
    for (index, spec) in specs.iter().enumerate() {
        let mut roles: Vec<String> =
            spec.roles.iter().map(|role| role.trim().to_string()).filter(|role| !role.is_empty()).collect();
        roles.sort();
        roles.dedup();
        let mut users: Vec<String> =
            spec.users.iter().map(|user| user.trim().to_string()).filter(|user| !user.is_empty()).collect();
        users.sort();
        users.dedup();
        let mut required: Vec<String> = users.clone();
        for role in &roles {
            required.extend(role_members.get(role).cloned().unwrap_or_default());
        }
        required.sort();
        required.dedup();
        required.retain(|user| user != requester_id);
        if required.is_empty() {
            return Err(format!(
                "APPROVAL_STEP_NO_APPROVER: step {} has no approver other than the requester",
                index + 1
            ));
        }
        steps.push(ApprovalStep {
            id: uuid::Uuid::new_v4().to_string(),
            request_id: request_id.to_string(),
            step_no: i64::try_from(index + 1).unwrap_or(i64::MAX),
            mode: spec.mode,
            status: ApprovalStepStatus::Pending,
            approver_roles: roles,
            approver_users: users,
            required_user_ids: required,
            decided_by: None,
            decided_at_ms: None,
            comment: String::new(),
        });
    }
    Ok(steps)
}

/// The built-in single step: any holder of `approval:act` may decide.
pub fn default_approval_step(request_id: &str) -> ApprovalStep {
    ApprovalStep {
        id: uuid::Uuid::new_v4().to_string(),
        request_id: request_id.to_string(),
        step_no: 1,
        mode: ApprovalStepMode::Any,
        status: ApprovalStepStatus::Pending,
        approver_roles: Vec::new(),
        approver_users: Vec::new(),
        required_user_ids: Vec::new(),
        decided_by: None,
        decided_at_ms: None,
        comment: String::new(),
    }
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

    fn step(roles: &[&str], users: &[&str], required: &[&str]) -> ApprovalStep {
        ApprovalStep {
            id: "s1".to_string(),
            request_id: "r1".to_string(),
            step_no: 1,
            mode: ApprovalStepMode::Any,
            status: ApprovalStepStatus::Pending,
            approver_roles: roles.iter().map(|role| role.to_string()).collect(),
            approver_users: users.iter().map(|user| user.to_string()).collect(),
            required_user_ids: required.iter().map(|user| user.to_string()).collect(),
            decided_by: None,
            decided_at_ms: None,
            comment: String::new(),
        }
    }

    #[test]
    fn execution_modes_accept_dms_aliases_and_default_to_submitter() {
        assert_eq!(ApprovalExecutionMode::parse("submitter"), Some(ApprovalExecutionMode::Submitter));
        assert_eq!(ApprovalExecutionMode::parse("commitor"), Some(ApprovalExecutionMode::Submitter));
        assert_eq!(ApprovalExecutionMode::parse("last_approver"), Some(ApprovalExecutionMode::LastApprover));
        assert_eq!(ApprovalExecutionMode::parse("last_auditor"), Some(ApprovalExecutionMode::LastApprover));
        assert_eq!(ApprovalExecutionMode::parse("auto"), Some(ApprovalExecutionMode::Auto));
        assert_eq!(ApprovalExecutionMode::parse("unknown"), None);
        assert_eq!(ApprovalExecutionMode::default(), ApprovalExecutionMode::Submitter);
        assert!(!ApprovalExecutionMode::Submitter.requires_saved_credential());
        assert!(ApprovalExecutionMode::Auto.requires_saved_credential());
        assert_eq!(ApprovalStatus::parse("executing"), Some(ApprovalStatus::Executing));
        assert_eq!(ApprovalStatus::Executing.as_str(), "executing");
    }

    #[test]
    fn a_listed_step_only_accepts_the_creation_snapshot() {
        let listed = step(&["dba"], &[], &["bob"]);
        assert!(listed.allows("bob", &["dba".to_string()]));
        // A role holder who was not in the snapshot cannot join an in-flight
        // approval, and a snapshot member can vote even after losing the role.
        assert!(!listed.allows("mallory", &["dba".to_string()]));
        assert!(listed.allows("bob", &[]));
        // The built-in default step stays open to any `approval:act` holder.
        assert!(step(&[], &[], &[]).allows("anyone", &[]));
    }
}
