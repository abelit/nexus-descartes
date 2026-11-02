//! Server-side operation audit.
//!
//! The audit log is intentionally separate from `history`: history is a
//! user-facing convenience that the client may write or delete, while audit
//! events are written by the server, append-only, and hash-chained.

use serde::{Deserialize, Serialize};

pub mod context;
pub mod execution;
pub mod exporter;
pub mod redaction;
pub mod signature;
pub mod sink;
#[cfg(feature = "enterprise-audit")]
pub mod writer;

pub use context::{current_audit_context, spawn_with_audit_context, with_audit_context};
pub use redaction::{mask_credentials, sql_fingerprint, RetainedSql, SqlRetention, SqlRetentionMode};
pub use sink::{AuditDurableFuture, AuditSink, MemoryAuditSink, NoopAuditSink};
#[cfg(feature = "enterprise-audit")]
pub use writer::SqliteAuditSink;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    Bootstrap,
    Human,
    Service,
    AiAgent,
    System,
}

impl ActorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Human => "human",
            Self::Service => "service",
            Self::AiAgent => "ai_agent",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSource {
    Web,
    Desktop,
    Cli,
    Mcp,
    Ai,
    System,
    /// Server-side execution of an approved ticket (DMS-style).
    Approval,
}

impl AuditSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Desktop => "desktop",
            Self::Cli => "cli",
            Self::Mcp => "mcp",
            Self::Ai => "ai",
            Self::System => "system",
            Self::Approval => "approval",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    Query,
    Dml,
    Ddl,
    Transaction,
    Export,
    Import,
    Backup,
    Config,
    Connection,
    Auth,
    Policy,
    Approval,
    Admin,
}

impl AuditOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Dml => "dml",
            Self::Ddl => "ddl",
            Self::Transaction => "transaction",
            Self::Export => "export",
            Self::Import => "import",
            Self::Backup => "backup",
            Self::Config => "config",
            Self::Connection => "connection",
            Self::Auth => "auth",
            Self::Policy => "policy",
            Self::Approval => "approval",
            Self::Admin => "admin",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allowed,
    Denied,
    Warned,
    ApprovalRequired,
    Blocked,
    Error,
}

impl AuditDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Warned => "warned",
            Self::ApprovalRequired => "approval_required",
            Self::Blocked => "blocked",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Error,
    Canceled,
    Unknown,
    NotStarted,
}

impl AuditOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
            Self::Canceled => "canceled",
            Self::Unknown => "unknown",
            Self::NotStarted => "not_started",
        }
    }
}

/// The authenticated principal an audit event belongs to.
///
/// P0 only produces `Bootstrap`/`Human` actors for the single local admin.
/// Once nexus-hilbert is wired in, the same shape carries its subject, roles,
/// and tenant without changing the audit or policy layers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
    pub display_name: String,
    pub kind: ActorKind,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub auth_method: String,
}

impl Actor {
    pub fn bootstrap() -> Self {
        Self {
            id: "local:admin".to_string(),
            display_name: "Administrator".to_string(),
            kind: ActorKind::Bootstrap,
            roles: vec!["admin".to_string(), "auditor".to_string()],
            tenant_id: None,
            session_id: None,
            auth_method: "local_password".to_string(),
        }
    }

    pub fn system() -> Self {
        Self {
            id: "system".to_string(),
            display_name: "System".to_string(),
            kind: ActorKind::System,
            roles: vec![],
            tenant_id: None,
            session_id: None,
            auth_method: "system".to_string(),
        }
    }
}

/// Per-operation context supplied by an entry point (Web handler, CLI, MCP,
/// AI tool call, ...). It is deliberately separate from the event itself so a
/// single context can stamp many statements in one batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditContext {
    pub actor: Actor,
    pub source: AuditSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
}

impl AuditContext {
    pub fn system() -> Self {
        Self {
            actor: Actor::system(),
            source: AuditSource::System,
            client_ip: None,
            user_agent: None,
            request_id: None,
            execution_id: None,
        }
    }
}

/// A fully populated event before the storage layer assigns `seq` and hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventInsert {
    pub event_id: String,
    pub occurred_at: String,
    /// Coarse event family: `sql`, `http`, or `domain` (non-SQL operations).
    #[serde(default = "default_event_type")]
    pub event_type: String,
    pub actor: Actor,
    pub source: AuditSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    pub operation: AuditOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_text: Option<String>,
    /// Whitespace-normalized hash of the raw statement, used to bind approvals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_digest: Option<String>,
    /// Literal-normalized form for aggregation and statistics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    pub decision: AuditDecision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub matched_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub outcome: AuditOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affected_rows: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details_json: Option<String>,
    /// Position of the statement within its execution, so one script can be
    /// reconstructed and retried idempotently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_index: Option<i64>,
    /// How much of the statement was retained (`full` / `redacted` / `digest`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_mode: Option<String>,
    /// False while the actor is a client-asserted label rather than a
    /// server-authenticated principal.
    #[serde(default)]
    pub actor_verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<String>,
}

fn default_event_type() -> String {
    "domain".to_string()
}

impl AuditEventInsert {
    pub fn new(
        context: &AuditContext,
        operation: AuditOperation,
        decision: AuditDecision,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event_type: default_event_type(),
            actor: context.actor.clone(),
            source: context.source.clone(),
            client_ip: context.client_ip.clone(),
            user_agent: context.user_agent.clone(),
            request_id: context.request_id.clone(),
            request_method: None,
            request_path: None,
            http_status: None,
            connection_id: None,
            connection_name: None,
            database: None,
            schema_name: None,
            table_name: None,
            resource_type: None,
            resource_id: None,
            operation,
            sql_text: None,
            sql_digest: None,
            sql_fingerprint: None,
            risk_level: None,
            decision,
            rule_id: None,
            matched_rule_ids: Vec::new(),
            policy_version: None,
            policy_bundle_hash: None,
            approval_id: None,
            outcome,
            error_code: None,
            error_message: None,
            affected_rows: None,
            duration_ms: None,
            details_json: None,
            execution_id: context.execution_id.clone(),
            statement_index: None,
            redaction_mode: None,
            actor_verified: false,
            on_behalf_of: None,
            delegated_by: None,
        }
    }
}

/// A stored event, including the chain position assigned by SQLite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: i64,
    #[serde(flatten)]
    pub event: AuditEventInsert,
    pub prev_hash: String,
    pub event_hash: String,
}

#[derive(Clone, Debug, Default)]
pub struct AuditQuery {
    pub actor_id: Option<String>,
    pub connection_id: Option<String>,
    pub database: Option<String>,
    pub operation: Option<AuditOperation>,
    pub decision: Option<AuditDecision>,
    pub outcome: Option<AuditOutcome>,
    /// Case-insensitive substring match on the retained statement text.
    pub sql_contains: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub cursor_seq: Option<i64>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_cursor: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditChainHead {
    pub chain_id: String,
    pub last_seq: i64,
    pub last_hash: String,
    pub event_count: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditChainReport {
    pub checked: i64,
    pub first_broken_seq: Option<i64>,
    pub head_seq: i64,
    pub head_hash: String,
}

/// One row of an aggregate ("how many events per decision").
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCount {
    pub key: String,
    pub count: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditStats {
    pub total: i64,
    pub by_decision: Vec<AuditCount>,
    pub by_operation: Vec<AuditCount>,
    pub by_actor: Vec<AuditCount>,
    pub by_risk: Vec<AuditCount>,
}

/// Result of verifying from the newest checkpoint instead of genesis.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditCheckpointReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<AuditCheckpoint>,
    pub report: AuditChainReport,
}

/// A retained proof that the chain reached `seq` with `event_hash`.
///
/// The local hash chain detects edits, but not deletion of the whole database.
/// A checkpoint that is copied off-host (and signed with a key the database
/// never stores) is what makes truncation detectable after the fact.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCheckpoint {
    pub seq: i64,
    pub event_hash: String,
    pub signed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported_at: Option<String>,
}
