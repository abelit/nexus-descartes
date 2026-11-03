//! Structural choke for SQL that DBX generates itself.
//!
//! User-typed SQL reaches the audited entry points in `query`. Schema changes,
//! imports, exports, and rebuilds build their own statements and call drivers
//! directly, so they would otherwise execute without an audit trail.
//!
//! Modules that generate SQL must run their driver call through
//! [`execute_generated_sql`]. The CI guard (`scripts/check-governed-sql.mjs`)
//! keeps the set of direct driver calls from growing silently.

use std::future::Future;
use std::time::Instant;

pub mod approval;
pub mod assets;
pub mod notification;
pub mod policy;
pub mod rules;

pub use policy::{CompiledPolicy, PolicyDocument, ScopedPolicy, StoredRule};
pub use rules::{
    builtin_rules, evaluate, PolicyDecision, PolicyEffect, Rule, RuleContext, RuleHit, RuleMatch, RuleScope,
};

use crate::models::connection::DatabaseType;
use crate::production_safety::is_production_database;

/// `DBX_GOVERNANCE_MODE=enforce` turns rule decisions into request failures.
/// The default (`observe`) keeps execution behavior unchanged.
pub fn enforcement_enabled() -> bool {
    matches!(std::env::var("DBX_GOVERNANCE_MODE").ok().as_deref().map(str::trim), Some("enforce"))
}

/// Evaluates the current compiled policy (built-ins plus published documents)
/// for one statement against a connection.
pub fn decide(
    connection_id: &str,
    config: &crate::models::connection::ConnectionConfig,
    database: &str,
    db_type: DatabaseType,
    sql: &str,
) -> PolicyDecision {
    let is_production = is_production_database(config, database);
    policy::current_policy().decide(connection_id, database, db_type, sql, is_production)
}

use crate::audit::{
    current_audit_context, AuditContext, AuditDecision, AuditEventInsert, AuditOperation, AuditOutcome,
};
use crate::connection::AppState;

/// One DBX-initiated operation that will execute generated SQL.
pub struct GeneratedSql<'a> {
    pub connection_id: &'a str,
    pub database: &'a str,
    pub schema: Option<&'a str>,
    /// Stable label for the operation, for example `schema.sqlite_rebuild`.
    pub purpose: &'a str,
    /// The statements, when they are known before execution. May be empty for
    /// operations that build statements while running.
    pub statements: &'a [String],
}

const MAX_RECORDED_SQL_BYTES: usize = 64 * 1024;

fn operation_for(purpose: &str) -> AuditOperation {
    if purpose.starts_with("schema") {
        AuditOperation::Ddl
    } else if purpose.starts_with("import") {
        AuditOperation::Import
    } else if purpose.starts_with("export") {
        AuditOperation::Export
    } else if purpose.starts_with("backup") {
        AuditOperation::Backup
    } else {
        AuditOperation::Admin
    }
}

/// Runs `body` and records one audit event for the operation.
///
/// The body keeps ownership of how the statements are executed (pool,
/// transaction, agent), so this wrapper does not change execution semantics.
/// It exists to guarantee that a generated-SQL operation is recorded even when
/// it never passes through the user-SQL entry points.
pub async fn execute_generated_sql<T, F, Fut>(state: &AppState, request: GeneratedSql<'_>, body: F) -> Result<T, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let context = current_audit_context();
    let started = Instant::now();
    let result = body().await;
    let duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    record_event(state, context.as_ref(), &request, result.as_ref().err(), duration_ms);
    result
}

fn record_event(
    state: &AppState,
    context: Option<&AuditContext>,
    request: &GeneratedSql<'_>,
    error: Option<&String>,
    duration_ms: i64,
) {
    if context.is_none() && current_audit_context().is_none() {
        return;
    }
    let Some(context) = context.cloned().or_else(current_audit_context) else {
        return;
    };
    let operation = operation_for(request.purpose);
    let (decision, outcome) = match error {
        Some(_) => (AuditDecision::Error, AuditOutcome::Error),
        None => (AuditDecision::Allowed, AuditOutcome::Success),
    };
    let mut event = AuditEventInsert::new(&context, operation, decision, outcome);
    event.event_type = "domain".to_string();
    event.resource_type = Some("generated_sql".to_string());
    event.resource_id = Some(request.purpose.to_string());
    event.connection_id = Some(request.connection_id.to_string());
    event.database = (!request.database.trim().is_empty()).then(|| request.database.to_string());
    event.schema_name = request.schema.map(str::to_string);
    event.error_message = error.cloned();
    event.duration_ms = Some(duration_ms);
    let joined = bounded_join(request.statements);
    if !joined.is_empty() {
        event.sql_digest = Some(crate::audit::execution::sql_digest(&joined));
        event.sql_fingerprint = Some(crate::audit::sql_fingerprint(&joined));
        let retained = crate::audit::SqlRetention::for_process().retain(&joined);
        event.sql_text = retained.text;
        event.redaction_mode = Some(retained.redaction_mode.to_string());
    }
    event.details_json = Some(
        serde_json::json!({
            "purpose": request.purpose,
            "generated": true,
            "statement_count": request.statements.len(),
        })
        .to_string(),
    );
    state.record_audit(event);
}

/// Evaluates every statement of a batch/transaction and fails on the strictest
/// decision. Approval tokens are not accepted for batches yet, so
/// `require_approval` is a hard stop there.
pub fn enforce_statement_list(
    config: &crate::models::connection::ConnectionConfig,
    connection_id: &str,
    database: &str,
    db_type: DatabaseType,
    statements: &[String],
) -> Result<(), String> {
    for sql in statements {
        let decision = decide(connection_id, config, database, db_type, sql);
        match decision.effect {
            PolicyEffect::Block => {
                return Err(format!(
                    "POLICY_DENIED: {} (rule {})",
                    decision.reason,
                    decision.rule_id.as_deref().unwrap_or("unknown")
                ));
            }
            PolicyEffect::RequireApproval => {
                return Err(format!(
                    "POLICY_APPROVAL_REQUIRED: {} (rule {})",
                    decision.reason,
                    decision.rule_id.as_deref().unwrap_or("unknown")
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Resource-scope authorization for local users.
///
/// A user with bindings may only touch connections covered by a binding whose
/// role grants the permission the statement needs. Users without bindings keep
/// the role-only behavior (single administrator / legacy). This runs in every
/// governance mode: it is authorization, not rule observation.
///
/// `approval_authorized` says a one-time approval already authorized these
/// statements. DDL then needs `query:write` instead of `query:ddl`, so an
/// operator without the DDL capability can still execute the statement a DBA
/// approved; without an approval the capability is required as usual.
pub async fn authorize_connection_scope(
    state: &AppState,
    actor_id: Option<&str>,
    connection_id: &str,
    database: Option<&str>,
    schema: Option<&str>,
    statements: &[String],
    db_type: Option<DatabaseType>,
    approval_authorized: bool,
) -> Result<(), String> {
    let database = database.map(str::trim).filter(|value| !value.is_empty()).unwrap_or("");
    let schema = schema.map(str::trim).filter(|value| !value.is_empty());
    crate::governance::assets::authorize_statements(
        state,
        actor_id,
        connection_id,
        database,
        schema,
        statements,
        db_type,
        approval_authorized,
    )
    .await
}

/// Enforcement for batch-capable entry points: resolves the connection and
/// applies [`enforce_statement_list`] to every statement.
pub async fn enforce_statements_for_connection(
    state: &AppState,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    statements: &[String],
) -> Result<(), String> {
    if statements.is_empty() {
        return Ok(());
    }
    let config = {
        let configs = state.configs.read().await;
        configs.get(connection_id).cloned()
    };
    let Some(config) = config else {
        return Ok(());
    };
    let actor_id = current_audit_context().map(|context| context.actor.id);
    authorize_connection_scope(
        state,
        actor_id.as_deref(),
        connection_id,
        Some(database),
        schema,
        statements,
        Some(config.db_type),
        false,
    )
    .await?;
    if !enforcement_enabled() {
        return Ok(());
    }
    enforce_statement_list(&config, connection_id, database, config.db_type, statements)
}

/// If an approved, not-yet-executed request already covers exactly these
/// statements for this actor, return its id. Query paths use it to answer
/// "approval is already granted, execute the ticket" instead of asking the
/// user to request approval a second time.
pub async fn ready_approval_hint(
    state: &AppState,
    actor_id: Option<&str>,
    connection_id: &str,
    database: &str,
    statements: &[String],
) -> Option<String> {
    let actor_id = actor_id.filter(|id| !id.starts_with("system") && !id.contains(':'))?;
    let digest = approval::statements_digest(statements);
    state
        .storage
        .approved_approval_for_execution(actor_id.to_string(), connection_id.to_string(), database.to_string(), digest)
        .await
        .ok()
        .flatten()
        .map(|request| request.id)
}

/// Authorizes a whole batch: every statement is evaluated with the compiled
/// policy, a `block` anywhere stops the batch, and `require_approval` rules are
/// satisfied by one token bound to the complete statement list.
///
/// Returns `true` when the token was consumed, so the caller can prevent the
/// per-statement funnel from asking for it again.
#[allow(clippy::too_many_arguments)]
pub async fn authorize_batch(
    state: &AppState,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    statements: &[String],
    approval_token: Option<&str>,
    actor_id: Option<&str>,
) -> Result<bool, String> {
    if statements.is_empty() {
        return Ok(false);
    }
    let config = {
        let configs = state.configs.read().await;
        configs.get(connection_id).cloned()
    };
    let Some(config) = config else {
        return Ok(false);
    };
    if !enforcement_enabled() {
        authorize_connection_scope(
            state,
            actor_id,
            connection_id,
            Some(database),
            schema,
            statements,
            Some(config.db_type),
            false,
        )
        .await?;
        return Ok(false);
    }
    let policy = policy::current_policy();
    let db_type = config.db_type;
    let is_production = is_production_database(&config, database);
    let mut required_rule_ids: Vec<String> = Vec::new();
    for sql in statements {
        let decision = policy.decide(connection_id, database, db_type, sql, is_production);
        match decision.effect {
            PolicyEffect::Block => {
                return Err(format!(
                    "POLICY_DENIED: {} (rule {})",
                    decision.reason,
                    decision.rule_id.as_deref().unwrap_or("unknown")
                ));
            }
            PolicyEffect::RequireApproval => {
                required_rule_ids.extend(
                    decision
                        .matched
                        .iter()
                        .filter(|hit| hit.effect == PolicyEffect::RequireApproval)
                        .map(|hit| hit.rule_id.clone()),
                );
            }
            _ => {}
        }
    }
    if required_rule_ids.is_empty() {
        authorize_connection_scope(
            state,
            actor_id,
            connection_id,
            Some(database),
            schema,
            statements,
            Some(config.db_type),
            false,
        )
        .await?;
        return Ok(false);
    }
    required_rule_ids.sort();
    required_rule_ids.dedup();
    let (Some(raw_token), Some(actor_id)) = (approval_token, actor_id) else {
        if let Some(approval_id) = ready_approval_hint(state, actor_id, connection_id, database, statements).await {
            return Err(format!(
                "APPROVAL_READY: approval {approval_id} is already approved; execute it with POST /api/approvals/{approval_id}/execute or the approval center"
            ));
        }
        return Err(format!(
            "POLICY_APPROVAL_REQUIRED: {} statement(s) require approval (rules {})",
            statements.len(),
            required_rule_ids.join(", ")
        ));
    };

    let token_hash = approval::sha256_hex(raw_token.as_bytes());
    let token =
        state.storage.approval_token_by_hash(token_hash).await?.ok_or_else(|| "APPROVAL_TOKEN_UNKNOWN".to_string())?;
    let request = state
        .storage
        .approval_request_by_id(token.request_id.clone())
        .await?
        .ok_or_else(|| "APPROVAL_REQUEST_MISSING".to_string())?;
    if request.status != approval::ApprovalStatus::Approved {
        return Err("APPROVAL_NOT_APPROVED".to_string());
    }
    let digest = approval::statements_digest(statements);
    let config_hash = approval::connection_config_hash(&config);
    let hash = approval::request_hash(&approval::ApprovalBinding {
        connection_id,
        connection_config_hash: &config_hash,
        database,
        schema,
        statements_digest: &digest,
        policy_bundle_hash: Some(policy.bundle_hash()),
        rule_ids: &required_rule_ids,
    });
    approval::token_authorizes(&token, actor_id, &hash, chrono::Utc::now().timestamp_millis())?;
    // The approval covers DDL even when the operator lacks `query:ddl`; the
    // scope check runs before consumption so a scope failure cannot burn the
    // token.
    authorize_connection_scope(
        state,
        Some(actor_id),
        connection_id,
        Some(database),
        schema,
        statements,
        Some(config.db_type),
        true,
    )
    .await?;
    if !state.storage.consume_approval_token(token.id.clone(), chrono::Utc::now().timestamp_millis()).await? {
        return Err("APPROVAL_TOKEN_ALREADY_USED".to_string());
    }
    Ok(true)
}

/// Validates and consumes a one-time approval token for exactly this statement.
///
/// The binding is recomputed server-side from the connection configuration,
/// the statement, and the rules that currently require approval; a token issued
/// for different SQL, a different connection, or a different rule set fails.
pub async fn consume_approval_for_sql(
    state: &AppState,
    config: &crate::models::connection::ConnectionConfig,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    sql: &str,
    decision: &PolicyDecision,
    raw_token: &str,
    actor_id: &str,
) -> Result<(), String> {
    let token_hash = approval::sha256_hex(raw_token.as_bytes());
    let token =
        state.storage.approval_token_by_hash(token_hash).await?.ok_or_else(|| "APPROVAL_TOKEN_UNKNOWN".to_string())?;
    let request = state
        .storage
        .approval_request_by_id(token.request_id.clone())
        .await?
        .ok_or_else(|| "APPROVAL_REQUEST_MISSING".to_string())?;
    if request.status != approval::ApprovalStatus::Approved {
        return Err("APPROVAL_NOT_APPROVED".to_string());
    }

    let rule_ids: Vec<String> = decision
        .matched
        .iter()
        .filter(|hit| hit.effect == PolicyEffect::RequireApproval)
        .map(|hit| hit.rule_id.clone())
        .collect();
    let statements = vec![sql.to_string()];
    let digest = approval::statements_digest(&statements);
    let config_hash = approval::connection_config_hash(config);
    let hash = approval::request_hash(&approval::ApprovalBinding {
        connection_id,
        connection_config_hash: &config_hash,
        database,
        schema,
        statements_digest: &digest,
        policy_bundle_hash: request.policy_bundle_hash.as_deref(),
        rule_ids: &rule_ids,
    });
    approval::token_authorizes(&token, actor_id, &hash, chrono::Utc::now().timestamp_millis())?;
    if !state.storage.consume_approval_token(token.id.clone(), chrono::Utc::now().timestamp_millis()).await? {
        return Err("APPROVAL_TOKEN_ALREADY_USED".to_string());
    }
    Ok(())
}

fn bounded_join(statements: &[String]) -> String {
    let mut joined = String::new();
    for statement in statements {
        if joined.len() + statement.len() + 2 > MAX_RECORDED_SQL_BYTES {
            joined.push_str("\n-- [truncated]");
            break;
        }
        if !joined.is_empty() {
            joined.push_str(";\n");
        }
        joined.push_str(statement);
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_map_to_operations() {
        assert_eq!(operation_for("schema.sqlite_rebuild"), AuditOperation::Ddl);
        assert_eq!(operation_for("import.csv"), AuditOperation::Import);
        assert_eq!(operation_for("export.csv"), AuditOperation::Export);
        assert_eq!(operation_for("backup.snapshot"), AuditOperation::Backup);
        assert_eq!(operation_for("maintenance"), AuditOperation::Admin);
    }

    #[test]
    fn joined_sql_is_bounded() {
        let statements = vec!["SELECT 1".to_string(); 20_000];
        let joined = bounded_join(&statements);
        assert!(joined.len() <= MAX_RECORDED_SQL_BYTES + 32, "joined SQL must be capped");
        assert!(joined.ends_with("-- [truncated]"));
    }
}
