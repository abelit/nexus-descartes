//! Building audit events for SQL execution.

use sha2::{Digest, Sha256};

use super::{
    current_audit_context, sql_fingerprint, AuditContext, AuditDecision, AuditEventInsert, AuditOperation,
    AuditOutcome, SqlRetention,
};
use crate::models::connection::DatabaseType;
use crate::sql_risk::{classify_sql_risk_for_database, SqlRisk};

pub struct SqlAuditOutcome<'a> {
    pub connection_id: &'a str,
    pub connection_name: Option<&'a str>,
    pub database: &'a str,
    pub schema: Option<&'a str>,
    pub sql: &'a str,
    pub db_type: Option<DatabaseType>,
    pub outcome: AuditOutcome,
    pub error: Option<String>,
    pub affected_rows: Option<i64>,
    pub duration_ms: i64,
}

/// Returns `None` when the entry point did not supply a context and no
/// task-local context is active, so internal calls stay silent by default.
pub fn build_sql_event(explicit: Option<&AuditContext>, audit: SqlAuditOutcome<'_>) -> Option<AuditEventInsert> {
    let context = explicit.cloned().or_else(current_audit_context)?;
    let risk = audit
        .db_type
        .and_then(|db_type| classify_sql_risk_for_database(audit.sql, db_type).ok())
        .unwrap_or(SqlRisk::Write);
    let operation = match risk {
        SqlRisk::ReadOnly => AuditOperation::Query,
        SqlRisk::Write => AuditOperation::Dml,
        SqlRisk::Ddl => AuditOperation::Ddl,
        SqlRisk::Transaction => AuditOperation::Transaction,
    };
    let decision = if audit.error.as_deref().is_some_and(is_denied_message) {
        AuditDecision::Denied
    } else if audit.error.as_deref().is_some_and(is_approval_required_message) {
        AuditDecision::ApprovalRequired
    } else {
        match &audit.outcome {
            AuditOutcome::Success | AuditOutcome::Canceled | AuditOutcome::Unknown => {
                if audit.error.as_deref().is_some_and(is_blocked_message) {
                    AuditDecision::Blocked
                } else {
                    AuditDecision::Allowed
                }
            }
            AuditOutcome::Error | AuditOutcome::NotStarted => {
                if audit.error.as_deref().is_some_and(is_blocked_message) {
                    AuditDecision::Blocked
                } else {
                    AuditDecision::Error
                }
            }
        }
    };
    let mut event = AuditEventInsert::new(&context, operation, decision, audit.outcome);
    event.event_type = "sql".to_string();
    event.connection_id = Some(audit.connection_id.to_string());
    event.connection_name = audit.connection_name.map(str::to_string);
    event.database = (!audit.database.trim().is_empty()).then(|| audit.database.to_string());
    event.schema_name = audit.schema.map(str::to_string);
    // The digest binds approvals and must be computed on the raw statement;
    // masking only affects what is retained for reading.
    event.sql_digest = Some(sql_digest(audit.sql));
    event.sql_fingerprint = Some(sql_fingerprint(audit.sql));
    let retained = SqlRetention::for_process().retain(audit.sql);
    event.sql_text = retained.text;
    event.redaction_mode = Some(retained.redaction_mode.to_string());
    event.risk_level = Some(risk.to_string());
    event.error_message = audit.error;
    event.affected_rows = audit.affected_rows;
    event.duration_ms = Some(audit.duration_ms);
    event.details_json = Some(
        serde_json::json!({
            "risk": risk.to_string(),
            "schema": audit.schema,
            "credentials_masked": retained.credentials_masked,
        })
        .to_string(),
    );
    Some(event)
}

pub struct TransactionAudit<'a> {
    pub connection_id: &'a str,
    pub connection_name: Option<&'a str>,
    pub database: &'a str,
    pub schema: Option<&'a str>,
    pub statements: &'a [String],
    pub db_type: Option<DatabaseType>,
    pub outcome: AuditOutcome,
    pub error: Option<String>,
    pub duration_ms: i64,
}

/// Audits an explicit transaction as one `transaction` operation.
///
/// The transaction kernels return a single combined result, so claiming
/// per-statement outcomes here would be fabrication; the statement count and
/// joined text identify what ran, and `statement_index` stays empty.
pub fn build_transaction_event(
    explicit: Option<&AuditContext>,
    audit: TransactionAudit<'_>,
) -> Option<AuditEventInsert> {
    let context = explicit.cloned().or_else(current_audit_context)?;
    let risk = audit
        .statements
        .iter()
        .filter_map(|sql| audit.db_type.and_then(|db_type| classify_sql_risk_for_database(sql, db_type).ok()))
        .max_by_key(|risk| risk_rank(*risk))
        .unwrap_or(SqlRisk::Write);
    let joined = join_statements(audit.statements);
    let mut event =
        AuditEventInsert::new(&context, AuditOperation::Transaction, AuditDecision::Allowed, audit.outcome.clone());
    event.event_type = "sql".to_string();
    event.connection_id = Some(audit.connection_id.to_string());
    event.connection_name = audit.connection_name.map(str::to_string);
    event.database = (!audit.database.trim().is_empty()).then(|| audit.database.to_string());
    event.schema_name = audit.schema.map(str::to_string);
    event.sql_digest = Some(sql_digest(&joined));
    event.sql_fingerprint = Some(sql_fingerprint(&joined));
    let retained = SqlRetention::for_process().retain(&joined);
    event.sql_text = retained.text;
    event.redaction_mode = Some(retained.redaction_mode.to_string());
    event.risk_level = Some(risk.to_string());
    event.error_message = audit.error;
    event.duration_ms = Some(audit.duration_ms);
    event.details_json = Some(
        serde_json::json!({
            "risk": risk.to_string(),
            "transaction": true,
            "statement_count": audit.statements.len(),
            "credentials_masked": retained.credentials_masked,
        })
        .to_string(),
    );
    Some(event)
}

fn risk_rank(risk: SqlRisk) -> u8 {
    match risk {
        SqlRisk::ReadOnly => 0,
        SqlRisk::Transaction => 1,
        SqlRisk::Write => 2,
        SqlRisk::Ddl => 3,
    }
}

/// One statement's result inside a batch the driver executed as a whole.
pub struct BatchStatementOutcome {
    pub index: usize,
    pub outcome: AuditOutcome,
    pub affected_rows: Option<i64>,
    pub error: Option<String>,
}

pub struct BatchAudit<'a> {
    pub connection_id: &'a str,
    pub connection_name: Option<&'a str>,
    pub database: &'a str,
    pub schema: Option<&'a str>,
    pub statements: &'a [String],
    pub db_type: Option<DatabaseType>,
    pub duration_ms: i64,
}

/// Audits a batch path (`execute_multi_mysql`, `execute_multi_sqlserver`) that
/// runs inside the driver and therefore never reaches the single-statement
/// instrumentation.
///
/// When the driver reports per-statement results, each statement gets its own
/// event with its `statement_index`. When it only reports a summary, one batch
/// event carries the statement count and the joined digest instead of
/// pretending the driver returned per-statement outcomes.
pub fn build_batch_events(
    explicit: Option<&AuditContext>,
    audit: BatchAudit<'_>,
    results: Option<&[BatchStatementOutcome]>,
    error: Option<&str>,
) -> Vec<AuditEventInsert> {
    if explicit.is_none() && current_audit_context().is_none() {
        return Vec::new();
    }
    let statement_count = audit.statements.len();
    let mut events = Vec::new();
    match results.filter(|results| !results.is_empty()) {
        Some(results) => {
            for result in results {
                let Some(sql) = audit.statements.get(result.index) else {
                    continue;
                };
                let outcome = SqlAuditOutcome {
                    connection_id: audit.connection_id,
                    connection_name: audit.connection_name,
                    database: audit.database,
                    schema: audit.schema,
                    sql,
                    db_type: audit.db_type,
                    outcome: result.outcome.clone(),
                    error: result.error.clone(),
                    affected_rows: result.affected_rows,
                    duration_ms: audit.duration_ms,
                };
                if let Some(mut event) = build_sql_event(explicit, outcome) {
                    event.statement_index = Some(result.index as i64);
                    event.details_json =
                        Some(batch_details(event.details_json.as_deref(), statement_count, Some(result.index)));
                    events.push(event);
                }
            }
        }
        None => {
            let joined = join_statements(audit.statements);
            let outcome = SqlAuditOutcome {
                connection_id: audit.connection_id,
                connection_name: audit.connection_name,
                database: audit.database,
                schema: audit.schema,
                sql: &joined,
                db_type: audit.db_type,
                outcome: if error.is_some() { AuditOutcome::Error } else { AuditOutcome::Success },
                error: error.map(str::to_string),
                affected_rows: None,
                duration_ms: audit.duration_ms,
            };
            if let Some(mut event) = build_sql_event(explicit, outcome) {
                event.details_json = Some(batch_details(event.details_json.as_deref(), statement_count, None));
                events.push(event);
            }
        }
    }
    events
}

/// A batch may hold a large script; the joined form is a summary, not the
/// primary evidence, so it is capped.
const MAX_BATCH_SQL_BYTES: usize = 64 * 1024;

fn join_statements(statements: &[String]) -> String {
    let mut joined = String::new();
    for statement in statements {
        if joined.len() + statement.len() + 2 > MAX_BATCH_SQL_BYTES {
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

fn batch_details(existing: Option<&str>, statement_count: usize, statement_index: Option<usize>) -> String {
    let mut value: serde_json::Value =
        existing.and_then(|text| serde_json::from_str(text).ok()).unwrap_or_else(|| serde_json::json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("batch".to_string(), serde_json::Value::Bool(true));
        object.insert("statement_count".to_string(), serde_json::json!(statement_count));
        if let Some(index) = statement_index {
            object.insert("statement_index".to_string(), serde_json::json!(index));
        }
    }
    value.to_string()
}

fn is_denied_message(message: &str) -> bool {
    message.contains("PERMISSION_DENIED") || message.contains("CONNECTION_SCOPE_DENIED")
}

fn is_approval_required_message(message: &str) -> bool {
    message.contains("POLICY_APPROVAL_REQUIRED") || message.contains("APPROVAL_REQUIRED")
}

fn is_blocked_message(message: &str) -> bool {
    message.contains("POLICY_DENIED")
        || message.contains("Read-only mode")
        || message.contains("SQL_BLOCKED")
        || message.contains("PRODUCTION_DATABASE_READ_ONLY")
        || message.contains("PRODUCTION_WRITE_BLOCKED")
        || message.contains("CONNECTION_READ_ONLY")
}

pub fn sql_digest(sql: &str) -> String {
    let normalized = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let digest = Sha256::digest(normalized.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Actor, AuditSource};

    fn context() -> AuditContext {
        AuditContext {
            actor: Actor::bootstrap(),
            source: AuditSource::Web,
            client_ip: None,
            user_agent: None,
            request_id: None,
            execution_id: None,
        }
    }

    fn outcome() -> SqlAuditOutcome<'static> {
        SqlAuditOutcome {
            connection_id: "conn",
            connection_name: Some("Main"),
            database: "app",
            schema: Some("public"),
            sql: "DROP TABLE users",
            db_type: Some(DatabaseType::Postgres),
            outcome: AuditOutcome::Success,
            error: None,
            affected_rows: None,
            duration_ms: 5,
        }
    }

    #[test]
    fn classifies_ddl_and_records_the_context() {
        let context = context();
        let event = build_sql_event(Some(&context), outcome()).unwrap();
        assert_eq!(event.operation, AuditOperation::Ddl);
        assert_eq!(event.decision, AuditDecision::Allowed);
        assert_eq!(event.connection_id.as_deref(), Some("conn"));
        assert_eq!(event.risk_level.as_deref(), Some("DDL"));
        assert_eq!(event.sql_digest.as_deref(), Some(sql_digest("DROP TABLE users").as_str()));
    }

    #[test]
    fn blocked_errors_are_marked_as_blocked() {
        let context = context();
        let mut outcome = outcome();
        outcome.sql = "DELETE FROM users";
        outcome.outcome = AuditOutcome::Error;
        outcome.error = Some("Read-only mode: connection 'Main' has read-only protection enabled".to_string());
        let event = build_sql_event(Some(&context), outcome).unwrap();
        assert_eq!(event.operation, AuditOperation::Dml);
        assert_eq!(event.decision, AuditDecision::Blocked);
    }

    #[test]
    fn digest_is_whitespace_insensitive() {
        assert_eq!(sql_digest("SELECT  1"), sql_digest(" SELECT 1\n"));
        assert_ne!(sql_digest("SELECT 1"), sql_digest("SELECT 2"));
    }

    #[test]
    fn a_sql_event_records_its_type_fingerprint_and_retention() {
        let context = context();
        let mut outcome = outcome();
        outcome.sql = "UPDATE users SET name = 'bob' WHERE id = 1";
        let event = build_sql_event(Some(&context), outcome).unwrap();
        assert_eq!(event.event_type, "sql");
        assert!(event.sql_fingerprint.is_some());
        assert!(event.redaction_mode.is_some(), "the reader must know how the text was retained");
    }

    #[test]
    fn a_batch_with_per_statement_results_audits_each_statement() {
        let context = context();
        let statements = vec!["UPDATE users SET name = 'a' WHERE id = 1".to_string(), "SELECT 1".to_string()];
        let results = vec![
            BatchStatementOutcome { index: 0, outcome: AuditOutcome::Success, affected_rows: Some(1), error: None },
            BatchStatementOutcome { index: 1, outcome: AuditOutcome::Success, affected_rows: None, error: None },
        ];
        let events = build_batch_events(Some(&context), batch_audit(&statements), Some(&results), None);
        assert_eq!(events.len(), 2, "each statement gets its own event");
        assert_eq!(events[0].statement_index, Some(0));
        assert_eq!(events[1].statement_index, Some(1));
        assert_eq!(events[0].operation, AuditOperation::Dml);
        assert!(events[0].details_json.as_deref().unwrap().contains("\"batch\":true"));
    }

    #[test]
    fn a_summary_only_batch_does_not_invent_per_statement_results() {
        let context = context();
        let statements = vec!["SELECT 1".to_string(), "SELECT 2".to_string()];
        let events = build_batch_events(Some(&context), batch_audit(&statements), None, Some("driver failed"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Error);
        assert_eq!(events[0].statement_index, None);
        let details = events[0].details_json.as_deref().unwrap();
        assert!(details.contains("\"statement_count\":2"), "{details}");
    }

    #[test]
    fn a_batch_without_a_context_writes_nothing() {
        let statements = vec!["SELECT 1".to_string()];
        let events = build_batch_events(None, batch_audit(&statements), None, None);
        assert!(events.is_empty());
    }

    fn batch_audit<'a>(statements: &'a [String]) -> BatchAudit<'a> {
        BatchAudit {
            connection_id: "conn",
            connection_name: Some("Main"),
            database: "app",
            schema: None,
            statements,
            db_type: Some(DatabaseType::Postgres),
            duration_ms: 3,
        }
    }

    #[test]
    fn credential_literals_are_not_retained_when_masking_is_on() {
        let retention = SqlRetention::for_process();
        if retention.mode() != crate::audit::SqlRetentionMode::Full || !retention.masks_credentials() {
            return;
        }
        let context = context();
        let mut outcome = outcome();
        outcome.sql = "ALTER USER app SET PASSWORD = 'hunter2'";
        let event = build_sql_event(Some(&context), outcome).unwrap();
        let text = event.sql_text.unwrap_or_default();
        assert!(!text.contains("hunter2"), "credentials must not reach the audit log: {text}");
        // Masking must not weaken approval binding.
        assert_eq!(event.sql_digest.as_deref(), Some(sql_digest("ALTER USER app SET PASSWORD = 'hunter2'").as_str()));
    }
}
