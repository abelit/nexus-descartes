//! Persistence for approval templates, requests, steps, and one-time tokens.

use std::collections::HashSet;

use super::{params, OptionalExtension, Storage};
use crate::governance::approval::{
    ApprovalDecisionOutcome, ApprovalExecutionMode, ApprovalRequest, ApprovalStatus, ApprovalStep,
    ApprovalStepDecision, ApprovalStepMode, ApprovalStepStatus, ApprovalTemplate, ApprovalToken, ApprovalVote,
};

pub(super) fn ensure_approval_schema_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS approval_requests (
            id TEXT PRIMARY KEY,
            request_type TEXT NOT NULL DEFAULT 'sql',
            status TEXT NOT NULL,
            requester_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            database TEXT NOT NULL DEFAULT '',
            schema_name TEXT,
            sql_text TEXT NOT NULL,
            statements_json TEXT NOT NULL DEFAULT '[]',
            sql_digest TEXT NOT NULL,
            statement_count INTEGER NOT NULL DEFAULT 1,
            risk_level TEXT,
            rule_ids_json TEXT NOT NULL DEFAULT '[]',
            policy_bundle_hash TEXT,
            justification TEXT NOT NULL DEFAULT '',
            request_hash TEXT NOT NULL,
            template_id TEXT NOT NULL DEFAULT '',
            current_step_no INTEGER NOT NULL DEFAULT 1,
            step_count INTEGER NOT NULL DEFAULT 1,
            execution_mode TEXT NOT NULL DEFAULT 'submitter',
            execution_error TEXT,
            executed_by TEXT,
            expires_at_ms INTEGER,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            executed_at_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_approval_requests_status
            ON approval_requests(status, created_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_approval_requests_requester
            ON approval_requests(requester_id, created_at_ms DESC);
        CREATE TABLE IF NOT EXISTS approval_templates (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            scope_type TEXT NOT NULL DEFAULT 'global',
            scope_id TEXT NOT NULL DEFAULT '',
            steps_json TEXT NOT NULL,
            sla_secs INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_templates_scope
            ON approval_templates(scope_type, scope_id);
        CREATE TABLE IF NOT EXISTS approval_steps (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            step_no INTEGER NOT NULL,
            mode TEXT NOT NULL DEFAULT 'any',
            status TEXT NOT NULL DEFAULT 'pending',
            approver_roles_json TEXT NOT NULL DEFAULT '[]',
            approver_users_json TEXT NOT NULL DEFAULT '[]',
            required_user_ids_json TEXT NOT NULL DEFAULT '[]',
            decided_by TEXT,
            decided_at_ms INTEGER,
            comment TEXT NOT NULL DEFAULT '',
            UNIQUE(request_id, step_no)
        );
        CREATE INDEX IF NOT EXISTS idx_approval_steps_request
            ON approval_steps(request_id, step_no);
        CREATE TABLE IF NOT EXISTS approval_step_decisions (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            step_id TEXT NOT NULL,
            step_no INTEGER NOT NULL,
            actor_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            comment TEXT NOT NULL DEFAULT '',
            created_at_ms INTEGER NOT NULL,
            UNIQUE(step_id, actor_id)
        );
        CREATE INDEX IF NOT EXISTS idx_approval_step_decisions_request
            ON approval_step_decisions(request_id, step_no);
        CREATE TABLE IF NOT EXISTS approval_tokens (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            actor_id TEXT NOT NULL,
            request_hash TEXT NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            consumed_at_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_approval_tokens_request ON approval_tokens(request_id);",
    )
    .map_err(|error| format!("APPROVAL_SCHEMA: {error}"))?;
    ensure_approval_request_columns_sync(conn)
}

/// Older databases predate multi-step approvals; add the columns in place.
fn ensure_approval_request_columns_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    let mut columns = HashSet::new();
    let mut statement = conn.prepare("PRAGMA table_info(approval_requests)").map_err(|error| error.to_string())?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1)).map_err(|error| error.to_string())?;
    for row in rows {
        columns.insert(row.map_err(|error| error.to_string())?);
    }
    for (name, definition) in [
        ("template_id", "TEXT NOT NULL DEFAULT ''"),
        ("current_step_no", "INTEGER NOT NULL DEFAULT 1"),
        ("step_count", "INTEGER NOT NULL DEFAULT 1"),
        ("statements_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("execution_mode", "TEXT NOT NULL DEFAULT 'submitter'"),
        ("execution_error", "TEXT"),
        ("executed_by", "TEXT"),
    ] {
        if !columns.contains(name) {
            conn.execute(&format!("ALTER TABLE approval_requests ADD COLUMN {name} {definition}"), [])
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn parse_json_vec(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

fn row_to_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRequest> {
    let rule_ids_json: String = row.get("rule_ids_json")?;
    let status: String = row.get("status")?;
    let execution_mode: String = row.get("execution_mode")?;
    let sql_text: String = row.get("sql_text")?;
    let mut statements = parse_json_vec(&row.get::<_, String>("statements_json")?);
    if statements.is_empty() {
        // Rows created before statements_json existed stored one joined text.
        statements = vec![sql_text.clone()];
    }
    Ok(ApprovalRequest {
        id: row.get("id")?,
        request_type: row.get("request_type")?,
        status: ApprovalStatus::parse(&status).unwrap_or(ApprovalStatus::Pending),
        requester_id: row.get("requester_id")?,
        connection_id: row.get("connection_id")?,
        database: row.get("database")?,
        schema_name: row.get("schema_name")?,
        sql_text,
        statements,
        sql_digest: row.get("sql_digest")?,
        statement_count: row.get("statement_count")?,
        risk_level: row.get("risk_level")?,
        rule_ids: serde_json::from_str(&rule_ids_json).unwrap_or_default(),
        policy_bundle_hash: row.get("policy_bundle_hash")?,
        justification: row.get("justification")?,
        request_hash: row.get("request_hash")?,
        template_id: row.get("template_id")?,
        current_step_no: row.get("current_step_no")?,
        step_count: row.get("step_count")?,
        execution_mode: ApprovalExecutionMode::parse(&execution_mode).unwrap_or_default(),
        execution_error: row.get("execution_error")?,
        executed_by: row.get("executed_by")?,
        expires_at_ms: row.get("expires_at_ms")?,
        created_at_ms: row.get("created_at_ms")?,
        updated_at_ms: row.get("updated_at_ms")?,
        executed_at_ms: row.get("executed_at_ms")?,
    })
}

fn row_to_step(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalStep> {
    let mode: String = row.get("mode")?;
    let status: String = row.get("status")?;
    Ok(ApprovalStep {
        id: row.get("id")?,
        request_id: row.get("request_id")?,
        step_no: row.get("step_no")?,
        mode: ApprovalStepMode::parse(&mode).unwrap_or_default(),
        status: ApprovalStepStatus::parse(&status).unwrap_or(ApprovalStepStatus::Pending),
        approver_roles: parse_json_vec(&row.get::<_, String>("approver_roles_json")?),
        approver_users: parse_json_vec(&row.get::<_, String>("approver_users_json")?),
        required_user_ids: parse_json_vec(&row.get::<_, String>("required_user_ids_json")?),
        decided_by: row.get("decided_by")?,
        decided_at_ms: row.get("decided_at_ms")?,
        comment: row.get("comment")?,
    })
}

fn row_to_decision(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalStepDecision> {
    let decision: String = row.get("decision")?;
    Ok(ApprovalStepDecision {
        id: row.get("id")?,
        request_id: row.get("request_id")?,
        step_id: row.get("step_id")?,
        step_no: row.get("step_no")?,
        actor_id: row.get("actor_id")?,
        decision: ApprovalVote::parse(&decision).unwrap_or(ApprovalVote::Reject),
        comment: row.get("comment")?,
        created_at_ms: row.get("created_at_ms")?,
    })
}

fn row_to_template(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalTemplate> {
    let steps_json: String = row.get("steps_json")?;
    let enabled: i64 = row.get("enabled")?;
    Ok(ApprovalTemplate {
        id: row.get("id")?,
        name: row.get("name")?,
        scope_type: row.get("scope_type")?,
        scope_id: row.get("scope_id")?,
        steps: crate::governance::approval::parse_steps_document(&steps_json).unwrap_or_default(),
        sla_secs: row.get("sla_secs")?,
        enabled: enabled != 0,
        created_by: row.get("created_by")?,
        created_at_ms: row.get("created_at_ms")?,
        updated_at_ms: row.get("updated_at_ms")?,
    })
}

fn row_to_decision_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalToken> {
    Ok(ApprovalToken {
        id: row.get("id")?,
        request_id: row.get("request_id")?,
        token_hash: row.get("token_hash")?,
        actor_id: row.get("actor_id")?,
        request_hash: row.get("request_hash")?,
        expires_at_ms: row.get("expires_at_ms")?,
        consumed_at_ms: row.get("consumed_at_ms")?,
    })
}

impl Storage {
    /// Creates a request and its steps atomically, so a request can never be
    /// pending without a step anyone can decide.
    pub async fn create_approval_request_with_steps(
        &self,
        request: ApprovalRequest,
        steps: Vec<ApprovalStep>,
    ) -> Result<(), String> {
        self.with_conn(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            let rule_ids_json = serde_json::to_string(&request.rule_ids).map_err(|error| error.to_string())?;
            let statements_json = serde_json::to_string(&request.statements).map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO approval_requests (
                    id, request_type, status, requester_id, connection_id, database, schema_name,
                    sql_text, statements_json, sql_digest, statement_count, risk_level, rule_ids_json,
                    policy_bundle_hash, justification, request_hash, template_id, current_step_no,
                    step_count, execution_mode, execution_error, executed_by, expires_at_ms,
                    created_at_ms, updated_at_ms, executed_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                           ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, NULL)",
                params![
                    request.id,
                    request.request_type,
                    request.status.as_str(),
                    request.requester_id,
                    request.connection_id,
                    request.database,
                    request.schema_name,
                    request.sql_text,
                    statements_json,
                    request.sql_digest,
                    request.statement_count,
                    request.risk_level,
                    rule_ids_json,
                    request.policy_bundle_hash,
                    request.justification,
                    request.request_hash,
                    request.template_id,
                    request.current_step_no,
                    request.step_count,
                    request.execution_mode.as_str(),
                    request.execution_error,
                    request.executed_by,
                    request.expires_at_ms,
                    request.created_at_ms,
                    request.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
            for step in &steps {
                let roles = serde_json::to_string(&step.approver_roles).map_err(|error| error.to_string())?;
                let users = serde_json::to_string(&step.approver_users).map_err(|error| error.to_string())?;
                let required = serde_json::to_string(&step.required_user_ids).map_err(|error| error.to_string())?;
                tx.execute(
                    "INSERT INTO approval_steps (
                        id, request_id, step_no, mode, status, approver_roles_json,
                        approver_users_json, required_user_ids_json, decided_by, decided_at_ms, comment
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        step.id,
                        step.request_id,
                        step.step_no,
                        step.mode.as_str(),
                        step.status.as_str(),
                        roles,
                        users,
                        required,
                        step.decided_by,
                        step.decided_at_ms,
                        step.comment,
                    ],
                )
                .map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn create_approval_request(&self, request: ApprovalRequest) -> Result<(), String> {
        self.create_approval_request_with_steps(request, Vec::new()).await
    }

    pub async fn approval_request_by_id(&self, id: String) -> Result<Option<ApprovalRequest>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM approval_requests WHERE id = ?1", [id], row_to_request)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// Lists requests, newest first. `requester_id` narrows to one user;
    /// `status` narrows to one state.
    pub async fn list_approval_requests(
        &self,
        requester_id: Option<String>,
        status: Option<String>,
        limit: usize,
    ) -> Result<Vec<ApprovalRequest>, String> {
        let limit = limit.clamp(1, 500) as i64;
        self.with_conn(move |conn| {
            let mut sql = String::from("SELECT * FROM approval_requests WHERE 1=1");
            let mut values: Vec<rusqlite::types::Value> = Vec::new();
            if let Some(requester_id) = requester_id {
                sql.push_str(" AND requester_id = ?");
                values.push(rusqlite::types::Value::Text(requester_id));
            }
            if let Some(status) = status {
                sql.push_str(" AND status = ?");
                values.push(rusqlite::types::Value::Text(status));
            }
            sql.push_str(" ORDER BY created_at_ms DESC LIMIT ?");
            values.push(rusqlite::types::Value::Integer(limit));
            let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(super::params_from_iter(values.iter()), row_to_request)
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn approval_steps_for_request(&self, request_id: String) -> Result<Vec<ApprovalStep>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM approval_steps WHERE request_id = ?1 ORDER BY step_no")
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([request_id], row_to_step).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    /// Steps for several requests in one round trip, ordered by request and step.
    pub async fn approval_steps_for_requests(&self, request_ids: Vec<String>) -> Result<Vec<ApprovalStep>, String> {
        if request_ids.is_empty() {
            return Ok(Vec::new());
        }
        self.with_conn(move |conn| {
            let placeholders = vec!["?"; request_ids.len()].join(", ");
            let sql = format!(
                "SELECT * FROM approval_steps WHERE request_id IN ({placeholders}) ORDER BY request_id, step_no"
            );
            let mut stmt = conn.prepare(&sql).map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(super::params_from_iter(request_ids.iter()), row_to_step)
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn approval_step_decisions_for_request(
        &self,
        request_id: String,
    ) -> Result<Vec<ApprovalStepDecision>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM approval_step_decisions WHERE request_id = ?1 ORDER BY step_no, created_at_ms")
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([request_id], row_to_decision).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    /// Records one approver's vote and advances the request state machine.
    ///
    /// All checks and state transitions happen in one `IMMEDIATE` transaction:
    /// the first vote on a step wins, a duplicate vote is refused, a rejection
    /// skips the remaining steps, and the request only becomes `approved` after
    /// the last step is satisfied. Authorization is checked against the same
    /// step snapshot inside the transaction.
    pub async fn decide_approval_step(
        &self,
        request_id: String,
        actor_id: String,
        actor_roles: Vec<String>,
        vote: ApprovalVote,
        comment: String,
        now_ms: i64,
    ) -> Result<ApprovalDecisionOutcome, String> {
        self.with_conn(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            let request: Option<(String, Option<i64>)> = tx
                .query_row("SELECT status, expires_at_ms FROM approval_requests WHERE id = ?1", [&request_id], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()
                .map_err(|error| error.to_string())?;
            let (status, expires_at_ms) = request.ok_or_else(|| "APPROVAL_NOT_FOUND".to_string())?;
            if status != ApprovalStatus::Pending.as_str() {
                return Err("APPROVAL_NOT_PENDING".to_string());
            }
            if expires_at_ms.is_some_and(|expires_at_ms| now_ms >= expires_at_ms) {
                tx.execute(
                    "UPDATE approval_requests SET status = 'expired', updated_at_ms = ?1 WHERE id = ?2",
                    params![now_ms, request_id],
                )
                .map_err(|error| error.to_string())?;
                tx.commit().map_err(|error| error.to_string())?;
                return Err("APPROVAL_EXPIRED".to_string());
            }

            let step = {
                let mut stmt = tx
                    .prepare(
                        "SELECT * FROM approval_steps WHERE request_id = ?1 AND status = 'pending' \
                         ORDER BY step_no LIMIT 1",
                    )
                    .map_err(|error| error.to_string())?;
                let step = stmt.query_row([&request_id], row_to_step).optional().map_err(|error| error.to_string())?;
                step
            }
            .ok_or_else(|| "APPROVAL_STEP_MISSING".to_string())?;
            if !step.allows(&actor_id, &actor_roles) {
                return Err("APPROVAL_NOT_APPROVER".to_string());
            }
            let already_voted: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM approval_step_decisions WHERE step_id = ?1 AND actor_id = ?2",
                    params![step.id, actor_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if already_voted > 0 {
                return Err("APPROVAL_ALREADY_DECIDED".to_string());
            }
            tx.execute(
                "INSERT INTO approval_step_decisions \
                 (id, request_id, step_id, step_no, actor_id, decision, comment, created_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    request_id,
                    step.id,
                    step.step_no,
                    actor_id,
                    vote.as_str(),
                    comment,
                    now_ms,
                ],
            )
            .map_err(|error| error.to_string())?;

            let (step_status, request_status, step_completed) = if vote == ApprovalVote::Reject {
                tx.execute(
                    "UPDATE approval_steps SET status = 'rejected', decided_by = ?1, decided_at_ms = ?2, \
                     comment = ?3 WHERE id = ?4",
                    params![actor_id, now_ms, comment, step.id],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "UPDATE approval_steps SET status = 'skipped' WHERE request_id = ?1 AND status = 'pending'",
                    [&request_id],
                )
                .map_err(|error| error.to_string())?;
                tx.execute(
                    "UPDATE approval_requests SET status = 'rejected', updated_at_ms = ?1 WHERE id = ?2",
                    params![now_ms, request_id],
                )
                .map_err(|error| error.to_string())?;
                (ApprovalStepStatus::Rejected, ApprovalStatus::Rejected, true)
            } else {
                let step_satisfied = if step.mode == ApprovalStepMode::All {
                    let approved: Vec<String> = {
                        let mut stmt = tx
                            .prepare(
                                "SELECT actor_id FROM approval_step_decisions \
                                 WHERE step_id = ?1 AND decision = 'approve'",
                            )
                            .map_err(|error| error.to_string())?;
                        let rows = stmt
                            .query_map([&step.id], |row| row.get::<_, String>(0))
                            .map_err(|error| error.to_string())?;
                        rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?
                    };
                    step.required_user_ids.iter().all(|required| approved.iter().any(|actor| actor == required))
                } else {
                    true
                };
                if step_satisfied {
                    tx.execute(
                        "UPDATE approval_steps SET status = 'approved', decided_by = ?1, decided_at_ms = ?2, \
                         comment = ?3 WHERE id = ?4",
                        params![actor_id, now_ms, comment, step.id],
                    )
                    .map_err(|error| error.to_string())?;
                    let next_step_no: Option<i64> = tx
                        .query_row(
                            "SELECT step_no FROM approval_steps WHERE request_id = ?1 AND status = 'pending' \
                             ORDER BY step_no LIMIT 1",
                            [&request_id],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|error| error.to_string())?;
                    match next_step_no {
                        Some(next_step_no) => {
                            tx.execute(
                                "UPDATE approval_requests SET current_step_no = ?1, updated_at_ms = ?2 WHERE id = ?3",
                                params![next_step_no, now_ms, request_id],
                            )
                            .map_err(|error| error.to_string())?;
                            (ApprovalStepStatus::Approved, ApprovalStatus::Pending, true)
                        }
                        None => {
                            tx.execute(
                                "UPDATE approval_requests SET status = 'approved', \
                                 current_step_no = step_count, updated_at_ms = ?1 WHERE id = ?2",
                                params![now_ms, request_id],
                            )
                            .map_err(|error| error.to_string())?;
                            (ApprovalStepStatus::Approved, ApprovalStatus::Approved, true)
                        }
                    }
                } else {
                    // Countersign in progress: the step stays open for the
                    // remaining approvers.
                    (ApprovalStepStatus::Pending, ApprovalStatus::Pending, false)
                }
            };

            tx.commit().map_err(|error| error.to_string())?;
            Ok(ApprovalDecisionOutcome { step_no: step.step_no, step_status, request_status, step_completed })
        })
        .await
    }

    /// Atomically takes ownership of an approved request for execution. The
    /// first caller wins; a second execution gets `false`, so one approval can
    /// run at most once.
    pub async fn claim_approval_execution(&self, id: String, now_ms: i64) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE approval_requests SET status = 'executing', execution_error = NULL, \
                     updated_at_ms = ?1 WHERE id = ?2 AND status = 'approved'",
                    params![now_ms, id],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    /// Closes an execution attempt. Only a request currently in `executing`
    /// moves, so a stale worker cannot overwrite a later decision.
    pub async fn finish_approval_execution(
        &self,
        id: String,
        status: ApprovalStatus,
        executed_by: String,
        error: Option<String>,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE approval_requests SET status = ?1, executed_by = ?2, execution_error = ?3, \
                     executed_at_ms = ?4, updated_at_ms = ?4 WHERE id = ?5 AND status = 'executing'",
                    params![status.as_str(), executed_by, error, now_ms, id],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    /// Marks a request failed before an execution slot was claimed (for
    /// example a binding mismatch after the policy changed).
    pub async fn fail_approval_execution(
        &self,
        id: String,
        executed_by: String,
        error: String,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE approval_requests SET status = 'execution_failed', executed_by = ?1, \
                     execution_error = ?2, executed_at_ms = ?3, updated_at_ms = ?3 \
                     WHERE id = ?4 AND status = 'approved'",
                    params![executed_by, error, now_ms, id],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn create_approval_template(&self, template: ApprovalTemplate) -> Result<(), String> {
        self.with_conn(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            // One enabled template per scope keeps request resolution
            // deterministic; publishing a new one replaces the old.
            tx.execute(
                "DELETE FROM approval_templates WHERE scope_type = ?1 AND scope_id = ?2",
                params![template.scope_type, template.scope_id],
            )
            .map_err(|error| error.to_string())?;
            let steps_json = crate::governance::approval::steps_document_json(&template.steps)?;
            tx.execute(
                "INSERT INTO approval_templates \
                 (id, name, scope_type, scope_id, steps_json, sla_secs, enabled, created_by, \
                  created_at_ms, updated_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    template.id,
                    template.name,
                    template.scope_type,
                    template.scope_id,
                    steps_json,
                    template.sla_secs,
                    i64::from(template.enabled),
                    template.created_by,
                    template.created_at_ms,
                    template.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn update_approval_template(&self, template: ApprovalTemplate) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let steps_json = crate::governance::approval::steps_document_json(&template.steps)?;
            let changed = conn
                .execute(
                    "UPDATE approval_templates SET name = ?1, scope_type = ?2, scope_id = ?3, steps_json = ?4, \
                     sla_secs = ?5, enabled = ?6, updated_at_ms = ?7 WHERE id = ?8",
                    params![
                        template.name,
                        template.scope_type,
                        template.scope_id,
                        steps_json,
                        template.sla_secs,
                        i64::from(template.enabled),
                        template.updated_at_ms,
                        template.id,
                    ],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn delete_approval_template(&self, id: String) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute("DELETE FROM approval_templates WHERE id = ?1", [id])
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn list_approval_templates(&self) -> Result<Vec<ApprovalTemplate>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM approval_templates ORDER BY scope_type, scope_id, name")
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([], row_to_template).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn approval_template_by_id(&self, id: String) -> Result<Option<ApprovalTemplate>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM approval_templates WHERE id = ?1", [id], row_to_template)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// The template a request on `connection_id` inherits: a connection
    /// template wins over a global one.
    pub async fn resolve_approval_template(&self, connection_id: String) -> Result<Option<ApprovalTemplate>, String> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT * FROM approval_templates \
                 WHERE enabled = 1 AND ((scope_type = 'connection' AND scope_id = ?1) OR scope_type = 'global') \
                 ORDER BY CASE scope_type WHEN 'connection' THEN 0 ELSE 1 END, updated_at_ms DESC LIMIT 1",
                [connection_id],
                row_to_template,
            )
            .optional()
            .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn create_approval_token(&self, token: ApprovalToken) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO approval_tokens (id, request_id, token_hash, actor_id, request_hash, expires_at_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    token.id,
                    token.request_id,
                    token.token_hash,
                    token.actor_id,
                    token.request_hash,
                    token.expires_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn approval_token_by_hash(&self, token_hash: String) -> Result<Option<ApprovalToken>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM approval_tokens WHERE token_hash = ?1", [token_hash], row_to_decision_token)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// Consumes a token atomically; `false` means it was already used.
    pub async fn consume_approval_token(&self, id: String, now_ms: i64) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE approval_tokens SET consumed_at_ms = ?1 WHERE id = ?2 AND consumed_at_ms IS NULL",
                    params![now_ms, id],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }
}

#[cfg(all(test, feature = "enterprise-audit"))]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::governance::approval::{
        default_approval_step, materialize_approval_steps, new_approval_token, statements_digest, ApprovalStepSpec,
    };

    async fn storage() -> Storage {
        let path = std::env::temp_dir().join(format!("dbx-approval-{}.db", uuid::Uuid::new_v4()));
        crate::persistence::test_storage::open(&path).await.unwrap()
    }

    fn request(id: &str, status: ApprovalStatus) -> ApprovalRequest {
        ApprovalRequest {
            id: id.to_string(),
            request_type: "sql".to_string(),
            status,
            requester_id: "alice".to_string(),
            connection_id: "conn".to_string(),
            database: "app".to_string(),
            schema_name: Some("public".to_string()),
            sql_text: "ALTER TABLE users ADD COLUMN age int".to_string(),
            statements: vec!["ALTER TABLE users ADD COLUMN age int".to_string()],
            sql_digest: statements_digest(&["ALTER TABLE users ADD COLUMN age int".to_string()]),
            statement_count: 1,
            risk_level: Some("DDL".to_string()),
            rule_ids: vec!["prod.ddl.approval".to_string()],
            policy_bundle_hash: Some("bundle".to_string()),
            justification: "add column".to_string(),
            request_hash: "hash-1".to_string(),
            template_id: String::new(),
            current_step_no: 1,
            step_count: 1,
            execution_mode: ApprovalExecutionMode::Submitter,
            execution_error: None,
            executed_by: None,
            expires_at_ms: None,
            created_at_ms: 1,
            updated_at_ms: 1,
            executed_at_ms: None,
        }
    }

    fn spec(mode: ApprovalStepMode, roles: &[&str], users: &[&str]) -> ApprovalStepSpec {
        ApprovalStepSpec {
            mode,
            roles: roles.iter().map(|role| role.to_string()).collect(),
            users: users.iter().map(|user| user.to_string()).collect(),
        }
    }

    async fn request_with_steps(
        storage: &Storage,
        id: &str,
        specs: &[ApprovalStepSpec],
        role_members: &HashMap<String, Vec<String>>,
    ) {
        let mut request = request(id, ApprovalStatus::Pending);
        request.step_count = i64::try_from(specs.len()).unwrap();
        let steps = materialize_approval_steps(id, "alice", specs, role_members).unwrap();
        storage.create_approval_request_with_steps(request, steps).await.unwrap();
    }

    #[tokio::test]
    async fn a_request_round_trips_and_only_one_decision_wins() {
        let storage = storage().await;
        let mut request = request("r1", ApprovalStatus::Pending);
        request.step_count = 1;
        let step = default_approval_step("r1");
        storage.create_approval_request_with_steps(request, vec![step]).await.unwrap();
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.rule_ids, vec!["prod.ddl.approval".to_string()]);
        assert_eq!(loaded.step_count, 1);
        assert_eq!(loaded.current_step_no, 1);

        let outcome = storage
            .decide_approval_step(
                "r1".to_string(),
                "bob".to_string(),
                vec!["dba".to_string()],
                ApprovalVote::Approve,
                String::new(),
                10,
            )
            .await
            .unwrap();
        assert_eq!(outcome.request_status, ApprovalStatus::Approved);
        assert_eq!(
            storage
                .decide_approval_step(
                    "r1".to_string(),
                    "carol".to_string(),
                    vec!["dba".to_string()],
                    ApprovalVote::Reject,
                    String::new(),
                    11,
                )
                .await
                .unwrap_err(),
            "APPROVAL_NOT_PENDING"
        );
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn any_mode_steps_run_in_order() {
        let storage = storage().await;
        let members = HashMap::from([("dba".to_string(), vec!["bob".to_string()])]);
        request_with_steps(
            &storage,
            "r1",
            &[spec(ApprovalStepMode::Any, &["dba"], &[]), spec(ApprovalStepMode::Any, &["dba"], &[])],
            &members,
        )
        .await;

        let first = storage
            .decide_approval_step(
                "r1".to_string(),
                "bob".to_string(),
                vec!["dba".to_string()],
                ApprovalVote::Approve,
                String::new(),
                10,
            )
            .await
            .unwrap();
        assert_eq!(first.step_no, 1);
        assert!(first.step_completed);
        assert_eq!(first.request_status, ApprovalStatus::Pending);
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.current_step_no, 2);

        let second = storage
            .decide_approval_step(
                "r1".to_string(),
                "bob".to_string(),
                vec!["dba".to_string()],
                ApprovalVote::Approve,
                String::new(),
                11,
            )
            .await
            .unwrap();
        assert_eq!(second.step_no, 2);
        assert_eq!(second.request_status, ApprovalStatus::Approved);
        let steps = storage.approval_steps_for_request("r1".to_string()).await.unwrap();
        assert!(steps.iter().all(|step| step.status == ApprovalStepStatus::Approved));
    }

    #[tokio::test]
    async fn countersign_needs_every_snapshot_approver() {
        let storage = storage().await;
        let members = HashMap::from([("dba".to_string(), vec!["bob".to_string(), "carol".to_string()])]);
        request_with_steps(&storage, "r1", &[spec(ApprovalStepMode::All, &["dba"], &[])], &members).await;

        let first = storage
            .decide_approval_step(
                "r1".to_string(),
                "bob".to_string(),
                vec!["dba".to_string()],
                ApprovalVote::Approve,
                "looks fine".to_string(),
                10,
            )
            .await
            .unwrap();
        assert_eq!(first.step_status, ApprovalStepStatus::Pending);
        assert!(!first.step_completed);
        assert_eq!(
            storage
                .decide_approval_step(
                    "r1".to_string(),
                    "bob".to_string(),
                    vec!["dba".to_string()],
                    ApprovalVote::Approve,
                    String::new(),
                    11,
                )
                .await
                .unwrap_err(),
            "APPROVAL_ALREADY_DECIDED"
        );

        let second = storage
            .decide_approval_step(
                "r1".to_string(),
                "carol".to_string(),
                vec!["dba".to_string()],
                ApprovalVote::Approve,
                String::new(),
                12,
            )
            .await
            .unwrap();
        assert!(second.step_completed);
        assert_eq!(second.request_status, ApprovalStatus::Approved);
        assert_eq!(storage.approval_step_decisions_for_request("r1".to_string()).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_rejection_skips_the_remaining_steps() {
        let storage = storage().await;
        let members = HashMap::from([("dba".to_string(), vec!["bob".to_string()])]);
        request_with_steps(
            &storage,
            "r1",
            &[spec(ApprovalStepMode::Any, &["dba"], &[]), spec(ApprovalStepMode::Any, &["dba"], &[])],
            &members,
        )
        .await;

        let outcome = storage
            .decide_approval_step(
                "r1".to_string(),
                "bob".to_string(),
                vec!["dba".to_string()],
                ApprovalVote::Reject,
                "too risky".to_string(),
                10,
            )
            .await
            .unwrap();
        assert_eq!(outcome.step_status, ApprovalStepStatus::Rejected);
        assert_eq!(outcome.request_status, ApprovalStatus::Rejected);
        let steps = storage.approval_steps_for_request("r1".to_string()).await.unwrap();
        assert_eq!(steps[0].status, ApprovalStepStatus::Rejected);
        assert_eq!(steps[1].status, ApprovalStepStatus::Skipped);
    }

    #[tokio::test]
    async fn only_a_listed_approver_can_vote() {
        let storage = storage().await;
        let members = HashMap::from([("dba".to_string(), vec!["bob".to_string()])]);
        request_with_steps(&storage, "r1", &[spec(ApprovalStepMode::Any, &["dba"], &[])], &members).await;
        assert_eq!(
            storage
                .decide_approval_step(
                    "r1".to_string(),
                    "mallory".to_string(),
                    vec!["dba".to_string()],
                    ApprovalVote::Approve,
                    String::new(),
                    10,
                )
                .await
                .unwrap_err(),
            "APPROVAL_NOT_APPROVER"
        );
        // A snapshot member can still vote after losing the role: only the
        // creation-time snapshot decides who may act.
        let outcome = storage
            .decide_approval_step(
                "r1".to_string(),
                "bob".to_string(),
                Vec::new(),
                ApprovalVote::Approve,
                String::new(),
                10,
            )
            .await
            .unwrap();
        assert_eq!(outcome.request_status, ApprovalStatus::Approved);
    }

    #[tokio::test]
    async fn the_requester_is_removed_from_countersign_sets() {
        let members = HashMap::from([("dba".to_string(), vec!["alice".to_string(), "bob".to_string()])]);
        let steps =
            materialize_approval_steps("r1", "alice", &[spec(ApprovalStepMode::All, &["dba"], &[])], &members).unwrap();
        assert_eq!(steps[0].required_user_ids, vec!["bob".to_string()]);
        assert_eq!(
            materialize_approval_steps(
                "r1",
                "alice",
                &[spec(ApprovalStepMode::Any, &["dba"], &[])],
                &HashMap::from([("dba".to_string(), vec!["alice".to_string()])])
            )
            .unwrap_err(),
            "APPROVAL_STEP_NO_APPROVER: step 1 has no approver other than the requester"
        );
    }

    #[tokio::test]
    async fn templates_resolve_to_the_most_specific_scope() {
        let storage = storage().await;
        let now = 1_000;
        let global = ApprovalTemplate {
            id: "t-global".to_string(),
            name: "Default".to_string(),
            scope_type: "global".to_string(),
            scope_id: String::new(),
            steps: vec![spec(ApprovalStepMode::Any, &["security_admin"], &[])],
            sla_secs: None,
            enabled: true,
            created_by: "admin".to_string(),
            created_at_ms: now,
            updated_at_ms: now,
        };
        storage.create_approval_template(global).await.unwrap();
        assert_eq!(storage.resolve_approval_template("conn".to_string()).await.unwrap().unwrap().id, "t-global");

        let connection = ApprovalTemplate {
            id: "t-conn".to_string(),
            name: "Prod".to_string(),
            scope_type: "connection".to_string(),
            scope_id: "conn".to_string(),
            steps: vec![spec(ApprovalStepMode::All, &["dba"], &[])],
            sla_secs: Some(3600),
            enabled: true,
            created_by: "admin".to_string(),
            created_at_ms: now,
            updated_at_ms: now + 1,
        };
        storage.create_approval_template(connection).await.unwrap();
        let resolved = storage.resolve_approval_template("conn".to_string()).await.unwrap().unwrap();
        assert_eq!(resolved.id, "t-conn");
        assert_eq!(resolved.steps[0].mode, ApprovalStepMode::All);
        assert_eq!(storage.list_approval_templates().await.unwrap().len(), 2);
        assert!(storage.delete_approval_template("t-conn".to_string()).await.unwrap());
        assert_eq!(storage.resolve_approval_template("conn".to_string()).await.unwrap().unwrap().id, "t-global");
    }

    #[tokio::test]
    async fn publishing_a_template_replaces_the_scope() {
        let storage = storage().await;
        let template = |id: &str, name: &str| ApprovalTemplate {
            id: id.to_string(),
            name: name.to_string(),
            scope_type: "global".to_string(),
            scope_id: String::new(),
            steps: vec![spec(ApprovalStepMode::Any, &["dba"], &[])],
            sla_secs: None,
            enabled: true,
            created_by: "admin".to_string(),
            created_at_ms: 1,
            updated_at_ms: 1,
        };
        storage.create_approval_template(template("t1", "v1")).await.unwrap();
        storage.create_approval_template(template("t2", "v2")).await.unwrap();
        let templates = storage.list_approval_templates().await.unwrap();
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].id, "t2");
    }

    #[tokio::test]
    async fn listing_filters_by_requester_and_status() {
        let storage = storage().await;
        storage.create_approval_request(request("r1", ApprovalStatus::Pending)).await.unwrap();
        let mut other = request("r2", ApprovalStatus::Approved);
        other.requester_id = "bob".to_string();
        storage.create_approval_request(other).await.unwrap();

        assert_eq!(storage.list_approval_requests(Some("alice".to_string()), None, 10).await.unwrap().len(), 1);
        assert_eq!(storage.list_approval_requests(None, Some("approved".to_string()), 10).await.unwrap()[0].id, "r2");
    }

    #[test]
    fn template_documents_are_validated() {
        use crate::governance::approval::{parse_steps_document, validate_steps, MAX_APPROVAL_STEPS};

        let wrapped = parse_steps_document(r#"{"steps":[{"mode":"all","roles":["dba"],"users":[]}]}"#).unwrap();
        assert_eq!(wrapped.len(), 1);
        let bare = parse_steps_document(r#"[{"roles":["dba"]}]"#).unwrap();
        assert_eq!(bare.len(), 1);
        assert!(parse_steps_document("[]").unwrap_err().starts_with("APPROVAL_TEMPLATE_EMPTY"));
        assert!(parse_steps_document("not json").unwrap_err().starts_with("APPROVAL_TEMPLATE_INVALID"));
        assert!(parse_steps_document(r#"[{"mode":"sometimes","roles":["dba"]}]"#).is_err());

        assert!(validate_steps(&[]).unwrap_err().starts_with("APPROVAL_TEMPLATE_EMPTY"));
        let too_many = vec![spec(ApprovalStepMode::Any, &["dba"], &[]); MAX_APPROVAL_STEPS + 1];
        assert!(validate_steps(&too_many).unwrap_err().starts_with("APPROVAL_TEMPLATE_INVALID"));
        assert!(validate_steps(&[spec(ApprovalStepMode::Any, &[], &[])])
            .unwrap_err()
            .starts_with("APPROVAL_TEMPLATE_INVALID"));
        assert!(validate_steps(&[spec(ApprovalStepMode::Any, &[" "], &[])])
            .unwrap_err()
            .starts_with("APPROVAL_TEMPLATE_INVALID"));
    }

    #[tokio::test]
    async fn an_approval_can_be_claimed_for_execution_only_once() {
        let storage = storage().await;
        storage.create_approval_request(request("r1", ApprovalStatus::Approved)).await.unwrap();

        assert!(storage.claim_approval_execution("r1".to_string(), 10).await.unwrap());
        assert!(!storage.claim_approval_execution("r1".to_string(), 11).await.unwrap(), "second claim must lose");
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Executing);

        assert!(storage
            .finish_approval_execution("r1".to_string(), ApprovalStatus::Executed, "bob".to_string(), None, 12,)
            .await
            .unwrap());
        assert!(!storage
            .finish_approval_execution(
                "r1".to_string(),
                ApprovalStatus::ExecutionFailed,
                "carol".to_string(),
                Some("late".to_string()),
                13,
            )
            .await
            .unwrap());
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Executed);
        assert_eq!(loaded.executed_by.as_deref(), Some("bob"));
        assert_eq!(loaded.executed_at_ms, Some(12));
        assert!(loaded.execution_error.is_none());
    }

    #[tokio::test]
    async fn a_binding_failure_fails_only_a_still_approved_request() {
        let storage = storage().await;
        storage.create_approval_request(request("r1", ApprovalStatus::Approved)).await.unwrap();
        assert!(storage
            .fail_approval_execution("r1".to_string(), "bob".to_string(), "APPROVAL_BINDING_MISMATCH".to_string(), 20)
            .await
            .unwrap());
        assert!(!storage
            .fail_approval_execution("r1".to_string(), "bob".to_string(), "again".to_string(), 21)
            .await
            .unwrap());
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::ExecutionFailed);
        assert_eq!(loaded.execution_error.as_deref(), Some("APPROVAL_BINDING_MISMATCH"));
    }

    #[tokio::test]
    async fn a_token_can_only_be_consumed_once() {
        let storage = storage().await;
        storage.create_approval_request(request("r1", ApprovalStatus::Approved)).await.unwrap();
        let (raw, hash) = new_approval_token();
        storage
            .create_approval_token(ApprovalToken {
                id: "t1".to_string(),
                request_id: "r1".to_string(),
                token_hash: hash.clone(),
                actor_id: "alice".to_string(),
                request_hash: "hash-1".to_string(),
                expires_at_ms: i64::MAX,
                consumed_at_ms: None,
            })
            .await
            .unwrap();
        assert!(storage.approval_token_by_hash(hash.clone()).await.unwrap().is_some());
        assert_ne!(raw, hash);
        assert!(storage.consume_approval_token("t1".to_string(), 5).await.unwrap());
        assert!(!storage.consume_approval_token("t1".to_string(), 6).await.unwrap());
    }
}
