//! Persistence for approval requests and one-time execution tokens.

use super::{params, OptionalExtension, Storage};
use crate::governance::approval::{ApprovalRequest, ApprovalStatus, ApprovalToken};

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
            sql_digest TEXT NOT NULL,
            statement_count INTEGER NOT NULL DEFAULT 1,
            risk_level TEXT,
            rule_ids_json TEXT NOT NULL DEFAULT '[]',
            policy_bundle_hash TEXT,
            justification TEXT NOT NULL DEFAULT '',
            request_hash TEXT NOT NULL,
            expires_at_ms INTEGER,
            created_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            executed_at_ms INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_approval_requests_status
            ON approval_requests(status, created_at_ms DESC);
        CREATE INDEX IF NOT EXISTS idx_approval_requests_requester
            ON approval_requests(requester_id, created_at_ms DESC);
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
    .map_err(|error| format!("APPROVAL_SCHEMA: {error}"))
}

fn row_to_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRequest> {
    let rule_ids_json: String = row.get("rule_ids_json")?;
    let status: String = row.get("status")?;
    Ok(ApprovalRequest {
        id: row.get("id")?,
        request_type: row.get("request_type")?,
        status: ApprovalStatus::parse(&status).unwrap_or(ApprovalStatus::Pending),
        requester_id: row.get("requester_id")?,
        connection_id: row.get("connection_id")?,
        database: row.get("database")?,
        schema_name: row.get("schema_name")?,
        sql_text: row.get("sql_text")?,
        sql_digest: row.get("sql_digest")?,
        statement_count: row.get("statement_count")?,
        risk_level: row.get("risk_level")?,
        rule_ids: serde_json::from_str(&rule_ids_json).unwrap_or_default(),
        policy_bundle_hash: row.get("policy_bundle_hash")?,
        justification: row.get("justification")?,
        request_hash: row.get("request_hash")?,
        expires_at_ms: row.get("expires_at_ms")?,
        created_at_ms: row.get("created_at_ms")?,
        updated_at_ms: row.get("updated_at_ms")?,
        executed_at_ms: row.get("executed_at_ms")?,
    })
}

fn row_to_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalToken> {
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
    pub async fn create_approval_request(&self, request: ApprovalRequest) -> Result<(), String> {
        self.with_conn(move |conn| {
            let rule_ids_json = serde_json::to_string(&request.rule_ids).map_err(|error| error.to_string())?;
            conn.execute(
                "INSERT INTO approval_requests (
                    id, request_type, status, requester_id, connection_id, database, schema_name,
                    sql_text, sql_digest, statement_count, risk_level, rule_ids_json,
                    policy_bundle_hash, justification, request_hash, expires_at_ms,
                    created_at_ms, updated_at_ms, executed_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, NULL)",
                params![
                    request.id,
                    request.request_type,
                    request.status.as_str(),
                    request.requester_id,
                    request.connection_id,
                    request.database,
                    request.schema_name,
                    request.sql_text,
                    request.sql_digest,
                    request.statement_count,
                    request.risk_level,
                    rule_ids_json,
                    request.policy_bundle_hash,
                    request.justification,
                    request.request_hash,
                    request.expires_at_ms,
                    request.created_at_ms,
                    request.updated_at_ms,
                ],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
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

    /// Moves a request to `status` only when it is still pending, so two
    /// approvers cannot both decide (and the first decision wins).
    pub async fn decide_approval_request(
        &self,
        id: String,
        status: ApprovalStatus,
        now_ms: i64,
    ) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE approval_requests SET status = ?1, updated_at_ms = ?2 \
                     WHERE id = ?3 AND status = 'pending'",
                    params![status.as_str(), now_ms, id],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn mark_approval_executed(
        &self,
        id: String,
        status: ApprovalStatus,
        executed_at_ms: i64,
    ) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE approval_requests SET status = ?1, executed_at_ms = ?2, updated_at_ms = ?2 WHERE id = ?3",
                params![status.as_str(), executed_at_ms, id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
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
            conn.query_row("SELECT * FROM approval_tokens WHERE token_hash = ?1", [token_hash], row_to_token)
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
    use super::*;
    use crate::governance::approval::{new_approval_token, statements_digest};

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
            sql_digest: statements_digest(&["ALTER TABLE users ADD COLUMN age int".to_string()]),
            statement_count: 1,
            risk_level: Some("DDL".to_string()),
            rule_ids: vec!["prod.ddl.approval".to_string()],
            policy_bundle_hash: Some("bundle".to_string()),
            justification: "add column".to_string(),
            request_hash: "hash-1".to_string(),
            expires_at_ms: None,
            created_at_ms: 1,
            updated_at_ms: 1,
            executed_at_ms: None,
        }
    }

    #[tokio::test]
    async fn a_request_round_trips_and_only_one_decision_wins() {
        let storage = storage().await;
        storage.create_approval_request(request("r1", ApprovalStatus::Pending)).await.unwrap();
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.rule_ids, vec!["prod.ddl.approval".to_string()]);

        assert!(storage.decide_approval_request("r1".to_string(), ApprovalStatus::Approved, 10).await.unwrap());
        assert!(
            !storage.decide_approval_request("r1".to_string(), ApprovalStatus::Rejected, 11).await.unwrap(),
            "a decided request must not be decided again"
        );
        let loaded = storage.approval_request_by_id("r1".to_string()).await.unwrap().unwrap();
        assert_eq!(loaded.status, ApprovalStatus::Approved);
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
