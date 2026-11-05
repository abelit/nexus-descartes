//! Self-service access requests and their approval decisions.

use super::{params, OptionalExtension, Storage};
use crate::governance::assets::{AccessRequest, AccessRequestStatus, AssetGrant, AssetTargetKind};

pub(super) fn ensure_access_request_schema_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS access_requests (
            id TEXT PRIMARY KEY,
            requester_id TEXT NOT NULL,
            role_code TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            connection_group_id TEXT,
            connection_id TEXT,
            database_name TEXT,
            schema_name TEXT,
            table_name TEXT,
            name_pattern INTEGER NOT NULL DEFAULT 0,
            duration_hours INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            justification TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            decided_by TEXT,
            decided_at TEXT,
            decision_note TEXT NOT NULL DEFAULT '',
            grant_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_access_requests_requester
            ON access_requests(requester_id, status, created_at);
        CREATE INDEX IF NOT EXISTS idx_access_requests_status
            ON access_requests(status, created_at);",
    )
    .map_err(|error| format!("ACCESS_REQUEST_SCHEMA: {error}"))
}

fn row_to_access_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccessRequest> {
    let target_kind: String = row.get("target_kind")?;
    let status: String = row.get("status")?;
    Ok(AccessRequest {
        id: row.get("id")?,
        requester_id: row.get("requester_id")?,
        role_code: row.get("role_code")?,
        target_kind: AssetTargetKind::parse(&target_kind).unwrap_or(AssetTargetKind::Connection),
        connection_group_id: row.get("connection_group_id")?,
        connection_id: row.get("connection_id")?,
        database_name: row.get("database_name")?,
        schema_name: row.get("schema_name")?,
        table_name: row.get("table_name")?,
        name_pattern: row.get::<_, i64>("name_pattern")? != 0,
        duration_hours: row.get("duration_hours")?,
        expires_at: row.get("expires_at")?,
        justification: row.get("justification")?,
        status: AccessRequestStatus::parse(&status).unwrap_or(AccessRequestStatus::Pending),
        decided_by: row.get("decided_by")?,
        decided_at: row.get("decided_at")?,
        decision_note: row.get("decision_note")?,
        grant_id: row.get("grant_id")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

impl Storage {
    pub async fn create_access_request(&self, request: AccessRequest) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO access_requests (
                    id, requester_id, role_code, target_kind, connection_group_id, connection_id,
                    database_name, schema_name, table_name, name_pattern, duration_hours,
                    expires_at, justification, status, decided_by, decided_at, decision_note,
                    grant_id, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'pending',
                           NULL, NULL, '', NULL, ?14, ?15)",
                params![
                    request.id,
                    request.requester_id,
                    request.role_code,
                    request.target_kind.as_str(),
                    request.connection_group_id,
                    request.connection_id,
                    request.database_name,
                    request.schema_name,
                    request.table_name,
                    i64::from(request.name_pattern),
                    request.duration_hours,
                    request.expires_at,
                    request.justification,
                    request.created_at,
                    request.updated_at,
                ],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn access_request_by_id(&self, id: String) -> Result<Option<AccessRequest>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM access_requests WHERE id = ?1", [id], row_to_access_request)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// `requester_id = None` lists every request (administrators only; the
    /// caller enforces that). Newest first.
    pub async fn list_access_requests(
        &self,
        requester_id: Option<String>,
        status: Option<String>,
        limit: i64,
    ) -> Result<Vec<AccessRequest>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM access_requests \
                     WHERE (?1 IS NULL OR requester_id = ?1) \
                       AND (?2 IS NULL OR status = ?2) \
                     ORDER BY created_at DESC, id DESC LIMIT ?3",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(params![requester_id, status, limit], row_to_access_request)
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    /// True when the same requester already has a pending request for the same
    /// role and target. Repeated submissions are rejected instead of creating
    /// duplicate tickets.
    pub async fn pending_access_request_exists(&self, request: AccessRequest) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM access_requests \
                     WHERE requester_id = ?1 AND status = 'pending' AND role_code = ?2 \
                       AND target_kind = ?3 \
                       AND COALESCE(connection_group_id, '') = COALESCE(?4, '') \
                       AND COALESCE(connection_id, '') = COALESCE(?5, '') \
                       AND COALESCE(database_name, '') = COALESCE(?6, '') \
                       AND COALESCE(schema_name, '') = COALESCE(?7, '') \
                       AND COALESCE(table_name, '') = COALESCE(?8, '') \
                       AND name_pattern = ?9 \
                     LIMIT 1",
                    params![
                        request.requester_id,
                        request.role_code,
                        request.target_kind.as_str(),
                        request.connection_group_id,
                        request.connection_id,
                        request.database_name,
                        request.schema_name,
                        request.table_name,
                        i64::from(request.name_pattern),
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|error| error.to_string())?;
            Ok(exists.is_some())
        })
        .await
    }

    /// Marks the request approved and inserts the resulting grant atomically.
    /// Returns `false` when another approver won the race (status no longer
    /// pending) or the request was cancelled.
    pub async fn approve_access_request(
        &self,
        request_id: String,
        actor_id: String,
        note: String,
        decided_at: String,
        grant: AssetGrant,
    ) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let tx = conn.unchecked_transaction().map_err(|error| error.to_string())?;
            let changed = tx
                .execute(
                    "UPDATE access_requests SET status = 'approved', decided_by = ?1, decided_at = ?2, \
                     decision_note = ?3, grant_id = ?4, updated_at = ?2 \
                     WHERE id = ?5 AND status = 'pending'",
                    params![actor_id, decided_at, note, grant.id, request_id],
                )
                .map_err(|error| error.to_string())?;
            if changed == 0 {
                return Ok(false);
            }
            super::asset_grants::insert_asset_grant_sync(&tx, &grant)?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(true)
        })
        .await
    }

    pub async fn reject_access_request(
        &self,
        request_id: String,
        actor_id: String,
        note: String,
        decided_at: String,
    ) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE access_requests SET status = 'rejected', decided_by = ?1, decided_at = ?2, \
                     decision_note = ?3, updated_at = ?2 WHERE id = ?4 AND status = 'pending'",
                    params![actor_id, decided_at, note, request_id],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn cancel_access_request(
        &self,
        request_id: String,
        requester_id: String,
        cancelled_at: String,
    ) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE access_requests SET status = 'cancelled', updated_at = ?1 \
                     WHERE id = ?2 AND requester_id = ?3 AND status = 'pending'",
                    params![cancelled_at, request_id, requester_id],
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
    use crate::governance::assets::{AccessRequest, AccessRequestStatus, AssetGrant};

    fn request(id: &str, requester: &str) -> AccessRequest {
        let now = super::super::identity::now_rfc3339();
        AccessRequest {
            id: id.to_string(),
            requester_id: requester.to_string(),
            role_code: "viewer".to_string(),
            target_kind: AssetTargetKind::Connection,
            connection_group_id: None,
            connection_id: Some("conn-1".to_string()),
            database_name: None,
            schema_name: None,
            table_name: None,
            name_pattern: false,
            duration_hours: 24,
            expires_at: "2099-01-01T00:00:00.000Z".to_string(),
            justification: "test".to_string(),
            status: AccessRequestStatus::Pending,
            decided_by: None,
            decided_at: None,
            decision_note: String::new(),
            grant_id: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    fn grant(request: &AccessRequest) -> AssetGrant {
        let now = super::super::identity::now_rfc3339();
        AssetGrant {
            id: uuid::Uuid::new_v4().to_string(),
            principal_type: "user".to_string(),
            principal_id: request.requester_id.clone(),
            role_code: request.role_code.clone(),
            target_kind: request.target_kind,
            connection_group_id: request.connection_group_id.clone(),
            connection_id: request.connection_id.clone(),
            database_name: None,
            schema_name: None,
            table_name: None,
            name_pattern: false,
            expires_at: Some(request.expires_at.clone()),
            granted_by: Some("approver".to_string()),
            reason: "Access request: test".to_string(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn approving_inserts_the_grant_once_and_links_it() {
        let path = std::env::temp_dir().join(format!("dbx-access-request-{}.db", uuid::Uuid::new_v4()));
        let storage = crate::persistence::test_storage::open(&path).await.unwrap();
        let request = request("req-1", "user-1");
        storage.create_access_request(request.clone()).await.unwrap();
        assert!(storage.pending_access_request_exists(request.clone()).await.unwrap());
        assert_eq!(storage.list_access_requests(Some("user-1".to_string()), None, 10).await.unwrap().len(), 1);
        assert!(storage.list_access_requests(Some("other".to_string()), None, 10).await.unwrap().is_empty());

        let grant = grant(&request);
        let now = super::super::identity::now_rfc3339();
        assert!(storage
            .approve_access_request(
                request.id.clone(),
                "approver".to_string(),
                "ok".to_string(),
                now.clone(),
                grant.clone()
            )
            .await
            .unwrap());
        let approved = storage.access_request_by_id(request.id.clone()).await.unwrap().unwrap();
        assert_eq!(approved.status, AccessRequestStatus::Approved);
        assert_eq!(approved.grant_id.as_deref(), Some(grant.id.as_str()));
        assert_eq!(storage.effective_asset_grants_for_user("user-1".to_string()).await.unwrap().len(), 1);
        // A second approval cannot insert a second grant.
        assert!(!storage
            .approve_access_request(request.id.clone(), "approver".to_string(), "again".to_string(), now, grant)
            .await
            .unwrap());
        assert!(!storage.pending_access_request_exists(request).await.unwrap());
    }

    #[tokio::test]
    async fn cancelling_requires_the_requester_and_pending_status() {
        let path = std::env::temp_dir().join(format!("dbx-access-request-{}.db", uuid::Uuid::new_v4()));
        let storage = crate::persistence::test_storage::open(&path).await.unwrap();
        let request = request("req-2", "user-2");
        storage.create_access_request(request.clone()).await.unwrap();
        assert!(!storage
            .cancel_access_request(request.id.clone(), "other".to_string(), request.created_at.clone())
            .await
            .unwrap());
        assert!(storage
            .cancel_access_request(request.id.clone(), "user-2".to_string(), request.created_at)
            .await
            .unwrap());
        let cancelled = storage.access_request_by_id(request.id).await.unwrap().unwrap();
        assert_eq!(cancelled.status, AccessRequestStatus::Cancelled);
    }
}
