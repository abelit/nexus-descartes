//! Versioned policy documents (append-only versions, latest published wins).

use super::{params, OptionalExtension, Storage};
use chrono::Utc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDocumentRow {
    pub id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub version: i64,
    pub status: String,
    pub document_json: String,
    pub created_by: Option<String>,
    pub created_at_ms: i64,
    pub note: String,
}

pub(super) fn ensure_policy_schema_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS policy_documents (
            id TEXT PRIMARY KEY,
            scope_type TEXT NOT NULL,
            scope_id TEXT NOT NULL DEFAULT '',
            version INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'published',
            document_json TEXT NOT NULL,
            created_by TEXT,
            created_at_ms INTEGER NOT NULL,
            published_at_ms INTEGER,
            published_by TEXT,
            note TEXT NOT NULL DEFAULT '',
            UNIQUE(scope_type, scope_id, version)
        );
        CREATE INDEX IF NOT EXISTS idx_policy_documents_scope
            ON policy_documents(scope_type, scope_id, version DESC);",
    )
    .map_err(|error| format!("POLICY_SCHEMA: {error}"))
}

fn row_to_document(row: &rusqlite::Row<'_>) -> rusqlite::Result<PolicyDocumentRow> {
    Ok(PolicyDocumentRow {
        id: row.get("id")?,
        scope_type: row.get("scope_type")?,
        scope_id: row.get("scope_id")?,
        version: row.get("version")?,
        status: row.get("status")?,
        document_json: row.get("document_json")?,
        created_by: row.get("created_by")?,
        created_at_ms: row.get("created_at_ms")?,
        note: row.get("note")?,
    })
}

impl Storage {
    /// Publishes a new immutable version. Versions are per scope and never
    /// reused, so a rollback publishes a new version rather than deleting.
    pub async fn publish_policy(
        &self,
        scope_type: String,
        scope_id: String,
        document_json: String,
        actor: String,
        note: String,
    ) -> Result<i64, String> {
        self.with_conn(move |conn| {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            let next_version: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(version), 0) + 1 FROM policy_documents \
                     WHERE scope_type = ?1 AND scope_id = ?2",
                    params![scope_type, scope_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            let now = Utc::now().timestamp_millis();
            tx.execute(
                "INSERT INTO policy_documents \
                 (id, scope_type, scope_id, version, status, document_json, created_by, created_at_ms, \
                  published_at_ms, published_by, note) \
                 VALUES (?1, ?2, ?3, ?4, 'published', ?5, ?6, ?7, ?7, ?6, ?8)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    scope_type,
                    scope_id,
                    next_version,
                    document_json,
                    actor,
                    now,
                    note,
                ],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(next_version)
        })
        .await
    }

    /// Publishes a copy of `source_version` as a new version (rollback).
    pub async fn rollback_policy(
        &self,
        scope_type: String,
        scope_id: String,
        source_version: i64,
        actor: String,
        note: String,
    ) -> Result<i64, String> {
        let document = self
            .policy_document_at(scope_type.clone(), scope_id.clone(), source_version)
            .await?
            .ok_or_else(|| "POLICY_VERSION_NOT_FOUND".to_string())?;
        self.publish_policy(scope_type, scope_id, document.document_json, actor, note).await
    }

    pub async fn policy_document_at(
        &self,
        scope_type: String,
        scope_id: String,
        version: i64,
    ) -> Result<Option<PolicyDocumentRow>, String> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT * FROM policy_documents \
                 WHERE scope_type = ?1 AND scope_id = ?2 AND version = ?3",
                params![scope_type, scope_id, version],
                row_to_document,
            )
            .optional()
            .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn list_policy_documents(
        &self,
        scope_type: String,
        scope_id: String,
        limit: usize,
    ) -> Result<Vec<PolicyDocumentRow>, String> {
        let limit = limit.clamp(1, 200) as i64;
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM policy_documents WHERE scope_type = ?1 AND scope_id = ?2 \
                     ORDER BY version DESC LIMIT ?3",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(params![scope_type, scope_id, limit], row_to_document)
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    /// The latest published version of every scope, for compilation.
    pub async fn latest_policy_documents(&self) -> Result<Vec<PolicyDocumentRow>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT p.* FROM policy_documents p \
                     JOIN (SELECT scope_type, scope_id, MAX(version) AS version FROM policy_documents \
                           GROUP BY scope_type, scope_id) latest \
                       ON p.scope_type = latest.scope_type AND p.scope_id = latest.scope_id \
                      AND p.version = latest.version \
                     ORDER BY p.scope_type, p.scope_id",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([], row_to_document).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }
}

#[cfg(all(test, feature = "enterprise-audit"))]
mod tests {
    use super::*;

    async fn storage() -> Storage {
        let path = std::env::temp_dir().join(format!("dbx-policy-{}.db", uuid::Uuid::new_v4()));
        crate::persistence::test_storage::open(&path).await.unwrap()
    }

    #[tokio::test]
    async fn versions_are_monotonic_and_latest_wins() {
        let storage = storage().await;
        let doc = r#"{"rules":[]}"#.to_string();
        assert_eq!(
            storage
                .publish_policy("global".into(), String::new(), doc.clone(), "admin".into(), "v1".into())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .publish_policy("global".into(), String::new(), doc.clone(), "admin".into(), "v2".into())
                .await
                .unwrap(),
            2
        );
        let latest = storage.latest_policy_documents().await.unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].version, 2);
        assert_eq!(storage.list_policy_documents("global".into(), String::new(), 10).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn scopes_are_versioned_independently_and_rollback_copies() {
        let storage = storage().await;
        let doc = r#"{"rules":[]}"#.to_string();
        storage.publish_policy("global".into(), String::new(), doc.clone(), "admin".into(), "v1".into()).await.unwrap();
        storage.publish_policy("connection".into(), "conn-1".into(), doc, "admin".into(), "v1".into()).await.unwrap();

        let version = storage
            .rollback_policy("global".into(), String::new(), 1, "admin".into(), "rollback".into())
            .await
            .unwrap();
        assert_eq!(version, 2);
        let latest = storage.latest_policy_documents().await.unwrap();
        assert_eq!(latest.len(), 2, "each scope keeps its own latest version");
    }
}
