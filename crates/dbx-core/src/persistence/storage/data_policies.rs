//! Column-mask and read-row-filter policy storage.

use super::{params, OptionalExtension, Storage};
use crate::governance::data_policies::{DataPolicy, DataPolicyKind};

pub(super) fn ensure_data_policy_schema_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS data_policies (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            database_name TEXT,
            schema_name TEXT,
            table_name TEXT NOT NULL,
            name_pattern INTEGER NOT NULL DEFAULT 0,
            column_name TEXT NOT NULL,
            mask_type TEXT NOT NULL DEFAULT 'full',
            replacement TEXT NOT NULL DEFAULT '***',
            allowed_values_json TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_data_policies_connection
            ON data_policies(connection_id, enabled);",
    )
    .map_err(|error| format!("DATA_POLICY_SCHEMA: {error}"))
}

fn row_to_data_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<DataPolicy> {
    let kind: String = row.get("kind")?;
    let allowed_values_json: String = row.get("allowed_values_json")?;
    Ok(DataPolicy {
        id: row.get("id")?,
        name: row.get("name")?,
        kind: DataPolicyKind::parse(&kind).unwrap_or(DataPolicyKind::Mask),
        connection_id: row.get("connection_id")?,
        database_name: row.get("database_name")?,
        schema_name: row.get("schema_name")?,
        table_name: row.get("table_name")?,
        name_pattern: row.get::<_, i64>("name_pattern")? != 0,
        column_name: row.get("column_name")?,
        mask_type: row.get("mask_type")?,
        replacement: row.get("replacement")?,
        allowed_values: serde_json::from_str(&allowed_values_json).unwrap_or_default(),
        enabled: row.get::<_, i64>("enabled")? != 0,
        created_by: row.get("created_by")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

fn allowed_values_json(policy: &DataPolicy) -> String {
    serde_json::to_string(&policy.allowed_values).unwrap_or_else(|_| "[]".to_string())
}

impl Storage {
    pub async fn list_data_policies(&self, connection_id: Option<String>) -> Result<Vec<DataPolicy>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM data_policies \
                     WHERE (?1 IS NULL OR connection_id = ?1) \
                     ORDER BY connection_id, name COLLATE NOCASE, created_at",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map(params![connection_id], row_to_data_policy).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn list_enabled_data_policies(&self, connection_id: String) -> Result<Vec<DataPolicy>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM data_policies WHERE connection_id = ?1 AND enabled = 1 ORDER BY name")
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([connection_id], row_to_data_policy).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn data_policy_by_id(&self, id: String) -> Result<Option<DataPolicy>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM data_policies WHERE id = ?1", [id], row_to_data_policy)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn create_data_policy(&self, policy: DataPolicy) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO data_policies (
                    id, name, kind, connection_id, database_name, schema_name, table_name,
                    name_pattern, column_name, mask_type, replacement, allowed_values_json,
                    enabled, created_by, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    policy.id,
                    policy.name,
                    policy.kind.as_str(),
                    policy.connection_id,
                    policy.database_name,
                    policy.schema_name,
                    policy.table_name,
                    i64::from(policy.name_pattern),
                    policy.column_name,
                    policy.mask_type,
                    policy.replacement,
                    allowed_values_json(&policy),
                    i64::from(policy.enabled),
                    policy.created_by,
                    policy.created_at,
                    policy.updated_at,
                ],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn update_data_policy(&self, policy: DataPolicy) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let values = allowed_values_json(&policy);
            let changed = conn
                .execute(
                    "UPDATE data_policies SET name = ?1, kind = ?2, connection_id = ?3, database_name = ?4, \
                     schema_name = ?5, table_name = ?6, name_pattern = ?7, column_name = ?8, mask_type = ?9, \
                     replacement = ?10, allowed_values_json = ?11, enabled = ?12, updated_at = ?13 WHERE id = ?14",
                    params![
                        policy.name,
                        policy.kind.as_str(),
                        policy.connection_id,
                        policy.database_name,
                        policy.schema_name,
                        policy.table_name,
                        i64::from(policy.name_pattern),
                        policy.column_name,
                        policy.mask_type,
                        policy.replacement,
                        values,
                        i64::from(policy.enabled),
                        policy.updated_at,
                        policy.id,
                    ],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn delete_data_policy(&self, id: String) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed =
                conn.execute("DELETE FROM data_policies WHERE id = ?1", [id]).map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn cleanup_connection_data_policies(&self, connection_id: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute("DELETE FROM data_policies WHERE connection_id = ?1", [connection_id])
                .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }
}

#[cfg(all(test, feature = "enterprise-audit"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn policies_round_trip_and_are_scoped_to_their_connection() {
        let path = std::env::temp_dir().join(format!("dbx-data-policy-{}.db", uuid::Uuid::new_v4()));
        let storage = crate::persistence::test_storage::open(&path).await.unwrap();
        let now = super::super::identity::now_rfc3339();
        let policy = DataPolicy {
            id: uuid::Uuid::new_v4().to_string(),
            name: "hide email".to_string(),
            kind: DataPolicyKind::Mask,
            connection_id: "conn-1".to_string(),
            database_name: Some("app".to_string()),
            schema_name: None,
            table_name: "customers".to_string(),
            name_pattern: false,
            column_name: "email".to_string(),
            mask_type: "email".to_string(),
            replacement: "***".to_string(),
            allowed_values: Vec::new(),
            enabled: true,
            created_by: Some("admin".to_string()),
            created_at: now.clone(),
            updated_at: now,
        };
        storage.create_data_policy(policy.clone()).await.unwrap();
        assert_eq!(storage.list_data_policies(Some("conn-1".to_string())).await.unwrap().len(), 1);
        assert_eq!(storage.list_data_policies(Some("conn-2".to_string())).await.unwrap().len(), 0);
        assert_eq!(storage.list_enabled_data_policies("conn-1".to_string()).await.unwrap().len(), 1);
        let mut disabled = policy.clone();
        disabled.enabled = false;
        assert!(storage.update_data_policy(disabled).await.unwrap());
        assert!(storage.list_enabled_data_policies("conn-1".to_string()).await.unwrap().is_empty());
        assert!(storage.delete_data_policy(policy.id).await.unwrap());
        assert!(storage.data_policy_by_id("missing".to_string()).await.unwrap().is_none());
    }
}
