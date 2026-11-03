//! Asset grants: connection, database, schema, and table targets.

use super::{params, OptionalExtension, Storage};
use crate::governance::assets::{AssetGrant, AssetSnapshotData, AssetTargetKind};

pub(super) fn ensure_asset_grant_schema_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS asset_grants (
            id TEXT PRIMARY KEY,
            principal_type TEXT NOT NULL DEFAULT 'user',
            principal_id TEXT NOT NULL,
            role_code TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            connection_group_id TEXT,
            connection_id TEXT,
            database_name TEXT,
            schema_name TEXT,
            table_name TEXT,
            name_pattern INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT,
            granted_by TEXT,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_asset_grants_principal
            ON asset_grants(principal_type, principal_id, expires_at);
        CREATE INDEX IF NOT EXISTS idx_asset_grants_connection
            ON asset_grants(connection_id, target_kind);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_grants_natural
            ON asset_grants(principal_type, principal_id, role_code, target_kind,
                COALESCE(connection_group_id,''), COALESCE(connection_id,''),
                COALESCE(database_name,''), COALESCE(schema_name,''), COALESCE(table_name,''),
                name_pattern, COALESCE(expires_at,''));",
    )
    .map_err(|error| format!("ASSET_GRANT_SCHEMA: {error}"))?;
    migrate_legacy_scopes_sync(conn)
}

/// Moves legacy non-global `role_bindings` rows into `asset_grants` and deletes
/// them in the same transaction. Global bindings stay in `role_bindings`.
fn migrate_legacy_scopes_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    let legacy: Vec<(
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
    )> = {
        let mut stmt = conn
            .prepare(
                "SELECT id, principal_type, principal_id, role_code, scope_type, scope_id, expires_at, \
                        granted_by, reason, created_at FROM role_bindings WHERE scope_type != 'global'",
            )
            .map_err(|error| error.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            })
            .map_err(|error| error.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?
    };
    if legacy.is_empty() {
        return Ok(());
    }
    let tx = conn.unchecked_transaction().map_err(|error| error.to_string())?;
    for (
        binding_id,
        principal_type,
        principal_id,
        role_code,
        scope_type,
        scope_id,
        expires_at,
        granted_by,
        reason,
        created_at,
    ) in legacy
    {
        let Some(scope_id) = scope_id.filter(|value| !value.trim().is_empty()) else {
            // An invalid legacy row still has to go; otherwise it would keep
            // granting role-only behavior after the migration.
            tx.execute("DELETE FROM role_bindings WHERE id = ?1", params![binding_id])
                .map_err(|error| error.to_string())?;
            continue;
        };
        let target = match scope_type.as_str() {
            "connection" => Some((AssetTargetKind::Connection, Some(scope_id.clone()), None, None)),
            "connection_group" => Some((AssetTargetKind::ConnectionGroup, None, Some(scope_id.clone()), None)),
            "database" => scope_id.split_once("::").and_then(|(connection, database)| {
                (!connection.is_empty() && !database.is_empty()).then(|| {
                    (AssetTargetKind::Database, Some(connection.to_string()), None, Some(database.to_string()))
                })
            }),
            _ => None,
        };
        if let Some((target_kind, connection_id, group_id, database_name)) = target {
            let now = super::identity::now_rfc3339();
            tx.execute(
                "INSERT OR IGNORE INTO asset_grants (
                    id, principal_type, principal_id, role_code, target_kind, connection_group_id,
                    connection_id, database_name, schema_name, table_name, name_pattern,
                    expires_at, granted_by, reason, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, 0, ?9, ?10, ?11, ?12, ?13)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    principal_type,
                    principal_id,
                    role_code,
                    target_kind.as_str(),
                    group_id,
                    connection_id,
                    database_name,
                    expires_at,
                    granted_by,
                    reason,
                    created_at,
                    now,
                ],
            )
            .map_err(|error| error.to_string())?;
        }
        tx.execute("DELETE FROM role_bindings WHERE id = ?1", params![binding_id])
            .map_err(|error| error.to_string())?;
    }
    tx.commit().map_err(|error| error.to_string())
}

fn row_to_grant(row: &rusqlite::Row<'_>) -> rusqlite::Result<AssetGrant> {
    let target_kind: String = row.get("target_kind")?;
    Ok(AssetGrant {
        id: row.get("id")?,
        principal_type: row.get("principal_type")?,
        principal_id: row.get("principal_id")?,
        role_code: row.get("role_code")?,
        target_kind: AssetTargetKind::parse(&target_kind).unwrap_or(AssetTargetKind::Connection),
        connection_group_id: row.get("connection_group_id")?,
        connection_id: row.get("connection_id")?,
        database_name: row.get("database_name")?,
        schema_name: row.get("schema_name")?,
        table_name: row.get("table_name")?,
        name_pattern: row.get::<_, i64>("name_pattern")? != 0,
        expires_at: row.get("expires_at")?,
        granted_by: row.get("granted_by")?,
        reason: row.get("reason")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

pub(super) fn insert_asset_grant_sync(conn: &rusqlite::Connection, grant: &AssetGrant) -> Result<(), String> {
    conn.execute(
        "INSERT INTO asset_grants (
            id, principal_type, principal_id, role_code, target_kind, connection_group_id,
            connection_id, database_name, schema_name, table_name, name_pattern,
            expires_at, granted_by, reason, created_at, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            grant.id,
            grant.principal_type,
            grant.principal_id,
            grant.role_code,
            grant.target_kind.as_str(),
            grant.connection_group_id,
            grant.connection_id,
            grant.database_name,
            grant.schema_name,
            grant.table_name,
            i64::from(grant.name_pattern),
            grant.expires_at,
            grant.granted_by,
            grant.reason,
            grant.created_at,
            grant.updated_at,
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

impl Storage {
    pub async fn asset_snapshot_data(&self, user_id: String) -> Result<AssetSnapshotData, String> {
        self.with_conn(move |conn| {
            let mut data = AssetSnapshotData::default();
            {
                let mut stmt = conn
                    .prepare(
                        "SELECT role_code FROM role_bindings \
                         WHERE principal_type = 'user' AND principal_id = ?1 AND scope_type = 'global' \
                           AND (expires_at IS NULL OR expires_at > ?2) ORDER BY role_code",
                    )
                    .map_err(|error| error.to_string())?;
                let rows = stmt
                    .query_map(params![user_id, super::identity::now_rfc3339()], |row| row.get::<_, String>(0))
                    .map_err(|error| error.to_string())?;
                data.global_roles = rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
            }
            {
                let mut stmt = conn
                    .prepare(
                        "SELECT * FROM asset_grants WHERE principal_type = 'user' AND principal_id = ?1 \
                         AND (expires_at IS NULL OR expires_at > ?2) ORDER BY created_at",
                    )
                    .map_err(|error| error.to_string())?;
                let rows = stmt
                    .query_map(params![user_id, super::identity::now_rfc3339()], row_to_grant)
                    .map_err(|error| error.to_string())?;
                data.grants = rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
            }
            {
                let mut stmt = conn
                    .prepare("SELECT group_id, connection_id FROM connection_group_members")
                    .map_err(|error| error.to_string())?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
                    .map_err(|error| error.to_string())?;
                data.group_members = rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
            }
            {
                let mut stmt =
                    conn.prepare("SELECT id, parent_id FROM connection_groups").map_err(|error| error.to_string())?;
                let rows = stmt
                    .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)))
                    .map_err(|error| error.to_string())?;
                data.groups = rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())?;
            }
            Ok(data)
        })
        .await
    }

    pub async fn asset_grants_for_user(&self, user_id: String) -> Result<Vec<AssetGrant>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM asset_grants WHERE principal_type = 'user' AND principal_id = ?1 ORDER BY created_at")
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([user_id], row_to_grant).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn asset_grant_by_id(&self, id: String) -> Result<Option<AssetGrant>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM asset_grants WHERE id = ?1", [id], row_to_grant)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn create_asset_grant(&self, grant: AssetGrant) -> Result<(), String> {
        self.with_conn(move |conn| insert_asset_grant_sync(conn, &grant)).await
    }

    pub async fn update_asset_grant(&self, grant: AssetGrant) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE asset_grants SET role_code = ?1, target_kind = ?2, connection_group_id = ?3, \
                     connection_id = ?4, database_name = ?5, schema_name = ?6, table_name = ?7, \
                     name_pattern = ?8, expires_at = ?9, reason = ?10, updated_at = ?11 WHERE id = ?12",
                    params![
                        grant.role_code,
                        grant.target_kind.as_str(),
                        grant.connection_group_id,
                        grant.connection_id,
                        grant.database_name,
                        grant.schema_name,
                        grant.table_name,
                        i64::from(grant.name_pattern),
                        grant.expires_at,
                        grant.reason,
                        grant.updated_at,
                        grant.id,
                    ],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn delete_asset_grant(&self, id: String, user_id: String) -> Result<bool, String> {
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "DELETE FROM asset_grants WHERE id = ?1 AND principal_type = 'user' AND principal_id = ?2",
                    params![id, user_id],
                )
                .map_err(|error| error.to_string())?;
            Ok(changed == 1)
        })
        .await
    }

    pub async fn asset_role_codes_for_user(&self, user_id: String) -> Result<Vec<String>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT role_code FROM asset_grants WHERE principal_type = 'user' AND principal_id = ?1 \
                     AND (expires_at IS NULL OR expires_at > ?2) ORDER BY role_code",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(params![user_id, super::identity::now_rfc3339()], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn asset_user_ids_for_role(&self, role_code: String) -> Result<Vec<String>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT principal_id FROM asset_grants \
                     WHERE principal_type = 'user' AND role_code = ?1 \
                       AND (expires_at IS NULL OR expires_at > ?2) ORDER BY principal_id",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(params![role_code, super::identity::now_rfc3339()], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn delete_asset_grants_for_user(&self, user_id: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute("DELETE FROM asset_grants WHERE principal_type = 'user' AND principal_id = ?1", [user_id])
                .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn cleanup_connection_asset_grants(&self, connection_id: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute("DELETE FROM asset_grants WHERE connection_id = ?1", [connection_id])
                .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }
}
