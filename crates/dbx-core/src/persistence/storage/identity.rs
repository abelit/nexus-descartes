//! Users, roles, role bindings, and persistent web sessions.

use super::{params, OptionalExtension, Storage};
use crate::identity::{BuiltinRole, User, WebSessionRecord};
use chrono::Utc;

/// Creates the identity tables and seeds the built-in roles. Idempotent: every
/// statement uses `IF NOT EXISTS`, and role rows use `INSERT OR IGNORE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomRoleRow {
    pub code: String,
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleBindingRow {
    pub role_code: String,
    pub scope_type: String,
    pub scope_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionGroupRow {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub connection_ids: Vec<String>,
}

pub(super) fn ensure_identity_schema_sync(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            is_builtin INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login_at TEXT
        );
        CREATE TABLE IF NOT EXISTS roles (
            code TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            builtin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_code TEXT NOT NULL,
            permission TEXT NOT NULL,
            PRIMARY KEY (role_code, permission)
        );
        CREATE TABLE IF NOT EXISTS role_bindings (
            id TEXT PRIMARY KEY,
            principal_type TEXT NOT NULL DEFAULT 'user',
            principal_id TEXT NOT NULL,
            role_code TEXT NOT NULL,
            scope_type TEXT NOT NULL DEFAULT 'global',
            scope_id TEXT,
            expires_at TEXT,
            granted_by TEXT,
            reason TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_role_bindings_principal
            ON role_bindings(principal_type, principal_id);
        CREATE TABLE IF NOT EXISTS web_sessions (
            id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            user_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            last_seen_at_ms INTEGER NOT NULL,
            expires_at_ms INTEGER NOT NULL,
            revoked_at_ms INTEGER,
            client_ip TEXT,
            user_agent TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id, expires_at_ms);
        CREATE TABLE IF NOT EXISTS connection_groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            parent_id TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS connection_group_members (
            group_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            PRIMARY KEY (group_id, connection_id)
        );
        CREATE INDEX IF NOT EXISTS idx_connection_group_members_conn
            ON connection_group_members(connection_id);",
    )
    .map_err(|error| format!("IDENTITY_SCHEMA: {error}"))?;

    for role in BuiltinRole::ALL {
        conn.execute(
            "INSERT OR IGNORE INTO roles (code, name, description, builtin) VALUES (?1, ?2, ?3, 1)",
            params![role.code(), role.name(), role.description()],
        )
        .map_err(|error| format!("IDENTITY_ROLE_SEED: {error}"))?;
        for (role_code, permission) in role.permission_rows() {
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions (role_code, permission) VALUES (?1, ?2)",
                params![role_code, permission],
            )
            .map_err(|error| format!("IDENTITY_PERMISSION_SEED: {error}"))?;
        }
    }
    Ok(())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get("id")?,
        email: row.get("email")?,
        display_name: row.get("display_name")?,
        password_hash: row.get("password_hash")?,
        status: row.get("status")?,
        is_builtin: row.get::<_, i64>("is_builtin")? != 0,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        last_login_at: row.get("last_login_at")?,
    })
}

fn row_to_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<WebSessionRecord> {
    Ok(WebSessionRecord {
        id: row.get("id")?,
        token_hash: row.get("token_hash")?,
        user_id: row.get("user_id")?,
        created_at_ms: row.get("created_at_ms")?,
        last_seen_at_ms: row.get("last_seen_at_ms")?,
        expires_at_ms: row.get("expires_at_ms")?,
        revoked_at_ms: row.get("revoked_at_ms")?,
        client_ip: row.get("client_ip")?,
        user_agent: row.get("user_agent")?,
    })
}

impl Storage {
    /// Creates the built-in administrator when the database has no users.
    /// Returns the existing administrator when one is already present, so the
    /// legacy `DBX_PASSWORD` migration is idempotent.
    pub async fn ensure_builtin_admin(&self, password_hash: String) -> Result<User, String> {
        self.with_conn(move |conn| {
            let existing: Option<User> = conn
                .query_row(
                    "SELECT * FROM users WHERE is_builtin = 1 ORDER BY created_at LIMIT 1",
                    [],
                    row_to_user,
                )
                .optional()
                .map_err(|error| error.to_string())?;
            if let Some(user) = existing {
                return Ok(user);
            }
            let now = now_rfc3339();
            let user = User {
                id: uuid::Uuid::new_v4().to_string(),
                email: "admin".to_string(),
                display_name: "Administrator".to_string(),
                password_hash,
                status: "active".to_string(),
                is_builtin: true,
                created_at: now.clone(),
                updated_at: now.clone(),
                last_login_at: None,
            };
            conn.execute(
                "INSERT INTO users (id, email, display_name, password_hash, status, is_builtin, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6)",
                params![user.id, user.email, user.display_name, user.password_hash, user.status, user.created_at],
            )
            .map_err(|error| error.to_string())?;
            conn.execute(
                "INSERT OR IGNORE INTO role_bindings \
                 (id, principal_type, principal_id, role_code, scope_type, scope_id, granted_by, reason, created_at) \
                 VALUES (?1, 'user', ?2, 'admin', 'global', NULL, 'system', 'built-in administrator', ?3)",
                params![uuid::Uuid::new_v4().to_string(), user.id, now],
            )
            .map_err(|error| error.to_string())?;
            Ok(user)
        })
        .await
    }

    pub async fn user_by_email(&self, email: String) -> Result<Option<User>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM users WHERE email = ?1", [email], row_to_user)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn user_by_id(&self, user_id: String) -> Result<Option<User>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM users WHERE id = ?1", [user_id], row_to_user)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    /// Creates a non-builtin user and binds one global role.
    pub async fn create_user(
        &self,
        email: String,
        display_name: String,
        password_hash: String,
        role_code: String,
        granted_by: String,
    ) -> Result<User, String> {
        self.with_conn(move |conn| {
            let now = now_rfc3339();
            let user = User {
                id: uuid::Uuid::new_v4().to_string(),
                email,
                display_name,
                password_hash,
                status: "active".to_string(),
                is_builtin: false,
                created_at: now.clone(),
                updated_at: now.clone(),
                last_login_at: None,
            };
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO users (id, email, display_name, password_hash, status, is_builtin, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)",
                params![user.id, user.email, user.display_name, user.password_hash, user.status, user.created_at],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO role_bindings \
                 (id, principal_type, principal_id, role_code, scope_type, scope_id, granted_by, reason, created_at) \
                 VALUES (?1, 'user', ?2, ?3, 'global', NULL, ?4, '', ?5)",
                params![uuid::Uuid::new_v4().to_string(), user.id, role_code, granted_by, now],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(user)
        })
        .await
    }

    pub async fn update_user_display_name(&self, user_id: String, display_name: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE users SET display_name = ?1, updated_at = ?2 WHERE id = ?3",
                params![display_name, now_rfc3339(), user_id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn set_user_status(&self, user_id: String, status: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE users SET status = ?1, updated_at = ?2 WHERE id = ?3",
                params![status, now_rfc3339(), user_id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn bind_role(&self, user_id: String, role_code: String, granted_by: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            let now = now_rfc3339();
            conn.execute(
                "INSERT INTO role_bindings \
                 (id, principal_type, principal_id, role_code, scope_type, scope_id, granted_by, reason, created_at) \
                 VALUES (?1, 'user', ?2, ?3, 'global', NULL, ?4, '', ?5)",
                params![uuid::Uuid::new_v4().to_string(), user_id, role_code, granted_by, now],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn unbind_role(&self, user_id: String, role_code: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "DELETE FROM role_bindings WHERE principal_type = 'user' AND principal_id = ?1 AND role_code = ?2",
                params![user_id, role_code],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    /// Every session that may still authenticate a request. Used to restore the
    /// in-memory map after a restart.
    pub async fn live_web_sessions(&self, now_ms: i64) -> Result<Vec<WebSessionRecord>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare("SELECT * FROM web_sessions WHERE revoked_at_ms IS NULL AND expires_at_ms > ?1")
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([now_ms], row_to_session).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn list_users(&self) -> Result<Vec<User>, String> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT * FROM users ORDER BY created_at").map_err(|error| error.to_string())?;
            let rows = stmt.query_map([], row_to_user).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn update_user_password(&self, user_id: String, password_hash: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                params![password_hash, now_rfc3339(), user_id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn record_user_login(&self, user_id: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute("UPDATE users SET last_login_at = ?1 WHERE id = ?2", params![now_rfc3339(), user_id])
                .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn create_connection_group(
        &self,
        name: String,
        parent_id: Option<String>,
        created_by: Option<String>,
    ) -> Result<String, String> {
        self.with_conn(move |conn| {
            if name.trim().is_empty() {
                return Err("GROUP_NAME_REQUIRED".to_string());
            }
            if let Some(parent_id) = parent_id.as_deref() {
                let exists: bool = conn
                    .query_row("SELECT EXISTS(SELECT 1 FROM connection_groups WHERE id = ?1)", [parent_id], |row| {
                        row.get(0)
                    })
                    .map_err(|error| error.to_string())?;
                if !exists {
                    return Err("GROUP_PARENT_NOT_FOUND".to_string());
                }
            }
            let id = uuid::Uuid::new_v4().to_string();
            let now = now_rfc3339();
            conn.execute(
                "INSERT INTO connection_groups (id, name, parent_id, created_by, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                params![id, name.trim(), parent_id, created_by, now],
            )
            .map_err(|error| error.to_string())?;
            Ok(id)
        })
        .await
    }

    pub async fn list_connection_groups(&self) -> Result<Vec<ConnectionGroupRow>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT id, name, parent_id FROM connection_groups ORDER BY name")
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?))
                })
                .map_err(|error| error.to_string())?;
            let mut groups = Vec::new();
            for row in rows {
                let (id, name, parent_id) = row.map_err(|error| error.to_string())?;
                let mut member_stmt = conn
                    .prepare(
                        "SELECT connection_id FROM connection_group_members WHERE group_id = ?1 ORDER BY connection_id",
                    )
                    .map_err(|error| error.to_string())?;
                let connection_ids = member_stmt
                    .query_map([&id], |row| row.get::<_, String>(0))
                    .map_err(|error| error.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
                groups.push(ConnectionGroupRow { id, name, parent_id, connection_ids });
            }
            Ok(groups)
        })
        .await
    }

    pub async fn update_connection_group(
        &self,
        id: String,
        name: String,
        parent_id: Option<String>,
    ) -> Result<(), String> {
        self.with_conn(move |conn| {
            if name.trim().is_empty() {
                return Err("GROUP_NAME_REQUIRED".to_string());
            }
            if let Some(parent_id) = parent_id.as_deref() {
                if parent_id == id {
                    return Err("GROUP_CYCLE".to_string());
                }
                let descendants: bool = conn
                    .query_row(
                        "WITH RECURSIVE descendants(id) AS (\
                            SELECT id FROM connection_groups WHERE parent_id = ?1 \
                            UNION SELECT g.id FROM connection_groups g JOIN descendants d ON g.parent_id = d.id) \
                         SELECT EXISTS(SELECT 1 FROM descendants WHERE id = ?2)",
                        params![id, parent_id],
                        |row| row.get(0),
                    )
                    .map_err(|error| error.to_string())?;
                if descendants {
                    return Err("GROUP_CYCLE".to_string());
                }
            }
            conn.execute(
                "UPDATE connection_groups SET name = ?1, parent_id = ?2, updated_at = ?3 WHERE id = ?4",
                params![name.trim(), parent_id, now_rfc3339(), id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn delete_connection_group(&self, id: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            let children: i64 = conn
                .query_row("SELECT COUNT(*) FROM connection_groups WHERE parent_id = ?1", [&id], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            if children > 0 {
                return Err("GROUP_HAS_CHILDREN".to_string());
            }
            let bound: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM role_bindings WHERE scope_type = 'connection_group' AND scope_id = ?1",
                    [&id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if bound > 0 {
                return Err("GROUP_IN_USE".to_string());
            }
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM connection_group_members WHERE group_id = ?1", [&id])
                .map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM connection_groups WHERE id = ?1", [&id]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn set_connection_group_members(
        &self,
        group_id: String,
        connection_ids: Vec<String>,
    ) -> Result<(), String> {
        self.with_conn(move |conn| {
            let exists: bool = conn
                .query_row("SELECT EXISTS(SELECT 1 FROM connection_groups WHERE id = ?1)", [&group_id], |row| {
                    row.get(0)
                })
                .map_err(|error| error.to_string())?;
            if !exists {
                return Err("GROUP_NOT_FOUND".to_string());
            }
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM connection_group_members WHERE group_id = ?1", [&group_id])
                .map_err(|error| error.to_string())?;
            for connection_id in connection_ids {
                tx.execute(
                    "INSERT OR IGNORE INTO connection_group_members (group_id, connection_id) VALUES (?1, ?2)",
                    params![group_id, connection_id],
                )
                .map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    /// Permissions a user holds for one connection through their scoped
    /// bindings. `None` means the user has no bindings at all (legacy/single
    /// admin), so callers keep the role-only behavior.
    pub async fn scoped_permissions_for_connection(
        &self,
        user_id: String,
        connection_id: String,
        database: Option<String>,
    ) -> Result<Option<Vec<String>>, String> {
        self.with_conn(move |conn| {
            // Database scope encodes both the connection and the database as
            // `<connection_id>::<database>`; connection ids are UUIDs and never
            // contain the separator.
            let database_scope = database.map(|database| format!("{connection_id}::{database}"));
            let binding_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM role_bindings WHERE principal_type = 'user' AND principal_id = ?1",
                    [&user_id],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())?;
            if binding_count == 0 {
                return Ok(None);
            }
            let mut stmt = conn
                .prepare(
                    "WITH RECURSIVE ancestors(id) AS (\
                        SELECT group_id FROM connection_group_members WHERE connection_id = ?2 \
                        UNION \
                        SELECT g.parent_id FROM connection_groups g JOIN ancestors a ON g.id = a.id \
                          WHERE g.parent_id IS NOT NULL) \
                     SELECT DISTINCT rp.permission \
                     FROM role_bindings rb \
                     JOIN role_permissions rp ON rp.role_code = rb.role_code \
                     WHERE rb.principal_type = 'user' AND rb.principal_id = ?1 \
                       AND (rb.expires_at IS NULL OR rb.expires_at > ?3) \
                       AND (rb.scope_type = 'global' \
                            OR (rb.scope_type = 'connection' AND rb.scope_id = ?2) \
                            OR (rb.scope_type = 'connection_group' AND rb.scope_id IN (SELECT id FROM ancestors)) \
                            OR (rb.scope_type = 'database' AND ?4 IS NOT NULL AND rb.scope_id = ?4)) \
                     ORDER BY rp.permission",
                )
                .map_err(|error| error.to_string())?;
            let permissions = stmt
                .query_map(params![user_id, connection_id, now_rfc3339(), database_scope], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|error| error.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            Ok(Some(permissions))
        })
        .await
    }

    /// Binds a role with an explicit resource scope.
    pub async fn bind_role_scoped(
        &self,
        user_id: String,
        role_code: String,
        scope_type: String,
        scope_id: Option<String>,
        granted_by: String,
    ) -> Result<(), String> {
        self.with_conn(move |conn| {
            let now = now_rfc3339();
            conn.execute(
                "INSERT INTO role_bindings \
                 (id, principal_type, principal_id, role_code, scope_type, scope_id, granted_by, reason, created_at) \
                 VALUES (?1, 'user', ?2, ?3, ?4, ?5, ?6, '', ?7)",
                params![uuid::Uuid::new_v4().to_string(), user_id, role_code, scope_type, scope_id, granted_by, now],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn bindings_for_user(&self, user_id: String) -> Result<Vec<RoleBindingRow>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT role_code, scope_type, scope_id FROM role_bindings \
                     WHERE principal_type = 'user' AND principal_id = ?1 \
                       AND (expires_at IS NULL OR expires_at > ?2) \
                     ORDER BY scope_type, role_code",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(params![user_id, now_rfc3339()], |row| {
                    Ok(RoleBindingRow { role_code: row.get(0)?, scope_type: row.get(1)?, scope_id: row.get(2)? })
                })
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    /// Variant of `create_user` that binds the role to an explicit scope.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_user_scoped(
        &self,
        email: String,
        display_name: String,
        password_hash: String,
        role_code: String,
        scope_type: String,
        scope_id: Option<String>,
        granted_by: String,
    ) -> Result<User, String> {
        self.with_conn(move |conn| {
            let now = now_rfc3339();
            let user = User {
                id: uuid::Uuid::new_v4().to_string(),
                email,
                display_name,
                password_hash,
                status: "active".to_string(),
                is_builtin: false,
                created_at: now.clone(),
                updated_at: now.clone(),
                last_login_at: None,
            };
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO users (id, email, display_name, password_hash, status, is_builtin, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?6)",
                params![user.id, user.email, user.display_name, user.password_hash, user.status, user.created_at],
            )
            .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO role_bindings \
                 (id, principal_type, principal_id, role_code, scope_type, scope_id, granted_by, reason, created_at) \
                 VALUES (?1, 'user', ?2, ?3, ?4, ?5, ?6, '', ?7)",
                params![uuid::Uuid::new_v4().to_string(), user.id, role_code, scope_type, scope_id, granted_by, now],
            )
            .map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(user)
        })
        .await
    }

    /// Custom roles with their permissions (built-in roles are code-defined).
    pub async fn list_custom_roles(&self) -> Result<Vec<CustomRoleRow>, String> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT code, name, description FROM roles WHERE builtin = 0 ORDER BY code")
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
                .map_err(|error| error.to_string())?;
            let mut roles = Vec::new();
            for row in rows {
                let (code, name, description) = row.map_err(|error| error.to_string())?;
                let mut permission_stmt = conn
                    .prepare("SELECT permission FROM role_permissions WHERE role_code = ?1 ORDER BY permission")
                    .map_err(|error| error.to_string())?;
                let permissions = permission_stmt
                    .query_map([&code], |row| row.get::<_, String>(0))
                    .map_err(|error| error.to_string())?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
                roles.push(CustomRoleRow { code, name, description, permissions });
            }
            Ok(roles)
        })
        .await
    }

    pub async fn create_custom_role(
        &self,
        code: String,
        name: String,
        description: String,
        permissions: Vec<String>,
    ) -> Result<(), String> {
        self.with_conn(move |conn| {
            let builtin: Option<i64> = conn
                .query_row("SELECT builtin FROM roles WHERE code = ?1", [&code], |row| row.get(0))
                .optional()
                .map_err(|error| error.to_string())?;
            if builtin.is_some() {
                return Err("ROLE_CODE_TAKEN".to_string());
            }
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            tx.execute(
                "INSERT INTO roles (code, name, description, builtin) VALUES (?1, ?2, ?3, 0)",
                params![code, name, description],
            )
            .map_err(|error| error.to_string())?;
            for permission in permissions {
                tx.execute(
                    "INSERT OR IGNORE INTO role_permissions (role_code, permission) VALUES (?1, ?2)",
                    params![code, permission],
                )
                .map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn update_custom_role(
        &self,
        code: String,
        name: String,
        description: String,
        permissions: Vec<String>,
    ) -> Result<(), String> {
        self.with_conn(move |conn| {
            let builtin: i64 = conn
                .query_row("SELECT builtin FROM roles WHERE code = ?1", [&code], |row| row.get(0))
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "ROLE_NOT_FOUND".to_string())?;
            if builtin != 0 {
                return Err("ROLE_BUILTIN_IMMUTABLE".to_string());
            }
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            tx.execute(
                "UPDATE roles SET name = ?1, description = ?2 WHERE code = ?3",
                params![name, description, code],
            )
            .map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM role_permissions WHERE role_code = ?1", [&code])
                .map_err(|error| error.to_string())?;
            for permission in permissions {
                tx.execute(
                    "INSERT OR IGNORE INTO role_permissions (role_code, permission) VALUES (?1, ?2)",
                    params![code, permission],
                )
                .map_err(|error| error.to_string())?;
            }
            tx.commit().map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn delete_custom_role(&self, code: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            let builtin: i64 = conn
                .query_row("SELECT builtin FROM roles WHERE code = ?1", [&code], |row| row.get(0))
                .optional()
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "ROLE_NOT_FOUND".to_string())?;
            if builtin != 0 {
                return Err("ROLE_BUILTIN_IMMUTABLE".to_string());
            }
            let bindings: i64 = conn
                .query_row("SELECT COUNT(*) FROM role_bindings WHERE role_code = ?1", [&code], |row| row.get(0))
                .map_err(|error| error.to_string())?;
            if bindings > 0 {
                return Err("ROLE_IN_USE".to_string());
            }
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM role_permissions WHERE role_code = ?1", [&code])
                .map_err(|error| error.to_string())?;
            tx.execute("DELETE FROM roles WHERE code = ?1", [&code]).map_err(|error| error.to_string())?;
            tx.commit().map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn user_ids_for_role(&self, role_code: String) -> Result<Vec<String>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT principal_id FROM role_bindings WHERE principal_type = 'user' AND role_code = ?1",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map([role_code], |row| row.get::<_, String>(0)).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    /// Role codes bound to a user that have not expired.
    pub async fn role_codes_for_user(&self, user_id: String) -> Result<Vec<String>, String> {
        self.with_conn(move |conn| {
            let now = now_rfc3339();
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT role_code FROM role_bindings \
                     WHERE principal_type = 'user' AND principal_id = ?1 \
                       AND (expires_at IS NULL OR expires_at > ?2) \
                     ORDER BY role_code",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt
                .query_map(params![user_id, now], |row| row.get::<_, String>(0))
                .map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn insert_web_session(&self, session: WebSessionRecord) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO web_sessions \
                 (id, token_hash, user_id, created_at_ms, last_seen_at_ms, expires_at_ms, client_ip, user_agent) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    session.id,
                    session.token_hash,
                    session.user_id,
                    session.created_at_ms,
                    session.last_seen_at_ms,
                    session.expires_at_ms,
                    session.client_ip,
                    session.user_agent,
                ],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn web_session_by_token_hash(&self, token_hash: String) -> Result<Option<WebSessionRecord>, String> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT * FROM web_sessions WHERE token_hash = ?1", [token_hash], row_to_session)
                .optional()
                .map_err(|error| error.to_string())
        })
        .await
    }

    pub async fn touch_web_session(&self, session_id: String, last_seen_at_ms: i64) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE web_sessions SET last_seen_at_ms = ?1 WHERE id = ?2",
                params![last_seen_at_ms, session_id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn revoke_web_session(&self, session_id: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE web_sessions SET revoked_at_ms = ?1 WHERE id = ?2",
                params![Utc::now().timestamp_millis(), session_id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    pub async fn revoke_user_sessions(&self, user_id: String) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE web_sessions SET revoked_at_ms = ?1 WHERE user_id = ?2 AND revoked_at_ms IS NULL",
                params![Utc::now().timestamp_millis(), user_id],
            )
            .map_err(|error| error.to_string())?;
            Ok(())
        })
        .await
    }

    /// Removes sessions that expired long ago. Their rows are not evidence, so
    /// deleting them is safe; audit events already record login and logout.
    pub async fn purge_expired_web_sessions(&self, now_ms: i64) -> Result<u64, String> {
        self.with_conn(move |conn| {
            conn.execute(
                "DELETE FROM web_sessions WHERE expires_at_ms < ?1 OR (revoked_at_ms IS NOT NULL AND revoked_at_ms < ?1)",
                [now_ms],
            )
            .map(|count| u64::try_from(count).unwrap_or(u64::MAX))
            .map_err(|error| error.to_string())
        })
        .await
    }

    /// Live, non-revoked sessions for one user (for "sign out everywhere").
    pub async fn live_web_sessions_for_user(
        &self,
        user_id: String,
        now_ms: i64,
    ) -> Result<Vec<WebSessionRecord>, String> {
        self.with_conn(move |conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM web_sessions WHERE user_id = ?1 AND revoked_at_ms IS NULL AND expires_at_ms > ?2",
                )
                .map_err(|error| error.to_string())?;
            let rows = stmt.query_map(params![user_id, now_ms], row_to_session).map_err(|error| error.to_string())?;
            rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
        })
        .await
    }
}

#[cfg(all(test, feature = "enterprise-audit"))]
mod tests {
    use super::*;
    use crate::identity::{hash_password, verify_password, BuiltinRole};

    async fn storage() -> (Storage, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("dbx-identity-{}.db", uuid::Uuid::new_v4()));
        (crate::persistence::test_storage::open(&path).await.unwrap(), path)
    }

    #[tokio::test]
    async fn the_builtin_admin_is_created_once_and_keeps_its_role() {
        let (storage, _) = storage().await;
        let hash = hash_password("secret").unwrap();
        let first = storage.ensure_builtin_admin(hash.clone()).await.unwrap();
        let second = storage.ensure_builtin_admin(hash).await.unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.email, "admin");
        assert_eq!(storage.role_codes_for_user(first.id).await.unwrap(), vec!["admin".to_string()]);
        assert!(verify_password("secret", &second.password_hash));
    }

    #[tokio::test]
    async fn builtin_roles_and_permissions_are_seeded() {
        let (storage, _) = storage().await;
        let permissions = storage
            .with_conn(|conn| {
                let mut stmt = conn
                    .prepare("SELECT permission FROM role_permissions WHERE role_code = 'viewer' ORDER BY permission")
                    .map_err(|error| error.to_string())?;
                let rows = stmt.query_map([], |row| row.get::<_, String>(0)).map_err(|error| error.to_string())?;
                rows.collect::<Result<Vec<_>, _>>().map_err(|error| error.to_string())
            })
            .await
            .unwrap();
        assert_eq!(permissions, vec!["connection:read".to_string(), "query:read".to_string()]);
        for role in BuiltinRole::ALL {
            assert!(!role.permissions().is_empty(), "{}", role.code());
        }
    }

    #[tokio::test]
    async fn custom_roles_round_trip_and_refuse_builtin_bindings() {
        let (storage, _) = storage().await;
        storage
            .create_custom_role(
                "ops_readonly".to_string(),
                "Ops read-only".to_string(),
                "reads only".to_string(),
                vec!["query:read".to_string(), "audit:read".to_string()],
            )
            .await
            .unwrap();
        let roles = storage.list_custom_roles().await.unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].permissions, vec!["audit:read".to_string(), "query:read".to_string()]);

        storage
            .update_custom_role(
                "ops_readonly".to_string(),
                "Ops read-only".to_string(),
                "reads and exports".to_string(),
                vec!["query:read".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(storage.list_custom_roles().await.unwrap()[0].permissions, vec!["query:read".to_string()]);

        // A bound role cannot be deleted.
        storage
            .create_user(
                "ops@example.com".to_string(),
                "Ops".to_string(),
                hash_password("secret123").unwrap(),
                "ops_readonly".to_string(),
                "admin".to_string(),
            )
            .await
            .unwrap();
        let user = storage.user_by_email("ops@example.com".to_string()).await.unwrap().unwrap();
        assert_eq!(storage.user_ids_for_role("ops_readonly".to_string()).await.unwrap(), vec![user.id.clone()]);
        assert_eq!(storage.delete_custom_role("ops_readonly".to_string()).await.unwrap_err(), "ROLE_IN_USE");
        storage.unbind_role(user.id, "ops_readonly".to_string()).await.unwrap();
        storage.delete_custom_role("ops_readonly".to_string()).await.unwrap();
        assert!(storage.list_custom_roles().await.unwrap().is_empty());

        assert_eq!(storage.delete_custom_role("viewer".to_string()).await.unwrap_err(), "ROLE_BUILTIN_IMMUTABLE");
    }

    #[tokio::test]
    async fn scoped_bindings_only_cover_their_connections_and_child_groups() {
        let (storage, _) = storage().await;
        let parent =
            storage.create_connection_group("prod".to_string(), None, Some("admin".to_string())).await.unwrap();
        let child = storage
            .create_connection_group("prod-eu".to_string(), Some(parent.clone()), Some("admin".to_string()))
            .await
            .unwrap();
        storage.set_connection_group_members(parent.clone(), vec!["conn-a".to_string()]).await.unwrap();
        storage.set_connection_group_members(child.clone(), vec!["conn-c".to_string()]).await.unwrap();

        let user = storage
            .create_user_scoped(
                "ops@example.com".to_string(),
                "Ops".to_string(),
                hash_password("secret123").unwrap(),
                "operator".to_string(),
                "connection_group".to_string(),
                Some(parent),
                "admin".to_string(),
            )
            .await
            .unwrap();

        let covered = storage
            .scoped_permissions_for_connection(user.id.clone(), "conn-a".to_string(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(covered.contains(&"query:write".to_string()));
        let inherited = storage
            .scoped_permissions_for_connection(user.id.clone(), "conn-c".to_string(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(inherited.contains(&"query:write".to_string()), "child groups inherit the binding");
        let outside = storage
            .scoped_permissions_for_connection(user.id.clone(), "conn-b".to_string(), None)
            .await
            .unwrap()
            .unwrap();
        assert!(outside.is_empty(), "unrelated connections are not covered");

        // A user without any binding keeps role-only behavior (`None`).
        storage
            .with_conn(|conn| {
                conn.execute(
                    "INSERT INTO users (id, email, display_name, password_hash, status, is_builtin, created_at, updated_at) \
                     VALUES ('unbound', 'unbound@example.com', 'Unbound', 'x', 'active', 0, '2020-01-01', '2020-01-01')",
                    [],
                )
                .map_err(|error| error.to_string())?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(storage
            .scoped_permissions_for_connection("unbound".to_string(), "conn-a".to_string(), None)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn database_scope_matches_only_its_database() {
        let (storage, _) = storage().await;
        let user = storage
            .create_user_scoped(
                "db-ops@example.com".to_string(),
                "DB Ops".to_string(),
                hash_password("secret123").unwrap(),
                "operator".to_string(),
                "database".to_string(),
                Some("conn-a::app".to_string()),
                "admin".to_string(),
            )
            .await
            .unwrap();
        let matching = storage
            .scoped_permissions_for_connection(user.id.clone(), "conn-a".to_string(), Some("app".to_string()))
            .await
            .unwrap()
            .unwrap();
        assert!(matching.contains(&"query:write".to_string()));
        let other_database = storage
            .scoped_permissions_for_connection(user.id.clone(), "conn-a".to_string(), Some("other".to_string()))
            .await
            .unwrap()
            .unwrap();
        assert!(other_database.is_empty());
        let other_connection = storage
            .scoped_permissions_for_connection(user.id.clone(), "conn-b".to_string(), Some("app".to_string()))
            .await
            .unwrap()
            .unwrap();
        assert!(other_connection.is_empty());
    }

    #[tokio::test]
    async fn expired_bindings_do_not_grant_a_role() {
        let (storage, _) = storage().await;
        let user = storage.ensure_builtin_admin(hash_password("x").unwrap()).await.unwrap();
        let user_id = user.id.clone();
        storage
            .with_conn(move |conn| {
                conn.execute(
                    "INSERT INTO role_bindings \
                     (id, principal_type, principal_id, role_code, scope_type, expires_at, created_at) \
                     VALUES ('b1', 'user', ?1, 'auditor', 'global', '2000-01-01T00:00:00.000Z', '2020-01-01T00:00:00.000Z')",
                    [user_id],
                )
                .map_err(|error| error.to_string())?;
                Ok(())
            })
            .await
            .unwrap();
        let roles = storage.role_codes_for_user(user.id).await.unwrap();
        assert!(!roles.contains(&"auditor".to_string()), "an expired binding must not grant access");
    }

    #[tokio::test]
    async fn a_session_can_be_stored_found_and_revoked() {
        let (storage, _) = storage().await;
        let user = storage.ensure_builtin_admin(hash_password("x").unwrap()).await.unwrap();
        let session = WebSessionRecord {
            id: "s1".to_string(),
            token_hash: "hash".to_string(),
            user_id: user.id.clone(),
            created_at_ms: 1,
            last_seen_at_ms: 1,
            expires_at_ms: i64::MAX,
            revoked_at_ms: None,
            client_ip: None,
            user_agent: None,
        };
        storage.insert_web_session(session).await.unwrap();
        let found = storage.web_session_by_token_hash("hash".to_string()).await.unwrap().unwrap();
        assert_eq!(found.user_id, user.id);
        assert_eq!(storage.live_web_sessions_for_user(user.id.clone(), 2).await.unwrap().len(), 1);

        storage.revoke_web_session("s1".to_string()).await.unwrap();
        assert!(storage.live_web_sessions_for_user(user.id, 2).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn expired_sessions_are_purged() {
        let (storage, _) = storage().await;
        let user = storage.ensure_builtin_admin(hash_password("x").unwrap()).await.unwrap();
        for (id, expires_at_ms) in [("old", 10i64), ("live", i64::MAX)] {
            storage
                .insert_web_session(WebSessionRecord {
                    id: id.to_string(),
                    token_hash: format!("hash-{id}"),
                    user_id: user.id.clone(),
                    created_at_ms: 1,
                    last_seen_at_ms: 1,
                    expires_at_ms,
                    revoked_at_ms: None,
                    client_ip: None,
                    user_agent: None,
                })
                .await
                .unwrap();
        }
        assert_eq!(storage.purge_expired_web_sessions(1_000).await.unwrap(), 1);
        assert!(storage.web_session_by_token_hash("hash-live".to_string()).await.unwrap().is_some());
        assert!(storage.web_session_by_token_hash("hash-old".to_string()).await.unwrap().is_none());
    }
}
