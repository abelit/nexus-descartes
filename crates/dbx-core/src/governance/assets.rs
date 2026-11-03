//! Asset-level authorization: connection, database, schema, and table grants.
//!
//! RBAC is allow-only. A global role covers everything; otherwise every
//! referenced object of a statement must be covered by a grant that also holds
//! the permission the statement needs. Table grants never authorize a
//! database-wide operation, and statements whose object references cannot be
//! proven require a connection/database/schema grant ("fail closed for narrow
//! grants").

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::connection::AppState;
use crate::identity::has_permission;
use crate::sql_analysis;
use crate::sql_risk::{classify_sql_risk_for_database, SqlRisk};

/// Local human actors are subject to asset grants. Bootstrap, system, service,
/// desktop, MCP, and external IdP actors keep their previous behavior until
/// they are mapped to local users.
pub fn actor_is_managed(actor: &crate::audit::Actor) -> bool {
    matches!(actor.kind, crate::audit::ActorKind::Human) && !actor.id.starts_with("hilbert:")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetTargetKind {
    ConnectionGroup,
    Connection,
    Database,
    Schema,
    Table,
}

impl AssetTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionGroup => "connection_group",
            Self::Connection => "connection",
            Self::Database => "database",
            Self::Schema => "schema",
            Self::Table => "table",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "connection_group" => Some(Self::ConnectionGroup),
            "connection" => Some(Self::Connection),
            "database" => Some(Self::Database),
            "schema" => Some(Self::Schema),
            "table" => Some(Self::Table),
            _ => None,
        }
    }
}

/// One asset grant. `role_code` is the role whose permissions apply inside the
/// target; `expires_at` is RFC3339. `name_pattern` enables `*`/`?` in the name
/// at the most specific level (`table_name` for table grants).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetGrant {
    pub id: String,
    pub principal_type: String,
    pub principal_id: String,
    pub role_code: String,
    pub target_kind: AssetTargetKind,
    pub connection_group_id: Option<String>,
    pub connection_id: Option<String>,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub table_name: Option<String>,
    pub name_pattern: bool,
    pub expires_at: Option<String>,
    pub granted_by: Option<String>,
    pub reason: String,
    pub created_at: String,
    pub updated_at: String,
}

impl AssetGrant {
    pub fn is_expired(&self, now: &str) -> bool {
        self.expires_at.as_deref().is_some_and(|expires| expires <= now)
    }
}

/// Builds a grant from the legacy `scope_type`/`scope_id` API shape. Returns
/// `None` for `global` (which stays in `role_bindings`) or an invalid encoding.
pub fn grant_from_scope(
    user_id: &str,
    role_code: &str,
    scope_type: &str,
    scope_id: Option<&str>,
    granted_by: Option<&str>,
) -> Option<AssetGrant> {
    let scope_id = scope_id.map(str::trim).filter(|value| !value.is_empty())?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let (target_kind, connection_group_id, connection_id, database_name, schema_name, table_name) = match scope_type {
        "connection" => (AssetTargetKind::Connection, None, Some(scope_id.to_string()), None, None, None),
        "connection_group" => (AssetTargetKind::ConnectionGroup, Some(scope_id.to_string()), None, None, None, None),
        "database" => {
            let mut parts = scope_id.split("::");
            let connection = parts.next()?.to_string();
            let database = parts.next()?.to_string();
            if connection.is_empty() || database.is_empty() {
                return None;
            }
            (AssetTargetKind::Database, None, Some(connection), Some(database), None, None)
        }
        "schema" => {
            let mut parts = scope_id.split("::");
            let connection = parts.next()?.to_string();
            let database = parts.next()?.to_string();
            let schema = parts.next()?.to_string();
            if connection.is_empty() || database.is_empty() || schema.is_empty() {
                return None;
            }
            (AssetTargetKind::Schema, None, Some(connection), Some(database), Some(schema), None)
        }
        "table" => {
            let mut parts = scope_id.split("::");
            let connection = parts.next()?.to_string();
            let database = parts.next()?.to_string();
            let schema = parts.next()?.to_string();
            let table = parts.next()?.to_string();
            if connection.is_empty() || database.is_empty() || schema.is_empty() || table.is_empty() {
                return None;
            }
            (AssetTargetKind::Table, None, Some(connection), Some(database), Some(schema), Some(table))
        }
        _ => return None,
    };
    Some(AssetGrant {
        id: uuid::Uuid::new_v4().to_string(),
        principal_type: "user".to_string(),
        principal_id: user_id.to_string(),
        role_code: role_code.to_string(),
        target_kind,
        connection_group_id,
        connection_id,
        database_name,
        schema_name,
        table_name,
        name_pattern: false,
        expires_at: None,
        granted_by: granted_by.map(str::to_string),
        reason: String::new(),
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Rows needed to build a snapshot; storage fills this without depending on the
/// resolver.
#[derive(Clone, Debug, Default)]
pub struct AssetSnapshotData {
    pub global_roles: Vec<String>,
    pub grants: Vec<AssetGrant>,
    pub group_members: Vec<(String, String)>,
    pub groups: Vec<(String, Option<String>)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssetMatch {
    /// True when a grant at connection/database/schema level covers the object,
    /// as opposed to a table-only grant.
    pub broad: bool,
    pub grant_ids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct AssetScopeSnapshot {
    pub user_id: String,
    pub global_roles: Vec<String>,
    pub grants: Vec<AssetGrant>,
    /// group id -> all connections in the group and its descendant groups.
    pub group_connections: HashMap<String, HashSet<String>>,
}

impl AssetScopeSnapshot {
    pub fn has_global_permission(&self, permission: &str) -> bool {
        self.global_roles.iter().any(|role| role_grants_permission(role, permission))
    }

    /// Whether `grant` covers the requested object at the requested level.
    /// `table = None` asks for broad coverage of the database/schema.
    fn grant_covers(
        &self,
        grant: &AssetGrant,
        connection_id: &str,
        database: Option<&str>,
        schema: Option<&str>,
        table: Option<&str>,
    ) -> bool {
        match grant.target_kind {
            AssetTargetKind::ConnectionGroup => grant
                .connection_group_id
                .as_ref()
                .is_some_and(|group| self.group_connections.get(group).is_some_and(|ids| ids.contains(connection_id))),
            AssetTargetKind::Connection => grant.connection_id.as_deref() == Some(connection_id),
            AssetTargetKind::Database => {
                grant.connection_id.as_deref() == Some(connection_id)
                    && name_matches(grant.database_name.as_deref(), database, false)
            }
            AssetTargetKind::Schema => {
                grant.connection_id.as_deref() == Some(connection_id)
                    && name_matches(grant.database_name.as_deref(), database, false)
                    && name_matches(grant.schema_name.as_deref(), schema, false)
            }
            AssetTargetKind::Table => {
                table.is_some()
                    && grant.connection_id.as_deref() == Some(connection_id)
                    && name_matches(grant.database_name.as_deref(), database, false)
                    && name_matches(grant.schema_name.as_deref(), schema, true)
                    && name_matches(grant.table_name.as_deref(), table, grant.name_pattern)
            }
        }
    }

    pub fn permits(
        &self,
        connection_id: &str,
        database: Option<&str>,
        schema: Option<&str>,
        table: Option<&str>,
        permission: &str,
        approval_authorized: bool,
    ) -> Option<AssetMatch> {
        if self.has_global_permission(permission) {
            return Some(AssetMatch { broad: true, grant_ids: Vec::new() });
        }
        let mut matched = AssetMatch::default();
        for grant in &self.grants {
            let role_ok = role_grants_permission(&grant.role_code, permission)
                || (approval_authorized
                    && permission == "query:ddl"
                    && role_grants_permission(&grant.role_code, "query:write"));
            if !role_ok || !self.grant_covers(grant, connection_id, database, schema, table) {
                continue;
            }
            matched.grant_ids.push(grant.id.clone());
            if table.is_none() || grant.target_kind != AssetTargetKind::Table {
                matched.broad = true;
            }
        }
        if matched.grant_ids.is_empty() {
            None
        } else {
            Some(matched)
        }
    }

    /// Parent nodes stay visible when a narrower grant exists beneath them, so
    /// the user can navigate to a granted table. A database/schema/table grant
    /// names its connection explicitly; asking `grant_covers` with an unknown
    /// database would hide the connection the grant belongs to.
    pub fn can_navigate_connection(&self, connection_id: &str) -> bool {
        if self.has_global_permission("connection:read") {
            return true;
        }
        self.grants.iter().any(|grant| {
            role_grants_permission(&grant.role_code, "connection:read")
                && self.grant_connection_matches(grant, connection_id)
        })
    }

    pub fn can_navigate_database(&self, connection_id: &str, database: &str) -> bool {
        if self.has_global_permission("connection:read") {
            return true;
        }
        self.grants.iter().any(|grant| {
            role_grants_permission(&grant.role_code, "connection:read")
                && self.grant_connection_matches(grant, connection_id)
                && match grant.target_kind {
                    AssetTargetKind::ConnectionGroup | AssetTargetKind::Connection => true,
                    AssetTargetKind::Database | AssetTargetKind::Schema | AssetTargetKind::Table => {
                        name_matches(grant.database_name.as_deref(), Some(database), false)
                    }
                }
        })
    }

    pub fn can_navigate_schema(&self, connection_id: &str, database: &str, schema: &str) -> bool {
        if self.has_global_permission("connection:read") {
            return true;
        }
        self.grants.iter().any(|grant| {
            role_grants_permission(&grant.role_code, "connection:read")
                && self.grant_connection_matches(grant, connection_id)
                && match grant.target_kind {
                    AssetTargetKind::ConnectionGroup | AssetTargetKind::Connection => true,
                    AssetTargetKind::Database => name_matches(grant.database_name.as_deref(), Some(database), false),
                    AssetTargetKind::Schema | AssetTargetKind::Table => {
                        name_matches(grant.database_name.as_deref(), Some(database), false)
                            && name_matches(grant.schema_name.as_deref(), Some(schema), false)
                    }
                }
        })
    }

    fn grant_connection_matches(&self, grant: &AssetGrant, connection_id: &str) -> bool {
        match grant.target_kind {
            AssetTargetKind::ConnectionGroup => grant
                .connection_group_id
                .as_ref()
                .is_some_and(|group| self.group_connections.get(group).is_some_and(|ids| ids.contains(connection_id))),
            _ => grant.connection_id.as_deref() == Some(connection_id),
        }
    }

    pub fn authorizes_table(&self, connection_id: &str, database: &str, schema: &str, table: &str) -> bool {
        self.permits(connection_id, Some(database), Some(schema), Some(table), "query:read", false).is_some()
    }
}

fn role_grants_permission(role: &str, permission: &str) -> bool {
    if has_permission(&[role.to_string()], parse_permission(permission)) {
        return true;
    }
    // A stronger query permission implies the weaker ones for asset checks.
    match permission {
        "query:read" => {
            has_permission(&[role.to_string()], crate::identity::Permission::QueryWrite)
                || has_permission(&[role.to_string()], crate::identity::Permission::QueryDdl)
        }
        "query:write" => has_permission(&[role.to_string()], crate::identity::Permission::QueryDdl),
        _ => false,
    }
}

fn parse_permission(value: &str) -> crate::identity::Permission {
    crate::identity::Permission::parse(value).unwrap_or(crate::identity::Permission::QueryRead)
}

fn name_matches(granted: Option<&str>, requested: Option<&str>, pattern: bool) -> bool {
    match (granted, requested) {
        // An absent selector means "any" at that level; this is how a
        // connection grant covers every database and a Mongo collection grant
        // omits the schema.
        (None, _) => true,
        (Some(granted), Some(requested)) if !pattern => granted.eq_ignore_ascii_case(requested),
        (Some(granted), Some(requested)) => like_match(granted, requested),
        (Some(_), None) => false,
    }
}

fn like_match(pattern: &str, value: &str) -> bool {
    fn inner(pattern: &[char], value: &[char]) -> bool {
        match pattern.split_first() {
            None => value.is_empty(),
            Some(('*', rest)) => (0..=value.len()).any(|offset| inner(rest, &value[offset..])),
            Some(('?', rest)) => !value.is_empty() && inner(rest, &value[1..]),
            Some((ch, rest)) => {
                value.first().is_some_and(|first| first.eq_ignore_ascii_case(ch)) && inner(rest, &value[1..])
            }
        }
    }
    inner(&pattern.chars().collect::<Vec<_>>(), &value.chars().collect::<Vec<_>>())
}

/// Builds a user's snapshot from storage. Global roles and asset grants are
/// loaded once per authorization call, not per statement.
pub async fn load_asset_snapshot(state: &AppState, user_id: &str) -> Result<AssetScopeSnapshot, String> {
    let data = state.storage.asset_snapshot_data(user_id.to_string()).await?;
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut group_children: HashMap<String, Vec<String>> = HashMap::new();
    for (id, parent) in &data.groups {
        if let Some(parent) = parent {
            group_children.entry(parent.clone()).or_default().push(id.clone());
        }
    }
    let mut direct_members: HashMap<String, Vec<String>> = HashMap::new();
    for (group, connection) in &data.group_members {
        direct_members.entry(group.clone()).or_default().push(connection.clone());
    }
    let mut group_connections: HashMap<String, HashSet<String>> = HashMap::new();
    for (id, _) in &data.groups {
        let mut pending = vec![id.clone()];
        let mut seen = HashSet::new();
        let mut connections = HashSet::new();
        while let Some(group) = pending.pop() {
            if !seen.insert(group.clone()) {
                continue;
            }
            if let Some(members) = direct_members.get(&group) {
                connections.extend(members.iter().cloned());
            }
            if let Some(children) = group_children.get(&group) {
                pending.extend(children.iter().cloned());
            }
        }
        group_connections.insert(id.clone(), connections);
    }
    Ok(AssetScopeSnapshot {
        user_id: user_id.to_string(),
        global_roles: data.global_roles,
        grants: data.grants.into_iter().filter(|grant| !grant.is_expired(&now)).collect(),
        group_connections,
    })
}

/// Authorizes a whole statement list before anything executes. The caller must
/// pass an explicit actor; task-local state is deliberately not consulted.
pub async fn authorize_statements(
    state: &AppState,
    actor_id: Option<&str>,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    statements: &[String],
    db_type: Option<dbx_types::models::connection::DatabaseType>,
    approval_authorized: bool,
) -> Result<(), String> {
    let Some(actor_id) = actor_id.filter(|id| !id.starts_with("system") && !id.contains(':')) else {
        return Ok(());
    };
    let snapshot = load_asset_snapshot(state, actor_id).await?;
    for sql in statements {
        authorize_statement(&snapshot, connection_id, database, schema, sql, db_type, approval_authorized)?;
    }
    Ok(())
}

fn authorize_statement(
    snapshot: &AssetScopeSnapshot,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    sql: &str,
    db_type: Option<dbx_types::models::connection::DatabaseType>,
    approval_authorized: bool,
) -> Result<(), String> {
    let required = match db_type {
        Some(db_type) => match classify_sql_risk_for_database(sql, db_type) {
            Ok(SqlRisk::ReadOnly) => "query:read",
            Ok(SqlRisk::Ddl) => "query:ddl",
            Ok(SqlRisk::Write) | Ok(SqlRisk::Transaction) => "query:write",
            Err(_) => "query:write",
        },
        None => "query:read",
    };
    let parsed = db_type
        .map(|db_type| sql_analysis::analyze_sql_references(sql, Some(db_type.as_str())))
        .unwrap_or_else(|| sql_analysis::analyze_sql_references(sql, None));
    let Ok(analysis) = parsed else {
        return broad_or_unproven(snapshot, connection_id, database, schema, required, approval_authorized);
    };
    if analysis.tables.is_empty() {
        // Constant queries touch no asset, but the user still needs read access
        // to the connection; DDL/write statements with no extracted target are
        // treated as broad operations.
        if required == "query:read" {
            if snapshot.can_navigate_connection(connection_id) {
                return Ok(());
            }
            return Err(denial(required));
        }
        return broad_or_unproven(snapshot, connection_id, database, schema, required, approval_authorized);
    }
    for reference in &analysis.tables {
        let object_schema = reference.schema.as_deref().or(schema).filter(|value| !value.is_empty()).or_else(|| {
            // MySQL has no separate schema: the database is the schema.
            db_type.filter(|db_type| *db_type == dbx_types::models::connection::DatabaseType::Mysql).map(|_| database)
        });
        if snapshot
            .permits(
                connection_id,
                Some(database),
                object_schema,
                Some(reference.name.as_str()),
                required,
                approval_authorized,
            )
            .is_none()
        {
            // A DDL statement may be covered by a broader grant even when the
            // parser reports only the target table; permits(table=Some) accepts
            // database/schema grants as well.
            return Err(denial(required));
        }
    }
    Ok(())
}

fn broad_or_unproven(
    snapshot: &AssetScopeSnapshot,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    required: &str,
    approval_authorized: bool,
) -> Result<(), String> {
    if snapshot.permits(connection_id, Some(database), schema, None, required, approval_authorized).is_some() {
        Ok(())
    } else {
        Err(format!("ASSET_SCOPE_UNPROVEN: the statement's objects cannot be proven for {required}"))
    }
}

fn denial(required: &str) -> String {
    format!("ASSET_ACCESS_DENIED: the user's asset grants do not cover this object for {required}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(
        id: &str,
        role: &str,
        kind: AssetTargetKind,
        database: Option<&str>,
        schema: Option<&str>,
        table: Option<&str>,
    ) -> AssetGrant {
        AssetGrant {
            id: id.to_string(),
            principal_type: "user".to_string(),
            principal_id: "u1".to_string(),
            role_code: role.to_string(),
            target_kind: kind,
            connection_group_id: None,
            connection_id: Some("conn".to_string()),
            database_name: database.map(str::to_string),
            schema_name: schema.map(str::to_string),
            table_name: table.map(str::to_string),
            name_pattern: false,
            expires_at: None,
            granted_by: None,
            reason: String::new(),
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
            updated_at: "2026-01-01T00:00:00.000Z".to_string(),
        }
    }

    fn make_snapshot(grants: Vec<AssetGrant>) -> AssetScopeSnapshot {
        AssetScopeSnapshot {
            user_id: "u1".to_string(),
            global_roles: Vec::new(),
            grants,
            group_connections: HashMap::new(),
        }
    }

    #[test]
    fn a_table_grant_allows_only_its_table_and_permission() {
        let snapshot = make_snapshot(vec![grant(
            "g1",
            "viewer",
            AssetTargetKind::Table,
            Some("app"),
            Some("public"),
            Some("orders"),
        )]);
        assert!(snapshot.permits("conn", Some("app"), Some("public"), Some("orders"), "query:read", false).is_some());
        assert!(snapshot.permits("conn", Some("app"), Some("public"), Some("secrets"), "query:read", false).is_none());
        assert!(snapshot.permits("conn", Some("app"), Some("public"), Some("orders"), "query:write", false).is_none());
        // A table grant never covers the whole database.
        assert!(snapshot.permits("conn", Some("app"), Some("public"), None, "query:read", false).is_none());
        assert!(snapshot.can_navigate_connection("conn"));
        assert!(!snapshot.can_navigate_connection("other-conn"));
        assert!(snapshot.can_navigate_database("conn", "app"));
        assert!(snapshot.can_navigate_schema("conn", "app", "public"));
    }

    #[test]
    fn schema_and_database_grants_cover_their_children() {
        let schema_snapshot =
            make_snapshot(vec![grant("g1", "viewer", AssetTargetKind::Schema, Some("app"), Some("public"), None)]);
        assert!(schema_snapshot
            .permits("conn", Some("app"), Some("public"), Some("orders"), "query:read", false)
            .is_some());
        assert!(schema_snapshot
            .permits("conn", Some("app"), Some("private"), Some("orders"), "query:read", false)
            .is_none());

        let database_snapshot =
            make_snapshot(vec![grant("g1", "viewer", AssetTargetKind::Database, Some("app"), None, None)]);
        assert!(database_snapshot
            .permits("conn", Some("app"), Some("anything"), Some("orders"), "query:read", false)
            .is_some());
        assert!(database_snapshot
            .permits("conn", Some("other"), Some("anything"), Some("orders"), "query:read", false)
            .is_none());
    }

    #[test]
    fn global_roles_cover_everything_and_write_needs_write_permission() {
        let mut snapshot = make_snapshot(Vec::new());
        snapshot.global_roles = vec!["admin".to_string()];
        assert!(snapshot.permits("conn", Some("app"), Some("public"), Some("orders"), "query:ddl", false).is_some());
        let mut viewer = make_snapshot(Vec::new());
        viewer.global_roles = vec!["viewer".to_string()];
        assert!(viewer.permits("conn", Some("app"), Some("public"), Some("orders"), "query:read", false).is_some());
        assert!(viewer.permits("conn", Some("app"), Some("public"), Some("orders"), "query:write", false).is_none());
    }

    #[test]
    fn table_grants_authorize_reads_but_not_ddl_or_unproven_sql() {
        let snapshot = make_snapshot(vec![grant(
            "g1",
            "viewer",
            AssetTargetKind::Table,
            Some("app"),
            Some("public"),
            Some("orders"),
        )]);
        let db_type = Some(dbx_types::models::connection::DatabaseType::Sqlite);
        assert!(authorize_statement(&snapshot, "conn", "app", Some("public"), "SELECT * FROM orders", db_type, false)
            .is_ok());
        let denied =
            authorize_statement(&snapshot, "conn", "app", Some("public"), "SELECT * FROM secrets", db_type, false)
                .unwrap_err();
        assert!(denied.starts_with("ASSET_ACCESS_DENIED"), "{denied}");
        // A viewer's table grant cannot carry query:ddl, even for the granted table.
        let ddl = authorize_statement(&snapshot, "conn", "app", Some("public"), "DROP TABLE orders", db_type, false)
            .unwrap_err();
        // The dialect analysis may omit a DROP target, turning this into the
        // opaque-statement denial; either way a table grant cannot carry DDL.
        assert!(ddl.starts_with("ASSET_ACCESS_DENIED") || ddl.starts_with("ASSET_SCOPE_UNPROVEN"), "{ddl}");
        // Opaque statements cannot be bounded by a table-only grant.
        let unproven =
            authorize_statement(&snapshot, "conn", "app", Some("public"), "CALL do_something()", db_type, false)
                .unwrap_err();
        assert!(unproven.starts_with("ASSET_SCOPE_UNPROVEN"), "{unproven}");
    }

    #[test]
    fn schema_grants_cover_ddl_in_their_schema() {
        let snapshot =
            make_snapshot(vec![grant("g1", "dba", AssetTargetKind::Schema, Some("app"), Some("public"), None)]);
        let db_type = Some(dbx_types::models::connection::DatabaseType::Sqlite);
        assert!(authorize_statement(
            &snapshot,
            "conn",
            "app",
            Some("public"),
            "CREATE TABLE orders (id INTEGER)",
            db_type,
            false
        )
        .is_ok());
        assert!(authorize_statement(
            &snapshot,
            "conn",
            "app",
            Some("private"),
            "CREATE TABLE orders (id INTEGER)",
            db_type,
            false
        )
        .is_err());
    }

    #[test]
    fn table_patterns_match_within_the_granted_scope() {
        let mut patterned =
            grant("g1", "viewer", AssetTargetKind::Table, Some("app"), Some("public"), Some("report_*"));
        patterned.name_pattern = true;
        let snapshot = make_snapshot(vec![patterned]);
        assert!(snapshot
            .permits("conn", Some("app"), Some("public"), Some("report_q1"), "query:read", false)
            .is_some());
        assert!(snapshot.permits("conn", Some("app"), Some("public"), Some("orders"), "query:read", false).is_none());
    }
}
