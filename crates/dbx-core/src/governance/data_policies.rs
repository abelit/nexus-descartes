//! Column masking and read row-filter policies.
//!
//! Policies attach to a connection and optionally narrow to a database,
//! schema, table (exact or `*`/`?` pattern), and column (pattern). They are
//! applied to every SQL result produced for a managed actor, after the driver
//! returns rows and before the response (or export) is serialized. The
//! application is fail-closed:
//!
//! - if a masked column is selected under an alias, the original column name is
//!   absent from the result, so the query is refused rather than leaking it;
//! - a row filter whose discriminator column is not present in the result
//!   (for example `SELECT COUNT(*)`) is refused;
//! - SQL that cannot be parsed while applicable policies exist is refused.
//!
//! Administrators (`admin:settings`) and system actors bypass policies; a
//! policy change is otherwise effective immediately. Row filters are read
//! filters: write statements are still governed by policy rules, approvals, and
//! asset grants.

use serde::{Deserialize, Serialize};

use crate::audit::Actor;
use crate::connection::AppState;
use crate::db::QueryResult;
use crate::governance::assets::load_asset_snapshot;
use crate::identity::{has_permission, Permission};
use crate::sql_analysis::{analyze_sql_references, SqlTableReference};
use crate::sql_risk::{classify_sql_risk_for_database, SqlRisk};
use crate::types::QueryMessage;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPolicyKind {
    Mask,
    RowFilter,
}

impl DataPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mask => "mask",
            Self::RowFilter => "row_filter",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mask" => Some(Self::Mask),
            "row_filter" => Some(Self::RowFilter),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataPolicy {
    pub id: String,
    pub name: String,
    pub kind: DataPolicyKind,
    pub connection_id: String,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub table_name: String,
    pub name_pattern: bool,
    pub column_name: String,
    pub mask_type: String,
    pub replacement: String,
    pub allowed_values: Vec<String>,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Applies matching policies to a result. Returns an error message the caller
/// must surface as a query failure when the policy cannot be enforced safely.
pub async fn apply_result_policies(
    state: &AppState,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    sql: &str,
    db_type: Option<dbx_types::models::connection::DatabaseType>,
    actor: Option<&Actor>,
    result: &mut QueryResult,
) -> Result<Vec<usize>, String> {
    let Some(actor) = actor else {
        return Ok(Vec::new());
    };
    if actor.id.starts_with("system") || has_permission(&actor.roles, Permission::AdminSettings) {
        return Ok(Vec::new());
    }
    if result.columns.is_empty() {
        return Ok(Vec::new());
    }
    let policies = state
        .storage
        .list_enabled_data_policies(connection_id.to_string())
        .await
        .map_err(|error| format!("DATA_POLICY_LOAD_FAILED: {error}"))?;
    if policies.is_empty() {
        return Ok(Vec::new());
    }
    // Only read results expose rows that policies target.
    let read_only = db_type
        .and_then(|db_type| classify_sql_risk_for_database(sql, db_type).ok())
        .is_some_and(|risk| risk == SqlRisk::ReadOnly);
    if !read_only {
        return Ok(Vec::new());
    }
    let analysis = analyze_sql_references(sql, db_type.map(|db_type| db_type.as_str()))
        .map_err(|_| "DATA_POLICY_UNPROVEN: the statement cannot be analyzed while data policies apply".to_string())?;
    let applicable: Vec<&DataPolicy> =
        policies.iter().filter(|policy| table_matches(policy, &analysis.tables, database, schema)).collect();
    if applicable.is_empty() {
        return Ok(Vec::new());
    }

    let global_unmask = has_permission(&actor.roles, Permission::UnmaskData);
    let global_row_bypass = has_permission(&actor.roles, Permission::RowFilterBypass);
    let needs_snapshot = (!global_unmask && applicable.iter().any(|policy| policy.kind == DataPolicyKind::Mask))
        || (!global_row_bypass && applicable.iter().any(|policy| policy.kind == DataPolicyKind::RowFilter));
    let unmask_snapshot = if needs_snapshot { load_asset_snapshot(state, &actor.id).await.ok() } else { None };
    let mut masks: Vec<Option<&DataPolicy>> = vec![None; result.columns.len()];
    let mut mask_columns: Vec<(&DataPolicy, Vec<usize>)> = Vec::new();
    for policy in applicable.iter().filter(|policy| policy.kind == DataPolicyKind::Mask) {
        if global_unmask {
            continue;
        }
        if unmask_snapshot
            .as_ref()
            .is_some_and(|snapshot| policy_covered_by(snapshot, policy, connection_id, database, schema, "unmask:data"))
        {
            continue;
        }
        let indexes: Vec<usize> = result
            .columns
            .iter()
            .enumerate()
            .filter(|(_, column)| glob_matches(&policy.column_name, column))
            .map(|(index, _)| index)
            .collect();
        if indexes.is_empty() {
            // The column is referenced but not exposed under its own name
            // (for example `SELECT email AS e`); refusing is the only safe
            // option because we cannot prove the alias mapping.
            if analysis.columns.iter().any(|column| glob_matches(&policy.column_name, &column.name)) {
                return Err(format!(
                    "COLUMN_MASK_UNPROVEN: policy '{}' masks column '{}' but the result does not expose it under that name",
                    policy.name, policy.column_name
                ));
            }
            continue;
        }
        for index in &indexes {
            let current = masks[*index];
            if current.is_none() || current.is_some_and(|current| strongest_mask(policy, current)) {
                masks[*index] = Some(*policy);
            }
        }
        mask_columns.push((*policy, indexes));
    }

    for policy in applicable.iter().filter(|policy| policy.kind == DataPolicyKind::RowFilter) {
        if global_row_bypass {
            continue;
        }
        if unmask_snapshot.as_ref().is_some_and(|snapshot| {
            policy_covered_by(snapshot, policy, connection_id, database, schema, "row_filter:bypass")
        }) {
            continue;
        }
        let Some(index) = result.columns.iter().position(|column| column.eq_ignore_ascii_case(&policy.column_name))
        else {
            return Err(format!(
                "ROW_POLICY_UNPROVEN: policy '{}' filters by '{}' but the result does not expose that column",
                policy.name, policy.column_name
            ));
        };
        result.messages.push(policy_notice(
            "row_filter",
            policy,
            &[result.columns[index].clone()],
            connection_id,
            database,
            schema,
        ));
        let allowed = &policy.allowed_values;
        result.rows.retain(|row| {
            row.get(index).map(|value| allowed.iter().any(|allowed| allowed == &value_key(value))).unwrap_or(false)
        });
        result.raw_key_cells.retain(|cell| cell.column_index != index);
        result.deferred_large_value_cells.retain(|cell| cell.column_index != index);
    }

    let mut masked_columns = Vec::new();
    for (index, policy) in masks.iter().enumerate() {
        let Some(policy) = policy else {
            continue;
        };
        masked_columns.push(index);
        for row in &mut result.rows {
            if let Some(value) = row.get_mut(index) {
                if !value.is_null() {
                    *value = serde_json::Value::String(mask_value(value, policy));
                }
            }
        }
        for cell in result.raw_key_cells.iter_mut().filter(|cell| cell.column_index == index) {
            cell.value = serde_json::Value::String(mask_value(&cell.value, policy));
        }
        // Deferred values are fetched later by locator; drop them so a masked
        // cell cannot be re-read in full through the result session.
        result.deferred_large_value_cells.retain(|cell| cell.column_index != index);
    }
    for (policy, indexes) in mask_columns {
        let columns: Vec<String> = indexes.into_iter().filter_map(|index| result.columns.get(index).cloned()).collect();
        result.messages.push(policy_notice("mask", policy, &columns, connection_id, database, schema));
    }
    Ok(masked_columns)
}

fn policy_notice(
    kind: &str,
    policy: &DataPolicy,
    columns: &[String],
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
) -> QueryMessage {
    let role = if kind == "mask" { "unmasker" } else { "row_accessor" };
    let detail = serde_json::json!({
        "kind": kind,
        "connection_id": connection_id,
        "database": policy.database_name.as_deref().unwrap_or(database),
        "schema": policy.schema_name.as_deref().or(schema),
        "table": policy.table_name,
        "columns": columns,
        "policy": policy.name,
        "request_role": role,
    });
    let label = if kind == "mask" { "columns" } else { "rows" };
    QueryMessage {
        severity: "NOTICE".to_string(),
        message: format!(
            "Data policy '{}' applied: {} {} are restricted (request role: {})",
            policy.name,
            label,
            if kind == "mask" { columns.join(", ") } else { policy.column_name.clone() },
            role
        ),
        code: Some(if kind == "mask" { "DATA_POLICY_MASK" } else { "DATA_POLICY_ROW_FILTER" }.to_string()),
        detail: Some(detail.to_string()),
        hint: None,
    }
}

fn policy_covered_by(
    snapshot: &crate::governance::assets::AssetScopeSnapshot,
    policy: &DataPolicy,
    connection_id: &str,
    database: &str,
    schema: Option<&str>,
    permission: &str,
) -> bool {
    let database = policy.database_name.as_deref().unwrap_or(database);
    let table = (!policy.name_pattern).then_some(policy.table_name.as_str());
    let policy_schema = policy.schema_name.as_deref();
    let mut candidates: Vec<Option<&str>> = vec![policy_schema.or(schema)];
    // MySQL has no separate schema namespace; PostgreSQL defaults to
    // `public`. Try those when the statement does not name a schema.
    for fallback in [Some(database), Some("public")] {
        if !candidates.contains(&fallback) {
            candidates.push(fallback);
        }
    }
    candidates.iter().any(|candidate| {
        snapshot.permits(connection_id, Some(database), *candidate, table, permission, false).is_some()
    })
}

fn strongest_mask(candidate: &DataPolicy, current: &DataPolicy) -> bool {
    mask_rank(&candidate.mask_type) > mask_rank(&current.mask_type)
}

fn mask_rank(mask_type: &str) -> u8 {
    match mask_type {
        "full" => 3,
        "email" => 2,
        "partial" => 1,
        _ => 0,
    }
}

fn mask_value(value: &serde_json::Value, policy: &DataPolicy) -> String {
    let text = value_key(value);
    let replacement = if policy.replacement.is_empty() { "***" } else { policy.replacement.as_str() };
    match policy.mask_type.as_str() {
        "partial" => {
            let chars: Vec<char> = text.chars().collect();
            if chars.len() <= 4 {
                replacement.to_string()
            } else {
                let head: String = chars.iter().take(2).collect();
                let tail: String = chars.iter().skip(chars.len() - 2).collect();
                format!("{head}{replacement}{tail}")
            }
        }
        "email" => match text.split_once('@') {
            Some((local, domain)) if !local.is_empty() => {
                let first = local.chars().next().unwrap_or('*');
                format!("{first}{replacement}@{domain}")
            }
            _ => replacement.to_string(),
        },
        _ => replacement.to_string(),
    }
}

fn value_key(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn table_matches(policy: &DataPolicy, tables: &[SqlTableReference], database: &str, schema: Option<&str>) -> bool {
    if let Some(policy_database) = policy.database_name.as_deref() {
        if !policy_database.eq_ignore_ascii_case(database) {
            return false;
        }
    }
    tables.iter().any(|table| {
        if let Some(policy_schema) = policy.schema_name.as_deref() {
            let reference_schema = table.schema.as_deref().or(schema).unwrap_or("");
            if !policy_schema.eq_ignore_ascii_case(reference_schema) {
                return false;
            }
        }
        if policy.name_pattern {
            glob_matches(&policy.table_name, &table.name)
        } else {
            table.name.eq_ignore_ascii_case(&policy.table_name)
                || table
                    .schema
                    .as_ref()
                    .is_some_and(|schema| format!("{schema}.{}", table.name).eq_ignore_ascii_case(&policy.table_name))
        }
    })
}

/// Case-insensitive `*`/`?` glob used for table and column patterns.
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    fn inner(pattern: &[char], value: &[char]) -> bool {
        match pattern.split_first() {
            None => value.is_empty(),
            Some(('*', rest)) => (0..=value.len()).any(|offset| inner(rest, &value[offset..])),
            Some(('?', rest)) => !value.is_empty() && inner(rest, &value[1..]),
            Some((expected, rest)) => {
                value.first().is_some_and(|actual| actual.eq_ignore_ascii_case(expected)) && inner(rest, &value[1..])
            }
        }
    }
    inner(&pattern.chars().collect::<Vec<_>>(), &value.chars().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(kind: DataPolicyKind, column: &str, mask_type: &str, replacement: &str) -> DataPolicy {
        DataPolicy {
            id: "p1".to_string(),
            name: "test".to_string(),
            kind,
            connection_id: "conn".to_string(),
            database_name: None,
            schema_name: None,
            table_name: "customers".to_string(),
            name_pattern: false,
            column_name: column.to_string(),
            mask_type: mask_type.to_string(),
            replacement: replacement.to_string(),
            allowed_values: Vec::new(),
            enabled: true,
            created_by: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn globs_support_star_and_question_mark() {
        assert!(glob_matches("cust*", "customers"));
        assert!(glob_matches("public.cust*", "public.customers"));
        assert!(glob_matches("cust?mers", "customers"));
        assert!(!glob_matches("orders", "customers"));
    }

    #[test]
    fn mask_styles_keep_the_expected_shape() {
        let value = serde_json::json!("alice@example.com");
        assert_eq!(mask_value(&value, &policy(DataPolicyKind::Mask, "email", "full", "***")), "***");
        assert_eq!(mask_value(&value, &policy(DataPolicyKind::Mask, "email", "email", "***")), "a***@example.com");
        assert_eq!(
            mask_value(&serde_json::json!("13800138000"), &policy(DataPolicyKind::Mask, "phone", "partial", "***")),
            "13***00"
        );
        assert_eq!(
            mask_value(&serde_json::json!("abc"), &policy(DataPolicyKind::Mask, "code", "partial", "***")),
            "***"
        );
    }
}
