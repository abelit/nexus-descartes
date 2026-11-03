//! Local identity: permissions, built-in roles, password hashing, and the
//! session lifetime policy.
//!
//! Phase A authenticated one shared password. This module introduces the
//! permission vocabulary the rest of the server checks, so a route can ask
//! "does this actor hold `audit:read`?" instead of guessing from a session.

pub mod hilbert;

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_IDLE_TTL_SECS: u64 = 30 * 60;
const DEFAULT_ABSOLUTE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub display_name: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub status: String,
    pub is_builtin: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
}

impl User {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
}

/// One row of `web_sessions`. The raw token is never stored, only its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSessionRecord {
    pub id: String,
    pub token_hash: String,
    pub user_id: String,
    pub created_at_ms: i64,
    pub last_seen_at_ms: i64,
    pub expires_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Permission codes. Adding a code here makes it assignable to a custom role,
/// so keep the list conservative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    AuditRead,
    AuditExport,
    AuditVerify,
    PolicyRead,
    PolicyWrite,
    PolicyPublish,
    ApprovalRead,
    ApprovalAct,
    ApprovalBypass,
    ConnectionRead,
    ConnectionWrite,
    QueryRead,
    QueryWrite,
    QueryDdl,
    ExportData,
    ImportData,
    AdminUsers,
    AdminSettings,
    AdminPlugins,
}

impl Permission {
    pub const ALL: &'static [Permission] = &[
        Self::AuditRead,
        Self::AuditExport,
        Self::AuditVerify,
        Self::PolicyRead,
        Self::PolicyWrite,
        Self::PolicyPublish,
        Self::ApprovalRead,
        Self::ApprovalAct,
        Self::ApprovalBypass,
        Self::ConnectionRead,
        Self::ConnectionWrite,
        Self::QueryRead,
        Self::QueryWrite,
        Self::QueryDdl,
        Self::ExportData,
        Self::ImportData,
        Self::AdminUsers,
        Self::AdminSettings,
        Self::AdminPlugins,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AuditRead => "audit:read",
            Self::AuditExport => "audit:export",
            Self::AuditVerify => "audit:verify",
            Self::PolicyRead => "policy:read",
            Self::PolicyWrite => "policy:write",
            Self::PolicyPublish => "policy:publish",
            Self::ApprovalRead => "approval:read",
            Self::ApprovalAct => "approval:act",
            Self::ApprovalBypass => "approval:bypass",
            Self::ConnectionRead => "connection:read",
            Self::ConnectionWrite => "connection:write",
            Self::QueryRead => "query:read",
            Self::QueryWrite => "query:write",
            Self::QueryDdl => "query:ddl",
            Self::ExportData => "export:data",
            Self::ImportData => "import:data",
            Self::AdminUsers => "admin:users",
            Self::AdminSettings => "admin:settings",
            Self::AdminPlugins => "admin:plugins",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|permission| permission.as_str() == value.trim())
    }

    /// Permissions that asset grants can satisfy inside their target. Other
    /// permissions remain global-only, so a connection-scoped role cannot read
    /// the global audit log or administer users.
    pub fn is_asset_scopeable(self) -> bool {
        matches!(
            self,
            // Connection *configuration* writes stay global: a scoped role
            // must not be able to retarget a granted connection or add a new
            // one. Data access needs only ConnectionRead plus the per-object
            // query/export/import grants.
            Self::ConnectionRead
                | Self::QueryRead
                | Self::QueryWrite
                | Self::QueryDdl
                | Self::ExportData
                | Self::ImportData
                | Self::ApprovalRead
                | Self::ApprovalAct
        )
    }
}

/// Built-in roles. Their permission sets are code, not rows, so a fresh
/// database cannot start with a role that grants nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinRole {
    Admin,
    SecurityAdmin,
    Dba,
    Auditor,
    Operator,
    Viewer,
}

impl BuiltinRole {
    pub const ALL: &'static [BuiltinRole] =
        &[Self::Admin, Self::SecurityAdmin, Self::Dba, Self::Auditor, Self::Operator, Self::Viewer];

    pub fn code(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::SecurityAdmin => "security_admin",
            Self::Dba => "dba",
            Self::Auditor => "auditor",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|role| role.code() == code.trim())
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Admin => "Administrator",
            Self::SecurityAdmin => "Security Administrator",
            Self::Dba => "DBA",
            Self::Auditor => "Auditor",
            Self::Operator => "Operator",
            Self::Viewer => "Viewer",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Admin => "Full control including users, policies, and settings",
            Self::SecurityAdmin => "Policies, approvals, and audit read; cannot execute SQL",
            Self::Dba => "Execute and approve within assigned scopes, including DDL",
            Self::Auditor => "Read, export, and verify the audit log; cannot execute SQL",
            Self::Operator => "Read/write SQL within assigned scopes; DDL needs approval",
            Self::Viewer => "Read-only queries",
        }
    }

    pub fn permissions(&self) -> &'static [Permission] {
        match self {
            Self::Admin => Permission::ALL,
            Self::SecurityAdmin => &[
                Permission::AuditRead,
                Permission::AuditExport,
                Permission::AuditVerify,
                Permission::PolicyRead,
                Permission::PolicyWrite,
                Permission::PolicyPublish,
                Permission::ApprovalRead,
                Permission::ApprovalAct,
                Permission::AdminUsers,
            ],
            Self::Dba => &[
                Permission::ConnectionRead,
                Permission::ConnectionWrite,
                Permission::QueryRead,
                Permission::QueryWrite,
                Permission::QueryDdl,
                Permission::ExportData,
                Permission::ImportData,
                Permission::ApprovalRead,
                Permission::ApprovalAct,
                Permission::AuditRead,
            ],
            Self::Auditor => {
                &[Permission::AuditRead, Permission::AuditExport, Permission::AuditVerify, Permission::PolicyRead]
            }
            Self::Operator => &[
                Permission::ConnectionRead,
                Permission::QueryRead,
                Permission::QueryWrite,
                Permission::ExportData,
                Permission::ImportData,
                Permission::ApprovalRead,
            ],
            Self::Viewer => &[Permission::ConnectionRead, Permission::QueryRead],
        }
    }

    /// Rows for `role_permissions`, seeded on first open. Keeping the table in
    /// sync lets custom-role UIs list a role's effective permissions.
    pub fn permission_rows(&self) -> Vec<(&'static str, &'static str)> {
        self.permissions().iter().map(|permission| (self.code(), permission.as_str())).collect()
    }
}

/// Resolved permission codes per role. Built-ins are always present; custom
/// roles come from `roles`/`role_permissions` and are installed by the server.
/// A custom role may never reuse a built-in code.
static ROLES: LazyLock<RwLock<HashMap<String, Vec<String>>>> = LazyLock::new(|| {
    let mut roles = HashMap::new();
    for role in BuiltinRole::ALL {
        roles.insert(
            role.code().to_string(),
            role.permissions().iter().map(|permission| permission.as_str().to_string()).collect(),
        );
    }
    RwLock::new(roles)
});

/// Replaces the custom roles with the given set (built-ins stay). Unknown
/// permission codes are dropped rather than trusted.
pub fn install_custom_roles(roles: Vec<(String, Vec<String>)>) {
    let mut registry = ROLES.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.retain(|code, _| BuiltinRole::parse(code).is_some());
    for (code, permissions) in roles {
        if code.trim().is_empty() || BuiltinRole::parse(&code).is_some() {
            continue;
        }
        let mut permissions: Vec<String> =
            permissions.into_iter().filter(|permission| Permission::parse(permission).is_some()).collect();
        permissions.sort();
        permissions.dedup();
        registry.insert(code, permissions);
    }
}

/// Every known role code with its resolved permissions (built-ins first).
pub fn known_roles() -> Vec<(String, Vec<String>)> {
    let registry = ROLES.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut roles = registry.iter().map(|(code, permissions)| (code.clone(), permissions.clone())).collect::<Vec<_>>();
    roles.sort_by(|left, right| {
        let left_builtin = BuiltinRole::parse(&left.0).is_some();
        let right_builtin = BuiltinRole::parse(&right.0).is_some();
        right_builtin.cmp(&left_builtin).then_with(|| left.0.cmp(&right.0))
    });
    roles
}

pub fn role_permissions(code: &str) -> Option<Vec<String>> {
    ROLES.read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(code).cloned()
}

/// Effective permissions for a set of role codes. Unknown codes contribute
/// nothing rather than failing open.
pub fn permissions_for_roles(role_codes: &[String]) -> Vec<String> {
    let registry = ROLES.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut permissions = Vec::new();
    for code in role_codes {
        if let Some(granted) = registry.get(code) {
            for permission in granted {
                if !permissions.contains(permission) {
                    permissions.push(permission.clone());
                }
            }
        }
    }
    permissions.sort();
    permissions
}

pub fn has_permission(role_codes: &[String], permission: Permission) -> bool {
    let registry = ROLES.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    role_codes
        .iter()
        .any(|code| registry.get(code).is_some_and(|granted| granted.iter().any(|value| value == permission.as_str())))
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("PASSWORD_HASH: {error}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Session tokens are stored hashed: a database copy must not be a login.
pub fn hash_session_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    pub idle_ttl_ms: i64,
    pub absolute_ttl_ms: i64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_ttl_ms: i64::try_from(DEFAULT_IDLE_TTL_SECS * 1000).unwrap_or(i64::MAX),
            absolute_ttl_ms: i64::try_from(DEFAULT_ABSOLUTE_TTL_SECS * 1000).unwrap_or(i64::MAX),
        }
    }
}

impl SessionPolicy {
    pub fn from_env() -> Self {
        let mut policy = Self::default();
        if let Some(secs) = positive_env("DBX_SESSION_IDLE_SECS") {
            policy.idle_ttl_ms = i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        }
        if let Some(secs) = positive_env("DBX_SESSION_TTL_SECS") {
            policy.absolute_ttl_ms = i64::try_from(secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        }
        policy
    }
}

fn positive_env(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|value| value.trim().parse::<u64>().ok()).filter(|value| *value > 0)
}

/// True when the session must no longer be accepted.
pub fn session_expired(created_at_ms: i64, last_seen_at_ms: i64, now_ms: i64, policy: SessionPolicy) -> bool {
    now_ms >= created_at_ms.saturating_add(policy.absolute_ttl_ms)
        || now_ms >= last_seen_at_ms.saturating_add(policy.idle_ttl_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_holds_every_permission() {
        let roles = vec!["admin".to_string()];
        for permission in Permission::ALL {
            assert!(has_permission(&roles, *permission), "{}", permission.as_str());
        }
    }

    #[test]
    fn viewer_is_read_only() {
        let roles = vec!["viewer".to_string()];
        assert!(has_permission(&roles, Permission::QueryRead));
        assert!(!has_permission(&roles, Permission::QueryWrite));
        assert!(!has_permission(&roles, Permission::AuditRead));
        assert!(!has_permission(&roles, Permission::QueryDdl));
    }

    #[test]
    fn auditor_cannot_execute_but_can_export() {
        let roles = vec!["auditor".to_string()];
        assert!(has_permission(&roles, Permission::AuditExport));
        assert!(!has_permission(&roles, Permission::QueryRead));
        assert!(!has_permission(&roles, Permission::QueryWrite));
    }

    #[test]
    fn unknown_roles_grant_nothing() {
        let roles = vec!["custom_role".to_string()];
        assert!(permissions_for_roles(&roles).is_empty());
        assert!(!has_permission(&roles, Permission::AuditRead));
    }

    #[test]
    fn permissions_are_deduplicated_and_sorted() {
        let roles = vec!["viewer".to_string(), "operator".to_string(), "viewer".to_string()];
        let permissions = permissions_for_roles(&roles);
        let mut sorted = permissions.clone();
        sorted.sort();
        assert_eq!(permissions, sorted);
        let unique = permissions.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), permissions.len());
    }

    #[test]
    fn passwords_round_trip_and_reject_a_wrong_password() {
        let hash = hash_password("correct horse").expect("hash");
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong horse", &hash));
        assert!(!verify_password("correct horse", "not-a-hash"));
    }

    #[test]
    fn session_tokens_are_stored_hashed() {
        let digest = hash_session_token("token-1");
        assert_eq!(digest.len(), 64);
        assert_ne!(digest, hash_session_token("token-2"));
        assert_ne!(digest, "token-1");
    }

    #[test]
    fn idle_and_absolute_limits_both_expire_a_session() {
        let policy = SessionPolicy { idle_ttl_ms: 1_000, absolute_ttl_ms: 10_000 };
        assert!(!session_expired(0, 500, 900, policy));
        assert!(session_expired(0, 0, 1_000, policy), "idle limit");
        assert!(session_expired(0, 9_500, 10_000, policy), "absolute limit");
    }

    #[test]
    fn custom_roles_grant_their_installed_permissions() {
        let code = format!("test.custom.{}", uuid::Uuid::new_v4());
        install_custom_roles(vec![(
            code.clone(),
            vec!["audit:read".to_string(), "query:read".to_string(), "bogus".to_string()],
        )]);
        let roles = vec![code.clone()];
        assert!(has_permission(&roles, Permission::AuditRead));
        assert!(has_permission(&roles, Permission::QueryRead));
        assert!(!has_permission(&roles, Permission::QueryWrite));
        assert_eq!(role_permissions(&code).unwrap(), vec!["audit:read".to_string(), "query:read".to_string()]);
        install_custom_roles(Vec::new());
        assert!(!has_permission(&roles, Permission::AuditRead));
    }

    #[test]
    fn custom_roles_cannot_reuse_a_builtin_code() {
        install_custom_roles(vec![("admin".to_string(), vec!["query:read".to_string()])]);
        // Built-in admin still holds everything.
        assert!(has_permission(&["admin".to_string()], Permission::AdminUsers));
        install_custom_roles(Vec::new());
    }

    #[test]
    fn permission_codes_round_trip() {
        for permission in Permission::ALL {
            assert_eq!(Permission::parse(permission.as_str()), Some(*permission));
        }
        assert_eq!(Permission::parse("audit:write"), None);
    }
}
