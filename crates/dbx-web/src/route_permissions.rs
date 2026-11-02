//! Route-level permission enforcement.
//!
//! Handlers stay readable: this table maps an API prefix and method to the
//! permission an actor must hold. It is deliberately conservative about what
//! it classifies — an unclassified route is visible in observe mode and denied
//! in enforce mode, which is what forces new routes to be reviewed instead of
//! silently inheriting "any session may call it".

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dbx_core::audit::Actor;
use dbx_core::identity::Permission;

use crate::state::WebState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodClass {
    Read,
    Write,
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteAccess {
    Classified(Permission),
    Unclassified,
}

impl RouteAccess {
    pub fn permission(self) -> Option<Permission> {
        match self {
            Self::Classified(permission) => Some(permission),
            Self::Unclassified => None,
        }
    }
}

/// Prefix → permission. Ordered: the first matching entry wins, so put the
/// more specific prefixes first.
const RULES: &[(&str, MethodClass, Permission)] = &[
    // Owned by their handlers / separate gates.
    ("auth/", MethodClass::Any, Permission::QueryRead),
    // Simulation only; the handler enforces `query:read` itself.
    ("governance/simulate", MethodClass::Any, Permission::QueryRead),
    // Approval reads; mutations additionally check `approval:act`.
    ("approvals", MethodClass::Any, Permission::ApprovalRead),
    // Template reads; writes additionally check `policy:publish`.
    ("approval-templates", MethodClass::Any, Permission::ApprovalRead),
    // Policy reads; write/publish are checked in the handlers.
    ("policies", MethodClass::Any, Permission::PolicyRead),
    // Bootstrap metadata every signed-in client needs, including non-admins:
    // the workspace reads capabilities and the one-time migration state before
    // it can render. Mutating migration routes stay admin-only below.
    ("app-settings/web-capabilities", MethodClass::Any, Permission::QueryRead),
    ("migration/status", MethodClass::Read, Permission::QueryRead),
    // Read-only metadata and UI support endpoints.
    ("api", MethodClass::Any, Permission::QueryRead),
    ("changelog", MethodClass::Any, Permission::QueryRead),
    ("dialect", MethodClass::Any, Permission::QueryRead),
    ("general", MethodClass::Any, Permission::QueryRead),
    ("version", MethodClass::Any, Permission::QueryRead),
    // Administration
    ("users", MethodClass::Any, Permission::AdminUsers),
    ("roles", MethodClass::Any, Permission::AdminUsers),
    ("connection-groups", MethodClass::Any, Permission::AdminUsers),
    ("app-settings/", MethodClass::Any, Permission::AdminSettings),
    ("mcp", MethodClass::Any, Permission::AdminSettings),
    ("cloud-sync/", MethodClass::Any, Permission::AdminSettings),
    ("migration/", MethodClass::Any, Permission::AdminSettings),
    ("update", MethodClass::Any, Permission::AdminSettings),
    ("system", MethodClass::Any, Permission::AdminSettings),
    ("agents/", MethodClass::Any, Permission::AdminSettings),
    ("jdbc/", MethodClass::Any, Permission::AdminSettings),
    ("plugins/", MethodClass::Any, Permission::AdminPlugins),
    ("plugin/", MethodClass::Any, Permission::AdminPlugins),
    ("database-backups/", MethodClass::Any, Permission::AdminSettings),
    ("tunnel-profiles", MethodClass::Any, Permission::AdminSettings),
    ("ssh/", MethodClass::Any, Permission::ConnectionWrite),
    // Data movement
    ("export", MethodClass::Any, Permission::ExportData),
    ("import", MethodClass::Any, Permission::ImportData),
    ("transfer", MethodClass::Any, Permission::ExportData),
    // Connections
    ("connection/", MethodClass::Read, Permission::ConnectionRead),
    ("connection/", MethodClass::Write, Permission::ConnectionWrite),
    // SQL and schema
    ("query/", MethodClass::Read, Permission::QueryRead),
    ("query/", MethodClass::Write, Permission::QueryWrite),
    ("sql-file/", MethodClass::Read, Permission::QueryRead),
    ("sql-file/", MethodClass::Write, Permission::QueryWrite),
    ("schema/", MethodClass::Read, Permission::QueryRead),
    ("schema/", MethodClass::Write, Permission::QueryWrite),
    ("schema-diff/", MethodClass::Read, Permission::QueryRead),
    ("schema-diff/", MethodClass::Write, Permission::QueryWrite),
    ("pl-debug/", MethodClass::Read, Permission::QueryRead),
    ("pl-debug/", MethodClass::Write, Permission::QueryWrite),
    ("data-compare/", MethodClass::Read, Permission::QueryRead),
    ("data-compare/", MethodClass::Write, Permission::QueryWrite),
    // Other database and message-broker clients
    ("redis/", MethodClass::Read, Permission::QueryRead),
    ("redis/", MethodClass::Write, Permission::QueryWrite),
    ("mongo", MethodClass::Read, Permission::QueryRead),
    ("mongo", MethodClass::Write, Permission::QueryWrite),
    ("mq", MethodClass::Read, Permission::QueryRead),
    ("mq", MethodClass::Write, Permission::QueryWrite),
    ("nacos/", MethodClass::Read, Permission::QueryRead),
    ("nacos/", MethodClass::Write, Permission::QueryWrite),
    ("consul/", MethodClass::Read, Permission::QueryRead),
    ("consul/", MethodClass::Write, Permission::QueryWrite),
    ("etcd/", MethodClass::Read, Permission::QueryRead),
    ("etcd/", MethodClass::Write, Permission::QueryWrite),
    ("zookeeper/", MethodClass::Read, Permission::QueryRead),
    ("zookeeper/", MethodClass::Write, Permission::QueryWrite),
    ("hbase/", MethodClass::Read, Permission::QueryRead),
    ("hbase/", MethodClass::Write, Permission::QueryWrite),
    ("vector/", MethodClass::Read, Permission::QueryRead),
    ("vector/", MethodClass::Write, Permission::QueryWrite),
    ("document-store/", MethodClass::Read, Permission::QueryRead),
    ("document-store/", MethodClass::Write, Permission::QueryWrite),
    ("salesforce/", MethodClass::Read, Permission::QueryRead),
    ("salesforce/", MethodClass::Write, Permission::QueryWrite),
    // Editor state and history are per-user conveniences, not data access.
    ("history/", MethodClass::Read, Permission::QueryRead),
    ("history/", MethodClass::Write, Permission::QueryWrite),
    ("saved-sql/", MethodClass::Any, Permission::QueryWrite),
    ("layout", MethodClass::Any, Permission::QueryRead),
    ("tab-runtime-cache/", MethodClass::Any, Permission::QueryRead),
    ("task-runs/", MethodClass::Read, Permission::QueryRead),
    ("task-runs/", MethodClass::Write, Permission::QueryWrite),
    ("ai/", MethodClass::Read, Permission::QueryRead),
    ("ai/", MethodClass::Write, Permission::QueryWrite),
    ("docs/", MethodClass::Any, Permission::QueryRead),
    ("prompt-templates", MethodClass::Any, Permission::QueryRead),
];

/// Prefix match that also accepts the bare path (`/history` against a
/// `history/` rule), so an index route and its children share one rule.
fn prefix_matches(suffix: &str, prefix: &str) -> bool {
    let base = prefix.trim_end_matches('/');
    suffix == base || suffix.starts_with(prefix)
}

/// Classifies a normalized API suffix (for example `query/execute`).
pub fn classify(method: &Method, suffix: &str) -> RouteAccess {
    let read = method == Method::GET || method == Method::HEAD;
    for (prefix, class, permission) in RULES {
        if !prefix_matches(suffix, prefix) {
            continue;
        }
        let matches = match class {
            MethodClass::Any => true,
            MethodClass::Read => read,
            MethodClass::Write => !read,
        };
        if matches {
            return RouteAccess::Classified(*permission);
        }
    }
    RouteAccess::Unclassified
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GovernanceMode {
    Observe,
    Enforce,
}

impl GovernanceMode {
    pub fn from_env() -> Self {
        match std::env::var("DBX_GOVERNANCE_MODE").ok().as_deref().map(str::trim) {
            Some("enforce") => Self::Enforce,
            _ => Self::Observe,
        }
    }
}

/// Enforces [`classify`] for a session actor.
///
/// Unclassified routes are allowed in observe mode (the default, which keeps
/// today's behavior). In enforce mode they require `admin:settings`, so a new
/// route is usable by administrators while the table is completed but is never
/// granted to a regular user by accident. `/audit/*` has its own gate.
pub async fn enforce_route_permissions(
    State(state): State<Arc<WebState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let suffix = crate::auth::middleware_api_path_suffix(req.uri().path(), &state.public_base_path)
        .map(|suffix| suffix.strip_prefix("api/").unwrap_or(suffix).trim_start_matches('/').to_string());
    let Some(suffix) = suffix else {
        return next.run(req).await;
    };
    if suffix.starts_with("audit/") || suffix.starts_with("auth/") {
        return next.run(req).await;
    }

    let access = classify(req.method(), &suffix);
    let mode = GovernanceMode::from_env();
    let actor = req.extensions().get::<Actor>().cloned();
    let has = |permission: Permission| {
        actor.as_ref().is_some_and(|actor| dbx_core::identity::has_permission(&actor.roles, permission))
    };
    let allowed = match access {
        RouteAccess::Classified(permission) => has(permission),
        RouteAccess::Unclassified => mode == GovernanceMode::Observe || has(Permission::AdminSettings),
    };

    if allowed {
        if access == RouteAccess::Unclassified && mode == GovernanceMode::Observe {
            log::debug!("[governance] unclassified route (observe): {} {}", req.method(), suffix);
        }
        return next.run(req).await;
    }

    let (status, code) = match access {
        RouteAccess::Unclassified => (StatusCode::FORBIDDEN, "ROUTE_PERMISSION_UNCLASSIFIED"),
        _ => (StatusCode::FORBIDDEN, "PERMISSION_DENIED"),
    };
    log::warn!("[governance] denied {} {} ({code})", req.method(), suffix);
    (
        status,
        axum::Json(serde_json::json!({
            "error": {
                "code": code,
                "message": format!("{} is required for {} {}", access.permission().map(|p| p.as_str()).unwrap_or("a classified permission"), req.method(), suffix),
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_bootstrap_metadata_is_readable_by_every_user() {
        assert_eq!(
            classify(&Method::GET, "app-settings/web-capabilities"),
            RouteAccess::Classified(Permission::QueryRead)
        );
        assert_eq!(classify(&Method::GET, "migration/status"), RouteAccess::Classified(Permission::QueryRead));
        // Starting a migration still needs the admin setting permission.
        assert_eq!(classify(&Method::POST, "migration/start"), RouteAccess::Classified(Permission::AdminSettings));
    }

    #[test]
    fn execution_requires_write_and_listing_requires_read() {
        assert_eq!(classify(&Method::POST, "query/execute"), RouteAccess::Classified(Permission::QueryWrite));
        assert_eq!(classify(&Method::GET, "query/execute"), RouteAccess::Classified(Permission::QueryRead));
        assert_eq!(classify(&Method::POST, "query/execute-script"), RouteAccess::Classified(Permission::QueryWrite));
    }

    #[test]
    fn connection_writes_are_not_reads() {
        assert_eq!(classify(&Method::GET, "connection/list"), RouteAccess::Classified(Permission::ConnectionRead));
        assert_eq!(classify(&Method::POST, "connection/save"), RouteAccess::Classified(Permission::ConnectionWrite));
    }

    #[test]
    fn administration_is_separately_gated() {
        assert_eq!(classify(&Method::GET, "users"), RouteAccess::Classified(Permission::AdminUsers));
        assert_eq!(classify(&Method::POST, "plugins/install"), RouteAccess::Classified(Permission::AdminPlugins));
        assert_eq!(classify(&Method::PUT, "app-settings/theme"), RouteAccess::Classified(Permission::AdminSettings));
    }

    #[test]
    fn exports_and_imports_have_their_own_permission() {
        assert_eq!(classify(&Method::GET, "export/csv"), RouteAccess::Classified(Permission::ExportData));
        assert_eq!(classify(&Method::POST, "import/table"), RouteAccess::Classified(Permission::ImportData));
    }

    #[test]
    fn audit_and_auth_have_their_own_handling() {
        // The middleware skips them; classification alone must not claim them.
        assert_eq!(classify(&Method::GET, "audit/events"), RouteAccess::Unclassified);
    }

    #[test]
    fn unknown_routes_are_unclassified() {
        assert_eq!(classify(&Method::POST, "some-new-feature/do"), RouteAccess::Unclassified);
        assert_eq!(classify(&Method::GET, "capabilities"), RouteAccess::Unclassified);
    }

    /// Every route registered in `main.rs` / `routes/mq.rs` must be classified,
    /// otherwise adding a route silently gives it the unclassified fallback.
    /// (`/audit` and `/auth` have their own gates.)
    #[test]
    fn every_registered_route_is_classified() {
        let sources = [include_str!("main.rs"), include_str!("routes/mq.rs")];
        let mut unclassified = Vec::new();
        for source in sources {
            let production = source.split("#[cfg(test)]\nmod tests").next().unwrap_or(source);
            for line in production.lines() {
                let Some(rest) = line.split(".route(\"").nth(1) else {
                    continue;
                };
                let Some(path) = rest.split('"').next() else {
                    continue;
                };
                let suffix = path.trim_start_matches('/');
                let first = suffix.split('/').next().unwrap_or("");
                if first == "audit" || first == "auth" {
                    continue;
                }
                if classify(&Method::GET, suffix) == RouteAccess::Unclassified
                    && classify(&Method::POST, suffix) == RouteAccess::Unclassified
                {
                    unclassified.push(path.to_string());
                }
            }
        }
        unclassified.sort();
        unclassified.dedup();
        assert!(
            unclassified.is_empty(),
            "routes need a permission classification in route_permissions.rs: {unclassified:?}"
        );
    }

    #[test]
    fn observe_is_the_default_mode() {
        // The environment is not set in tests.
        assert_eq!(GovernanceMode::from_env(), GovernanceMode::Observe);
    }
}
