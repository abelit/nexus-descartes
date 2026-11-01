use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::LazyLock;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dbx_core::audit::{
    Actor, ActorKind, AuditContext, AuditDecision, AuditEventInsert, AuditOperation, AuditOutcome, AuditSource,
};
use serde::{Deserialize, Serialize};

use crate::state::WebState;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
    /// Local user email. Omitted by the single-account login form, which maps
    /// to the built-in `admin` user.
    #[serde(default)]
    pub email: Option<String>,
    /// Required by first-run setup when `DBX_SETUP_TOKEN` is configured.
    #[serde(default)]
    pub setup_token: Option<String>,
    /// Attribution label shown in audit rows. This is not an authentication
    /// factor; the shared password remains the only credential until hilbert
    /// SSO lands.
    #[serde(default)]
    pub operator: Option<String>,
}

#[derive(Serialize)]
pub struct AuthActorView {
    pub id: String,
    pub display_name: String,
    pub roles: Vec<String>,
    /// Effective permission codes, so the UI can hide actions it cannot use.
    /// The server still enforces every one of them.
    pub permissions: Vec<String>,
}

impl From<&Actor> for AuthActorView {
    fn from(actor: &Actor) -> Self {
        Self {
            id: actor.id.clone(),
            display_name: actor.display_name.clone(),
            roles: actor.roles.clone(),
            permissions: dbx_core::identity::permissions_for_roles(&actor.roles),
        }
    }
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct AuthCheckResponse {
    pub authenticated: bool,
    pub required: bool,
    pub setup_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<AuthActorView>,
}

fn session_cookie_path(state: &WebState) -> &str {
    state.public_base_path.as_str()
}

/// `Secure` is opt-in: LAN/HTTP deployments would otherwise never receive the
/// session cookie back. Reverse-proxy TLS deployments set DBX_WEB_COOKIE_SECURE=1.
fn cookie_secure_enabled() -> bool {
    static SECURE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SECURE.get_or_init(|| matches!(std::env::var("DBX_WEB_COOKIE_SECURE").ok().as_deref(), Some("1") | Some("true")))
}

pub(crate) fn session_cookie(state: &WebState, token: &str) -> String {
    let secure = if cookie_secure_enabled() { "; Secure" } else { "" };
    format!("dbx_session={token}; Path={}; HttpOnly; SameSite=Lax{secure}", session_cookie_path(state))
}

fn api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = path.strip_prefix("/api/") {
        return Some(suffix);
    }
    let base = public_base_path.trim_end_matches('/');
    if base.is_empty() || base == "/" {
        return None;
    }
    path.strip_prefix(base)?.strip_prefix("/api/")
}

pub(crate) fn middleware_api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = api_path_suffix(path, public_base_path) {
        return Some(suffix);
    }

    let base = public_base_path.trim_end_matches('/');
    if !base.is_empty() && base != "/" && path.strip_prefix(base).is_some() {
        return None;
    }

    path.strip_prefix('/').filter(|suffix| !suffix.is_empty())
}

fn anonymous_actor() -> Actor {
    Actor {
        id: "anonymous:unauthenticated".to_string(),
        display_name: "Unauthenticated".to_string(),
        kind: ActorKind::Bootstrap,
        roles: Vec::new(),
        tenant_id: None,
        session_id: None,
        auth_method: "local_password".to_string(),
    }
}

/// The optional free-text caller label. It is recorded as `details.hint`; it
/// never determines who the event belongs to.
fn hint_label(operator: &Option<String>) -> Option<String> {
    operator.as_deref().map(str::trim).filter(|label| !label.is_empty()).map(str::to_string)
}

fn record_auth_event(
    state: &WebState,
    actor: Actor,
    decision: AuditDecision,
    outcome: AuditOutcome,
    detail: &str,
    hint: Option<&str>,
) {
    let context = AuditContext {
        actor,
        source: AuditSource::Web,
        client_ip: None,
        user_agent: None,
        request_id: None,
        execution_id: None,
    };
    let mut event = AuditEventInsert::new(&context, AuditOperation::Auth, decision, outcome);
    event.actor_verified = false;
    event.details_json = Some(
        serde_json::json!({
            "event": detail,
            "hint": hint,
            "actor_verified": false,
        })
        .to_string(),
    );
    state.app.record_audit(event);
}

pub async fn login(
    State(state): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Response, StatusCode> {
    let hint = hint_label(&body.operator);
    let user_agent =
        headers.get(axum::http::header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_string);
    if state.password_hash.read().await.is_none() {
        // No password configured: answer explicitly instead of an ok:true that
        // reads as "authenticated" — the API stays locked until setup.
        return Ok((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "setup_required"}))).into_response());
    }

    // The single-account form sends no email and maps to the built-in
    // administrator. Throttling is keyed by account, so one person guessing a
    // password cannot lock out everyone else.
    let email = body.email.as_deref().map(str::trim).filter(|value| !value.is_empty()).unwrap_or("admin").to_string();
    let rate_key = email.to_lowercase();
    if let Some(lockout) = state.login_locked_for(&rate_key).await {
        let remaining = lockout.as_secs().max(1);
        record_auth_event(
            &state,
            anonymous_actor(),
            AuditDecision::Blocked,
            AuditOutcome::NotStarted,
            "login:rate_limited",
            hint.as_deref(),
        );
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": format!("Please try again in {remaining}s")})),
        )
            .into_response());
    }
    let mut user = match state.app.storage.user_by_email(email.clone()).await {
        Ok(Some(user)) if user.is_active() => Some(user),
        Ok(Some(_)) => None, // disabled
        _ => None,
    };
    // A database written before local users existed (or a test fixture that
    // only set the legacy hash) has no admin row yet. Create it lazily, but
    // only for the default account — never authenticate another email against
    // the shared password.
    if user.is_none() && email == "admin" {
        if let Some(hash) = state.password_hash.read().await.clone() {
            user = state.app.storage.ensure_builtin_admin(hash).await.ok().filter(|user| user.is_active());
        }
    }
    let Some(user) = user else {
        state.note_login_failure(&rate_key).await;
        record_auth_event(
            &state,
            anonymous_actor(),
            AuditDecision::Denied,
            AuditOutcome::Error,
            "login:unknown_user",
            hint.as_deref(),
        );
        return Err(StatusCode::UNAUTHORIZED);
    };
    let user_hash = user.password_hash.clone();
    // Keep the legacy mirror in sync so the setup check and old paths agree.
    *state.password_hash.write().await = Some(user_hash.clone());

    if !dbx_core::identity::verify_password(&body.password, &user_hash) {
        state.note_login_failure(&rate_key).await;
        record_auth_event(
            &state,
            anonymous_actor(),
            AuditDecision::Denied,
            AuditOutcome::Error,
            "login:invalid_password",
            hint.as_deref(),
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    state.clear_login_failures(&rate_key).await;

    let token = uuid::Uuid::new_v4().to_string();
    let roles = state.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
    let session = state.create_user_session(token.clone(), &user, roles, None, user_agent).await;
    let actor = session.actor;
    let _ = state.app.storage.record_user_login(user.id.clone()).await;
    record_auth_event(&state, actor, AuditDecision::Allowed, AuditOutcome::Success, "login:success", hint.as_deref());

    let cookie = session_cookie(&state, &token);
    Ok((StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn setup(State(state): State<Arc<WebState>>, Json(body): Json<LoginRequest>) -> Result<Response, StatusCode> {
    if state.password_disabled {
        return Err(StatusCode::FORBIDDEN);
    }

    // Only allow setup when no password is configured and no local user exists.
    if state.password_hash.read().await.is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    if state.app.storage.user_by_email("admin".to_string()).await.ok().flatten().is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    // A reachable-but-unconfigured instance must not let the first visitor
    // become administrator. Set DBX_SETUP_TOKEN and pass it here.
    if let Ok(expected) = std::env::var("DBX_SETUP_TOKEN") {
        let expected = expected.trim();
        if !expected.is_empty() && body.setup_token.as_deref().map(str::trim) != Some(expected) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    if body.password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let hash = dbx_core::identity::hash_password(&body.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Save to database
    state.app.storage.save_password_hash(&hash).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user =
        state.app.storage.ensure_builtin_admin(hash.clone()).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update in-memory state
    *state.password_hash.write().await = Some(hash);
    if state.migration_ready.load(std::sync::atomic::Ordering::Acquire) {
        if let Err(error) = state.web_mcp.reload(&state.app.storage, true).await {
            log::error!("Web MCP remained disabled after password setup: {error}");
        }
    }

    // Auto-login: create session
    let token = uuid::Uuid::new_v4().to_string();
    let roles = vec!["admin".to_string()];
    let session = state.create_user_session(token.clone(), &user, roles, None, None).await;
    record_auth_event(
        &state,
        session.actor,
        AuditDecision::Allowed,
        AuditOutcome::Success,
        "setup:success",
        hint_label(&body.operator).as_deref(),
    );

    let cookie = session_cookie(&state, &token);
    Ok((StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn check(State(state): State<Arc<WebState>>, req: Request<axum::body::Body>) -> Json<AuthCheckResponse> {
    if state.password_disabled {
        return Json(AuthCheckResponse {
            authenticated: true,
            required: false,
            setup_required: false,
            actor: Some(AuthActorView::from(&Actor::bootstrap())),
        });
    }
    let has_password = state.password_hash.read().await.is_some();
    if !has_password {
        return Json(AuthCheckResponse { authenticated: false, required: false, setup_required: true, actor: None });
    }
    let actor = match extract_session_token(&req) {
        Some(token) => state.session_actor(&token).await.map(|session| AuthActorView::from(&session.actor)),
        None => None,
    };
    Json(AuthCheckResponse { authenticated: actor.is_some(), required: true, setup_required: false, actor })
}

pub async fn change_password(
    State(state): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Response, StatusCode> {
    // Session-bound: this endpoint used to sit outside the auth middleware,
    // giving unauthenticated callers an unlimited online guess at the admin
    // password with none of login's lockout. It now requires a live session
    // (defense in depth — the middleware gates it too) and, after a successful
    // change, revokes every OTHER session so a stolen old cookie cannot survive
    // a credential rotation.
    let current_token = session_token_from_headers(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if !state.sessions.read().await.contains(&current_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let actor = state.session_actor(&current_token).await.map(|session| session.actor).unwrap_or_else(Actor::bootstrap);

    if body.new_password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let user = state.app.storage.user_by_id(actor.id.clone()).await.ok().flatten().ok_or(StatusCode::BAD_REQUEST)?;
    if !dbx_core::identity::verify_password(&body.old_password, &user.password_hash) {
        record_auth_event(
            &state,
            actor.clone(),
            AuditDecision::Denied,
            AuditOutcome::Error,
            "password_change:invalid_old_password",
            None,
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    let new_hash =
        dbx_core::identity::hash_password(&body.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.app.storage.save_password_hash(&new_hash.clone()).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .app
        .storage
        .update_user_password(user.id.clone(), new_hash.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    *state.password_hash.write().await = Some(new_hash);

    // Rotation revokes sibling sessions; only the caller stays logged in.
    // Persisted rows are revoked first, otherwise an old cookie would be
    // accepted again through the database fallback after a restart.
    let sibling_session_ids: Vec<String> = {
        let actors = state.session_actors.read().await;
        actors
            .iter()
            .filter(|(token, _)| token.as_str() != current_token)
            .map(|(_, session)| session.db_id.clone())
            .filter(|db_id| !db_id.is_empty())
            .collect()
    };
    for db_id in sibling_session_ids {
        if let Err(error) = state.app.storage.revoke_web_session(db_id).await {
            log::warn!("[auth] sibling session revocation failed: {error}");
        }
    }
    {
        let mut sessions = state.sessions.write().await;
        for token in sessions.iter().filter(|token| **token != current_token) {
            dbx_core::query::pl_debug::pl_debug_revoke_web_owner_core(&state.app, token);
        }
        sessions.retain(|token| *token == current_token);
    }
    state.session_actors.write().await.retain(|token, _| token == &current_token);
    record_auth_event(&state, actor, AuditDecision::Allowed, AuditOutcome::Success, "password_change:success", None);

    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response())
}

pub async fn logout(State(state): State<Arc<WebState>>, req: Request<axum::body::Body>) -> Response {
    if let Some(token) = extract_session_token(&req) {
        let actor = state.session_actor(&token).await.map(|session| session.actor).unwrap_or_else(Actor::bootstrap);
        state.remove_session(&token).await;
        dbx_core::query::pl_debug::pl_debug_revoke_web_owner_core(&state.app, &token);
        // 登出只清除当前登录会话的临时密码，不影响其他会话与桌面端凭据。
        state.app.session_credentials.clear_owner(&token);
        record_auth_event(&state, actor, AuditDecision::Allowed, AuditOutcome::Success, "logout:success", None);
    }
    let cookie = format!("dbx_session=; Path={}; HttpOnly; Max-Age=0", session_cookie_path(&state));
    (StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({"ok": true}))).into_response()
}

pub fn session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("dbx_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn extract_session_token<B>(req: &Request<B>) -> Option<String> {
    session_token_from_headers(req.headers())
}

pub async fn auth_middleware(
    State(state): State<Arc<WebState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // `ConnectInfo` is a plain request extension, and it is only present when
    // the server was started with connect info, so it is read here instead of
    // being extracted (which would make it mandatory).
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
    let client_ip = client_ip_from(peer, req.headers());
    let request_id = request_id_from(req.headers());
    // Only the bootstrap auth endpoints are reachable without a session —
    // login/setup/check. change-password and logout require one: change-password
    // must not be an unauthenticated password oracle.
    let api_suffix = middleware_api_path_suffix(req.uri().path(), &state.public_base_path);
    if api_suffix.is_some_and(|suffix| matches!(suffix, "auth/login" | "auth/setup" | "auth/check")) {
        let mut response = next.run(req).await;
        attach_request_id(&mut response, &request_id);
        return response;
    }

    // Non-API requests (static files) are always accessible.
    if api_suffix.is_none() {
        return next.run(req).await;
    }

    let user_agent =
        req.headers().get(axum::http::header::USER_AGENT).and_then(|value| value.to_str().ok()).map(str::to_string);

    // Automation with the audit bootstrap token does not need a browser
    // session: the audit router performs its own token check and records the
    // read. Without this, a valid token would be rejected as an unknown
    // session before reaching that gate.
    if api_suffix.is_some_and(|suffix| suffix.starts_with("audit/"))
        && crate::routes::audit::bootstrap_token_valid(req.headers())
    {
        // Handlers still expect an actor for attribution; the token is not a
        // user identity, so automation is recorded as the system actor.
        let mut req = req;
        req.extensions_mut().insert(Actor::system());
        let mut response = next.run(req).await;
        attach_request_id(&mut response, &request_id);
        return response;
    }

    // A hilbert/ongrid access token authenticates the request directly. The
    // token is verified on every request (no DB session is created), so a
    // revocation on the identity provider takes effect immediately.
    if let (Some(verifier), Some(token)) = (state.hilbert.clone(), bearer_token(req.headers())) {
        match verifier.verify(&token) {
            Ok(claims) => {
                let subject = claims.user_id.clone().unwrap_or_else(|| claims.sub.clone());
                let actor = Actor {
                    id: format!("hilbert:{subject}"),
                    display_name: claims.email.clone().unwrap_or_else(|| claims.sub.clone()),
                    kind: ActorKind::Human,
                    roles: dbx_core::identity::hilbert::roles_for_claims(&claims),
                    tenant_id: None,
                    session_id: None,
                    auth_method: "hilbert_jwt".to_string(),
                };
                let context = AuditContext {
                    actor: actor.clone(),
                    source: AuditSource::Web,
                    client_ip,
                    user_agent,
                    request_id: Some(request_id.clone()),
                    execution_id: None,
                };
                let mut req = req;
                req.extensions_mut().insert(actor);
                let mut response =
                    dbx_core::audit::with_audit_context(context, async move { next.run(req).await }).await;
                attach_request_id(&mut response, &request_id);
                return response;
            }
            Err(error) => {
                log::warn!("[auth] hilbert token rejected: {error}");
                let mut response =
                    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "hilbert_token_invalid" })))
                        .into_response();
                attach_request_id(&mut response, &request_id);
                return response;
            }
        }
    }

    if state.password_disabled {
        let actor = Actor::bootstrap();
        let context = AuditContext {
            actor: actor.clone(),
            source: AuditSource::Web,
            client_ip,
            user_agent,
            request_id: Some(request_id.clone()),
            execution_id: None,
        };
        let mut req = req;
        req.extensions_mut().insert(actor);
        let mut response = dbx_core::audit::with_audit_context(context, async move { next.run(req).await }).await;
        attach_request_id(&mut response, &request_id);
        return response;
    }

    if state.password_hash.read().await.is_none() {
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        attach_request_id(&mut response, &request_id);
        return response;
    }

    // Check session token
    let token = extract_session_token(&req);
    if let Some(token) = token {
        if let Some(session) = state.session_actor(&token).await {
            let actor = session.actor;
            let context = AuditContext {
                actor: actor.clone(),
                source: AuditSource::Web,
                client_ip,
                user_agent,
                request_id: Some(request_id.clone()),
                execution_id: None,
            };
            let mut req = req;
            req.extensions_mut().insert(actor);
            // 在下游处理器及其 await 到的池创建路径上注入当前登录会话的 owner 作用域，
            // 使 save_password=false 连接的临时密码按会话隔离（见 SessionCredentialStore）。
            let owner = token;
            let mut response = dbx_core::session_credentials::with_credential_owner(
                Some(owner),
                dbx_core::audit::with_audit_context(context, async move { next.run(req).await }),
            )
            .await;
            attach_request_id(&mut response, &request_id);
            return response;
        }
    }

    StatusCode::UNAUTHORIZED.into_response()
}

/// Echoes the request id so an audit row can be correlated with the client's
/// own logs.
fn attach_request_id(response: &mut Response, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().entry("x-request-id").or_insert(value);
    }
}

/// `Authorization: Bearer <token>` (scheme compared case-insensitively).
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

fn request_id_from(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 200)
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// `DBX_TRUSTED_PROXIES` as a comma-separated list of addresses.
///
/// A forwarded header is only believed when the immediate peer is on this
/// list; otherwise any client could claim any source address in the audit log.
static TRUSTED_PROXIES: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    std::env::var("DBX_TRUSTED_PROXIES")
        .map(|value| value.split(',').filter_map(|entry| entry.trim().parse::<IpAddr>().ok()).collect::<Vec<_>>())
        .unwrap_or_default()
});

fn client_ip_from(peer: Option<SocketAddr>, headers: &HeaderMap) -> Option<String> {
    let peer_ip = peer?.ip();
    if TRUSTED_PROXIES.contains(&peer_ip) {
        let forwarded = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<IpAddr>().ok());
        if let Some(ip) = forwarded {
            return Some(ip.to_string());
        }
    }
    Some(peer_ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::{api_path_suffix, middleware_api_path_suffix};

    #[test]
    fn api_path_suffix_handles_root_api_paths() {
        assert_eq!(api_path_suffix("/api/auth/check", "/"), Some("auth/check"));
        assert_eq!(api_path_suffix("/api/query/execute", "/"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/"), None);
    }

    #[test]
    fn api_path_suffix_handles_mounted_api_paths() {
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/dbx"), Some("auth/check"));
        assert_eq!(api_path_suffix("/tools/dbx/api/query/execute", "/tools/dbx"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/login", "/dbx"), None);
    }

    #[test]
    pub(crate) fn middleware_api_path_suffix_handles_nested_router_paths() {
        assert_eq!(middleware_api_path_suffix("/auth/check", "/"), Some("auth/check"));
        assert_eq!(middleware_api_path_suffix("/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/api/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/api/connection/list", "/dbx"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/login", "/dbx"), None);
    }
}
