use dbx_core::audit::Actor;
use dbx_core::connection::AppState;
use dbx_core::identity::{hash_session_token, session_expired, SessionPolicy, User};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch, Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::sse::TransferProgressChannel;

/// Per-account login throttling.
///
/// The key is the submitted account (lowercased email), not a process-wide
/// counter: one person guessing a password must not lock out everyone else.
#[derive(Default)]
pub struct LoginRateLimit {
    pub attempts: HashMap<String, LoginAttempt>,
}

#[derive(Clone, Copy, Debug)]
pub struct LoginAttempt {
    pub fail_count: u32,
    pub last_attempt: Instant,
}

const LOGIN_MAX_ATTEMPTS: u32 = 5;
const LOGIN_LOCKOUT: Duration = Duration::from_secs(60);
/// Entries older than this are pruned so the map cannot grow without bound.
const LOGIN_ATTEMPT_TTL: Duration = Duration::from_secs(60 * 60);

/// The authenticated actor attached to one browser session.
///
/// `sessions` stays a membership-only set for compatibility with code that
/// iterates live sessions; this record is the authority for identity, limits,
/// and the database row that survives a restart.
#[derive(Clone, Debug)]
pub struct SessionActor {
    pub actor: Actor,
    /// `web_sessions.id`; empty for in-memory-only sessions created by tests.
    pub db_id: String,
    pub user_id: String,
    pub created_at: Instant,
    pub last_seen_at: Instant,
    pub expires_at: Instant,
    /// When `last_seen_at` was last written back, so a busy tab does not cause
    /// one database write per request.
    pub last_persisted_at: Instant,
}

impl SessionActor {
    pub fn new(actor: Actor, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            actor,
            db_id: String::new(),
            user_id: String::new(),
            created_at: now,
            last_seen_at: now,
            expires_at: now + ttl,
            last_persisted_at: now,
        }
    }

    /// Idle and absolute limits are both enforced; `Instant` arithmetic keeps
    /// them independent of wall-clock changes within one process.
    pub fn is_expired(&self, idle_ttl: Duration) -> bool {
        let now = Instant::now();
        now >= self.expires_at || now.duration_since(self.last_seen_at) >= idle_ttl
    }

    pub fn touch(&mut self) {
        self.last_seen_at = Instant::now();
    }
}

pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const SESSION_TOUCH_PERSIST_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebExportFile {
    pub file_path: String,
    pub download_filename: String,
    pub format: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NacosImportContext {
    pub owner_session: Option<String>,
    pub connection_id: String,
    pub target_namespace: String,
    pub plan_hash: String,
}

pub struct WebState {
    pub app: Arc<AppState>,
    pub data_dir: PathBuf,
    /// Extra absolute roots allowed for connection-level `docsNotesPath`
    /// beyond `data_dir/docs-notes` (`DBX_DOCS_NOTES_ROOTS`), resolved once at
    /// startup; injectable so notes containment is testable (see `docs`).
    pub notes_roots: Vec<PathBuf>,
    pub public_base_path: String,
    pub password_disabled: bool,
    /// Whether the web UI may reveal saved connection passwords.
    pub password_viewer_enabled: bool,
    /// `DBX_DEMO_MODE`：公网演示部署的封锁开关（见 `demo` 模块）。
    pub demo_mode: bool,
    pub password_hash: RwLock<Option<String>>,
    pub sessions: RwLock<HashSet<String>>,
    /// Actor and expiry for each live session token. A missing entry means the
    /// session predates actor tracking (or was created by a test); callers fall
    /// back to the bootstrap actor.
    pub session_actors: RwLock<HashMap<String, SessionActor>>,
    pub session_ttl: Duration,
    /// `DBX_SESSION_IDLE_SECS`, default 30 minutes.
    pub session_idle_ttl: Duration,
    pub sse_channels: RwLock<HashMap<String, broadcast::Sender<String>>>,
    pub transfer_progress_channels: RwLock<HashMap<String, Arc<TransferProgressChannel>>>,
    pub table_import_channels: RwLock<HashMap<String, watch::Sender<String>>>,
    pub sql_file_executions: RwLock<HashMap<String, CancellationToken>>,
    /// Failure logs of the executions this process ran, scoped to the session
    /// that started them (dbx#11619).
    pub sql_file_failure_logs: dbx_core::sql_file_import::SqlFileFailureLogRegistry,
    pub managed_sql_previews: crate::routes::sql_file::ManagedSqlPreviews,
    pub nacos_imports: RwLock<HashMap<String, NacosImportContext>>,
    pub login_rate_limit: Mutex<LoginRateLimit>,
    /// Completed Web export temp files waiting for the browser download.
    pub export_files: RwLock<HashMap<String, WebExportFile>>,
    pub ssh_prompts: Arc<crate::ssh_prompt::SshPromptHub>,
    pub migration_ready: Arc<AtomicBool>,
    pub web_mcp: Arc<crate::web_mcp::WebMcpRuntime>,
    /// hilbert/ongrid token verification, when enabled and configured.
    pub hilbert: Option<Arc<dbx_core::identity::hilbert::HilbertAuth>>,
}

impl WebState {
    /// Remaining lockout for an account, if one is active.
    pub async fn login_locked_for(&self, account: &str) -> Option<Duration> {
        let mut limit = self.login_rate_limit.lock().await;
        limit.attempts.retain(|_, attempt| attempt.last_attempt.elapsed() < LOGIN_ATTEMPT_TTL);
        let attempt = limit.attempts.get(account)?;
        if attempt.fail_count < LOGIN_MAX_ATTEMPTS {
            return None;
        }
        let elapsed = attempt.last_attempt.elapsed();
        if elapsed >= LOGIN_LOCKOUT {
            None
        } else {
            Some(LOGIN_LOCKOUT - elapsed)
        }
    }

    pub async fn note_login_failure(&self, account: &str) {
        let mut limit = self.login_rate_limit.lock().await;
        let now = Instant::now();
        let attempt =
            limit.attempts.entry(account.to_string()).or_insert(LoginAttempt { fail_count: 0, last_attempt: now });
        // A finished lockout starts a fresh counting window instead of
        // extending the old one on the very next failure.
        if attempt.fail_count >= LOGIN_MAX_ATTEMPTS && attempt.last_attempt.elapsed() >= LOGIN_LOCKOUT {
            attempt.fail_count = 0;
        }
        attempt.fail_count = attempt.fail_count.saturating_add(1);
        attempt.last_attempt = now;
    }

    pub async fn clear_login_failures(&self, account: &str) {
        self.login_rate_limit.lock().await.attempts.remove(account);
    }

    /// In-memory-only session (tests and the password-disabled demo mode).
    pub async fn insert_session(&self, token: String, mut actor: Actor) {
        if actor.session_id.is_none() {
            actor.session_id = Some(token.clone());
        }
        self.sessions.write().await.insert(token.clone());
        self.session_actors.write().await.insert(token, SessionActor::new(actor, self.session_ttl));
    }

    /// Creates a session for a real user and persists it, so a restart does not
    /// silently log everyone out and revocation survives a process restart.
    pub async fn create_user_session(
        &self,
        token: String,
        user: &User,
        roles: Vec<String>,
        asset_roles: Vec<String>,
        client_ip: Option<String>,
        user_agent: Option<String>,
    ) -> SessionActor {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let ttl_ms = i64::try_from(self.session_ttl.as_millis()).unwrap_or(i64::MAX);
        let db_id = uuid::Uuid::new_v4().to_string();
        let record = dbx_core::identity::WebSessionRecord {
            id: db_id.clone(),
            token_hash: hash_session_token(&token),
            user_id: user.id.clone(),
            created_at_ms: now_ms,
            last_seen_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            revoked_at_ms: None,
            client_ip: client_ip.clone(),
            user_agent: user_agent.clone(),
        };
        if let Err(error) = self.app.storage.insert_web_session(record).await {
            log::error!("[auth] session was not persisted: {error}");
        }

        let actor = Actor {
            id: user.id.clone(),
            display_name: user.display_name.clone(),
            kind: dbx_core::audit::ActorKind::Human,
            roles,
            asset_roles,
            tenant_id: None,
            session_id: Some(token.clone()),
            auth_method: "local_password".to_string(),
        };
        let mut session = SessionActor::new(actor, self.session_ttl);
        session.db_id = db_id;
        session.user_id = user.id.clone();
        self.sessions.write().await.insert(token.clone());
        self.session_actors.write().await.insert(token, session.clone());
        session
    }

    /// Drops every in-memory session belonging to a user. Called when the user
    /// is disabled or has a role change, so the change takes effect now rather
    /// than at the next login.
    /// Re-resolves the actor's role and asset-role codes for every live
    /// in-memory session. Permission changes (grants, access approvals) apply
    /// on the next request without forcing the user to sign in again.
    pub async fn refresh_user_authorization(&self, user_id: &str) {
        let roles = self.app.storage.role_codes_for_user(user_id.to_string()).await.unwrap_or_default();
        let asset_roles = self.app.storage.asset_role_codes_for_user(user_id.to_string()).await.unwrap_or_default();
        let mut actors = self.session_actors.write().await;
        for session in actors.values_mut() {
            if session.actor.id == user_id || session.user_id == user_id {
                session.actor.roles = roles.clone();
                session.actor.asset_roles = asset_roles.clone();
            }
        }
    }

    pub async fn drop_user_sessions(&self, user_id: &str) {
        let tokens: Vec<String> = {
            let mut actors = self.session_actors.write().await;
            let tokens = actors
                .iter()
                .filter(|(_, session)| session.user_id == user_id)
                .map(|(token, _)| token.clone())
                .collect::<Vec<_>>();
            for token in &tokens {
                actors.remove(token);
            }
            tokens
        };
        if tokens.is_empty() {
            return;
        }
        let mut sessions = self.sessions.write().await;
        for token in tokens {
            sessions.remove(&token);
        }
    }

    /// Revokes one persisted session by its database id (admin action).
    pub async fn revoke_session_by_db_id(&self, db_id: &str) {
        let tokens: Vec<String> = {
            let mut actors = self.session_actors.write().await;
            let tokens = actors
                .iter()
                .filter(|(_, session)| session.db_id == db_id)
                .map(|(token, _)| token.clone())
                .collect::<Vec<_>>();
            for token in &tokens {
                actors.remove(token);
            }
            tokens
        };
        {
            let mut sessions = self.sessions.write().await;
            for token in &tokens {
                sessions.remove(token);
            }
        }
        if let Err(error) = self.app.storage.revoke_web_session(db_id.to_string()).await {
            log::warn!("[auth] session revocation failed: {error}");
        }
    }

    pub async fn remove_session(&self, token: &str) {
        self.sessions.write().await.remove(token);
        let removed = self.session_actors.write().await.remove(token);
        if let Some(session) = removed.filter(|session| !session.db_id.is_empty()) {
            if let Err(error) = self.app.storage.revoke_web_session(session.db_id).await {
                log::error!("[auth] session revocation was not persisted: {error}");
            }
        }
    }

    /// Resolves the actor for a live token, enforcing idle and absolute expiry.
    ///
    /// There is deliberately no bootstrap fallback: an unknown token is never
    /// an administrator. Sessions missing from memory are looked up in the
    /// database, which is what lets sessions survive a restart.
    pub async fn session_actor(&self, token: &str) -> Option<SessionActor> {
        // One guard scope: never take the same lock twice while holding it.
        enum MemorySession {
            Live(SessionActor, bool),
            Expired(SessionActor),
            Absent,
        }
        let memory = {
            let mut actors = self.session_actors.write().await;
            match actors.get_mut(token) {
                Some(session) if session.is_expired(self.session_idle_ttl) => MemorySession::Expired(session.clone()),
                Some(session) => {
                    session.touch();
                    let should_persist = !session.db_id.is_empty()
                        && session.last_persisted_at.elapsed() >= SESSION_TOUCH_PERSIST_INTERVAL;
                    if should_persist {
                        session.last_persisted_at = Instant::now();
                    }
                    MemorySession::Live(session.clone(), should_persist)
                }
                None => MemorySession::Absent,
            }
        };

        match memory {
            MemorySession::Live(session, should_persist) => {
                if should_persist {
                    let db_id = session.db_id.clone();
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    let storage = self.app.storage.clone();
                    tokio::spawn(async move {
                        if let Err(error) = storage.touch_web_session(db_id, now_ms).await {
                            log::warn!("[auth] session touch was not persisted: {error}");
                        }
                    });
                }
                return Some(session);
            }
            MemorySession::Expired(session) => {
                self.sessions.write().await.remove(token);
                self.session_actors.write().await.remove(token);
                if !session.db_id.is_empty() {
                    if let Err(error) = self.app.storage.revoke_web_session(session.db_id).await {
                        log::warn!("[auth] expired session revocation failed: {error}");
                    }
                }
                return None;
            }
            MemorySession::Absent => {}
        }

        // Not in memory: try the persisted session (restart, or a tab that
        // arrived before the map was rebuilt).
        let token_hash = hash_session_token(token);
        let record = self.app.storage.web_session_by_token_hash(token_hash).await.ok().flatten()?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let policy = SessionPolicy {
            idle_ttl_ms: i64::try_from(self.session_idle_ttl.as_millis()).unwrap_or(i64::MAX),
            absolute_ttl_ms: i64::try_from(self.session_ttl.as_millis()).unwrap_or(i64::MAX),
        };
        if record.revoked_at_ms.is_some() {
            return None;
        }
        if session_expired(record.created_at_ms, record.last_seen_at_ms, now_ms, policy) {
            // Mark it revoked so an idle-expired row is not re-checked forever.
            let _ = self.app.storage.revoke_web_session(record.id).await;
            return None;
        }
        let user = self.app.storage.user_by_id(record.user_id.clone()).await.ok().flatten()?;
        if !user.is_active() {
            return None;
        }
        let roles = self.app.storage.role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        let asset_roles = self.app.storage.asset_role_codes_for_user(user.id.clone()).await.unwrap_or_default();
        let actor = Actor {
            id: user.id.clone(),
            display_name: user.display_name,
            kind: dbx_core::audit::ActorKind::Human,
            roles,
            asset_roles,
            tenant_id: None,
            session_id: Some(token.to_string()),
            auth_method: "local_password".to_string(),
        };
        let mut session = SessionActor::new(actor, self.session_ttl);
        session.db_id = record.id;
        session.user_id = user.id;
        // Keep the persisted timestamps as the authority for the limits.
        let now = Instant::now();
        let idle_age = Duration::from_millis(u64::try_from((now_ms - record.last_seen_at_ms).max(0)).unwrap_or(0));
        let created_age = Duration::from_millis(u64::try_from((now_ms - record.created_at_ms).max(0)).unwrap_or(0));
        session.last_seen_at = now.checked_sub(idle_age).unwrap_or(now);
        session.created_at = now.checked_sub(created_age).unwrap_or(now);
        session.expires_at = session.created_at.checked_add(self.session_ttl).unwrap_or(now + self.session_ttl);
        self.sessions.write().await.insert(token.to_string());
        self.session_actors.write().await.insert(token.to_string(), session.clone());
        Some(session)
    }

    /// Startup hook: removes session rows that can no longer authenticate.
    ///
    /// Live rows are resolved lazily by [`Self::session_actor`] — only the
    /// token hash is stored, so they cannot be rebuilt into the memory map
    /// without the client presenting the token again.
    pub async fn restore_sessions(&self) {
        let now_ms = chrono::Utc::now().timestamp_millis();
        if let Err(error) = self.app.storage.purge_expired_web_sessions(now_ms).await {
            log::warn!("[auth] expired session purge failed: {error}");
        }
    }

    pub async fn remove_sse_channel(&self, id: &str) {
        self.sse_channels.write().await.remove(id);
    }

    /// Test helper: full field set so new WebState fields don't break scattered test fixtures.
    #[cfg(test)]
    pub fn for_tests(app: Arc<AppState>, data_dir: PathBuf) -> Self {
        Self {
            app,
            data_dir,
            notes_roots: Vec::new(),
            public_base_path: "/".to_string(),
            password_disabled: false,
            password_viewer_enabled: true,
            demo_mode: false,
            password_hash: RwLock::new(None),
            sessions: RwLock::new(HashSet::new()),
            session_actors: RwLock::new(HashMap::new()),
            session_ttl: DEFAULT_SESSION_TTL,
            session_idle_ttl: DEFAULT_IDLE_TTL,
            sse_channels: RwLock::new(HashMap::new()),
            transfer_progress_channels: RwLock::new(HashMap::new()),
            table_import_channels: RwLock::new(HashMap::new()),
            sql_file_failure_logs: Default::default(),
            sql_file_executions: RwLock::new(HashMap::new()),
            managed_sql_previews: Default::default(),
            nacos_imports: RwLock::new(HashMap::new()),
            login_rate_limit: Mutex::new(LoginRateLimit::default()),
            export_files: RwLock::new(HashMap::new()),
            ssh_prompts: Arc::new(crate::ssh_prompt::SshPromptHub::new()),
            migration_ready: Arc::new(AtomicBool::new(true)),
            web_mcp: Arc::new(crate::web_mcp::WebMcpRuntime::disabled()),
            hilbert: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn state() -> (Arc<WebState>, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let storage = dbx_core::persistence::test_storage::open(&directory.path().join("dbx.db")).await.unwrap();
        let app = Arc::new(AppState::new(storage));
        let state = Arc::new(WebState::for_tests(app, directory.path().to_path_buf()));
        (state, directory)
    }

    #[tokio::test]
    async fn login_throttling_is_per_account() {
        let (state, _dir) = state().await;
        for _ in 0..4 {
            state.note_login_failure("alice").await;
        }
        assert!(state.login_locked_for("alice").await.is_none(), "four failures do not lock yet");
        state.note_login_failure("alice").await;
        assert!(state.login_locked_for("alice").await.is_some(), "the fifth failure locks the account");
        assert!(
            state.login_locked_for("bob").await.is_none(),
            "another account must not be locked out by alice's failures"
        );
    }

    #[tokio::test]
    async fn a_successful_login_clears_the_failure_counter() {
        let (state, _dir) = state().await;
        for _ in 0..4 {
            state.note_login_failure("alice").await;
        }
        state.clear_login_failures("alice").await;
        for _ in 0..4 {
            state.note_login_failure("alice").await;
        }
        assert!(state.login_locked_for("alice").await.is_none());
    }
}
