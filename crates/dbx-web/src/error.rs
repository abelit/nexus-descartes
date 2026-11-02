use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dbx_core::backend_error::BackendError;
use std::fmt;

#[derive(Debug)]
pub struct AppError {
    pub message: String,
    pub status: StatusCode,
    pub error: Box<BackendError>,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl AppError {
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::with_status(msg.into(), StatusCode::INTERNAL_SERVER_ERROR)
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::with_status(msg.into(), StatusCode::BAD_REQUEST)
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::with_status(msg.into(), StatusCode::CONFLICT)
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::with_status(msg.into(), StatusCode::FORBIDDEN)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::with_status(msg.into(), StatusCode::NOT_FOUND)
    }

    fn with_status(message: String, status: StatusCode) -> Self {
        let status = policy_status(&message).unwrap_or(status);
        let error = BackendError::from_legacy_string(&message);
        Self { message, status, error: Box::new(error) }
    }

    pub fn from_backend_error(error: BackendError) -> Self {
        // The execution gateway reports policy denials as legacy strings, and
        // most routes wrap them into a typed error before reaching the HTTP
        // boundary. Keep the 403/409 contract by classifying the detail too.
        let status = error.detail().and_then(policy_status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        Self { message: error.code().to_string(), status, error: Box::new(error) }
    }
}

/// Policy and approval failures are authorization outcomes, not server faults.
/// Only the execution-path codes are classified here; the approval API maps its
/// own errors explicitly, and its validation codes must stay 400/404.
fn policy_status(message: &str) -> Option<StatusCode> {
    let message = message.trim_start();
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "POLICY_DENIED:",
        "POLICY_APPROVAL_REQUIRED:",
        "APPROVAL_REQUIRED:",
        "PERMISSION_DENIED:",
        "APPROVAL_TOKEN_UNKNOWN",
        "APPROVAL_TOKEN_WRONG_ACTOR",
        "APPROVAL_TOKEN_BINDING_MISMATCH",
        "APPROVAL_TOKEN_FORBIDDEN",
        "APPROVAL_NOT_APPROVED",
        "APPROVAL_NOT_APPROVER",
    ];
    if FORBIDDEN_PREFIXES.iter().any(|prefix| message.starts_with(prefix)) {
        return Some(StatusCode::FORBIDDEN);
    }
    const CONFLICT_PREFIXES: &[&str] = &[
        "APPROVAL_READY",
        "APPROVAL_TOKEN_EXPIRED",
        "APPROVAL_TOKEN_ALREADY_USED",
        "APPROVAL_NOT_PENDING",
        "APPROVAL_ALREADY_DECIDED",
        "APPROVAL_EXPIRED",
    ];
    if CONFLICT_PREFIXES.iter().any(|prefix| message.starts_with(prefix)) {
        return Some(StatusCode::CONFLICT);
    }
    None
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, Json(*self.error)).into_response()
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        Self::internal(s)
    }
}

impl From<&str> for AppError {
    fn from(s: &str) -> Self {
        Self::internal(s)
    }
}

impl From<BackendError> for AppError {
    fn from(error: BackendError) -> Self {
        Self::from_backend_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_errors_are_exposed_as_the_shared_backend_envelope() {
        let error = AppError::internal("database failed");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.error.version(), 1);
        assert_eq!(error.error.code(), "DBX-LEGACY-0001");
        assert_eq!(error.message, "database failed");
    }

    #[test]
    fn policy_denials_surface_as_forbidden() {
        let denied = AppError::from("POLICY_DENIED: blocked by rule (rule x)".to_string());
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        let approval = AppError::from("POLICY_APPROVAL_REQUIRED: 1 statement(s) require approval".to_string());
        assert_eq!(approval.status, StatusCode::FORBIDDEN);
        let token = AppError::from("APPROVAL_TOKEN_BINDING_MISMATCH".to_string());
        assert_eq!(token.status, StatusCode::FORBIDDEN);
        let scope = AppError::from("PERMISSION_DENIED: the user's role bindings do not grant query:ddl".to_string());
        assert_eq!(scope.status, StatusCode::FORBIDDEN);
        let reused = AppError::from("APPROVAL_TOKEN_ALREADY_USED".to_string());
        assert_eq!(reused.status, StatusCode::CONFLICT);
        assert_eq!(AppError::from("database failed".to_string()).status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn typed_policy_errors_keep_the_forbidden_status() {
        let error = BackendError::from_legacy_string("POLICY_DENIED: blocked by rule (rule x)");
        assert_eq!(AppError::from_backend_error(error).status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn app_error_stays_small_for_route_result_types() {
        assert!(std::mem::size_of::<AppError>() <= 64);
    }

    #[test]
    fn structured_agent_text_keeps_catalog_identity_at_http_boundary() {
        let error = AppError::from(
            "Agent RPC error (-1): timed out\nDBX_AGENT_ERROR_DATA:{\"category\":\"timeout\",\"stage\":\"execute\"}",
        );
        assert_eq!(error.error.code(), "DBX-JDBC-9001");
        assert_eq!(error.error.source(), dbx_core::backend_error::BackendErrorSource::JdbcAgentLegacy);
    }

    #[tokio::test]
    async fn http_response_preserves_original_legacy_detail() {
        let response = AppError::internal("database failed").into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()[axum::http::header::CONTENT_TYPE], "application/json");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["version"], 1);
        assert_eq!(payload["code"], "DBX-LEGACY-0001");
        assert_eq!(payload["messageKey"], "backendErrors.legacy");
        assert_eq!(payload["detail"], "database failed");
    }

    #[tokio::test]
    async fn http_response_preserves_sql_keyword_diagnostic_detail() {
        let response = AppError::internal("Incorrect syntax near SELECT").into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["code"], "DBX-LEGACY-0001");
        assert_eq!(payload["detail"], "Incorrect syntax near SELECT");
    }

    #[tokio::test]
    async fn http_response_preserves_original_structured_agent_detail() {
        use dbx_core::db::agent_driver::{
            AgentCallError, AgentErrorCategory, AgentErrorContext, AgentErrorStage, AgentOperationOutcome,
            AgentSessionDisposition,
        };

        let error = BackendError::from_agent_call_error(&AgentCallError::Structured {
            rpc_code: -1,
            message: "relation customer_orders does not exist".to_string(),
            context: AgentErrorContext {
                contract_version: 1,
                category: AgentErrorCategory::Sql,
                retryable: false,
                session_disposition: AgentSessionDisposition::Keep,
                stage: AgentErrorStage::Execute,
                operation_outcome: AgentOperationOutcome::Unknown,
                agent_session_id: Some("session-1".to_string()),
                sql_state: Some("42P01".to_string()),
                vendor_code: None,
                exception_class: Some("java.sql.SQLException".to_string()),
            },
        });

        let response = AppError::from(error).into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload["code"], "DBX-JDBC-4001");
        assert_eq!(payload["source"], "jdbcAgent");
        assert_eq!(payload["detail"], "relation customer_orders does not exist");
        assert!(payload["diagnostics"].get("agentSessionId").is_none());
    }

    #[tokio::test]
    async fn http_response_preserves_duckdb_native_detail_and_worker_code() {
        let error = BackendError::from_duckdb_worker_error(
            "duckdb_execute_failed",
            "Catalog Error: Table missing_table does not exist",
        );

        let response = AppError::from(error).into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(payload["detail"], "Catalog Error: Table missing_table does not exist");
        assert_eq!(payload["origin"]["driver"], "duckdb");
        assert_eq!(payload["diagnostics"]["adapterCode"], "duckdb_execute_failed");
    }

    #[tokio::test]
    async fn http_response_preserves_native_sql_detail() {
        let error = BackendError::from_sql_detail(
            "ERROR: statement [UPDATE users SET password='user-input' WHERE email='literal-secret@example.com']",
        );

        let response = AppError::from(error).into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let detail = payload["detail"].as_str().unwrap();

        assert_eq!(
            detail,
            "ERROR: statement [UPDATE users SET password='user-input' WHERE email='literal-secret@example.com']"
        );
    }

    #[tokio::test]
    async fn http_response_redacts_common_sensitive_key_variants() {
        let error = AppError::internal(
            "driver failed: PASSWORD:secret-a refresh_token = \"secret-b\" api-key:secret-c authorization: Bearer secret-d sessionid=secret-e",
        );

        let response = error.into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let detail = payload["detail"].as_str().unwrap();

        for secret in ["secret-a", "secret-b", "secret-c", "secret-d", "secret-e"] {
            assert!(!detail.contains(secret), "sensitive value leaked: {secret}; detail={detail}");
        }
    }
}
