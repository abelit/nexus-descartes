//! Client address and browser-origin guards.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, OptionalFromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::WebState;

/// The client address resolved for this request (ConnectInfo + trusted proxy).
#[derive(Clone, Debug)]
pub struct ClientIp(pub String);

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<ClientIp>().cloned().ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl<S> OptionalFromRequestParts<S> for ClientIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<ClientIp>().cloned())
    }
}

/// Resolves the client address once and stores it as an extension, so handlers
/// (login throttling) and middleware share one trusted value.
pub async fn client_ip_middleware(
    State(_state): State<Arc<WebState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|info| info.0);
    let ip = crate::auth::client_ip_from_peer(peer, req.headers());
    let mut req = req;
    req.extensions_mut().insert(ClientIp(ip.unwrap_or_else(|| "unknown".to_string())));
    next.run(req).await
}

/// Rejects cross-origin browser writes.
///
/// A browser always sends `Origin` on cross-site requests; when it is present,
/// its host must match `Host`. Non-browser clients (CLI, MCP) send no Origin and
/// are unaffected. This complements SameSite=Lax for the cookie session.
pub async fn origin_guard(req: Request<axum::body::Body>, next: Next) -> Response {
    let unsafe_method = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if unsafe_method {
        if let Some(origin) = req.headers().get(axum::http::header::ORIGIN).and_then(|value| value.to_str().ok()) {
            let host = req.headers().get(axum::http::header::HOST).and_then(|value| value.to_str().ok());
            if !origin_matches_host(origin, host) {
                return (StatusCode::FORBIDDEN, "CROSS_ORIGIN_REQUEST_REJECTED").into_response();
            }
        }
    }
    next.run(req).await
}

/// Compares the origin's authority with the Host header. A missing Host or an
/// opaque origin (`null`) is rejected for safety.
fn origin_matches_host(origin: &str, host: Option<&str>) -> bool {
    let Some(host) = host.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https") {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    authority.eq_ignore_ascii_case(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_origins_are_accepted() {
        assert!(origin_matches_host("https://dbx.example.com", Some("dbx.example.com")));
        assert!(origin_matches_host("http://localhost:4224", Some("localhost:4224")));
    }

    #[test]
    fn cross_origin_and_opaque_origins_are_rejected() {
        assert!(!origin_matches_host("https://evil.example.com", Some("dbx.example.com")));
        assert!(!origin_matches_host("null", Some("dbx.example.com")));
        assert!(!origin_matches_host("https://dbx.example.com", None));
        assert!(!origin_matches_host("file:///tmp/x", Some("dbx.example.com")));
    }
}
