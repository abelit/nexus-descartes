//! Verification of nexus-hilbert / ongrid access tokens.
//!
//! Preconditions are deliberately strict. hilbert currently signs access and
//! refresh tokens with the same secret and claims; when `ONGRID_SECRET_KEY` is
//! unset it also derives the vault key from `ONGRID_JWT_SECRET`. Sharing that
//! secret with DBX would hand over hilbert's encrypted credentials, not just
//! token forging. DBX therefore refuses HS256 unless the operator explicitly
//! acknowledges a transition, and only accepts tokens that declare
//! `aud=dbx`, `iss=ongrid`, and an access token type.

use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

const DEFAULT_ISSUER: &str = "ongrid";
const DEFAULT_AUDIENCE: &str = "dbx";

#[derive(Clone, Debug, Deserialize)]
pub struct HilbertClaims {
    pub sub: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub is_superuser: bool,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub exp: Option<i64>,
}

/// DBX role codes a hilbert identity maps to.
///
/// Until `/v1/me` membership resolution exists, anything other than a
/// superuser or an explicitly mapped role is a read-only viewer: guessing a
/// wider role would grant more than the identity actually holds.
pub fn roles_for_claims(claims: &HilbertClaims) -> Vec<String> {
    if claims.is_superuser {
        return vec!["admin".to_string()];
    }
    match claims.role.as_deref().map(str::trim).unwrap_or_default() {
        "admin" | "owner" => vec!["admin".to_string()],
        "dba" => vec!["dba".to_string()],
        "security_admin" => vec!["security_admin".to_string()],
        "auditor" => vec!["auditor".to_string()],
        "operator" => vec!["operator".to_string()],
        _ => vec!["viewer".to_string()],
    }
}

#[derive(Debug)]
pub enum HilbertConfigError {
    /// HS256 without the explicit transition acknowledgement.
    SharedSecretNotAllowed,
    /// No usable key material.
    MissingKey,
    /// Configured PEM/key failed to parse.
    InvalidKey(String),
}

impl std::fmt::Display for HilbertConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SharedSecretNotAllowed => write!(
                formatter,
                "HILBERT_SHARED_SECRET_NOT_ALLOWED: set DBX_HILBERT_ALLOW_SHARED_SECRET=1 only for a \
                 transition, after hilbert configures an independent ONGRID_SECRET_KEY"
            ),
            Self::MissingKey => write!(formatter, "HILBERT_KEY_MISSING: no HS256 secret or RS256 public key"),
            Self::InvalidKey(reason) => write!(formatter, "HILBERT_KEY_INVALID: {reason}"),
        }
    }
}

pub struct HilbertVerifier {
    key: DecodingKey,
    algorithm: Algorithm,
    issuer: String,
    audience: String,
}

impl std::fmt::Debug for HilbertVerifier {
    /// Never print key material.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HilbertVerifier")
            .field("algorithm", &self.algorithm)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl HilbertVerifier {
    /// HS256 (transition only) or RS256 from a PEM public key file.
    pub fn new(
        hs256_secret: Option<String>,
        rs256_public_key_pem: Option<String>,
        issuer: String,
        audience: String,
        allow_shared_secret: bool,
    ) -> Result<Self, HilbertConfigError> {
        if let Some(pem) = rs256_public_key_pem.filter(|value| !value.trim().is_empty()) {
            let key = DecodingKey::from_rsa_pem(pem.as_bytes())
                .map_err(|error| HilbertConfigError::InvalidKey(error.to_string()))?;
            return Ok(Self { key, algorithm: Algorithm::RS256, issuer, audience });
        }
        match hs256_secret.filter(|value| !value.trim().is_empty()) {
            Some(secret) if allow_shared_secret => Ok(Self {
                key: DecodingKey::from_secret(secret.as_bytes()),
                algorithm: Algorithm::HS256,
                issuer,
                audience,
            }),
            Some(_) => Err(HilbertConfigError::SharedSecretNotAllowed),
            None => Err(HilbertConfigError::MissingKey),
        }
    }

    pub fn from_env() -> Result<Option<Self>, String> {
        let enabled = matches!(
            std::env::var("DBX_HILBERT_ENABLED").ok().as_deref().map(str::trim),
            Some("1") | Some("true") | Some("yes")
        );
        if !enabled {
            return Ok(None);
        }
        let public_key = match std::env::var("DBX_HILBERT_RS256_PUBLIC_KEY_FILE") {
            Ok(path) if !path.trim().is_empty() => {
                Some(std::fs::read_to_string(path.trim()).map_err(|error| format!("HILBERT_KEY_READ: {error}"))?)
            }
            _ => None,
        };
        let secret = std::env::var("DBX_HILBERT_HS256_SECRET").ok();
        let allow_shared_secret = matches!(
            std::env::var("DBX_HILBERT_ALLOW_SHARED_SECRET").ok().as_deref().map(str::trim),
            Some("1") | Some("true") | Some("yes")
        );
        let issuer = std::env::var("DBX_HILBERT_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_string());
        let audience = std::env::var("DBX_HILBERT_AUDIENCE").unwrap_or_else(|_| DEFAULT_AUDIENCE.to_string());
        Self::new(secret, public_key, issuer, audience, allow_shared_secret)
            .map(Some)
            .map_err(|error| error.to_string())
    }

    pub fn verify(&self, token: &str) -> Result<HilbertClaims, String> {
        let mut validation = Validation::new(self.algorithm);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.validate_exp = true;
        // hilbert must declare the token type; treat a missing one as a refresh
        // token and reject it rather than accepting an ambiguous credential.
        let claims = decode::<HilbertClaims>(token, &self.key, &validation)
            .map_err(|error| format!("HILBERT_TOKEN_INVALID: {error}"))?
            .claims;
        checked_claims(claims)
    }
}

/// Verifier backed by a JWK Set (RS256 keys normally, `oct` keys in tests).
pub struct JwksVerifier {
    jwks: JwkSet,
    issuer: String,
    audience: String,
}

impl JwksVerifier {
    pub fn new(jwks: JwkSet, issuer: String, audience: String) -> Self {
        Self { jwks, issuer, audience }
    }

    pub fn verify(&self, token: &str) -> Result<HilbertClaims, String> {
        let header = decode_header(token).map_err(|error| format!("HILBERT_TOKEN_INVALID: {error}"))?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::HS256) {
            return Err("HILBERT_ALGORITHM_NOT_ALLOWED".to_string());
        }
        let kid = header.kid.as_deref().ok_or_else(|| "HILBERT_KID_MISSING".to_string())?;
        let jwk = self.jwks.find(kid).ok_or_else(|| "HILBERT_KEY_NOT_FOUND".to_string())?;
        if let Some(algorithm) = jwk.common.key_algorithm {
            let matches = matches!(
                (algorithm, header.alg),
                (KeyAlgorithm::HS256, Algorithm::HS256) | (KeyAlgorithm::RS256, Algorithm::RS256)
            );
            if !matches {
                return Err("HILBERT_ALGORITHM_MISMATCH".to_string());
            }
        }
        let key = DecodingKey::from_jwk(jwk).map_err(|error| format!("HILBERT_KEY_INVALID: {error}"))?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.validate_exp = true;
        let claims = decode::<HilbertClaims>(token, &key, &validation)
            .map_err(|error| format!("HILBERT_TOKEN_INVALID: {error}"))?
            .claims;
        checked_claims(claims)
    }
}

fn checked_claims(claims: HilbertClaims) -> Result<HilbertClaims, String> {
    match claims.token_type.as_deref() {
        Some("access") => {}
        _ => return Err("HILBERT_TOKEN_NOT_ACCESS".to_string()),
    }
    if claims.sub.trim().is_empty() {
        return Err("HILBERT_SUBJECT_MISSING".to_string());
    }
    Ok(claims)
}

/// Key material selected by configuration: a PEM/secret, or a fetched JWK Set.
pub enum HilbertAuth {
    Key(HilbertVerifier),
    Jwks(JwksVerifier),
}

impl HilbertAuth {
    pub fn verify(&self, token: &str) -> Result<HilbertClaims, String> {
        match self {
            Self::Key(verifier) => verifier.verify(token),
            Self::Jwks(verifier) => verifier.verify(token),
        }
    }

    /// Fetches a JWKS document and builds a verifier for it.
    pub async fn from_jwks_url(jwks_url: &str, issuer: String, audience: String) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|error| format!("HILBERT_JWKS_CLIENT: {error}"))?;
        let response = client.get(jwks_url).send().await.map_err(|error| format!("HILBERT_JWKS_REQUEST: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("HILBERT_JWKS_STATUS: {}", response.status()));
        }
        let jwks: JwkSet = response.json().await.map_err(|error| format!("HILBERT_JWKS_PARSE: {error}"))?;
        if jwks.keys.is_empty() {
            return Err("HILBERT_JWKS_EMPTY".to_string());
        }
        Ok(Self::Jwks(JwksVerifier::new(jwks, issuer, audience)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    fn token(secret: &str, claims: serde_json::Value) -> String {
        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap()
    }

    fn verifier(secret: &str) -> HilbertVerifier {
        HilbertVerifier::new(Some(secret.to_string()), None, "ongrid".to_string(), "dbx".to_string(), true).unwrap()
    }

    fn claims() -> serde_json::Value {
        json!({
            "sub": "user-1",
            "user_id": "user-1",
            "email": "ops@example.com",
            "role": "operator",
            "is_superuser": false,
            "token_type": "access",
            "aud": "dbx",
            "iss": "ongrid",
            "exp": 4_000_000_000i64,
        })
    }

    fn token_with_kid(secret: &[u8], kid: &str) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_string());
        encode(&header, &claims(), &EncodingKey::from_secret(secret)).unwrap()
    }

    #[test]
    fn a_jwks_backed_token_verifies_and_requires_a_known_kid() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let secret = b"secret-test-key-0123456789abcdef";
        let encoded = URL_SAFE_NO_PAD.encode(secret);
        let jwks: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{ "kty": "oct", "kid": "k1", "alg": "HS256", "k": encoded }]
        }))
        .unwrap();
        let verifier = JwksVerifier::new(jwks, "ongrid".to_string(), "dbx".to_string());
        assert_eq!(verifier.verify(&token_with_kid(secret, "k1")).unwrap().sub, "user-1");
        assert_eq!(verifier.verify(&token_with_kid(secret, "missing")).unwrap_err(), "HILBERT_KEY_NOT_FOUND");
    }

    #[test]
    fn a_valid_access_token_verifies() {
        let claims = verifier("secret").verify(&token("secret", claims())).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.email.as_deref(), Some("ops@example.com"));
        assert_eq!(roles_for_claims(&claims), vec!["operator".to_string()]);
    }

    #[test]
    fn a_refresh_token_is_rejected() {
        let mut value = claims();
        value["token_type"] = json!("refresh");
        assert_eq!(verifier("secret").verify(&token("secret", value)).unwrap_err(), "HILBERT_TOKEN_NOT_ACCESS");
    }

    #[test]
    fn a_missing_token_type_is_rejected() {
        let mut value = claims();
        value.as_object_mut().unwrap().remove("token_type");
        assert_eq!(verifier("secret").verify(&token("secret", value)).unwrap_err(), "HILBERT_TOKEN_NOT_ACCESS");
    }

    #[test]
    fn a_wrong_audience_is_rejected() {
        let mut value = claims();
        value["aud"] = json!("other-service");
        assert!(verifier("secret").verify(&token("secret", value)).is_err());
    }

    #[test]
    fn a_wrong_issuer_is_rejected() {
        let mut value = claims();
        value["iss"] = json!("some-other-idp");
        assert!(verifier("secret").verify(&token("secret", value)).is_err());
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let mut value = claims();
        value["exp"] = json!(1_000);
        assert!(verifier("secret").verify(&token("secret", value)).is_err());
    }

    #[test]
    fn a_token_signed_with_another_secret_is_rejected() {
        assert!(verifier("secret").verify(&token("other-secret", claims())).is_err());
    }

    #[test]
    fn hs256_requires_the_explicit_transition_flag() {
        let error =
            HilbertVerifier::new(Some("secret".to_string()), None, "ongrid".to_string(), "dbx".to_string(), false)
                .unwrap_err();
        assert!(matches!(error, HilbertConfigError::SharedSecretNotAllowed));
    }

    #[test]
    fn superusers_map_to_admin_and_unknown_roles_to_viewer() {
        let mut superuser = claims();
        superuser["is_superuser"] = json!(true);
        let parsed: HilbertClaims = serde_json::from_value(superuser).unwrap();
        assert_eq!(roles_for_claims(&parsed), vec!["admin".to_string()]);

        let mut unknown = claims();
        unknown["role"] = json!("something_else");
        let parsed: HilbertClaims = serde_json::from_value(unknown).unwrap();
        assert_eq!(roles_for_claims(&parsed), vec!["viewer".to_string()]);
    }
}
