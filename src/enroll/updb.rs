//! `updb` enrolment: username/password (no key, no CSR, no cert). Oracle: enroll.go `enrollUpdb`
//! (:307-347). The client POSTs the chosen password (+ optional username) over a NON-mTLS connection;
//! the controller sets the password and returns the confirmed username. The result is
//! [`UpdbConfig`] (username/password credentials), NOT a cert-based [`crate::enroll::identity::Config`].
//!
//! This is a SEPARATE entry point from [`crate::enroll::ott::enroll`] because updb's inputs
//! (username/password — not in the JWT) and output (password credentials) differ fundamentally from
//! the cert methods. `enroll()` with a `updb` token returns [`EnrollError::UpdbRequiresCredentials`].
//!
//! Slice E4a covers enrolment only; using a `UpdbConfig` to authenticate (a password-auth path in
//! `EdgeClient`) is the committed follow-up E4b.

use crate::enroll::error::EnrollError;
use crate::enroll::ott::{EnrollOptions, ders_to_pem, parse_error_envelope, resolve_trust};
use crate::enroll::trust;

/// A `updb`-enrolled identity: username/password credentials + the controller CA bundle (for the
/// auth connection in E4b). NOT a cert identity — `updb` has no client key/cert.
#[derive(Clone)]
pub struct UpdbConfig {
    /// Controller client API base URL (`<iss>/edge/client/v1`).
    pub zt_api: String,
    /// Controller CA bundle, PEM (additional CAs first, then fetched; see `resolve_trust`).
    pub ca: String,
    /// Confirmed username (from the controller's `data.username`, or the supplied one).
    pub username: String,
    /// The password set during enrolment. Used by E4b to authenticate.
    pub password: String,
}

// Manual Debug: NEVER format `password` — a derived Debug would leak it via `{:?}`. Mirrors the
// redaction on `ProvidedIdentity`/`EnrollOptions`. (`ca`/username are not secret; ca shown as a length.)
impl std::fmt::Debug for UpdbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdbConfig")
            .field("zt_api", &self.zt_api)
            .field("ca_len", &self.ca.len())
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Enrol via `updb` (username/password). The caller supplies the username (may be empty → the
/// controller uses the identity's pre-set name) and the password to set. Honours `opts.additional_cas`;
/// `opts.key_alg` is irrelevant (updb generates no key).
///
/// # Errors
/// Any trust/transport error from [`resolve_trust`] or the POST; [`EnrollError::EnrollHttp`] on a
/// non-200 response.
pub async fn enroll_updb(
    jwt: &str,
    username: &str,
    password: &str,
    opts: EnrollOptions,
) -> Result<UpdbConfig, EnrollError> {
    let (claims, ca_ders) = resolve_trust(jwt, opts.additional_cas.as_deref()).await?;

    // Oracle: TLS client with RootCAs only, NO client cert (enrollUpdb :309-316). `verified_client`
    // is exactly that (roots + `with_no_client_auth`), already battle-tested for the ott CSR POST.
    let client = trust::verified_client(&ca_ders)?;
    let confirmed = request_updb(&client, &claims.enroll_url()?, username, password).await?;

    let ca_pem = ders_to_pem(&ca_ders)?;
    Ok(UpdbConfig {
        zt_api: claims.zt_api()?,
        ca: ca_pem,
        username: confirmed,
        password: password.to_string(),
    })
}

/// POST `{"password":..,"username":..?}` (username omitted if empty) to the enrol URL and return the
/// confirmed username. Oracle: enrollUpdb :318-346 — 200 → `data.username` (falling back to the
/// supplied username if absent, mirroring the v1.5.0 behaviour); else → error envelope.
async fn request_updb(
    client: &reqwest::Client,
    enroll_url: &str,
    username: &str,
    password: &str,
) -> Result<String, EnrollError> {
    // Build the body conditionally (username only if non-empty), matching the oracle.
    let body = if username.is_empty() {
        serde_json::json!({ "password": password })
    } else {
        serde_json::json!({ "password": password, "username": username })
    };

    let resp = client
        .post(enroll_url)
        .json(&body) // sets Content-Type: application/json
        .send()
        .await
        .map_err(|e| EnrollError::EnrollResponse(e.to_string()))?;

    let status = resp.status();
    let resp_body = resp
        .text()
        .await
        .map_err(|e| EnrollError::EnrollResponse(e.to_string()))?;

    if status == reqwest::StatusCode::OK {
        // Probed live: the 200 body is `{"data":{"username":"..."},"meta":{}}`. Fall back to the
        // supplied username if `data.username` is missing (oracle v1.5.0 fallback).
        let confirmed = serde_json::from_str::<serde_json::Value>(&resp_body)
            .ok()
            .as_ref()
            .and_then(|v| v.get("data")?.get("username")?.as_str())
            .filter(|s| !s.is_empty())
            .map_or_else(|| username.to_string(), str::to_string);
        return Ok(confirmed);
    }

    let (code, message) = parse_error_envelope(&resp_body);
    Err(EnrollError::EnrollHttp {
        status: status.as_u16(),
        code,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn http_client() -> reqwest::Client {
        crate::enroll::trust::ensure_crypto_provider();
        reqwest::Client::new()
    }

    #[tokio::test]
    async fn request_updb_posts_json_body_and_parses_confirmed_username() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/enroll"))
            .and(header("Content-Type", "application/json"))
            // EXACT body match (not a subset): password + username, nothing else.
            .and(body_json(
                serde_json::json!({ "password": "pw", "username": "alice" }),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "data": { "username": "alice-confirmed" } }),
                ),
            )
            .expect(1)
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let name = request_updb(&http_client(), &url, "alice", "pw")
            .await
            .expect("200 -> confirmed username");
        assert_eq!(name, "alice-confirmed");
    }

    #[tokio::test]
    async fn request_updb_falls_back_to_supplied_username_when_absent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/enroll"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "meta": {} })),
            )
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let name = request_updb(&http_client(), &url, "bob", "pw")
            .await
            .expect("200 without data.username -> supplied username");
        assert_eq!(name, "bob");
    }

    #[tokio::test]
    async fn request_updb_falls_back_when_data_username_is_empty() {
        // PRESENT-but-empty `data.username` must also fall back (the `.filter(!is_empty)`) — without
        // it, the caller would get an empty confirmed username.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/enroll"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "data": { "username": "" } })),
            )
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let name = request_updb(&http_client(), &url, "carol", "pw")
            .await
            .expect("empty data.username -> supplied username");
        assert_eq!(name, "carol");
    }

    #[tokio::test]
    async fn request_updb_omits_username_when_empty() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/enroll"))
            // EXACT match: the body must carry ONLY password (no username key) when the caller passes "".
            // (A subset matcher would let an erroneously-emitted empty username slip through.)
            .and(body_json(serde_json::json!({ "password": "pw" })))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "data": { "username": "from-controller" } }),
                ),
            )
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let name = request_updb(&http_client(), &url, "", "pw").await.unwrap();
        assert_eq!(name, "from-controller");
    }

    #[tokio::test]
    async fn request_updb_maps_error_status_to_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/enroll"))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                serde_json::json!({ "error": { "code": "NOT_FOUND", "message": "no such token" } }),
            ))
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let err = request_updb(&http_client(), &url, "x", "pw")
            .await
            .expect_err("404 -> error");
        assert!(
            matches!(err, EnrollError::EnrollHttp { status: 404, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn updb_config_debug_redacts_password() {
        let cfg = UpdbConfig {
            zt_api: "https://ctrl/edge/client/v1".into(),
            ca: "-----BEGIN CERTIFICATE-----\n...".into(),
            username: "alice".into(),
            password: "SUPER-SECRET-PW".into(),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-PW"),
            "Debug leaked the password: {dbg}"
        );
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("alice")); // username is not secret
    }
}
