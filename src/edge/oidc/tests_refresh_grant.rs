//! Tests de `refresh_grant` (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`).
//!
//! ───────────────────────────── OIDC-3: refresh-token-exchange grant ─────────────────────────────

use super::refresh_grant::*;
use super::*;

/// `parse_refresh_response` reads access/refresh/expires_in; an empty refresh → None (the caller
/// then keeps the prior refresh). No id_token/nonce is required (a refresh-grant response has none).
#[test]
fn parse_refresh_response_extracts_rotated_tokens() {
    let body = r#"{"access_token":"ey.NEWACC","refresh_token":"ey.NEWREF","expires_in":1799,"token_type":"Bearer","issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token"}"#;
    let r = parse_refresh_response(body).unwrap();
    assert_eq!(r.access, "ey.NEWACC");
    assert_eq!(r.refresh.as_deref(), Some("ey.NEWREF"));
    assert_eq!(r.expires_in, 1799);

    let empty_ref = r#"{"access_token":"a","refresh_token":"","expires_in":5}"#;
    let r2 = parse_refresh_response(empty_ref).unwrap();
    assert!(r2.refresh.is_none(), "empty refresh → None (keep prior)");
}

/// `do_oidc_refresh` POSTs the EXACT RFC 8693 token-exchange form (the oracle wire): grant_type =
/// token-exchange, subject_token = the refresh, subject_token_type + requested_token_type =
/// refresh_token, client_id = native. The body matcher pins every field — a wrong grant_type or a
/// plain `grant_type=refresh_token` would NOT match → the mock 404s → RED.
#[tokio::test]
async fn do_oidc_refresh_posts_token_exchange_form_and_parses() {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .and(body_string_contains(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange",
        ))
        .and(body_string_contains("client_id=native"))
        .and(body_string_contains("subject_token=ey.REFRESH1"))
        .and(body_string_contains(
            "subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token",
        ))
        .and(body_string_contains(
            "requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"ey.ACC2","refresh_token":"ey.REF2","expires_in":1799}"#,
        ))
        .mount(&server)
        .await;

    let http = reqwest::Client::new();
    let r = do_oidc_refresh(
        &http,
        &server.uri(),
        "ey.REFRESH1",
        OIDC_REFRESH_REQUEST_TIMEOUT,
    )
    .await
    .expect("token-exchange refresh succeeds");
    assert_eq!(r.access, "ey.ACC2");
    assert_eq!(r.refresh.as_deref(), Some("ey.REF2"));
    assert_eq!(r.expires_in, 1799);
}

/// A non-200 at the token endpoint (the refresh token gone/rejected → a full re-login is needed,
/// deferred) maps to [`EdgeError::OidcHttp`] naming the step.
#[tokio::test]
async fn do_oidc_refresh_maps_non_200_to_oidc_http() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid_grant"))
        .mount(&server)
        .await;

    let http = reqwest::Client::new();
    let err = do_oidc_refresh(
        &http,
        &server.uri(),
        "ey.dead",
        OIDC_REFRESH_REQUEST_TIMEOUT,
    )
    .await
    .expect_err("a 400 is an error");
    assert!(
        matches!(err, EdgeError::OidcHttp { status: 400, ref step, .. } if step == "oidc refresh"),
        "got {err:?}"
    );
}

/// FIX 1 (F2): the token-exchange POST is BOUNDED by the per-request timeout. The refresh runs
/// under `reauth_lock`, so a black-holed token endpoint must not hang the proactive timer or wedge
/// concurrent ops. A wiremock that delays a valid 200 WELL past a short injected timeout → the call
/// returns a transport error (mapped to `OidcResponse`) far under the delay. MUTATION CHECK: the
/// discriminator is Err-vs-Ok + the wall-clock bound — drop the `.timeout(...)` in `do_oidc_refresh`
/// and the client waits the full 2s and returns `Ok(RefreshedOidc)`, so this `expect_err` + the
/// `< 1s` bound both go RED. Mirrors `session_cert::cert_mint_post_is_bounded_by_request_timeout`.
#[tokio::test]
async fn oidc_refresh_post_is_bounded_by_request_timeout() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // A valid 200 — but delayed WELL past the short injected timeout. Without the per-request
    // timeout the client would happily wait the full 2s and return Ok.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"{"access_token":"ey.SLOW","refresh_token":"ey.SLOWREF","expires_in":1799}"#,
                )
                .set_delay(std::time::Duration::from_secs(2)),
        )
        .mount(&server)
        .await;

    let http = reqwest::Client::new();
    let start = std::time::Instant::now();
    let err = do_oidc_refresh(
        &http,
        &server.uri(),
        "ey.refresh",
        // Short injected timeout: comfortably under the 2s delay, comfortably over jitter.
        std::time::Duration::from_millis(100),
    )
    .await
    .expect_err("the slow 200 must be cut off by the request timeout, not awaited");
    // Bounded: it returned long before the 2s delay (proves the timeout fired, not the response).
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "refresh returned in {:?}, expected < 1s (timeout-bounded)",
        start.elapsed()
    );
    // A reqwest timeout maps through the existing transport-error path, not swallowed.
    assert!(matches!(err, EdgeError::OidcResponse(_)), "got {err:?}");
}
