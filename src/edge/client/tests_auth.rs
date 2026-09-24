use super::testsupport::*;
use super::*;

/// Guards the shared-`legacy_authenticate` refactor on the CERT path: `do_authenticate` must
/// still POST `?method=cert`. The `query_param("method","cert")` matcher fails the mock if the
/// method query drifts, so this is the deterministic safety net for the factoring (cert auth was
/// otherwise live-only). Oracle: edge-apis `legacyAuth` cert.
#[tokio::test]
async fn do_authenticate_posts_method_cert() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "cert"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"cert-tok","authQueries":[],"identity":{"name":"certid"}},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let session = do_authenticate(&reqwest::Client::new(), &base, "{}", None)
        .await
        .expect("cert auth 200 -> ApiSession");
    assert_eq!(session.token, "cert-tok");
    assert_eq!(session.identity.name, "certid");
}

/// Guards the password path: `do_authenticate_password` POSTs `?method=password` with EXACTLY
/// `{"username","password"}` (body_json is an exact match → a wrong key or extra field fails the
/// mock). Oracle: edge-apis `legacyAuth` with `AuthMethodUpdb="password"`.
#[tokio::test]
async fn do_authenticate_password_posts_method_password_and_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "password"))
            .and(header("Content-Type", "application/json"))
            .and(body_json(
                serde_json::json!({ "username": "alice", "password": "pw" }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"pw-tok","authQueries":[],"identity":{"name":"alice"}},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let session = do_authenticate_password(&reqwest::Client::new(), &base, "alice", "pw", None)
        .await
        .expect("password auth 200 -> ApiSession");
    assert_eq!(session.token, "pw-tok");
    assert_eq!(session.identity.name, "alice");
}

/// Guards the empty-username case: `do_authenticate_password` must OMIT the `username` key when
/// the caller passes `""` (oracle `omitempty` + parity with `enroll::updb::request_updb`). The
/// `body_json` matcher is an EXACT match — an erroneously-emitted `{"username":""}` would fail the
/// mock. Oracle: edge-api `authenticate.go` `omitempty` + sdk-golang `UpdbCredentials.Payload`.
#[tokio::test]
async fn do_authenticate_password_omits_username_when_empty() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "password"))
            .and(header("Content-Type", "application/json"))
            // EXACT match: ONLY password (no username key) when the caller passes "".
            .and(body_json(serde_json::json!({ "password": "pw" })))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"pw-tok","authQueries":[],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let session = do_authenticate_password(&reqwest::Client::new(), &base, "", "pw", None)
        .await
        .expect("empty username -> body omits the username key");
    assert_eq!(session.token, "pw-tok");
}

/// Password auth maps a non-2xx (401 bad credentials) to `AuthHttp`. Oracle: `legacyAuth` errors.
#[tokio::test]
async fn do_authenticate_password_maps_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "password"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "INVALID_AUTH", "message": "bad password" }
        })))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_authenticate_password(&reqwest::Client::new(), &base, "alice", "wrong", None)
        .await
        .expect_err("401 -> AuthHttp");
    assert!(
        matches!(err, EdgeError::AuthHttp { status: 401, .. }),
        "got {err:?}"
    );
}

/// The LEGACY producer of `MfaRequired`: a 200 auth response carrying a NON-EMPTY `authQueries`
/// (posture/MFA) → `legacy_authenticate` returns `EdgeError::MfaRequired` (the GENERIC variant,
/// distinct from the OIDC-TOTP `TotpProviderRequired`). MUTATION: dropping the
/// `!auth_queries.is_empty()` check (`edge/client/auth.rs`) would return a "ready" session → this RED;
/// emitting `TotpProviderRequired` here instead → also RED (the legacy path stays generic).
#[tokio::test]
async fn legacy_auth_with_posture_queries_is_mfa_required() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "password"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"pw-tok","authQueries":[{"typeId":"MFA"}],"identity":{"name":"alice"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_authenticate_password(&reqwest::Client::new(), &base, "alice", "pw", None)
        .await
        .expect_err("non-empty authQueries -> MfaRequired");
    assert!(matches!(err, EdgeError::MfaRequired), "got {err:?}");
}

/// A legacy partial session (`authQueries` non-empty) WITH an `mfa_provider` → the provider's code
/// is submitted to `POST /authenticate/mfa` (body `{"code":..}`, `zt-session` header pinned),
/// then the re-fetched session has empty `authQueries` → the COMPLETED session is returned.
/// MUTATION: dropping the submit (`expect(1)` on `/authenticate/mfa`) RED; not re-fetching (skipping
/// the empty-authQueries check) would let a still-partial session through → covered by the
/// `still_pending` test below.
#[tokio::test]
async fn legacy_auth_with_mfa_provider_submits_and_completes() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // (1) Initial cert-auth → 200 with the MFA authQuery + the PARTIAL token.
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "cert"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"partial-tok","authQueries":[{"typeId":"MFA","provider":"ziti","httpUrl":"./authenticate/mfa"}],"identity":{"name":"mfauser"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    // (2) The MFA submit: `{"code":"123456"}` body + `zt-session: partial-tok` header, EXACTLY once.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate/mfa"))
        .and(header("zt-session", "partial-tok"))
        .and(body_json(serde_json::json!({ "code": "123456" })))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":{},"meta":{}}"#))
        .expect(1)
        .mount(&server)
        .await;
    // (3) The re-fetch (oracle `Refresh()`): the SAME token is now upgraded, authQueries empty.
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/current-api-session"))
            .and(header("zt-session", "partial-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"partial-tok","authQueries":[],"identity":{"name":"mfauser"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let provider: MfaCodeProvider = Arc::new(|| Ok("123456".to_string()));
    let session = do_authenticate(&reqwest::Client::new(), &base, "{}", Some(&provider))
        .await
        .expect("MFA satisfied → completed session");
    assert!(session.auth_queries.is_empty(), "completed session");
    assert_eq!(session.token, "partial-tok");
}

/// A legacy partial session WITHOUT a provider → the generic [`EdgeError::MfaRequired`]
/// (byte-identical to before MFA support). MUTATION: routing the no-provider arm to a different
/// error (or satisfying without a code) would RED.
#[tokio::test]
async fn legacy_auth_mfa_no_provider_is_mfa_required() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "cert"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"partial-tok","authQueries":[{"typeId":"MFA"}],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    // No `/authenticate/mfa` mock: a submit attempt (provider present by mistake) would 404 →
    // assert the no-provider path does NOT submit, by leaving the endpoint unmounted.
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_authenticate(&reqwest::Client::new(), &base, "{}", None)
        .await
        .expect_err("no provider → MfaRequired");
    assert!(matches!(err, EdgeError::MfaRequired), "got {err:?}");
}

/// The MFA submit returning 400 (`MFA_INVALID_TOKEN`, probed live) → [`EdgeError::TotpCodeRejected`]
/// (NOT the generic `MfaRequired` and NOT a bare `AuthHttp`). MUTATION: classifying 400 as
/// `AuthHttp` would RED.
#[tokio::test]
async fn legacy_auth_mfa_bad_code_is_rejected() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "cert"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"partial-tok","authQueries":[{"typeId":"MFA"}],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate/mfa"))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                r#"{"error":{"code":"MFA_INVALID_TOKEN","message":"An invalid token/code was provided"},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let provider: MfaCodeProvider = Arc::new(|| Ok("000000".to_string()));
    let err = do_authenticate(&reqwest::Client::new(), &base, "{}", Some(&provider))
        .await
        .expect_err("bad code → TotpCodeRejected");
    assert!(matches!(err, EdgeError::TotpCodeRejected), "got {err:?}");
}

/// The provider returning an error aborts WITHOUT submitting (no `/authenticate/mfa` request) →
/// [`EdgeError::TotpProvider`]. `expect(0)` on the submit pins the "abort before submit" order.
#[tokio::test]
async fn legacy_auth_mfa_provider_error_aborts_without_submit() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "cert"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"partial-tok","authQueries":[{"typeId":"MFA"}],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate/mfa"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let provider: MfaCodeProvider =
        Arc::new(|| Err(EdgeError::TotpProvider("user cancelled".into())));
    let err = do_authenticate(&reqwest::Client::new(), &base, "{}", Some(&provider))
        .await
        .expect_err("provider error → TotpProvider, no submit");
    assert!(
        matches!(err, EdgeError::TotpProvider(ref m) if m.contains("user cancelled")),
        "got {err:?}"
    );
}

/// After a successful submit the re-fetch STILL carries `authQueries` (the controller demands more,
/// or our single submit was insufficient) → [`EdgeError::MfaRequired`] (single-submit deviation —
/// we are synchronous, the oracle is event-driven). MUTATION: skipping the post-submit
/// empty-authQueries check would wrongly return a partial session → this RED.
#[tokio::test]
async fn legacy_auth_mfa_still_pending_after_submit_is_mfa_required() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "cert"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"partial-tok","authQueries":[{"typeId":"MFA"}],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate/mfa"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":{},"meta":{}}"#))
        .mount(&server)
        .await;
    // The re-fetch STILL has a non-empty authQueries → unsatisfied by one submit.
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/current-api-session"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"partial-tok","authQueries":[{"typeId":"MFA"}],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let provider: MfaCodeProvider = Arc::new(|| Ok("123456".to_string()));
    let err = do_authenticate(&reqwest::Client::new(), &base, "{}", Some(&provider))
        .await
        .expect_err("still pending → MfaRequired");
    assert!(matches!(err, EdgeError::MfaRequired), "got {err:?}");
}

/// The MID-SESSION path: a legacy session re-auth (slice reauth-401) of an MFA identity funnels
/// through the SAME `legacy_authenticate`, so a stored provider re-satisfies MFA on the re-auth
/// (the genuine "mid-session MFA"). Wiremock is enough (only new wire needs a live test) — control flow over
/// the already-validated `/authenticate/mfa` wire. A 401 on `list_services` triggers the re-auth
/// (cert method); the re-auth returns a partial session → the provider's code completes it; the
/// retry of `list_services` then succeeds.
#[tokio::test]
async fn do_reauthenticate_mfa_completes_mid_session() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // (1) list_services with the STALE token → 401 (triggers re-auth).
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(header("zt-session", "stale-tok"))
        .respond_with(
            ResponseTemplate::new(401).set_body_string(
                r#"{"error":{"code":"UNAUTHORIZED","message":"expired"},"meta":{}}"#,
            ),
        )
        .mount(&server)
        .await;
    // (2) the cert re-auth → a fresh PARTIAL session.
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .and(query_param("method", "cert"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"fresh-tok","authQueries":[{"typeId":"MFA"}],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    // (3) the MFA submit on the fresh partial token.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate/mfa"))
        .and(header("zt-session", "fresh-tok"))
        .and(body_json(serde_json::json!({ "code": "654321" })))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":{},"meta":{}}"#))
        .expect(1)
        .mount(&server)
        .await;
    // (4) the re-fetch → empty authQueries (completed).
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/current-api-session"))
            .and(header("zt-session", "fresh-tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"fresh-tok","authQueries":[],"identity":{"name":"x"}},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    // (5) list_services retried with the COMPLETED fresh token → 200 (empty list, paginated).
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(header("zt-session", "fresh-tok"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":0}}}"#,
        ))
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "stale-tok");
    // The stored provider (as an MFA identity would have via `authenticate_with_totp`).
    client.mfa_provider = Some(Arc::new(|| Ok("654321".to_string())));
    let services = client
        .list_services()
        .await
        .expect("re-auth + MFA + retry succeeds");
    assert!(services.is_empty(), "completed: empty service list");
    // The token rotated to the completed fresh one.
    assert_eq!(client.token().as_deref(), Some("fresh-tok"));
}

/// The `authenticate_with_totp` future is `Send` (the stored `MfaCodeProvider` is
/// `Arc<dyn Fn + Send + Sync>`, so the future is spawnable). MUTATION: dropping `+ Send`/`+ Sync`
/// from the [`MfaCodeProvider`] alias → `Arc<dyn Fn>` is not `Send` → this assertion fails to
/// compile (a compile-time pin, the strongest mutation kill).
#[test]
fn authenticate_with_totp_future_is_send() {
    fn assert_send<T: Send>(_t: &T) {}
    crate::enroll::trust::ensure_crypto_provider();
    let cfg = cert_identity_config();
    let provider: MfaCodeProvider = Arc::new(|| Ok("123456".to_string()));
    let fut = async move {
        let mut client = EdgeClient::from_identity(&cfg).unwrap();
        client.authenticate_with_totp(Some(provider)).await
    };
    assert_send(&fut);
}
