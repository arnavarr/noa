use super::testsupport::*;
use super::*;

/// SUCCESS-FIRST (no re-auth): a `create_session` that 201s on the first try must NOT re-auth —
/// `/authenticate` `.expect(0)` is verified on drop.
#[tokio::test]
async fn create_session_success_first_does_not_reauth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    mount_cert_reauth(&server, "T1", 0).await; // must NOT be hit
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let session = client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect("first-try 201");
    assert_eq!(session.token, "jwt-1");
    assert_eq!(client.token().as_deref(), Some("T0"), "token unchanged");
}

/// NON-401 PROPAGATES (no re-auth): a 403 is not unauthorized-for-retry, so it propagates
/// unwrapped and `/authenticate` is never hit (`.expect(0)`).
#[tokio::test]
async fn create_session_non_401_propagates_without_reauth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "no dial permission" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_cert_reauth(&server, "T1", 0).await; // 403 ≠ 401 → no re-auth
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let err = client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect_err("403 propagates");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 403, .. }),
        "got {err:?}"
    );
    assert_eq!(
        client.token().as_deref(),
        Some("T0"),
        "no re-auth → token unchanged"
    );
}

/// SessionHttp(401) ARM: `create_session` on the stale token T0 → 401 → reactive re-auth (one
/// `/authenticate`, fresh token T1) → retry `POST /sessions` with T1 → 201. The two `/sessions`
/// mocks are keyed on the `zt-session` header so the retry MUST carry the rotated token.
#[tokio::test]
async fn create_session_401_reauthenticates_and_retries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("zt-session", "T0"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_cert_reauth(&server, "T1", 1).await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .and(header("zt-session", "T1"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let session = client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect("recovers after a reactive re-auth");
    assert_eq!(
        session.token, "jwt-1",
        "the retry (with T1) created the session"
    );
    assert_eq!(
        client.token().as_deref(),
        Some("T1"),
        "token rotated to the fresh one"
    );
    // §4.3 (REAUTH path): the reactive re-auth persists token AND expiry (the `/authenticate`
    // body now carries `expiresAt`). Mutate `do_reauthenticate` to drop the expiry → RED.
    assert!(
        client.expires_at().is_some(),
        "the re-auth persisted the fresh api-session expiry (§4.3)"
    );
}

/// CACHE-CLEAR ON REAUTH (mirrors the oracle's `setUnauthenticated` → `sessions.Clear()`):
/// a Dial session cached under the stale api-session MUST be evicted when a 401 triggers a
/// reactive re-auth, otherwise `get_or_create_dial_session` could later return a stale
/// session-token the router would reject. `create_session` itself never reads the Dial cache
/// (only `get_or_create_dial_session` does), so the ONLY thing that can drop "svc-1" here is
/// `reauthenticate`'s `dial_sessions.clear()` — drop that line and this assertion goes RED.
#[tokio::test]
async fn reauth_clears_dial_session_cache() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("zt-session", "T0"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_cert_reauth(&server, "T1", 1).await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .and(header("zt-session", "T1"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    // Pre-populate the Dial cache with a session minted under the (soon-to-be-stale) api-session.
    client.cache_dial_session("svc-1", dial_detail("svc-1", "stale-dial-token"));
    assert!(
        client.cached_dial_session("svc-1").is_some(),
        "precondition: the cache is populated before the re-auth"
    );

    // A 401 on the control-plane create → reactive re-auth (rotates T0→T1) → retry succeeds.
    client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect("recovers after a reactive re-auth");

    assert_eq!(
        client.token().as_deref(),
        Some("T1"),
        "the re-auth actually fired (token rotated)"
    );
    assert!(
        client.cached_dial_session("svc-1").is_none(),
        "the re-auth CLEARED the Dial-session cache (oracle sessions.Clear)"
    );
}

/// ServicesHttp(401) ARM: `list_services` on the stale token T0 → 401 → re-auth → retry
/// `GET /services` with T1 → 200. `bind()` inherits this for free (it calls `list_services`).
#[tokio::test]
async fn list_services_401_reauthenticates_and_retries() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(header("zt-session", "T0"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_cert_reauth(&server, "T1", 1).await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/services"))
            .and(header("zt-session", "T1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":[{"id":"svc-1","name":"alpha","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let services = client
        .list_services()
        .await
        .expect("recovers after re-auth");
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, "alpha");
    assert_eq!(client.token().as_deref(), Some("T1"));
}

/// SessionCertHttp(401) ARM — folds the cert-remint-401 the renewal slice deferred: a stale updb
/// holder re-mints, the re-mint on T0 → 401 → re-auth (T1) + CLEAR the holder → retry the re-mint
/// on T1 → 201, and `channel_client_config` builds TLS from the re-minted leaf. Reuses the
/// holder/CA scaffolding of `channel_client_config_updb_uses_reminted_holder_leaf_not_config`.
#[tokio::test]
async fn session_cert_remint_401_reauthenticates_and_retries() {
    crate::enroll::trust::ensure_crypto_provider();
    let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).unwrap();
    let ca_der = ca.der().to_vec();

    let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let original = p256_leaf_cn_signed("original-cn", &leaf_kp, &ca_params, &ca_kp);
    let reminted = p256_leaf_cn_signed("reminted-cn", &leaf_kp, &ca_params, &ca_kp);

    let server = MockServer::start().await;
    // Re-mint with the STALE token T0 → 401 (the api-session itself expired).
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/current-api-session/certificates"))
        .and(header("zt-session", "T0"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_cert_reauth(&server, "T1", 1).await;
    // Re-mint with the FRESH token T1 → 201 (re-minted leaf).
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/current-api-session/certificates"))
        .and(header("zt-session", "T1"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": { "id": "cert-1", "certificate": reminted }, "meta": {}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());

    let mut client = EdgeClient::for_test_with(&base, "T0");
    client.config.id.cert = format!("pem:{original}");
    client.config.id.key = format!("pem:{}", leaf_kp.serialize_pem());
    let holder = crate::edge::session_cert_renew::SessionCertState::new(
        &crate::edge::session_cert::SessionCert {
            leaf_pem: original.clone(),
            chain_pem: original.clone(),
            key_pem: leaf_kp.serialize_pem(),
            id: "cert-0".into(),
        },
        vec![ca_der],
    )
    .expect("holder builds");
    client.session_cert = Some(std::sync::Arc::new(tokio::sync::Mutex::new(holder)));
    // Force the holder stale so the FIRST channel_client_config re-mints (→ 401 on T0).
    client
        .session_cert
        .as_ref()
        .unwrap()
        .lock()
        .await
        .force_renew_from_now();

    let (_cc, cn) = client
        .channel_client_config()
        .await
        .expect("re-mint 401 → re-auth → retry re-mint builds the TLS config");
    assert_eq!(
        cn, "reminted-cn",
        "built TLS from the re-minted leaf after re-auth"
    );
    assert_eq!(
        client.token().as_deref(),
        Some("T1"),
        "token rotated by the fold"
    );
}

/// RE-AUTH FAILS → ORIGINAL 401: `create_session` 401, but `/authenticate` itself 401s (bad
/// credentials). `reauthenticate` errors, so `with_reauth_retry` returns the ORIGINAL `SessionHttp`
/// 401 (not the `AuthHttp` error) and the token is NOT rotated. Mirrors the oracle returning the
/// original `err` when `Authenticate()` fails.
#[tokio::test]
async fn reauth_failure_propagates_original_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("zt-session", "T0"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "session expired" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    // The re-auth attempt itself 401s (bad credentials) → reauthenticate fails.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "cert"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "INVALID_AUTH", "message": "cert rejected" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let err = client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect_err("re-auth failure → original 401");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 401, .. }),
        "the ORIGINAL create-session 401 propagates (not the AuthHttp): {err:?}"
    );
    assert_eq!(
        client.token().as_deref(),
        Some("T0"),
        "failed re-auth left the token"
    );
}

/// RE-AUTH OK, RETRY STILL 401 → PROPAGATE: `/sessions` 401s for ANY token; `/authenticate`
/// succeeds once (T1). `with_reauth_retry` re-auths then retries exactly ONCE; the retry still
/// 401s → propagate. `/sessions` is hit twice, `/authenticate` exactly once (retry-once, not a
/// loop), and the token still rotated to T1.
#[tokio::test]
async fn reauth_then_retry_still_401_propagates() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "still expired" }
        })))
        .expect(2) // op(T0) + retry op(T1) — retry-ONCE, not a loop
        .mount(&server)
        .await;
    mount_cert_reauth(&server, "T1", 1).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let err = client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect_err("a persistent 401 after re-auth propagates");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 401, .. }),
        "got {err:?}"
    );
    assert_eq!(
        client.token().as_deref(),
        Some("T1"),
        "re-auth still rotated the token"
    );
}

/// DEDUP (mandatory): N concurrent `create_session`, all 401 on the same stale token T0, must
/// collapse to EXACTLY ONE `POST /authenticate` (`.expect(1)`) — the riskiest correctness point.
/// The `reauth_lock` + token re-check serialize the burst: the first re-auths (T0→T1), the rest
/// see the already-rotated token and skip. All N recover with T1.
#[tokio::test]
async fn concurrent_create_session_401s_dedup_to_one_reauth() {
    const N: usize = 8;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("zt-session", "T0"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .mount(&server)
        .await;
    // EXACTLY ONE re-auth despite N concurrent 401s.
    mount_cert_reauth(&server, "T1", 1).await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .and(header("zt-session", "T1"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    // N create_session futures driven CONCURRENTLY (join_all polls them all on one task; each
    // fires its `POST /sessions` so all N 401s are in flight before any re-auth completes, which
    // is what makes them contend on `reauth_lock`). `join_all` (not `tokio::spawn`) avoids the
    // `Send`-not-general-enough limit on async-closure futures; the dedup is exercised either way.
    let futs = (0..N).map(|_| client.create_session("svc-1", SessionType::Dial));
    let results = futures_util::future::join_all(futs).await;
    for r in results {
        let session = r.expect("each concurrent create recovers");
        assert_eq!(session.token, "jwt-1");
    }
    assert_eq!(
        client.token().as_deref(),
        Some("T1"),
        "all converge on the one fresh token"
    );
    // `/authenticate` `.expect(1)` is verified on `server` drop: the burst deduped to ONE re-auth.
}
