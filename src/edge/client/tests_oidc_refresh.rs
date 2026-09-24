use super::testsupport::*;
use super::*;

/// REACTIVE refresh (OIDC-3, was the §4 blind-spot defer): `with_reauth_retry` with an OIDC token +
/// a 401 op EXTENDS the api-session via the RFC 8693 token-exchange grant (NOT a legacy re-auth),
/// then retries the op ONCE with the rotated Bearer. The discriminator preserved from the OIDC-1
/// defer test: the LEGACY endpoints (`POST /authenticate` AND `GET /current-api-session`) fire ZERO
/// times — only `POST /oidc/oauth/token` fires (once). Mutation: routing OIDC through the legacy
/// arm → `/authenticate` hit (`expect(0)` RED); dropping the OIDC arm entirely → token NOT rotated
/// + endpoint not hit → RED.
#[tokio::test]
async fn oidc_session_reactive_refresh_on_401() {
    let server = MockServer::start().await;
    // The legacy re-auth/refresh endpoints must NEVER fire for an OIDC session.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-HAPPEN"))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session"))
        .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-HAPPEN"))
        .expect(0)
        .mount(&server)
        .await;
    // The OIDC token-exchange fires EXACTLY once and rotates the tokens.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"ey.access2","refresh_token":"ey.refresh2","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with_oidc(&base, "ey.access.jwt", Some("ey.refresh1"));

    // The op 401s on the first call (original token), then succeeds on the retry (rotated token).
    let hits = std::sync::atomic::AtomicU8::new(0);
    let result = client
        .with_reauth_retry(async |_token: AuthToken| {
            let n = hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                Err(EdgeError::ServicesHttp {
                    status: 401,
                    code: "UNAUTHORIZED".into(),
                    message: "expired".into(),
                })
            } else {
                Ok(())
            }
        })
        .await;

    result.expect("the op succeeds after the OIDC refresh + retry");
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the op was retried once after the OIDC refresh"
    );
    // The token rotated to the new access (the Bearer the retry carried), and stayed OIDC.
    assert_eq!(
        client.token().as_deref(),
        Some("ey.access2"),
        "the OIDC token rotated via the token-exchange refresh"
    );
    assert_eq!(
        client.auth_token().map(|t| t.session_type()),
        Some(ApiSessionType::Oidc),
        "the session stayed OIDC (no degrade)"
    );
    // `expect(0)` on the legacy endpoints + `expect(1)` on /oidc/oauth/token verified on drop.
}

/// NO-CLEAR (the load-bearing fidelity assertion, MIRROR-IMAGE of `reauth_clears_dial_session_cache`):
/// an OIDC reactive refresh EXTENDS the SAME api-session (`z_asid` constant across rotations) →
/// the Dial-session cache minted under it SURVIVES. A 401 on `create_session` → the OIDC arm fires
/// the token-exchange refresh (rotates the Bearer) → retry succeeds; the cache populated before is
/// STILL there. Mutation: routing the OIDC 401 through `reauthenticate` (the legacy clear path)
/// instead of `oidc_session_refresh`, or adding a `sessions.Clear()` to the OIDC path → the entry
/// vanishes → RED. The legacy twin (above) clears; this one must NOT.
#[tokio::test]
async fn oidc_reactive_refresh_keeps_dial_cache() {
    let server = MockServer::start().await;
    // First create (Bearer access1) → 401 (api-session "expired").
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("authorization", "Bearer ey.access.jwt"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    // The OIDC token-exchange refresh rotates access1 → access2.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"ey.access2","refresh_token":"ey.refresh2","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    // Retry create (Bearer access2) → 201.
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .and(header("authorization", "Bearer ey.access2"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with_oidc(&base, "ey.access.jwt", Some("ey.refresh1"));

    // Pre-populate the Dial cache (a session minted under the SURVIVING api-session).
    client.cache_dial_session("svc-1", dial_detail("svc-1", "live-dial-token"));
    assert!(
        client.cached_dial_session("svc-1").is_some(),
        "precondition: the cache is populated before the OIDC refresh"
    );

    client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect("recovers after the OIDC token-exchange refresh");

    assert_eq!(
        client.token().as_deref(),
        Some("ey.access2"),
        "the OIDC refresh actually fired (Bearer rotated)"
    );
    assert!(
        client.cached_dial_session("svc-1").is_some(),
        "the OIDC refresh did NOT clear the Dial cache (EXTEND, not re-auth)"
    );
}

/// FIX 2 (TR) — OIDC REFRESH FAILS → ORIGINAL 401 (the OIDC twin of
/// `reauth_failure_propagates_original_401`): a control-plane op 401s, the OIDC token-exchange
/// refresh ALSO fails (the refresh token itself rejected → `/oidc/oauth/token` 400). The reactive
/// arm must propagate the ORIGINAL caller 401 — NOT the `EdgeError::OidcHttp` from the failed
/// exchange — mirroring the oracle returning the original `err` when recovery fails. This routes a
/// non-200 THROUGH `with_reauth_retry`'s OIDC arm for the first time (every other seam-reached mock
/// returns 200). MUTATION CHECK: flip the arm to propagate the OIDC error (`return Err(oidc_err)`
/// instead of `return Err(first)`) → the asserted variant becomes `OidcHttp` → RED; drop the
/// `.is_err()` guard (so the failed refresh is treated as success and the op is retried with the
/// STALE token) → the op 401s twice → still no rotation but the retry hits the op again → the
/// `expect(1)` on the op's 401 (here: the token stays access1) still pins it.
#[tokio::test]
async fn oidc_refresh_failure_propagates_original_401() {
    let server = MockServer::start().await;
    // The control-plane op (create-session) 401s for the original Bearer.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("authorization", "Bearer ey.access.jwt"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    // The OIDC token-exchange ALSO fails (the refresh token rejected) — a full re-login is needed
    // (deferred). The arm must NOT propagate THIS error; it must propagate the original op 401.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid_grant"))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with_oidc(&base, "ey.access.jwt", Some("ey.refresh1"));

    let err = client
        .create_session("svc-1", SessionType::Dial)
        .await
        .expect_err("OIDC refresh failure → original 401");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 401, .. }),
        "the ORIGINAL create-session 401 propagates (NOT the OidcHttp from the failed exchange): {err:?}"
    );
    // The failed refresh left the token untouched (no rotation on a rejected exchange).
    assert_eq!(
        client.token().as_deref(),
        Some("ey.access.jwt"),
        "a failed OIDC refresh left the token (no rotation)"
    );
    // `expect(1)` on /sessions (NOT retried with a stale token) + `expect(1)` on /oidc/oauth/token.
}

/// FIX 2 (TR) — `refresh()` PROPAGATES a token-endpoint failure (does not swallow it to `Ok`): an
/// OIDC `refresh()` whose `/oidc/oauth/token` returns a non-200 must return the error, not `Ok(())`.
/// MUTATION CHECK: swallowing the helper error (e.g. `let _ = self.oidc_session_refresh(...).await;
/// Ok(())`) → this `expect_err` goes RED. The token must stay unrotated.
#[tokio::test]
async fn oidc_refresh_propagates_token_endpoint_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid_grant"))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with_oidc(&base, "ey.access.jwt", Some("ey.refresh1"));

    let err = client
        .refresh()
        .await
        .expect_err("a non-200 token endpoint must propagate, not be swallowed to Ok");
    assert!(
        matches!(err, EdgeError::OidcHttp { status: 400, ref step, .. } if step == "oidc refresh"),
        "got {err:?}"
    );
    assert_eq!(
        client.token().as_deref(),
        Some("ey.access.jwt"),
        "a failed refresh() left the token unrotated"
    );
}

/// A LEGACY session, same shape, DOES attempt the legacy re-auth on a 401 — proves the guard
/// branches on the session TYPE, not a blanket disable.
#[tokio::test]
async fn legacy_session_does_legacy_reauth_on_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/authenticate"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"a","token":"T1","authQueries":[],"identity":{"name":"tester"}},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let hits = std::sync::atomic::AtomicU8::new(0);
    let _ = client
        .with_reauth_retry(async |_token: AuthToken| {
            let n = hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // First call (n==0) 401s (triggers re-auth); the retry succeeds.
            if n == 0 {
                Err::<(), _>(EdgeError::ServicesHttp {
                    status: 401,
                    code: "UNAUTHORIZED".into(),
                    message: "expired".into(),
                })
            } else {
                Ok(())
            }
        })
        .await;
    // The legacy re-auth rotated the token T0 → T1, and the op was retried.
    assert_eq!(
        client.token().as_deref(),
        Some("T1"),
        "legacy re-auth rotated the token"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the op was retried once after the re-auth"
    );
}

/// `refresh()` for OIDC (OIDC-3, spec §5.6, was a defer): the public `refresh(&mut self)` now DOES
/// the RFC 8693 token-exchange refresh (it early-returned `Ok` for OIDC in OIDC-1). It must NOT
/// issue the legacy GET `/current-api-session` and must NOT degrade the token to `AuthToken::Legacy`
/// (which would flip the control-plane header back to `zt-session`). It hits `/oidc/oauth/token`,
/// rotates the stored token, and stays OIDC. Discriminator preserved: the legacy GET fires ZERO
/// times. Mutation: an OIDC `return Ok(())` early-return → `/oidc/oauth/token` not hit + token NOT
/// rotated → RED; routing through the legacy GET path → `/current-api-session` hit + degrade → RED.
#[tokio::test]
async fn oidc_session_refresh_does_token_exchange() {
    let server = MockServer::start().await;
    // The legacy GET-refresh must NEVER fire for an OIDC session.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session"))
        .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-HAPPEN"))
        .expect(0)
        .mount(&server)
        .await;
    // The OIDC token-exchange fires (once) and rotates the tokens.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"ey.access2","refresh_token":"ey.refresh2","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with_oidc(&base, "ey.access.jwt", Some("ey.refresh1"));

    client
        .refresh()
        .await
        .expect("refresh() does the OIDC token-exchange (Ok)");

    // The token ROTATED to the new access (refresh() did the exchange, not a no-op).
    assert_eq!(
        client.token().as_deref(),
        Some("ey.access2"),
        "refresh() rotated the OIDC token via the token-exchange grant"
    );
    // The session is STILL OIDC (the variant did not flip to Legacy).
    assert_eq!(
        client.auth_token().map(|t| t.session_type()),
        Some(ApiSessionType::Oidc),
        "refresh() kept the session OIDC (did not degrade to Legacy)"
    );
    // The rotated refresh token was written back (so the NEXT refresh sends refresh2).
    assert_eq!(
        client
            .auth_token()
            .and_then(|t| t.refresh_token().map(str::to_string)),
        Some("ey.refresh2".to_string()),
        "refresh() wrote back the rotated refresh token"
    );
    // `expect(0)` on /current-api-session + `expect(1)` on /oidc/oauth/token verified on drop.
}

/// SEAM (funnel): `refresh()` — and thus the reactive `with_reauth_retry` OIDC arm, which shares the
/// `oidc_session_refresh` funnel — PUSHES the rotated Bearer to the live edge-router channels
/// registered on the client (the OIDC-2 wiring). A fake channel is registered via
/// `register_live_channel`; after `refresh()` exchanges the token, that channel's router must receive
/// an `UpdateToken` (60803) carrying the ROTATED access (`ey.rotated`). MUTATION: delete the
/// `push_token_to_live_channels` call from `oidc_session_refresh` → the router never sees the 60803
/// → RED.
#[tokio::test]
async fn refresh_pushes_rotated_oidc_token_to_live_channels() {
    use crate::channel::connect::{read_message, write_message};
    use crate::channel::message::{HDR_REPLY_FOR, Message};
    use crate::edge::data::{CT_UPDATE_TOKEN, CT_UPDATE_TOKEN_SUCCESS, EdgeChannel};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"ey.rotated","refresh_token":"ey.refresh2","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with_oidc(&base, "ey.access.jwt", Some("ey.refresh1"));

    // Register a fake live channel whose router records the UpdateToken it receives, then replies
    // UpdateTokenSuccess (correlated by ReplyFor).
    let (cli, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(cli);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    let router_task = tokio::spawn(async move {
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            read_message(&mut router),
        )
        .await
        {
            Ok(Ok(ut)) => {
                let _ = tx.send(Some((ut.content_type, ut.body.clone())));
                let mut ok = Message::new(CT_UPDATE_TOKEN_SUCCESS, vec![]);
                ok.headers
                    .insert(HDR_REPLY_FOR, ut.sequence.to_le_bytes().to_vec());
                let _ = write_message(&mut router, &ok).await;
            }
            _ => {
                let _ = tx.send(None);
            }
        }
    });
    client.register_live_channel(ch.state_weak());

    client
        .refresh()
        .await
        .expect("refresh() does the OIDC token-exchange + push");

    let pushed = rx.await.unwrap();
    assert_eq!(
        pushed,
        Some((CT_UPDATE_TOKEN, b"ey.rotated".to_vec())),
        "refresh() pushed the ROTATED Bearer (UpdateToken 60803) to the registered live channel"
    );
    router_task.abort();
    drop(ch);
}

/// CAPABILITY FAIL-FAST: `authenticate_oidc` against a controller that does NOT advertise
/// `OIDC_AUTH` returns `OidcNotSupported` BEFORE attempting the PKCE flow (the `/version` capability
/// gate, oracle `ControllerSupportsOidc`). A mock serves `/version` with capabilities lacking
/// `OIDC_AUTH`; the early return fires before any OIDC endpoint is hit. Mutation: making
/// `controller_supports_oidc` always-true would let the flow proceed (and fail differently) → this
/// goes RED. Pairs with the OIDC live tests which prove the TRUE branch + the capabilities JSON path.
#[tokio::test]
async fn authenticate_oidc_fails_fast_without_oidc_capability() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            // A valid version body WITHOUT OIDC_AUTH in capabilities.
            r#"{"data":{"version":"v1.0.0","capabilities":["HA_CONTROLLER"]},"meta":{}}"#,
        ))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");

    let err = client
        .authenticate_oidc()
        .await
        .expect_err("authenticate_oidc must fail fast when OIDC_AUTH is not advertised");
    assert!(
        matches!(err, EdgeError::OidcNotSupported),
        "got {err:?}; expected OidcNotSupported"
    );
}

/// The capability gate also fails fast (fail-CLOSED) when `/version` is unreachable / a non-2xx:
/// `controller_supports_oidc` returns false on any error → `OidcNotSupported` (no PKCE attempt).
#[tokio::test]
async fn authenticate_oidc_fails_fast_when_version_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/version"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");

    let err = client
        .authenticate_oidc()
        .await
        .expect_err("authenticate_oidc fails fast (closed) on a /version error");
    assert!(matches!(err, EdgeError::OidcNotSupported), "got {err:?}");
}
