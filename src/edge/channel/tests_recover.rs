//! Tests del guard 4b (`recover_empty_edge_routers`): refresh de una sesión sin edge-routers y
//! la evicción gateada opaque&&404 (DV-4b-4).
//! (F6 tramo 6: movidos verbatim del monolito de `edge/channel`.)

use std::collections::BTreeMap;

use crate::edge::client::EdgeClient;
use crate::edge::error::EdgeError;
use crate::edge::model::SessionEdgeRouter;

use super::testsupport::{detail_of, detail_with, er};

// ----- slice 4b: the oracle's EMPTY-EDGE-ROUTERS guard (`getEdgeRouterConn`, ziti.go:1667-1683) --
//
// The observation seam (offline, no live router): once the guard refreshes, the function DIALS the
// refreshed routers for real. A refreshed router whose `tls` address is UNPARSEABLE
// (`tls:refreshed-er` — no port) fails in `parse_tls_address`, which NAMES it, so the surfaced error
// CONTAINS `refreshed-er`. That is the discriminant between "refreshed AND used the fresh
// edge-routers" and "never refreshed" (`NoTlsEdgeRouter`) — and it also catches the subtle no-op of
// refreshing and then DISCARDING the result. It requires a client whose `channel_client_config()`
// builds offline (`for_test_with_cert_identity`), since that runs BEFORE the fan-out.
// Everything is asserted on STATE (the dial-session cache, the REST requests received) and on the
// ERROR — never on logs (a `#[tokio::test]` installs no `tracing` subscriber).

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A `wss`-only edge router: it makes `edge_routers` NON-empty while leaving `tls_addrs` empty.
fn wss_er(name: &str) -> SessionEdgeRouter {
    let mut supported_protocols = BTreeMap::new();
    supported_protocols.insert("wss".to_string(), "wss://r1:443".to_string());
    SessionEdgeRouter {
        name: name.to_string(),
        hostname: String::new(),
        supported_protocols,
    }
}

/// `GET /sessions/{id}` 200 body: the session is ALIVE and carries ONE (unparseable) refreshed router.
fn refreshed_session_body() -> &'static str {
    r#"{"data":{"id":"s","token":"jwt-tok","serviceId":"svc","type":"Dial","edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls:refreshed-er"}}]},"meta":{}}"#
}

/// T1 (★ POSITIVE control, anti-no-op): a cached session with ZERO edge-routers but ALIVE in the
/// controller must be REFRESHED and the FRESH routers DIALED — the oracle's `refreshSession` +
/// `session = refreshedSession` (`ziti.go:1667-1668`, `:1681`). Decisive assert: the error NAMES the
/// refreshed router (`refreshed-er`), proving both that the refresh ran and that its result was USED.
/// RED under (a) today's give-up (`NoTlsEdgeRouter`, no refresh) and (b) a guard that refreshes but
/// keeps dialing the ORIGINAL (empty) `detail`.
#[tokio::test]
async fn empty_edge_routers_refreshes_and_dials_the_refreshed_routers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/s"))
        .respond_with(ResponseTemplate::new(200).set_body_string(refreshed_session_body()))
        // `.expect(1)`: wiremock answers 404 to any UNMATCHED request, so without this a probe sent to
        // the WRONG url would still look like a refresh. Verified on `MockServer` drop.
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with_cert_identity(&base, "API-TOK");

    let err = client
        .open_or_reuse_pooled_channel(&detail_with(vec![]))
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        !matches!(err, EdgeError::NoTlsEdgeRouter),
        "an alive session with 0 edge-routers must be REFRESHED, not given up on: {err:?}"
    );
    assert!(
        err.to_string().contains("refreshed-er"),
        "the dial must use the REFRESHED edge-routers (the error names the refreshed router): {err}"
    );
}

/// T2: 0 edge-routers + an OPAQUE-token session whose refresh (`GET /sessions/{id}`) 404s ⇒ the dial
/// session is EVICTED (the oracle's `sessions.Remove("{serviceId}:{type}")`, `ziti.go:1671-1672`) and
/// the refresh's error is propagated (the oracle gives up right there, `:1675`). RED if the eviction is
/// not called. Pairs with T8 (JWT + 404 ⇒ NO eviction): together they pin the trigger to
/// (404 AND opaque branch), which is exactly what the oracle's `errors.As` can reach (DV-4b-4).
#[tokio::test]
async fn empty_edge_routers_evicts_the_dial_session_on_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/s"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#),
        )
        // LOAD-BEARING `.expect(1)`: wiremock's DEFAULT answer to an unmatched request is ALSO a 404,
        // so without it this test would stay green even if the probe hit the wrong url (C4).
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc", detail_with(vec![]));

    let err = client
        .open_or_reuse_pooled_channel(&detail_with(vec![]))
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 404, .. }),
        "the refresh's own error is propagated, not NoTlsEdgeRouter: {err:?}"
    );
    assert!(
        client.cached_dial_session("svc").is_none(),
        "a session the controller says is GONE (404) is evicted from the dial cache"
    );
}

/// T3 (narrowness): 0 edge-routers + a NON-404 refresh error (503) ⇒ NO eviction. The oracle only
/// evicts on `errors.As(&rest_session.DetailSessionNotFound{})` (`ziti.go:1669-1670`): a transport
/// blip or a 5xx is NOT proof the session is dead. RED if the eviction fires on any `Err`.
#[tokio::test]
async fn empty_edge_routers_does_not_evict_on_non_404_refresh_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/s"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_string(r#"{"error":{"code":"UNAVAILABLE","message":"controller busy"}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc", detail_with(vec![]));

    let err = client
        .open_or_reuse_pooled_channel(&detail_with(vec![]))
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 503, .. }),
        "the refresh's error is propagated: {err:?}"
    );
    assert!(
        client.cached_dial_session("svc").is_some(),
        "a 503 is NOT proof of death: the cached session must SURVIVE (oracle narrowness)"
    );
}

/// T4: 0 edge-routers and the refresh yields NO new routers either ⇒ give up with `NoTlsEdgeRouter`
/// and do NOT evict — the session is ALIVE, there is no proof of death (the oracle returns an error
/// at `:1677-1678` WITHOUT touching the cache). RED if the "alive but router-less" arm evicts.
#[tokio::test]
async fn refresh_yielding_no_edge_routers_is_no_tls_edge_router_and_does_not_evict() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/s"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"id":"s","token":"jwt-tok","serviceId":"svc","type":"Dial","edgeRouters":[]},"meta":{}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc", detail_with(vec![]));

    let err = client
        .open_or_reuse_pooled_channel(&detail_with(vec![]))
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, EdgeError::NoTlsEdgeRouter),
        "refresh yielded no edge routers ⇒ give up: {err:?}"
    );
    assert!(
        client.cached_dial_session("svc").is_some(),
        "an ALIVE session is never evicted (no proof of death)"
    );
}

/// T5 (★ pins the CALL SITE, not the helper): the guard fires on the RAW `edge_routers` list
/// (`len(session.EdgeRouters) == 0`, `ziti.go:1667`), NOT on the protocol-FILTERED `tls_addrs`. A
/// session with a `wss`-only router has a NON-empty `edge_routers` and an EMPTY `tls_addrs`: the
/// oracle does NOT refresh it. Decisive assert: ZERO REST requests reach the controller (a wiremock
/// with no mounts at all). RED if the guard is written over `tls_addrs(detail).is_empty()`.
#[tokio::test]
async fn non_empty_edge_routers_never_refreshes() {
    let server = MockServer::start().await; // NO mocks mounted: any request would 404 (and be recorded)
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let err = client
        .open_or_reuse_pooled_channel(&detail_with(vec![wss_er("r1")]))
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, EdgeError::NoTlsEdgeRouter),
        "a router-bearing session with no usable tls protocol still fails fast: {err:?}"
    );
    assert!(
        server
            .received_requests()
            .await
            .expect("wiremock records requests")
            .is_empty(),
        "a session WITH edge-routers must never trigger a refresh (the guard is on the RAW list)"
    );
}

/// T6: the guard's refresh goes through `refresh_session` — i.e. through the WRITE GATE
/// (`recache_refreshed_dial_session`, opción 7) — so it cannot CLOBBER a NEWER session that landed
/// under the same service key while we were probing (CN-2). Seed the cache with `s-new`, call the
/// guard with the stale `s-old`: the cache must still hold `s-new` afterwards. RED under a
/// `refresh_session_probe` + blind `cache_dial_session` implementation.
#[tokio::test]
async fn empty_edge_routers_refresh_does_not_clobber_a_newer_cached_session() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/s-old"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"id":"s-old","token":"jwt-tok","serviceId":"svc","type":"Dial","edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls:refreshed-er"}}]},"meta":{}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with_cert_identity(&base, "API-TOK");
    // A CONCURRENT connect already replaced the entry with a freshly minted session.
    client.cache_dial_session("svc", detail_of("s-new", "jwt-tok", vec![er("r1", None)]));

    let _ = client
        .open_or_reuse_pooled_channel(&detail_of("s-old", "jwt-tok", vec![]))
        .await
        .map(|_| ());
    assert_eq!(
        client
            .cached_dial_session("svc")
            .expect("the newer session survives")
            .id,
        "s-new",
        "the guard's refresh must not overwrite a NEWER cached session with the stale one (CN-2)"
    );
}

/// T7: the guard also recovers on the JWT branch of the probe (`refresh_session_probe` splits on the
/// token prefix, `edge/client/sessions_probe.rs`): a JWT session with 0 edge-routers refreshes via
/// `GET /services/{id}/edge-routers` and dials the routers it returns. Same decisive assert as T1
/// (the error NAMES the refreshed router). RED under a guard that only covers the opaque branch.
#[tokio::test]
async fn empty_edge_routers_jwt_branch_refreshes_via_service_edge_routers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc/edge-routers"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls:refreshed-er"}}]},"meta":{}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with_cert_identity(&base, "API-TOK");

    let err = client
        .open_or_reuse_pooled_channel(&detail_of("s", "eyJ.dial.jwt", vec![]))
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        err.to_string().contains("refreshed-er"),
        "the JWT branch must refresh and dial the fresh edge-routers too: {err}"
    );
}

/// T8 (★ the OTHER half of the discriminating pair with T2 — DV-4b-4): 0 edge-routers + a **JWT**
/// session whose probe (`GET /services/{id}/edge-routers`) **404s** ⇒ the error propagates but the
/// cached session SURVIVES. The oracle CANNOT evict here: its JWT branch is `GetSessionFromJwt` →
/// `ListServiceEdgeRouters` (`ziti/client.go:250-268`), so a 404 is a `ListServiceEdgeRoutersNotFound`
/// ("service not found / not visible"), which `errors.As(err, &rest_session.DetailSessionNotFound{})`
/// (`ziti.go:1669-1670`) can never match — only the OPAQUE branch's `DetailSession`
/// (`ziti/client.go:237-248`) yields that type. MUTATION THAT PUTS THIS RED: drop the branch guard in
/// `recover_empty_edge_routers` and evict on the bare `matches!(e, SessionHttp { status: 404, .. })`.
/// T2 (opaque + 404 ⇒ EVICTS) is the mutation's other half: only the pair pins the trigger.
#[tokio::test]
async fn empty_edge_routers_jwt_branch_404_does_not_evict_the_dial_session() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc/edge-routers"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"service not found"}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    let jwt_session = detail_of("s", "eyJ.dial.jwt", vec![]);
    client.cache_dial_session("svc", jwt_session.clone());

    let err = client
        .open_or_reuse_pooled_channel(&jwt_session)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 404, .. }),
        "the probe's error is propagated: {err:?}"
    );
    assert!(
        client.cached_dial_session("svc").is_some(),
        "a 404 from the JWT probe means 'service not found', NOT 'session dead': the oracle never \
         evicts on this branch, so neither do we (DV-4b-4)"
    );
}
