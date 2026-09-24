//! Tests del brazo PURGE del tick (4a, DV-4a-1..5): el único cuadrante que purga (legacy+404
//! durable), todos los vecinos que NO purgan, y la guarda de identidad de la eviction.
//! (F6 tramo 8: movidos verbatim del monolito de `edge/session_refresh`.)

use super::*;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing_test::traced_test;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::edge::model::SessionDetail;

use super::testsupport::{
    cached_ers, cached_id, detail_body, edge_routers_body, jwt_session, legacy_token, oidc_token,
    seed,
};

/// A `GET /sessions/{id}` 200 body with an EXPLICIT `token` — the controller's detail echoes the
/// STORED token, which in `ziti` v2 is the **cuid**, not the JWT (`session_api_model.go:58-59`,
/// `:128`). Adopting it would poison the cache (DV-4a-2); T4 pins that it is discarded.
fn detail_body_with_token(id: &str, service_id: &str, token: &str, er_name: &str) -> String {
    format!(
        r#"{{"data":{{"id":"{id}","token":"{token}","serviceId":"{service_id}","type":"Dial","edgeRouters":[{{"name":"{er_name}","supportedProtocols":{{"tls":"tls://router:443"}}}}]}},"meta":{{}}}}"#
    )
}

/// The cached session's session TOKEN under `service_id` (`None` if the key is absent). The
/// discriminant of DV-4a-2 (T4): the durable probe must NEVER adopt the detail body's `token`.
fn cached_token(
    dial: &Arc<Mutex<HashMap<String, SessionDetail>>>,
    service_id: &str,
) -> Option<String> {
    dial.lock()
        .unwrap()
        .get(service_id)
        .map(|s| s.token.clone())
}

// ───────── 4a: the eviction arm PURGES (DV-4a-1..5, spec 2026-07-11-4a-purge-…) ─────────
// SUPERSEDES `session_tick_keeps_dead_session_inert_eviction` (TB2), whose assert — "the dead
// session STAYS cached" — is exactly the contract 4a INVERTS (DV-A1 → DV-4a-1).
//
// The purge fires in ONE quadrant only: (legacy api-session, durable 404). T1 is that quadrant; T2
// pins the probe that reaches it; T5/T5b/T6/T6b pin every neighbouring cell as a NON-purge.

/// **T1** (G1/G7, the acceptance of 4a — and the ANTI-INERTIA control of the purge arm): a tick PURGES
/// a session the controller deleted, and it purges it under the **SNAPSHOT'S KEY** (`svcB`), never
/// under the bare `session.id` (the upstream key bug, `ziti.go:841`+`:854` vs the `serviceId:type`
/// keying at `:2121`). Legacy api-session ⇒ the session is DURABLE (`session_router.go:220-226`) ⇒
/// `GET /sessions/B-id` 404s ⇒ **proven dead**.
///
/// This test (with T8 in `client/tests_sessions_probe.rs`, the gate's own unit test) is what would go RED if the arm were
/// left INERT — **T2 would not**: T2 pins the DISCRIMINANT (which endpoint is probed), and an inert
/// purge arm probes exactly the same endpoint. Do not attribute the anti-inertia control to T2.
///
/// RED under: (a) leaving the arm inert → `svcB` survives the tick; (b) `remove(&session.id)` (the
/// upstream bug ported literally) → it deletes the key `"B-id"`, `svcB` survives; (c) reverting the
/// discriminant to the session-token prefix (`ziti.go:2106`) → the probe goes to the stateless route
/// and the DURABLE mock's `.expect(1)` fails. ⚠ (c) is caught by `.expect(1)` ALONE: `is_proven_dead`
/// keys off the API-TOKEN (still legacy here), so wiremock's default 404 on the unmounted stateless
/// route WOULD still read as proof of death and the cache assert would pass. The mock count is the
/// only detector of (c) — do not remove it.
///
/// The `logs_contain` assert names the SINGULAR event of `evict_dead_dial_session`. It discriminates
/// only because the batch line of step 3 says *"purge arm complete"* and NOT "purged dead dial
/// session(s)": that line fires whenever `to_purge` is non-empty, even if the identity gate skipped
/// every eviction. Keep the two texts disjoint.
#[traced_test]
#[tokio::test]
async fn session_tick_purges_dead_session_by_snapshot_key() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/B-id"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#),
        )
        .expect(1) // the DURABLE endpoint really was probed (else the green would be vacuous)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcB", "B-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &legacy_token("API-TOK"),
        &dial,
    )
    .await;

    assert!(
        !dial.lock().unwrap().contains_key("svcB"),
        "G1: the DEAD session is purged from the cache"
    );
    assert!(
        logs_contain("purged dead dial session"),
        "the purge is observable (and it really ran, not a vacuous green)"
    );
}

/// **T2** (the POSITIVE control of the **DISCRIMINANT**): with a **legacy** api-session the tick MUST
/// probe the DURABLE endpoint `GET /sessions/{id}` and MUST NOT touch the stateless
/// `GET /services/{id}/edge-routers`. Without it, reverting to the oracle's token-prefix test
/// (`ziti.go:2106`) would leave the tick probing the stateless route against the rig (whose session
/// tokens are ALWAYS JWTs) — blind to every deletion — and the rest of the suite would stay green.
///
/// ⚠ It is **NOT** the anti-inertia control (an earlier version of this doc claimed it was): if the
/// purge arm were gutted into a no-op, T2 would still pass — it asserts which ENDPOINT was probed and
/// that the alive session refreshed, never that anything is evicted. The anti-inertia controls are
/// **T1** (`assert!(!contains_key("svcB"))`) and **T8** in `client/tests_sessions_probe.rs` (the gate as a pure function).
///
/// RED under: reverting the discriminant to the session-token prefix (`ziti.go:2106`) → the stateless
/// route is called ⇒ `.expect(0)` fails and `.expect(1)` fails.
#[tokio::test]
async fn session_tick_probes_durable_endpoint_for_legacy_api_session() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // The DURABLE probe: the one the legacy api-session must use.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/D-id"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(detail_body("D-id", "svcD", "er_new")),
        )
        .expect(1)
        .mount(&server)
        .await;
    // The STATELESS probe: it must NOT be reached with a legacy api-session.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svcD/edge-routers"))
        .respond_with(ResponseTemplate::new(200).set_body_string(edge_routers_body("er_wrong")))
        .expect(0)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    // A JWT session token — the ONLY kind `ziti` v2 mints (`session_router.go:191`,`:214`) — under a
    // LEGACY api-session: exactly the rig's combination, the one the oracle's prefix test blinds.
    let dial = seed(&[jwt_session("svcD", "D-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &legacy_token("API-TOK"),
        &dial,
    )
    .await;

    assert_eq!(
        cached_ers(&dial, "svcD"),
        vec!["er_new".to_string()],
        "the alive session was refreshed FROM THE DURABLE endpoint"
    );
}

/// **T3** (DV-4a-3, the regression `client.go:236` feared): with an **OIDC** api-session the session
/// is NOT persisted (`session_router.go:220-226`) ⇒ `GET /sessions/{id}` would 404 for a session that
/// is perfectly ALIVE. So the OIDC branch MUST keep the stateless probe.
///
/// RED under: making the durable probe unconditional → the 404 would be read as proof of death and a
/// LIVE session would be purged (assert + `.expect(0)` both fail).
#[tokio::test]
async fn session_tick_keeps_stateless_probe_for_oidc_api_session() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svcO/edge-routers"))
        .respond_with(ResponseTemplate::new(200).set_body_string(edge_routers_body("er_new")))
        .expect(1)
        .mount(&server)
        .await;
    // The durable endpoint 404s for a LIVE OIDC session (it was never stored) — it must not be probed.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/O-id"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#),
        )
        .expect(0)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcO", "O-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &oidc_token("API-TOK"),
        &dial,
    )
    .await;

    assert_eq!(
        cached_ers(&dial, "svcO"),
        vec!["er_new".to_string()],
        "DV-4a-3: the OIDC branch keeps the STATELESS probe — the live session survives and refreshes"
    );
}

/// **T4** (DV-4a-2, the MINE — a SECURITY pin): the durable probe takes **only the `edgeRouters`**
/// from the detail body. The controller's `token` field is the **cuid** it stored, not the JWT
/// (`session_api_model.go:58-59` → `:128`); adopting the body wholesale would replace the cached JWT
/// with a cuid and every subsequent `Connect` (which carries ONLY the session token) would be rejected.
///
/// RED under: re-caching the body as-is (`Ok(detail)`) → the cached token becomes `"cuid-9999"`.
#[tokio::test]
async fn session_tick_durable_probe_preserves_cached_session_token() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/M-id"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(detail_body_with_token(
                "M-id",
                "svcM",
                "cuid-9999",
                "er_new",
            )),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcM", "M-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &legacy_token("API-TOK"),
        &dial,
    )
    .await;

    assert_eq!(
        cached_token(&dial, "svcM").as_deref(),
        Some("eyJ.dial.jwt"),
        "DV-4a-2: the cached session token (the JWT) is PRESERVED — the body's cuid is discarded"
    );
    assert_eq!(
        cached_ers(&dial, "svcM"),
        vec!["er_new".to_string()],
        "…and the edge-routers ARE refreshed from the body (the probe is not a no-op)"
    );
}

/// **T5** (G5, DV-4a-5): a transient failure is NOT proof of death. Legacy api-session, the durable
/// probe answers **503** → the entry stays cached. RED under evicting on any `Err` (what upstream's
/// `toDelete` does, `ziti.go:839-841` — it can afford it because its arm is inert; ours is not).
#[tokio::test]
async fn session_tick_does_not_purge_on_transient_error() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/T-id"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_string(r#"{"error":{"code":"UNAVAILABLE","message":"try later"}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcT", "T-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &legacy_token("API-TOK"),
        &dial,
    )
    .await;

    assert!(
        dial.lock().unwrap().contains_key("svcT"),
        "G5: a 5xx blip is NOT proof of death — the entry survives"
    );
}

/// **T5b** (§4.2, the stateless 404): with an OIDC api-session a 404 from
/// `GET /services/{id}/edge-routers` is the **SERVICE** not being visible (`service_router.go:441-442`),
/// NOT the session being gone — the svc-poll's `Removed` arm owns that eviction. So it must NOT purge.
/// RED under evicting on any 4xx of the stateless branch.
#[tokio::test]
async fn session_tick_does_not_purge_on_service_not_found_stateless() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svcN/edge-routers"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"service not found"}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcN", "N-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &oidc_token("API-TOK"),
        &dial,
    )
    .await;

    assert!(
        dial.lock().unwrap().contains_key("svcN"),
        "the stateless 404 is the SERVICE's, not the session's — the svc-poll owns that eviction"
    );
}

/// **T6** (the 401 of the STATELESS probe is NOT proof of death — the OIDC régime never purges): a 401
/// from `GET /services/{id}/edge-routers` does **not** single out the session. That route is registered
/// with `permissions.IsAuthenticated()` (`ziti@9bf62f3 controller/internal/routes/service_router.go:77-80`),
/// so `AppEnv.IsAllowed` answers a bare `errorz.NewUnauthorized()` — a **401** — as soon as the
/// **API-SESSION** is invalid, BEFORE the handler runs (`controller/env/appenv.go:991-1002`,
/// `controller/permissions/is_authed.go:27-29`); the handler then re-derives the same 401 from
/// `rc.SecurityCtx.GetApiSession()` (`service_router.go:407-412`) and only afterwards reaches
/// `ValidateServiceAccessToken` (`:428-435`), whose failure is **the same** `errorz.NewUnauthorized()`
/// (`foundation/v2 errorz/helpers.go:91-97`). Nothing in the envelope discriminates the two.
///
/// The damage a "401 ⇒ dead" rule would do: an OIDC access token expires (or the proactive refresh runs
/// late) just before a tick ⇒ the tick probes N **LIVE** sessions ⇒ N × 401 ⇒ the **WHOLE** dial-session
/// cache is purged. The tick reads the token once (`read_token`) and does NOT go through
/// `with_reauth_retry`, so it would neither refresh nor retry: it would purge in silence.
///
/// And it buys NOTHING: the controller does not PERSIST a session minted under an OIDC api-session
/// (`session_router.go:220-226`), so the corpse 4a exists to collect cannot exist in this régime. A
/// REVOKED OIDC session is still caught at the **DIAL** (D3/DV-C3), exactly as before 4a.
///
/// RED under the mutation this test replaced: `Oidc => matches!(err, SessionHttp { status: 401, .. })`
/// in `is_proven_dead` → `svcR` is evicted and the log fires.
#[traced_test]
#[tokio::test]
async fn session_tick_does_not_purge_on_401_stateless_probe() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svcR/edge-routers"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string(r#"{"error":{"code":"UNAUTHORIZED","message":"invalid token"}}"#),
        )
        .expect(1) // the probe really ran (else the green would be vacuous)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcR", "R-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &oidc_token("API-TOK"),
        &dial,
    )
    .await;

    assert!(
        dial.lock().unwrap().contains_key("svcR"),
        "the stateless 401 is ALSO what an expired API-SESSION produces — it does not prove the \
         SESSION dead, and purging on it would wipe the cache of LIVE sessions"
    );
    assert!(
        !logs_contain("purged dead dial session"),
        "nothing was purged (the map assert alone would not catch a purge+re-insert)"
    );
}

/// **T6b** (the 401 of the DURABLE probe is NOT proof of death either — the missing cell of the
/// table): legacy api-session, `GET /sessions/{id}` answers **401**. That is the API-SESSION talking,
/// not the session store: the reauth owns it (and `clear()`s the whole dial-session cache when it
/// re-authenticates). Only the **404** — the store's NotFound — proves the session is gone.
///
/// RED under the mutation `Legacy => matches!(err, SessionHttp { status: 404 | 401, .. })`, which the
/// rest of the suite does NOT catch: `svcQ` would be evicted and the purge log would fire.
#[traced_test]
#[tokio::test]
async fn session_tick_does_not_purge_on_401_durable_probe() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/Q-id"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string(r#"{"error":{"code":"UNAUTHORIZED","message":"invalid token"}}"#),
        )
        .expect(1) // the DURABLE probe really ran (else the green would be vacuous)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcQ", "Q-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &legacy_token("API-TOK"),
        &dial,
    )
    .await;

    assert!(
        dial.lock().unwrap().contains_key("svcQ"),
        "a 401 is the API-SESSION's business (the reauth's), not proof the SESSION is dead"
    );
    assert!(
        !logs_contain("purged dead dial session"),
        "nothing was purged"
    );
}

/// **T7** (G6, DV-4a-4 — the IDENTITY guard of the purge, symmetric to CN-2): while the (404-bound)
/// probe is in flight a third party — DV-C3's retry (`conn/retry.rs`) — REPLACES the entry with a NEWER,
/// LIVE session under the SAME key. A blind `remove(key)` would throw that live session away. The
/// purge gate compares the `session.id` it photographed and SKIPS (`reason="id-mismatch"`).
///
/// The window is forced by the mock's DELAY (300 ms) vs the test's sleep (100 ms), never by the poll
/// order. RED under a blind `remove(key)`: `svcA` disappears (S2, alive, evicted).
#[traced_test]
#[tokio::test]
async fn session_tick_purge_does_not_evict_a_newer_session() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/A1-id"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#)
                .set_delay(Duration::from_millis(300)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcA", "A1-id", "er_old")]);

    let http = reqwest::Client::new();
    let token = legacy_token("API-TOK");
    let dial_task = dial.clone();
    let handle = tokio::spawn(async move {
        session_refresh_tick(&http, &base, &token, &dial_task).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    dial.lock()
        .unwrap()
        .insert("svcA".into(), jwt_session("svcA", "A2-id", "er_s2"));
    handle.await.unwrap();

    assert_eq!(
        cached_id(&dial, "svcA").as_deref(),
        Some("A2-id"),
        "DV-4a-4: the NEWER session survives the purge of the corpse the snapshot photographed"
    );
    assert!(
        logs_contain(r#"reason="id-mismatch""#),
        "the purge gate fired on the IDENTITY comparison (a blind remove(key) would have evicted S2)"
    );
}
