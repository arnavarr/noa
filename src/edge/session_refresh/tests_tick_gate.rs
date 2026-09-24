//! Tests del WRITE GATE en el tick (CN-1/CN-2): no-resurrección (ventana estrecha y ancha),
//! no-clobber, y el `serviceId` mentiroso del body que nunca llega al caché.
//! (F6 tramo 8: movidos verbatim del monolito de `edge/session_refresh`.)

use super::*;

use std::time::Duration;

// The write-gate tests assert the gate FIRED (its skip `reason`), not just the final map state — a
// bare `#[tokio::test]` installs NO tracing subscriber and raw stdout carries ANSI, so `logs_contain`
// via `#[traced_test]` is the only sound way to read those events.
use tracing_test::traced_test;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::testsupport::{
    cached_ers, cached_id, detail_body, edge_routers_body, jwt_session, legacy_token, oidc_token,
    opaque_session, seed,
};

// ────────── T1/T1b/T2: the WRITE GATE (CN-1/CN-2, spec 2026-07-11 §5.1) ──────────

/// T1 (CN-1, no-resurrection): the tick's re-cache must NOT resurrect an entry that a third party
/// EVICTED while the probe was in flight. Seed `svcA → S(A-id)`; the probe answers 200 alive after
/// 300 ms; at 100 ms the test removes `svcA` (exactly what DV-C3's `evict()` does —
/// `EdgeClient::evict_dial_session`, `client/sessions.rs:265` — via the closure at `conn/flow.rs:177`). After the
/// tick the key must STILL be absent.
/// RED under the blind insert (`insert(refreshed.service_id, refreshed)`): the corpse reappears.
///
/// ⚠ **Anti-vacuity armour.** The final-state assert ALONE could pass for the wrong reason: the
/// ordering is enforced only by the clock (300 ms delay vs 100 ms sleep), so under load a late
/// intruder would `remove` whatever a BLIND insert had just re-created and the map would end up empty
/// anyway — green without ever exercising the gate. And a broken mock route (404) would make the probe
/// fail, skip the write entirely, and leave the assert green too. Hence `.expect(1)` (the probe really
/// ran) plus a `logs_contain` proving the gate REACHED the write and SKIPPED it with `reason=absent`.
/// `#[traced_test]` is mandatory for that: a bare `#[tokio::test]` installs NO subscriber, and raw
/// stdout carries ANSI.
#[traced_test]
#[tokio::test]
async fn session_tick_does_not_resurrect_evicted_session() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/A-id"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(detail_body("A-id", "svcA", "er_new"))
                .set_delay(Duration::from_millis(300)),
        )
        .expect(1) // the probe MUST have run, else the skip below would be vacuous
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[opaque_session("svcA", "A-id", "er_old")]);

    let http = reqwest::Client::new();
    let token = legacy_token("API-TOK");
    let dial_task = dial.clone();
    let handle = tokio::spawn(async move {
        session_refresh_tick(&http, &base, &token, &dial_task).await;
    });

    // The interleaving is forced by the wiremock DELAY (300 ms) > this sleep (100 ms), never by the
    // poll order (`join!`/`select!` rotate it): the evict lands strictly inside [snapshot, write].
    tokio::time::sleep(Duration::from_millis(100)).await;
    dial.lock().unwrap().remove("svcA");
    handle.await.unwrap();

    assert!(
        !dial.lock().unwrap().contains_key("svcA"),
        "CN-1: the evicted corpse is NOT resurrected — the refresh write found the key absent and skipped"
    );
    assert!(
        logs_contain("refresh re-cache skipped"),
        "the GATE fired: the write was REACHED and skipped (not a vacuous green)"
    );
    assert!(
        logs_contain(r#"reason="absent""#),
        "CN-1's discriminant: the key was ABSENT at write time"
    );
}

/// T1b (CN-1, the WIDE window): same as T1 but on the **STATELESS** probe branch — which, since 4a,
/// is selected by an **OIDC api-session** (DV-4a-3), not by the session token's prefix. That probe
/// hits `ListServiceEdgeRouters`, whose controller handler never reads the session store (evidence in
/// the module docs), so it answers `Ok` for a session the controller already DELETED — the damaging
/// window is the WHOLE `[snapshot, write]` RTT (§1.3). RED under the blind insert; also RED if the
/// guard were applied only to the durable branch (the gate is on the WRITE, not the probe). Same
/// anti-vacuity armour as T1 (`.expect(1)` + `logs_contain`).
///
/// ⚠ 4a MODIFIED this test's api-token (legacy → OIDC): the probe branch is no longer chosen by the
/// session token, so a legacy api-token would now take the DURABLE branch and this fixture would stop
/// exercising the stateless window it exists to pin.
#[traced_test]
#[tokio::test]
async fn session_tick_does_not_resurrect_evicted_session_jwt_probe() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svcJ/edge-routers"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(edge_routers_body("er_new"))
                .set_delay(Duration::from_millis(300)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[jwt_session("svcJ", "J-id", "er_old")]);

    let http = reqwest::Client::new();
    let token = oidc_token("API-TOK");
    let dial_task = dial.clone();
    let handle = tokio::spawn(async move {
        session_refresh_tick(&http, &base, &token, &dial_task).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    dial.lock().unwrap().remove("svcJ");
    handle.await.unwrap();

    assert!(
        !dial.lock().unwrap().contains_key("svcJ"),
        "CN-1: a stateless JWT probe says `Ok` for a DELETED session — only the write gate stops the resurrection"
    );
    assert!(
        logs_contain(r#"reason="absent""#),
        "the GATE fired on the ABSENT key — the probe DID answer Ok for a deleted session"
    );
}

/// T2 (CN-2, no-clobber): the tick's re-cache must NOT overwrite a session that is NEWER than the one
/// in its snapshot. Seed `svcA → S1(A-id)`; the probe of `A-id` answers 200 alive after 300 ms; at
/// 100 ms the test REPLACES the entry with a fresh `S2(A2-id)` (what the dial's retry does: evict +
/// `get_or_create` under the same key, `conn/retry.rs:138-139`). After the tick `svcA` must still be S2.
/// RED under the blind insert (S1' wins) **and** RED under a WEAK guard (write-if-key-exists, no id
/// comparison): the key IS occupied, so the weak guard would clobber S2 with the dead S1'. This is
/// the test that FORCES the identity comparison (§4.2).
///
/// ⚠ Anti-vacuity armour as in T1: a late intruder would overwrite a blind write anyway ⇒ `.expect(1)`
/// (the probe ran) + `logs_contain` proving the gate skipped on `reason=id-mismatch` (the IDENTITY
/// comparison, not mere existence).
#[traced_test]
#[tokio::test]
async fn session_tick_does_not_clobber_newer_session() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/A-id"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(detail_body("A-id", "svcA", "er_new"))
                .set_delay(Duration::from_millis(300)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[opaque_session("svcA", "A-id", "er_old")]);

    let http = reqwest::Client::new();
    let token = legacy_token("API-TOK");
    let dial_task = dial.clone();
    let handle = tokio::spawn(async move {
        session_refresh_tick(&http, &base, &token, &dial_task).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    dial.lock()
        .unwrap()
        .insert("svcA".into(), opaque_session("svcA", "A2-id", "er_s2"));
    handle.await.unwrap();

    assert!(
        logs_contain(r#"reason="id-mismatch""#),
        "the GATE fired on the IDENTITY comparison (an existence-only guard would have written)"
    );
    assert_eq!(
        cached_id(&dial, "svcA").as_deref(),
        Some("A2-id"),
        "CN-2: the NEWER session survives — the refresh write found a different session.id and skipped"
    );
    assert_eq!(
        cached_ers(&dial, "svcA"),
        vec!["er_s2".to_string()],
        "CN-2: S2's edge-routers are intact (S1' did not clobber them)"
    );
}

/// T3 (RE-DERIVED by 4a — read the ⚠ before trusting the name): **a LYING `serviceId` in the
/// controller's 200 body never reaches the cache, in any field or key.** The mock answers, for the
/// session cached under `svcA`, a body claiming `serviceId: "svcEVIL"`. Three asserts: the refresh
/// lands under `svcA` with the fresh edge-routers; the cached value's own `service_id` is STILL
/// `svcA`; `svcEVIL` exists nowhere.
///
/// ⚠ **What it does NOT pin any more.** Its original job was the CN-3 discriminant at the TICK's CALL
/// SITE — that swapping `recache_refreshed_dial_session(dial_sessions, key, …)` for
/// `&refreshed.service_id` goes RED. Since 4a that mutation is **UNOBSERVABLE, and not by accident**:
/// BOTH branches of the tick's probe rebuild the session as `SessionDetail { edge_routers: …,
/// ..session.clone() }` (`refresh_session_probe_durable`, DV-4a-2), so `refreshed.service_id ≡ key`
/// **by construction** and the two keyings are the same expression. It is a real strengthening (the
/// body's fields cannot reach the cache at all), not a hole — and the second assert below is what pins
/// it: it goes **RED** under `Ok(detail)` (adopting the body wholesale in the durable branch), the very
/// mutation DV-4a-2 forbids. T4 pins the same mine on the `token`; this one pins it on `service_id`.
///
/// Where the CN-3 property still lives: **T7(d) in `client/tests_sessions_refresh.rs`** (`recache_refreshed_dial_session`'s own
/// unit test — the GATE keys by the key it is handed, with a value whose `service_id` differs) and the
/// DIAL path's W2 call site, whose probe (`refresh_session_probe`) still has an opaque branch that
/// adopts the body.
///
/// Even if a body's lie ever did reach the cache, the worst case is a **misroute to a service the
/// controller already authorised for this identity** — the wire `Connect` carries only the token and the
/// controller derives the service from the session (`create_circuit.go:88-91` → `common.go:418`) —
/// **never an over-permit**.
#[tokio::test]
async fn session_tick_never_adopts_the_bodys_service_id() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/A-id"))
        .respond_with(
            // The body's `serviceId` DISAGREES with the key the entry is cached under.
            ResponseTemplate::new(200).set_body_string(detail_body("A-id", "svcEVIL", "er_new")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[opaque_session("svcA", "A-id", "er_old")]);

    let http = reqwest::Client::new();
    let token = legacy_token("API-TOK");
    session_refresh_tick(&http, &base, &token, &dial).await;

    assert_eq!(
        cached_ers(&dial, "svcA"),
        vec!["er_new".to_string()],
        "the refresh landed on the entry the snapshot photographed, with the fresh edge-routers"
    );
    // THE discriminant (DV-4a-2 on `service_id`): the body's field was DISCARDED, not adopted.
    assert_eq!(
        dial.lock()
            .unwrap()
            .get("svcA")
            .map(|s| s.service_id.clone()),
        Some("svcA".to_string()),
        "DV-4a-2: the durable probe rebuilds from the SNAPSHOT (`..session.clone()`) — the body's \
         `serviceId` is discarded. RED under `Ok(detail)` (adopting the body wholesale)"
    );
    assert!(
        !dial.lock().unwrap().contains_key("svcEVIL"),
        "no phantom key — holds under ANY keying, because a write gate never inserts"
    );
}
