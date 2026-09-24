//! Tests del núcleo del tick (TB1: re-cache del vivo · TB3: el guard nunca cruza el await).
//! (F6 tramo 8: movidos verbatim del monolito de `edge/session_refresh`; span NO contiguo declarado en el
//! spec §0.3 — en el monolito TB1 y TB3 estaban separados por la sección purge.)

use super::*;

use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::testsupport::{cached_ers, detail_body, legacy_token, opaque_session, seed};

// ───────────────────────── TB1/TB2: one tick ─────────────────────────

/// TB1: a tick RE-CACHES an ALIVE session with its refreshed edge-routers. Seed A (`[er_old]`);
/// `GET /sessions/{A.id}` → 200 with `[er_new]`; after ONE tick the cached A carries `[er_new]`.
/// RED without the re-cache in the tick core (M1).
#[tokio::test]
async fn session_tick_recaches_alive_with_refreshed_edge_routers() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/A-id"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(detail_body("A-id", "svcA", "er_new")),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[opaque_session("svcA", "A-id", "er_old")]);

    session_refresh_tick(
        &reqwest::Client::new(),
        &base,
        &legacy_token("API-TOK"),
        &dial,
    )
    .await;

    assert_eq!(
        cached_ers(&dial, "svcA"),
        vec!["er_new".to_string()],
        "the alive session was re-cached with refreshed edge-routers"
    );
}

/// TB3: the `std::sync::Mutex` guard NEVER crosses the probe `.await`. The tick is spawned (which
/// FORCES the future to be `Send` — a held `!Send` `MutexGuard` across the await would not compile,
/// the strongest half of M6); with a DELAYED probe in flight, `try_lock` on `dial_sessions` succeeds
/// (the guard is released during the probe). RED if the probe is moved inside the guard (clippy
/// `await_holding_lock` + the `try_lock` would return `WouldBlock`).
#[tokio::test]
async fn session_tick_lock_never_crosses_await() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // Delay the probe response so the probe await is measurably in flight.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/S-id"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(detail_body("S-id", "svcS", "er_new"))
                .set_delay(Duration::from_millis(400)),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[opaque_session("svcS", "S-id", "er_old")]);

    let http = reqwest::Client::new();
    let token = legacy_token("API-TOK");
    let dial_task = dial.clone();
    // Spawn REQUIRES `Send`: a guard held across the probe await would fail to compile here.
    let handle = tokio::spawn(async move {
        session_refresh_tick(&http, &base, &token, &dial_task).await;
    });

    // Let the tick take its snapshot and enter the (400ms-delayed) probe await.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The lock is FREE during the probe → `try_lock` succeeds (the guard is not held across await).
    assert!(
        dial.try_lock().is_ok(),
        "dial_sessions lock is free while the probe is in flight (guard not held across await)"
    );

    handle.await.unwrap();
}
