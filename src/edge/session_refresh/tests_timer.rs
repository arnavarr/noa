//! Test del loop del timer (TB4: el timer conduce el tick sobre una ventana — ≥1 tick, sin
//! hot-loop).
//! (F6 tramo 8: movidos verbatim del monolito de `edge/session_refresh`.)

use super::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::testsupport::{detail_body, legacy_token, opaque_session, seed};

// ───────────────────────── TB4: the timer over a window ─────────────────────────

/// A `/sessions/{id}` responder that counts hits and serves one alive session.
struct CountingDetail(Arc<AtomicUsize>);
impl Respond for CountingDetail {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        self.0.fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_string(detail_body("W-id", "svcW", "er_x"))
    }
}

/// TB4: the spawned timer DRIVES the session-refresh tick over a window — it probes the cached
/// session repeatedly (≥1) but is NOT a hot-loop (bounded by the ~8ms period). Mirror of
/// `timer_drives_gated_refresh_over_a_window`. RED: dropping `sleep(next)` → the probe count
/// explodes (M5); never ticking → 0 probes.
#[tokio::test]
async fn timer_drives_session_refresh_over_a_window() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    let probes = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/W-id"))
        .respond_with(CountingDetail(probes.clone()))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let dial = seed(&[opaque_session("svcW", "W-id", "er_old")]);

    let handle = tokio::spawn(run_session_refreshes(
        reqwest::Client::new(),
        base,
        legacy_token("API-TOK"),
        dial,
        SessionRefreshIntervals {
            interval: Duration::from_millis(8),
            jitter: 0.0,
        },
    ));
    tokio::time::sleep(Duration::from_millis(60)).await;
    handle.abort();

    let n = probes.load(Ordering::SeqCst);
    assert!(n >= 1, "the timer ran the session tick at least once");
    assert!(
        n < 60,
        "bounded by the ~8ms period, not a hot-loop: {n} probes"
    );
}
