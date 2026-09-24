//! Tests de `flow` (F6 tramo 5: movidos verbatim del monolito de `edge/conn`).

use super::*;
use crate::channel::connect::{read_message, write_message};
use crate::channel::message::Message;
use crate::edge::client::EdgeClient;
use crate::edge::data::EdgeChannel;
use crate::edge::dial::{CT_STATE_CLOSED, CT_STATE_CONNECTED, HDR_CIRCUIT_ID, HDR_CONN_ID};
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing_test::traced_test;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A connect-timeout generous enough that the existing fast-router e2e tests never trip it (they
/// resolve + dial in microseconds). Only the dedicated timeout test uses a tiny budget.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test]
async fn connect_without_auth_is_not_authenticated() {
    let client = EdgeClient::from_identity_for_test();
    let err = client.connect("testsvc").await.unwrap_err();
    assert!(matches!(err, EdgeError::NotAuthenticated));
}

// ----- connect_inner end-to-end: the deliverable, over wiremock + duplex routers -----

/// What a fake router replies to the Connect: either StateConnected (with a circuit id) or
/// StateClosed (a dial rejection with a reason).
enum RouterReply {
    Connected(&'static [u8]),
    Closed(&'static [u8]),
}

fn spawn_fake_router(mut router: tokio::io::DuplexStream, reply: RouterReply) {
    tokio::spawn(async move {
        let Ok(connect) = read_message(&mut router).await else {
            return;
        };
        let conn_id = connect
            .headers
            .get(&HDR_CONN_ID)
            .cloned()
            .unwrap_or_default();
        let mut msg = match reply {
            RouterReply::Connected(circuit) => {
                let mut m = Message::new(CT_STATE_CONNECTED, vec![]);
                m.headers.insert(HDR_CIRCUIT_ID, circuit.to_vec());
                m
            }
            RouterReply::Closed(reason) => Message::new(CT_STATE_CLOSED, reason.to_vec()),
        };
        msg.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec()); // ReplyFor = Connect seq
        msg.headers.insert(HDR_CONN_ID, conn_id);
        let _ = write_message(&mut router, &msg).await;
        let _ = read_message(&mut router).await; // stay alive for a possible StateClosed
    });
}

/// A duplex-backed `EdgeChannel` (shared, as the pool opener hands back) with a fake router task
/// answering the first dial as `reply`.
fn fake_channel(reply: RouterReply) -> Arc<EdgeChannel> {
    let (client_io, router_io) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client_io);
    spawn_fake_router(router_io, reply);
    Arc::new(EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        BTreeMap::new(),
    ))
}

/// Mount the REST steps `connect_inner` always hits: list services (one plaintext `svc9`,
/// id `svc-9`) and create a Dial session for it. `expected_creates` pins how many times
/// `POST /sessions` must be called (verified on server drop) — this is what makes the
/// evict + recreate observable end-to-end: a no-op evict would turn the retry's 2nd
/// get-or-create into a cache hit (0 extra POSTs) and fail the `expect(2)`.
async fn mount_resolve_and_create(server: &MockServer, expected_creates: u64) {
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"svc-9","name":"svc9","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            // A JWT-prefixed (`ey`) session token so the refresh probe stays on the JWT branch
            // (`GET /services/{id}/edge-routers`) these tests mount. (D1, dial-sessions-race:
            // opaque tokens now route to `GET /sessions/{id}` — see
            // `connect_recovers_from_dead_opaque_cached_session` for that branch.)
            r#"{"data":{"id":"sess","token":"eyJ.dial.9","serviceId":"svc-9","type":"Dial","edgeRouters":[{"name":"er1","supportedProtocols":{"tls":"tls://r:3022"}}]},"meta":{}}"#,
        ))
        .expect(expected_creates)
        .mount(server)
        .await;
}

#[tokio::test]
async fn connect_inner_succeeds_on_first_dial_no_probe() {
    let server = MockServer::start().await;
    mount_resolve_and_create(&server, 1).await; // one create, no retry
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let open_calls = AtomicUsize::new(0);
    let conn = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            open_calls.fetch_add(1, Ordering::Relaxed);
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(RouterReply::Connected(b"circ-happy")))
        })
        .await
        .expect("connect succeeds on the first dial");
    assert_eq!(conn.circuit_id(), Some("circ-happy"));
    assert_eq!(open_calls.load(Ordering::Relaxed), 1, "no retry on success");
}

/// O5: the `connect_inner` span records `service_name`, so any log emitted within the connect
/// flow (in production: the race-loser warns, the client crypto downgrade/established logs) is
/// correlated to the service. Drive it with an opener that emits a probe event INSIDE the span;
/// assert the span field is rendered on it.
#[traced_test]
#[tokio::test]
async fn connect_inner_span_records_service_for_correlation() {
    let server = MockServer::start().await;
    mount_resolve_and_create(&server, 1).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let _conn = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            tracing::warn!("connect-span-probe"); // emitted INSIDE the connect_inner span
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(RouterReply::Connected(b"circ-ok")))
        })
        .await
        .expect("connect ok");
    assert!(logs_contain("connect-span-probe"), "the probe event fired");
    // Pin the SPAN prefix + the value (`connect_inner{service_name="svc9"`): proves the connect
    // span itself records the service so inner logs correlate, and pins the bound value (not just
    // the field name). The probe event carries no `service_name` of its own, so this is span-only.
    assert!(
        logs_contain("connect_inner{service_name=\"svc9\""),
        "the connect span must record service_name=\"svc9\" so inner logs are correlated"
    );
}

#[tokio::test]
async fn connect_inner_does_not_retry_when_session_alive() {
    let server = MockServer::start().await;
    // expect(1): an alive session must NOT trigger a recreate (catches an inverted refresh branch).
    mount_resolve_and_create(&server, 1).await;
    // Liveness probe says ALIVE (200) → the dial failure is not session related → no retry.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-9/edge-routers"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"data":{"edgeRouters":[]},"meta":{}}"#),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let open_calls = AtomicUsize::new(0);
    let err = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            open_calls.fetch_add(1, Ordering::Relaxed);
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(RouterReply::Closed(b"boom")))
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&err, EdgeError::DialRejected(s) if s.contains("boom")),
        "original dial error propagates: {err:?}"
    );
    assert_eq!(
        open_calls.load(Ordering::Relaxed),
        1,
        "alive session → no second dial"
    );
}

#[tokio::test]
async fn connect_inner_retries_once_when_session_expired() {
    let server = MockServer::start().await;
    // expect(2): the expired-session path MUST evict + recreate (a 2nd POST /sessions). A no-op
    // evict would make the 2nd get-or-create a cache hit (1 POST) and fail this expectation.
    mount_resolve_and_create(&server, 2).await;
    // Liveness probe says EXPIRED (404) → evict + recreate + dial again.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-9/edge-routers"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session expired"}}"#),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let open_calls = AtomicUsize::new(0);
    let conn = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            let n = open_calls.fetch_add(1, Ordering::Relaxed);
            let reply = if n == 0 {
                RouterReply::Closed(b"stale") // dial #1 fails
            } else {
                RouterReply::Connected(b"circ-retry") // dial #2 after recreate
            };
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(reply))
        })
        .await
        .expect("connect succeeds after the retry");
    assert_eq!(
        conn.circuit_id(),
        Some("circ-retry"),
        "the SECOND dial established the circuit"
    );
    assert_eq!(
        open_calls.load(Ordering::Relaxed),
        2,
        "dial #1 failed, refresh 404 → recreate → dial #2"
    );
}

/// GWT-3 / T5 (dial-sessions-race): the OPAQUE-token twin of
/// `connect_inner_retries_once_when_session_expired`. A cached session with an OPAQUE token whose
/// dial fails must self-heal through the D1 branch: the liveness probe routes to
/// `GET /sessions/{id}` (DetailSession, 404 → dead) → evict + recreate + dial #2.
/// RED without D1: the old code routes the probe to `GET /services/{id}/edge-routers` — mounted
/// 200 here to model the api-session-authorized endpoint that ignores real session liveness — so
/// the probe reports Ok, no retry fires, and the connect fails with the original dial error.
///
/// ⚠ Dial #1 deliberately fails with a reason that is **not** `invalid session`: that exact string
/// is D3's short-circuit trigger (`is_dial_invalid_session`), which skips the probe entirely and
/// would recover via D3 — leaving this test green while never exercising the D1 probe it exists to
/// guard. The `.expect(1)` on the DetailSession mock pins that the probe really is hit.
/// (D3's own end-to-end path is covered by `connect_recovers_from_router_invalid_session_despite_alive_probe`.)
#[tokio::test]
async fn connect_recovers_from_dead_opaque_cached_session() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"svc-9","name":"svc9","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .mount(&server)
        .await;
    // Create + recreate of the OPAQUE-token session (id `sess-op`). expect(2) = create #1 + the
    // post-evict recreate; a no-op evict would make the 2nd get-or-create a cache HIT (1 POST).
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"data":{"id":"sess-op","token":"opaque-9","serviceId":"svc-9","type":"Dial","edgeRouters":[{"name":"er1","supportedProtocols":{"tls":"tls://r:3022"}}]},"meta":{}}"#,
        ))
        .expect(2)
        .mount(&server)
        .await;
    // D1 (opaque) probe target: DetailSession reports DEAD (404) → the fast-path evicts+recreates.
    // `.expect(1)` is load-bearing: without it, D3's short-circuit could skip the probe entirely
    // and this test would still pass, silently guarding nothing.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/sess-op"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    // The OLD (pre-D1) probe target: an api-session-authorized endpoint that reports ALIVE (200)
    // regardless of the session's real liveness. Before D1 the opaque token wrongly routed here →
    // Ok → no retry → RED. After D1 it is never hit for an opaque token.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-9/edge-routers"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"data":{"edgeRouters":[]},"meta":{}}"#),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let open_calls = AtomicUsize::new(0);
    let conn = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            let n = open_calls.fetch_add(1, Ordering::Relaxed);
            let reply = if n == 0 {
                // NOT `invalid session` (that is D3's trigger, which would skip the probe).
                RouterReply::Closed(b"no terminators") // dial #1 fails for a non-session reason
            } else {
                RouterReply::Connected(b"circ-op-retry") // dial #2 after evict + recreate
            };
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(reply))
        })
        .await
        .expect("an opaque dead cached session self-heals via the D1 /sessions/{id} probe");
    assert_eq!(
        conn.circuit_id(),
        Some("circ-op-retry"),
        "the SECOND dial (post evict+recreate) established the circuit"
    );
    assert_eq!(
        open_calls.load(Ordering::Relaxed),
        2,
        "dial #1 rejected → opaque probe 404 → evict → recreate → dial #2"
    );
}

/// T7 (GWT-7, the beyond-oracle observable, spec §6.3): a cached session that the ROUTER rejects
/// with `invalid session` recovers even though the controller's liveness probe reports it ALIVE
/// (200). This is impossible under the oracle's dial-gate (probe alive ⇒ no retry). Twin of D1's
/// `connect_recovers_from_dead_opaque_cached_session`, which recovers via a 404 (DEAD) probe — the
/// oracle route; T7 recovers with a 200 (ALIVE) probe — the route ONLY D3 enables. The
/// `RouterReply::Closed(b"invalid session")` reproduces the exact wire body
/// (`NewStateClosedMsg(err.Error())`, spec §1.3). RED without D3: the 200 probe ⇒ no retry ⇒ the
/// connect fails with `invalid session`.
#[tokio::test]
async fn connect_recovers_from_router_invalid_session_despite_alive_probe() {
    let server = MockServer::start().await;
    // JWT-prefixed token (`ey`) → the refresh probe routes to `GET /services/{id}/edge-routers`
    // (the api-session-authorized endpoint), mounted 200 ALIVE below. expect(2): create #1 + the
    // post-evict recreate; a no-op evict would make the 2nd get-or-create a cache HIT (1 POST).
    mount_resolve_and_create(&server, 2).await;
    // The liveness probe reports ALIVE (200) — the controller says the session is fine. D3 must
    // NEVER consult it for an `invalid session` rejection; even if it did, alive ⇒ the oracle would
    // refuse to retry. Recovery here proves the probe is SKIPPED.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-9/edge-routers"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"data":{"edgeRouters":[]},"meta":{}}"#),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let open_calls = AtomicUsize::new(0);
    let conn = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            let n = open_calls.fetch_add(1, Ordering::Relaxed);
            let reply = if n == 0 {
                RouterReply::Closed(b"invalid session") // dial #1: the router's exact-wire verdict
            } else {
                RouterReply::Connected(b"circ-heal") // dial #2 after evict + recreate
            };
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(reply))
        })
        .await
        .expect("an invalid-session dial rejection self-heals despite the alive probe");
    assert_eq!(
        conn.circuit_id(),
        Some("circ-heal"),
        "the SECOND dial (post evict+recreate) established the circuit"
    );
    assert_eq!(
        open_calls.load(Ordering::Relaxed),
        2,
        "dial #1 invalid session → probe SKIPPED → evict → recreate → dial #2"
    );
}

/// N-3 (GWT-5, D3-CHURN — **the OBSERVABLE of this slice**): under sustained session churn the
/// router rejects BOTH dials with `invalid session`. The connect fails (paridad C1: exactly 2
/// dials, no loop, no wait — `ziti.go:1484` + `:1502` + `:1507`), but the dial-session cache must
/// be left **EMPTY**: the fresh session is proven dead (the controller only mints `invalid session`
/// on `Session.Read` NotFound, ziti@9bf62f3 `handler_edge_ctrl/common.go:329-333`).
///
/// RED without DV-C3: the fresh session stays cached, so the NEXT `connect()` hits the cache, burns
/// its first dial on the corpse and is left with only ONE useful attempt instead of two — the churn
/// failure-rate doubler this slice removes. `expect(2)` pins the two `POST /sessions` (C1).
#[tokio::test]
async fn connect_inner_evicts_the_dead_fresh_session_when_retry_dial_is_also_invalid() {
    let server = MockServer::start().await;
    // expect(2): create #1 + the post-evict recreate. No probe mock is needed: D3 skips the probe
    // on `invalid session` (an unmatched request would 404 the mock server and be visible anyway).
    mount_resolve_and_create(&server, 2).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let open_calls = AtomicUsize::new(0);
    let err = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            open_calls.fetch_add(1, Ordering::Relaxed);
            // EVERY dial is rejected with the router's exact wire verdict.
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(RouterReply::Closed(b"invalid session")))
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&err, EdgeError::DialRejected(s) if s == "invalid session"),
        "the 2nd dial's error propagates as-is: {err:?}"
    );
    assert_eq!(
        open_calls.load(Ordering::Relaxed),
        2,
        "C1 (paridad con el oráculo): exactly two dials, never a loop"
    );
    assert!(
        client.cached_dial_session("svc-9").is_none(),
        "C3: the proven-dead fresh session must NOT be left in the cache — the next connect() must \
         start on a cache MISS with both of its dials intact"
    );
}

/// N-5 (GWT-3 at the `connect_inner` level — the POSITIVE CONTROL of the cache KEY, and the twin of
/// the closure-level `retry_orch_second_dial_non_invalid_error_keeps_the_fresh_session`).
///
/// Two jobs, both of which N-3 alone cannot do:
/// 1. **DV-C4's narrowness against the REAL cache** (N-1 only proves it against a mocked `evict`
///    closure): a 2nd dial that fails for an unrelated reason (`no terminators`) is NO proof of
///    death, so the fresh session **stays cached**.
/// 2. **Positive control of the KEY.** N-3 only ever asserts `is_none()`. A mutation that changed the
///    cache KEY (e.g. keying by service NAME `"svc9"` instead of id `"svc-9"`) would leave N-3
///    **GREEN** while turning DV-C3's evict into a **no-op** — the same shape as the upstream
///    `refreshSessions` key bug, which collects BARE session-ids (`ziti.go:841`) and removes them from
///    a cache keyed `"{serviceId}:{type}"` (`:2121`), so its eviction arm never matches anything. (That
///    bug is still real upstream; the deviation tag that used to be cited here, DV-A1, is DEAD — 4a
///    stopped porting the inert contract and made our own eviction arm evict for real, keyed by the
///    snapshot's `service_id`. See `session_refresh/mod.rs`, «The PURGE arm».) This test is the only place
///    that asserts the cache is `Some` at that key, so such a mutation goes RED here.
///
/// `expect(2)`: create #1 + the post-evict recreate (D3's evict on dial #1's `invalid session`).
#[tokio::test]
async fn connect_inner_keeps_the_fresh_session_when_retry_dial_fails_for_another_reason() {
    let server = MockServer::start().await;
    mount_resolve_and_create(&server, 2).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let open_calls = AtomicUsize::new(0);
    let err = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            let n = open_calls.fetch_add(1, Ordering::Relaxed);
            Ok::<Arc<EdgeChannel>, EdgeError>(if n == 0 {
                // dial #1: the router's `invalid session` verdict → D3 evicts, recreates, retries.
                fake_channel(RouterReply::Closed(b"invalid session"))
            } else {
                // dial #2 fails for an UNRELATED reason → the fresh session is NOT proven dead.
                fake_channel(RouterReply::Closed(b"no terminators"))
            })
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&err, EdgeError::DialRejected(s) if s == "no terminators"),
        "the 2nd dial's error propagates as-is: {err:?}"
    );
    assert_eq!(
        open_calls.load(Ordering::Relaxed),
        2,
        "C1: exactly two dials, never a loop"
    );
    assert!(
        client.cached_dial_session("svc-9").is_some(),
        "DV-C4 + KEY control: a non-`invalid session` 2nd-dial failure is no proof of death, so the \
         fresh session must STILL be cached under the SERVICE-ID key — if this is None, either \
         someone evicts unconditionally, or the cache key drifted and DV-C3's evict is a no-op"
    );
}

// ----- connect-timeout (slice 10b): the internal deadline over the whole connect flow -----

/// A duplex-backed `EdgeChannel` whose fake router reads the Connect but NEVER replies, so the
/// dial's reply-wait hangs forever — exactly the degraded-but-listening router the connect-timeout
/// must bound. (Keeps the router task alive holding its half so the channel doesn't see EOF.)
fn hanging_channel() -> Arc<EdgeChannel> {
    let (client_io, router_io) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client_io);
    tokio::spawn(async move {
        let mut router = router_io;
        let _ = read_message(&mut router).await; // consume the Connect, then hang holding `router`
        std::future::pending::<()>().await;
    });
    Arc::new(EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        BTreeMap::new(),
    ))
}

#[tokio::test]
async fn connect_inner_times_out_when_dial_never_replies() {
    let server = MockServer::start().await;
    mount_resolve_and_create(&server, 1).await; // REST resolves + creates fine; the dial hangs
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let timeout = Duration::from_millis(150);
    let start = std::time::Instant::now();
    let err = client
        .connect_inner("svc9", timeout, None, async |_d: &SessionDetail| {
            Ok::<Arc<EdgeChannel>, EdgeError>(hanging_channel())
        })
        .await
        .expect_err("a router that never replies must trip the connect-timeout");
    let elapsed = start.elapsed();
    assert!(
        matches!(&err, EdgeError::ConnectTimedOut { service, timeout: t }
            if service == "svc9" && *t == timeout),
        "expected ConnectTimedOut for svc9, got: {err:?}"
    );
    // The test itself must finish fast: the deadline fired, it did not run to a real router timeout.
    assert!(
        elapsed < Duration::from_secs(2),
        "connect-timeout did not bound wall-clock: {elapsed:?}"
    );
}

#[tokio::test]
async fn connect_with_timeout_succeeds_well_within_a_generous_budget() {
    let server = MockServer::start().await;
    mount_resolve_and_create(&server, 1).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    // A fast fake router replies StateConnected immediately → no spurious timeout.
    let conn = client
        .connect_inner(
            "svc9",
            Duration::from_secs(30),
            None,
            async |_d: &SessionDetail| {
                Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(RouterReply::Connected(b"circ-ok")))
            },
        )
        .await
        .expect("a fast dial succeeds well within the generous connect-timeout");
    assert_eq!(conn.circuit_id(), Some("circ-ok"));
}

/// Pins the slice-10b contract: `connect()`'s default budget is the oracle's 15s (`ziti.go:1450`).
/// `connect()` delegates to `connect_with_timeout(.., DEFAULT_CONNECT_TIMEOUT)`, which can't be
/// unit-tested without a live router (it wires `self.open_channel`), so this pins the constant the
/// glue passes — a drift to e.g. 5s or 0s fails here (a grossly-wrong default also fails live).
#[test]
fn default_connect_timeout_is_the_oracle_15s() {
    assert_eq!(DEFAULT_CONNECT_TIMEOUT, Duration::from_secs(15));
}

/// slice reauth-401: `connect_inner` wraps its OWN service resolution in `with_reauth_retry`
/// (spec §3.5 row 1, "list services (connect)"), NOT the `EdgeClient::list_services` method. This
/// is the discriminating test for that specific wiring: a 401 listing services (expired
/// api-session) re-authenticates + retries the resolve, then the connect proceeds. Deleting
/// `connect_inner`'s `with_reauth_retry` wrap makes the 401 propagate (no `/authenticate` hit, the
/// connect errors) → this goes RED (and `/authenticate` `.expect(1)` fails on drop). The two
/// `GET /services` mocks are keyed on `zt-session` so the retry MUST carry the rotated token.
#[tokio::test]
async fn connect_inner_reauthenticates_on_list_services_401() {
    use wiremock::matchers::{header, query_param};
    let server = MockServer::start().await;
    // List services on the stale token T0 → 401.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(header("zt-session", "T0"))
        .respond_with(ResponseTemplate::new(401).set_body_string(
            r#"{"error":{"code":"UNAUTHORIZED","message":"api session expired"}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    // Reactive cert re-auth → fresh token T1.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "cert"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"id":"a","token":"T1","authQueries":[],"identity":{"name":"tester"}},"meta":{}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    // Retry list services with the fresh token T1 → 200 (one plaintext svc9).
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(header("zt-session", "T1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"svc-9","name":"svc9","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    // The Dial session create then uses the rotated token → 201.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"data":{"id":"sess","token":"jwt-9","serviceId":"svc-9","type":"Dial","edgeRouters":[{"name":"er1","supportedProtocols":{"tls":"tls://r:3022"}}]},"meta":{}}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let conn = client
        .connect_inner("svc9", TEST_TIMEOUT, None, async |_d: &SessionDetail| {
            Ok::<Arc<EdgeChannel>, EdgeError>(fake_channel(RouterReply::Connected(b"circ-reauth")))
        })
        .await
        .expect("connect recovers after a list-services re-auth");
    assert_eq!(conn.circuit_id(), Some("circ-reauth"));
    assert_eq!(
        client.token().as_deref(),
        Some("T1"),
        "the resolve's re-auth rotated the token"
    );
}
