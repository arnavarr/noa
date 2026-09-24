//! Tests de `retry` (F6 tramo 5: movidos verbatim del monolito de `edge/conn`).

use super::retry::dial_with_refresh_retry;
use super::testsupport::detail;
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing_test::traced_test;

/// Anti-leak fixture (§6 convention): a `detail()` clone whose token carries the `TOKSECRET`
/// sentinel, for tests that assert the token never reaches the logs. Kept separate from
/// `detail()` (`edge/conn/testsupport.rs`) so existing tests that pin on `detail()`'s fields are not hijacked.
fn detail_toksecret() -> SessionDetail {
    SessionDetail {
        token: "TOKSECRET-p8".into(),
        ..detail()
    }
}

// ----- dial_with_refresh_retry: the pure retry orchestration (no IO) -----

fn session_http_404() -> EdgeError {
    EdgeError::SessionHttp {
        status: 404,
        code: "NOT_FOUND".into(),
        message: "session expired".into(),
    }
}

#[tokio::test]
async fn retry_orch_returns_on_first_dial_success() {
    let (goc, dials, refreshes, evicts) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let r = dial_with_refresh_retry(
        async || {
            goc.fetch_add(1, Ordering::Relaxed);
            Ok(detail())
        },
        async |_s: SessionDetail| {
            dials.fetch_add(1, Ordering::Relaxed);
            Ok::<u32, EdgeError>(7)
        },
        async |_s: SessionDetail| {
            refreshes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert_eq!(r.unwrap(), 7);
    assert_eq!(goc.load(Ordering::Relaxed), 1);
    assert_eq!(dials.load(Ordering::Relaxed), 1);
    assert_eq!(refreshes.load(Ordering::Relaxed), 0, "no probe on success");
    assert_eq!(evicts.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn retry_orch_no_retry_when_session_alive() {
    let (dials, evicts) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let r = dial_with_refresh_retry(
        async || Ok(detail()),
        async |_s: SessionDetail| {
            dials.fetch_add(1, Ordering::Relaxed);
            Err::<u32, EdgeError>(EdgeError::DialRejected("boom".into()))
        },
        async |_s: SessionDetail| Ok(()), // alive
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert!(matches!(r, Err(EdgeError::DialRejected(s)) if s == "boom"));
    assert_eq!(dials.load(Ordering::Relaxed), 1, "no second dial");
    assert_eq!(evicts.load(Ordering::Relaxed), 0, "alive → no evict");
}

#[tokio::test]
async fn retry_orch_retries_once_when_session_expired() {
    let (goc, dials, evicts) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let r = dial_with_refresh_retry(
        async || {
            goc.fetch_add(1, Ordering::Relaxed);
            Ok(detail())
        },
        async |_s: SessionDetail| {
            let n = dials.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Err(EdgeError::DialRejected("stale".into()))
            } else {
                Ok::<u32, EdgeError>(99)
            }
        },
        async |_s: SessionDetail| Err(session_http_404()), // expired
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert_eq!(r.unwrap(), 99, "second dial after recreate succeeds");
    assert_eq!(goc.load(Ordering::Relaxed), 2, "recreate after evict");
    assert_eq!(dials.load(Ordering::Relaxed), 2);
    assert_eq!(evicts.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn retry_orch_propagates_second_dial_error() {
    let dials = AtomicUsize::new(0);
    let r = dial_with_refresh_retry(
        async || Ok(detail()),
        async |_s: SessionDetail| {
            let n = dials.fetch_add(1, Ordering::Relaxed);
            Err::<u32, EdgeError>(EdgeError::DialRejected(format!("dial-{n}")))
        },
        async |_s: SessionDetail| Err(session_http_404()),
        || {},
    )
    .await;
    // The retry fired (dial-1) and its error — not the original (dial-0) — propagates.
    assert!(matches!(r, Err(EdgeError::DialRejected(s)) if s == "dial-1"));
    assert_eq!(dials.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn retry_orch_propagates_initial_create_error() {
    let dials = AtomicUsize::new(0);
    let r = dial_with_refresh_retry(
        async || Err(session_http_404()),
        async |_s: SessionDetail| {
            dials.fetch_add(1, Ordering::Relaxed);
            Ok::<u32, EdgeError>(1)
        },
        async |_s: SessionDetail| Ok(()),
        || {},
    )
    .await;
    assert!(matches!(r, Err(EdgeError::SessionHttp { status: 404, .. })));
    assert_eq!(
        dials.load(Ordering::Relaxed),
        0,
        "no dial without a session"
    );
}

#[tokio::test]
async fn retry_orch_propagates_recreate_error() {
    let (goc, dials, evicts) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let r = dial_with_refresh_retry(
        async || {
            let n = goc.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Ok(detail())
            } else {
                Err(session_http_404())
            }
        },
        async |_s: SessionDetail| {
            dials.fetch_add(1, Ordering::Relaxed);
            Err::<u32, EdgeError>(EdgeError::DialRejected("stale".into()))
        },
        async |_s: SessionDetail| Err(session_http_404()), // expired → triggers recreate
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert!(matches!(r, Err(EdgeError::SessionHttp { status: 404, .. })));
    assert_eq!(goc.load(Ordering::Relaxed), 2);
    assert_eq!(
        dials.load(Ordering::Relaxed),
        1,
        "recreate failed → no second dial"
    );
    assert_eq!(evicts.load(Ordering::Relaxed), 1);
}

// ----- D3: invalid-session evict+retry skips the probe (spec §6.2) -----

/// T4 (GWT-4): a router `invalid session` rejection evicts + recreates + retries WITHOUT consulting
/// the liveness probe. The `refresh` fake would report ALIVE (as the controller does, spec §2), so a
/// probe-gated retry would NOT fire — proving the beyond-oracle short-circuit. RED without D3:
/// `refreshes==1` and `r` is the original Err.
#[tokio::test]
async fn retry_orch_invalid_session_evicts_and_retries_without_probe() {
    let (goc, dials, refreshes, evicts) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let r = dial_with_refresh_retry(
        async || {
            goc.fetch_add(1, Ordering::Relaxed);
            Ok(detail())
        },
        async |_s: SessionDetail| {
            let n = dials.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Err(EdgeError::DialRejected("invalid session".into()))
            } else {
                Ok::<u32, EdgeError>(99)
            }
        },
        async |_s: SessionDetail| {
            refreshes.fetch_add(1, Ordering::Relaxed);
            Ok(()) // controller reports ALIVE — a probe-gate would refuse to retry
        },
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert_eq!(r.unwrap(), 99, "the recreated session's dial #2 succeeds");
    assert_eq!(
        refreshes.load(Ordering::Relaxed),
        0,
        "invalid session skips the probe (beyond-oracle)"
    );
    assert_eq!(dials.load(Ordering::Relaxed), 2);
    assert_eq!(evicts.load(Ordering::Relaxed), 1);
    assert_eq!(goc.load(Ordering::Relaxed), 2, "recreate after evict");
}

/// T5 (GWT-5): if the SECOND dial is ALSO `invalid session`, its error propagates with EXACTLY two
/// dials — a single retry, never a loop. RED with a `loop`: `dials > 2`.
///
/// D3-CHURN (GWT-1 + GWT-2, 2026-07-11): `evicts` is now **2**, not 1. The second evict is DV-C3:
/// the FRESH session the retry just created is *proven dead* (the controller mints `invalid session`
/// only when `Session.Read(id)` is NotFound — ziti@9bf62f3
/// `controller/handler_edge_ctrl/common.go:329-333`), and a deleted session never resurrects, so it
/// must not stay cached. Everything else is unchanged: 2 dials, 0 probes, error propagated verbatim.
#[tokio::test]
async fn retry_orch_invalid_session_second_dial_also_invalid_propagates() {
    let (dials, refreshes, evicts) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let r = dial_with_refresh_retry(
        async || Ok(detail()),
        // Both dials return the SAME exact reason (kept exact so the predicate keeps matching); the
        // "first vs second" distinction is by the atomic count, not the text (spec note T5).
        async |_s: SessionDetail| {
            dials.fetch_add(1, Ordering::Relaxed);
            Err::<u32, EdgeError>(EdgeError::DialRejected("invalid session".into()))
        },
        async |_s: SessionDetail| {
            refreshes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert!(
        matches!(r, Err(EdgeError::DialRejected(s)) if s == "invalid session"),
        "the second dial's error propagates as-is"
    );
    assert_eq!(
        dials.load(Ordering::Relaxed),
        2,
        "exactly two dials — no loop"
    );
    assert_eq!(
        evicts.load(Ordering::Relaxed),
        2,
        "DV-C3: the cached session is evicted (D3) AND the fresh one, proven dead by the 2nd \
         dial's `invalid session`, is evicted too — the cache must not retain a corpse"
    );
    assert_eq!(
        refreshes.load(Ordering::Relaxed),
        0,
        "the probe is skipped on both invalid-session rejections"
    );
}

/// N-1 (GWT-3, DV-C4's narrowness guard): when the SECOND dial fails for a reason that is NOT
/// `invalid session` (here `no terminators`), the fresh session is **kept** cached — we have no
/// proof it is dead, and dropping it would buy a gratuitous `POST /sessions` on every router
/// hiccup. Exactly one evict (D3's). GREEN today; goes RED if anyone evicts unconditionally on a
/// failed retry dial (spec §6.5, over-eviction mutation).
#[tokio::test]
async fn retry_orch_second_dial_non_invalid_error_keeps_the_fresh_session() {
    let (dials, evicts) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let r = dial_with_refresh_retry(
        async || Ok(detail()),
        async |_s: SessionDetail| {
            let n = dials.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                // dial #1: the router's `invalid session` verdict → D3 skips the probe, evicts,
                // recreates, retries once.
                Err::<u32, EdgeError>(EdgeError::DialRejected("invalid session".into()))
            } else {
                // dial #2 fails for an UNRELATED reason: the fresh session is not proven dead.
                Err(EdgeError::DialRejected("no terminators".into()))
            }
        },
        async |_s: SessionDetail| -> Result<(), EdgeError> {
            panic!("D3 skips the probe on invalid session; the refresh fake must not be called")
        },
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert!(
        matches!(r, Err(EdgeError::DialRejected(s)) if s == "no terminators"),
        "the second dial's error propagates as-is"
    );
    assert_eq!(dials.load(Ordering::Relaxed), 2, "exactly two dials");
    assert_eq!(
        evicts.load(Ordering::Relaxed),
        1,
        "C4: only D3's evict — a non-`invalid session` failure is NO proof of death, so the fresh \
         session stays cached (fidelity: the oracle never drops it either, ziti.go:1502-1507)"
    );
}

/// N-2 (GWT-4, DV-C4): the corpse-eviction lives in the retry's SHARED TAIL, so it also covers the
/// ORACLE's own arm (probe-dead), not just D3's. Dial #1 fails generically, the probe says DEAD
/// (the oracle's gate at `ziti.go:1489-1493` fires), the recreated session's dial #2 is rejected
/// `invalid session` ⇒ proven dead ⇒ evicted. RED without DV-C3: `evicts == 1`.
#[tokio::test]
async fn retry_orch_probe_dead_tail_evicts_when_second_dial_is_invalid() {
    let (dials, refreshes, evicts) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let r = dial_with_refresh_retry(
        async || Ok(detail()),
        async |_s: SessionDetail| {
            let n = dials.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Err::<u32, EdgeError>(EdgeError::DialRejected("stale".into())) // not D3's trigger
            } else {
                Err(EdgeError::DialRejected("invalid session".into()))
            }
        },
        async |_s: SessionDetail| {
            refreshes.fetch_add(1, Ordering::Relaxed);
            Err(session_http_404()) // the oracle's probe: session EXPIRED
        },
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert!(
        matches!(r, Err(EdgeError::DialRejected(s)) if s == "invalid session"),
        "the second dial's error propagates as-is"
    );
    assert_eq!(
        refreshes.load(Ordering::Relaxed),
        1,
        "this is the ORACLE's probe-gated arm, not D3's short-circuit"
    );
    assert_eq!(dials.load(Ordering::Relaxed), 2, "exactly two dials");
    assert_eq!(
        evicts.load(Ordering::Relaxed),
        2,
        "DV-C4: the corpse-evict sits in the SHARED tail, so the oracle's probe-dead arm gets it too"
    );
}

/// T6 (GWT-6): the ORACLE INVARIANT preserved — a NON-invalid rejection is still probe-gated. The
/// probe reports ALIVE, so the failure is not session related → no retry, original error returned.
/// Hardened twin of `retry_orch_no_retry_when_session_alive` that also pins `refreshes==1`. RED with
/// an unconditional skip (M6): `refreshes==0`.
#[tokio::test]
async fn retry_orch_non_invalid_rejection_is_probe_gated() {
    let (dials, refreshes, evicts) = (
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    );
    let r = dial_with_refresh_retry(
        async || Ok(detail()),
        async |_s: SessionDetail| {
            dials.fetch_add(1, Ordering::Relaxed);
            Err::<u32, EdgeError>(EdgeError::DialRejected("boom".into()))
        },
        async |_s: SessionDetail| {
            refreshes.fetch_add(1, Ordering::Relaxed);
            Ok(()) // alive
        },
        || {
            evicts.fetch_add(1, Ordering::Relaxed);
        },
    )
    .await;
    assert!(
        matches!(r, Err(EdgeError::DialRejected(s)) if s == "boom"),
        "a non-invalid rejection with an alive session returns the original error"
    );
    assert_eq!(
        refreshes.load(Ordering::Relaxed),
        1,
        "a non-invalid rejection IS probe-gated (oracle invariant, ziti.go:1489-1493)"
    );
    assert_eq!(dials.load(Ordering::Relaxed), 1, "alive → no second dial");
    assert_eq!(evicts.load(Ordering::Relaxed), 0, "alive → no evict");
}

// ----- Observability (opción 3 del MENÚ 2026-07-10): P8 logs the retry TRIGGER discriminant
// (invalid-session vs probe-dead) that the residual analysis needed. -----

/// T-OBS6: the D3 `invalid session` short-circuit logs `trigger=invalid-session`, never
/// `trigger=probe-dead`. Mirror of T4 (`retry_orch_invalid_session_evicts_and_retries_without_probe`);
/// the `refresh` fake would panic if called, pinning D3's probe-skip. RED
/// without P8 (§6.3 M7).
#[traced_test]
#[tokio::test]
async fn dial_retry_logs_invalid_session_trigger() {
    let dials = AtomicUsize::new(0);
    let r = dial_with_refresh_retry(
        async || Ok(detail_toksecret()),
        async |_s: SessionDetail| {
            let n = dials.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Err(EdgeError::DialRejected("invalid session".into()))
            } else {
                Ok::<u32, EdgeError>(99)
            }
        },
        async |_s: SessionDetail| -> Result<(), EdgeError> {
            panic!("D3 skips the probe on invalid session; the refresh fake must not be called")
        },
        || {},
    )
    .await;
    assert_eq!(r.unwrap(), 99);
    assert!(
        logs_contain("dial session dead"),
        "P8: the retry trigger is logged"
    );
    assert!(
        logs_contain("trigger=invalid-session"),
        "the discriminant is invalid-session"
    );
    assert!(
        !logs_contain("trigger=probe-dead"),
        "the other discriminant value must not appear"
    );
    assert!(
        !logs_contain("TOKSECRET"),
        "the session token must never be logged"
    );
}

/// T-OBS7: a non-`invalid session` rejection that the probe confirms dead logs
/// `trigger=probe-dead`, never `trigger=invalid-session`. Mirror of the expired-probe branch
/// of `retry_orch_retries_once_when_session_expired`. RED if P8's discriminator
/// is missing or inverted (§6.3 M7).
#[traced_test]
#[tokio::test]
async fn dial_retry_logs_probe_dead_trigger() {
    let dials = AtomicUsize::new(0);
    let r = dial_with_refresh_retry(
        async || Ok(detail_toksecret()),
        async |_s: SessionDetail| {
            let n = dials.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Err(EdgeError::DialRejected("stale".into()))
            } else {
                Ok::<u32, EdgeError>(99)
            }
        },
        async |_s: SessionDetail| Err(session_http_404()), // expired
        || {},
    )
    .await;
    assert_eq!(r.unwrap(), 99);
    assert!(
        logs_contain("trigger=probe-dead"),
        "the discriminant is probe-dead"
    );
    assert!(
        !logs_contain("trigger=invalid-session"),
        "the other discriminant value must not appear"
    );
    assert!(
        !logs_contain("TOKSECRET"),
        "the session token must never be logged"
    );
}

/// N-4 (GWT-6, D3-CHURN): the corpse-eviction of DV-C3 is OBSERVABLE — it emits a log with
/// `reason="dead-at-dial"`, in the P1..P8 idiom of the dial-session cache logs (OBS-DIAL-CACHE,
/// `617b3fa`). And it upholds **DV-O1**: the session TOKEN is never logged (the `TOKSECRET` sentinel
/// must not appear), even though the oracle does log it (`ziti.go:1483`,
/// `WithField("sessionToken", …)`). RED without DV-C3: `reason="dead-at-dial"` does not exist.
///
/// The ONLY load-bearing assertion is `reason="dead-at-dial"` (+ the token sentinel). It is
/// deliberately NOT asserting `session_id=s`: D3's own pre-existing log (`trigger=invalid-session`)
/// already emits `session_id=s` with this very fixture, so that assertion would pass even with DV-C3
/// **fully reverted** — it is not a discriminant. The EVICTION itself is pinned by M-1 / N-2 / N-3;
/// this test pins only its OBSERVABILITY.
#[traced_test]
#[tokio::test]
async fn dial_retry_logs_dead_fresh_session_eviction() {
    let r = dial_with_refresh_retry(
        async || Ok(detail_toksecret()),
        // EVERY dial is rejected `invalid session` — including the retry's, so the fresh session
        // is proven dead and gets evicted.
        async |_s: SessionDetail| {
            Err::<u32, EdgeError>(EdgeError::DialRejected("invalid session".into()))
        },
        async |_s: SessionDetail| -> Result<(), EdgeError> {
            panic!("D3 skips the probe on invalid session; the refresh fake must not be called")
        },
        || {},
    )
    .await;
    assert!(matches!(r, Err(EdgeError::DialRejected(s)) if s == "invalid session"));
    assert!(
        logs_contain("reason=\"dead-at-dial\""),
        "DV-C3's eviction of the proven-dead fresh session must be logged — this is the ONLY \
         discriminant here (`session_id=s` is NOT: D3's pre-existing `trigger=invalid-session` log \
         already emits it with this fixture, so it stays green with DV-C3 reverted)"
    );
    assert!(
        !logs_contain("TOKSECRET"),
        "DV-O1: the session token must NEVER be logged"
    );
}
