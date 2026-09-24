//! Tests del fan-out de openers detached (`fan_out_first_ok`, `spawn_router_openers`).
//! (F6 tramo 6: movidos verbatim del monolito de `edge/channel`.)

use super::*;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tracing_test::traced_test;

use crate::edge::data::EdgeChannel;
use crate::edge::error::EdgeError;

use super::testsupport::fake_channel;

/// A generous per-router dial timeout for the fan-out unit tests (the production value is
/// [`ROUTER_DIAL_TIMEOUT`] = 15s; the bounding behavior itself is pinned by
/// `fan_out_bounds_a_hung_opener`).
const TEST_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ----- fan-out-and-pool-all (slice (B) Phase-2): the spawn-based router fan-out -----

fn boom(which: &str) -> EdgeError {
    EdgeError::ChannelTls(format!("router {which} down"))
}

#[tokio::test]
async fn fan_out_empty_addrs_is_no_tls_edge_router() {
    let err = fan_out_first_ok::<String, _, _>(
        vec![],
        |_a: String| async { unreachable!("opener must not be called for empty addrs") },
        TEST_DIAL_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EdgeError::NoTlsEdgeRouter));
}

/// THE (B) contract, inverting 10c's loser-drop: a pool MISS dials ALL routers and pools EVERY
/// success — not just the race winner. Modeled at the fan-out level: each opener pools a channel
/// into a shared test pool; after the winner returns AND the DETACHED losers finish, the pool holds
/// ALL N. Mutation: a `select_ok`-keep-one (cancel the losers) would leave the pool at 1.
#[tokio::test]
async fn fan_out_pools_every_success_not_just_the_winner() {
    let pool: Arc<Mutex<HashMap<String, Arc<EdgeChannel>>>> = Arc::new(Mutex::new(HashMap::new()));
    let live: crate::edge::refresh::LiveChannels = Arc::new(Mutex::new(Vec::new()));
    let addrs = vec!["r1".to_string(), "r2".to_string(), "r3".to_string()];
    let pool_c = pool.clone();
    let live_c = live.clone();
    let winner = fan_out_first_ok(
        addrs,
        move |addr| {
            let pool = pool_c.clone();
            let live = live_c.clone();
            async move {
                // Each opener pools a fake channel for its addr (mirror of `open_and_pool_router`'s
                // `pool_store_or_reuse_into`). `_router` is dropped; the pool ENTRY persists regardless.
                let (ch, _router) = fake_channel();
                crate::edge::client::pool_store_or_reuse_into(&pool, &live, addr.clone(), ch);
                Ok::<String, EdgeError>(addr)
            }
        },
        TEST_DIAL_TIMEOUT,
    )
    .await
    .expect("a winner is returned");
    assert!(["r1", "r2", "r3"].contains(&winner.as_str()));
    // Wait (bounded) for the detached loser tasks to finish pooling.
    let mut polled = 0;
    while pool.lock().unwrap().len() < 3 && polled < 500 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        polled += 1;
    }
    assert_eq!(
        pool.lock().unwrap().len(),
        3,
        "every router's channel is pooled (losers complete + pool, not cancelled)"
    );
}

/// Failover: a fast-FAILING first router falls over to a live second; the winner is the live one,
/// and the genuinely-failed router warns (O3) while the winner does not. (10c failover, preserved.)
#[traced_test]
#[tokio::test]
async fn fan_out_failover_first_fails_second_wins() {
    let r = fan_out_first_ok(
        vec!["bad".to_string(), "ok".to_string()],
        |addr: String| async move {
            if addr == "bad" {
                Err::<String, _>(boom("first"))
            } else {
                Ok(addr)
            }
        },
        TEST_DIAL_TIMEOUT,
    )
    .await;
    assert_eq!(r.expect("the live router wins"), "ok");
    // The failing router's warn fires in its (detached) task; bounded-wait for it.
    let mut polled = 0;
    while !logs_contain("router=bad") && polled < 500 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        polled += 1;
    }
    assert!(
        logs_contain("edge router connect failed"),
        "a failing router must warn"
    );
    assert!(
        logs_contain("router=bad"),
        "the warn carries the failing router's address"
    );
    assert!(
        !logs_contain("router=ok"),
        "the winning router must NOT warn"
    );
}

/// All routers fail → an error surfaces (the connect-timeout, slice 10b, bounds the wait), and
/// EVERY failing router warns (O3). WHICH error is "last" is now nondeterministic across the
/// concurrent tasks (a conscious widening of 10c's deterministic last-error), so we assert it is an
/// `Err` matching ONE of the routers, plus all three warns.
#[traced_test]
#[tokio::test]
async fn fan_out_all_fail_returns_an_error_and_warns_each() {
    let err = fan_out_first_ok::<String, _, _>(
        vec!["one".to_string(), "two".to_string(), "three".to_string()],
        |addr: String| async move { Err(boom(&addr)) },
        TEST_DIAL_TIMEOUT,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, EdgeError::ChannelTls(m) if ["one", "two", "three"].iter().any(|a| m.contains(a))),
        "all-fail surfaces one of the routers' errors, got: {err:?}"
    );
    for addr in ["one", "two", "three"] {
        assert!(
            logs_contain(&format!("router={addr}")),
            "each failing router warns with its address ({addr})"
        );
    }
}

/// A single live router is returned trivially (the common production case: one `er1`); no warn.
#[traced_test]
#[tokio::test]
async fn fan_out_single_addr_returns_its_channel() {
    let r = fan_out_first_ok(
        vec!["only".to_string()],
        |addr: String| async move { Ok::<String, EdgeError>(addr) },
        TEST_DIAL_TIMEOUT,
    )
    .await;
    assert_eq!(r.expect("a single router is returned"), "only");
    assert!(
        !logs_contain("edge router connect failed"),
        "a clean success must not emit a failure warn"
    );
}

/// The per-router dial timeout BOUNDS a hung opener (review HIGH fix). A loser whose opener never
/// completes (here a `std::future::pending()`, modeling a TLS-stall router that holds TCP+TLS open but
/// withholds the channel Result) must NOT hang its detached task forever — `fan_out_first_ok` caps each
/// opener at `dial_timeout`, after which the opener future is DROPPED (its guard runs) and reported as a
/// dial failure. Re-covers the removed `race_second_wins_when_first_hangs`. A `FinishGuard` bumps a
/// counter when each opener future is dropped (completed OR timed-out): both must reach the counter.
/// Mutation (drop the per-router timeout in `fan_out_first_ok`): the hung opener parks forever → its
/// guard never drops → the counter stalls at 1 → the bounded poll → RED (NOT an infinite hang).
#[tokio::test]
async fn fan_out_bounds_a_hung_opener() {
    struct FinishGuard(Arc<AtomicUsize>);
    impl Drop for FinishGuard {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let finished = Arc::new(AtomicUsize::new(0));
    let finished_c = finished.clone();
    let r = fan_out_first_ok(
        vec!["win".to_string(), "hang".to_string()],
        move |addr| {
            let guard = FinishGuard(finished_c.clone());
            async move {
                let _g = guard; // bumps the counter when this future is dropped (completed or cancelled)
                if addr == "win" {
                    Ok::<String, EdgeError>(addr)
                } else {
                    std::future::pending::<()>().await;
                    unreachable!()
                }
            }
        },
        std::time::Duration::from_millis(100), // tiny per-router cap
    )
    .await;
    assert_eq!(r.expect("the live router wins"), "win");
    // The hung opener must be timed out (then dropped → its guard bumps), so BOTH guards drop.
    let mut polled = 0;
    while finished.load(Ordering::Relaxed) < 2 && polled < 500 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        polled += 1;
    }
    assert_eq!(
        finished.load(Ordering::Relaxed),
        2,
        "every opener is bounded — the hung one times out and is dropped, it does not leak"
    );
}

/// The fire-and-forget fan-out POOLS every router it opens — the oracle's nil-`ch` goroutine still runs
/// `connectEdgeRouter` + `Upsert` (`:1738` discards only the RESULT, `:1874` pools it). Deterministic
/// (fake openers, no TLS): each opener pools a channel and SIGNALS, so the assert runs after both have
/// pooled — no sleeping. `spawn_router_openers` itself returns IMMEDIATELY (nothing is awaited).
/// MUTATION → RED: make the openers `select`-cancelled (keep-one) or drop the `Upsert`/pool step ⇒ the
/// pool never reaches 2.
#[tokio::test]
async fn spawn_router_openers_pools_every_addr_fire_and_forget() {
    let pool: Arc<Mutex<HashMap<String, Arc<EdgeChannel>>>> = Arc::new(Mutex::new(HashMap::new()));
    let live: crate::edge::refresh::LiveChannels = Arc::new(Mutex::new(Vec::new()));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(2);
    let pool_c = pool.clone();
    let live_c = live.clone();
    spawn_router_openers(
        vec!["r1".to_string(), "r2".to_string()],
        move |addr| {
            let pool = pool_c.clone();
            let live = live_c.clone();
            let tx = tx.clone();
            async move {
                // Mirror of `open_and_pool_router`'s tail: dial (faked) then `pool_store_or_reuse_into`.
                let (ch, _router) = fake_channel();
                crate::edge::client::pool_store_or_reuse_into(&pool, &live, addr.clone(), ch);
                let _ = tx.send(addr.clone()).await; // signalled AFTER pooling
                Ok::<String, EdgeError>(addr)
            }
        },
        TEST_DIAL_TIMEOUT,
    );
    let mut pooled = vec![
        rx.recv().await.expect("opener 1 pooled its router"),
        rx.recv().await.expect("opener 2 pooled its router"),
    ];
    pooled.sort();
    assert_eq!(pooled, vec!["r1".to_string(), "r2".to_string()]);
    assert_eq!(
        pool.lock().unwrap().len(),
        2,
        "every unconnected router is POOLED by its detached opener (nobody waits for it)"
    );
}
