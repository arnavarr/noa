//! Tests del pool de canales de router: store/reuse, scoring por latencia, y el fan-out 4c
//! en el cache-HIT de `open_or_reuse_pooled_channel`.
//! (F6 tramo 6: movidos verbatim del monolito de `edge/channel`.)

use std::sync::Arc;

use crate::edge::client::EdgeClient;
use crate::edge::error::EdgeError;
use crate::edge::router_filter::EdgeRouterUrlFilter;

use super::testsupport::{detail_with, er, fake_channel};

/// A filter that rejects exactly ONE url and accepts the rest. Owned (not `&'static`) because the
/// cache-hit fan-out tests reject a probe whose port is assigned at runtime.
fn reject_url(url: String) -> EdgeRouterUrlFilter {
    Arc::new(move |u: &str| u != url)
}

// ----- router connection pool (slice pool-first) -----

/// `pool_store_or_reuse`: a NEW address is pooled (count 1) and registered ONCE in the live-channel
/// registry; a SECOND store of the same still-alive address is FIRST-WRITER-WINS — it returns the
/// EXISTING channel, keeps the count at 1, and does NOT re-register (no duplicate token pushes).
#[tokio::test]
async fn pool_stores_new_and_dedups_reuse() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    assert_eq!(client.pooled_channel_count(), 0);
    let (ch1, _r1) = fake_channel();
    let a = client.pool_store_or_reuse("tls://r1:6262".to_string(), ch1);
    assert_eq!(
        client.pooled_channel_count(),
        1,
        "a new address pools the channel"
    );
    assert_eq!(
        client.live_channel_count(),
        1,
        "a new pool entry registers once (OIDC-2)"
    );

    let (ch2, _r2) = fake_channel();
    let b = client.pool_store_or_reuse("tls://r1:6262".to_string(), ch2);
    assert!(
        Arc::ptr_eq(&a, &b),
        "first-writer-wins: the second store returns the EXISTING pooled channel"
    );
    assert_eq!(
        client.pooled_channel_count(),
        1,
        "dedup keeps a single channel per router"
    );
    assert_eq!(
        client.live_channel_count(),
        1,
        "reuse must NOT re-register the channel (no duplicate token pushes)"
    );
}

/// `pool_get_alive`: an ALIVE pooled channel is reused; a DEAD one (rx-loop exited after its router
/// dropped) is a MISS and is LAZILY EVICTED — the mirror of the oracle's get-time `!IsClosed()`.
#[tokio::test]
async fn pool_get_alive_reuses_alive_and_lazily_evicts_dead() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");

    // A pooled channel whose router END is dropped → rx-loop sees EOF, exits → dead.
    let (dead_ch, dead_router) = fake_channel();
    let _dead = client.pool_store_or_reuse("tls://dead:6262".to_string(), dead_ch);
    drop(dead_router);
    // Give the spawned rx-loop a chance to observe EOF and finish.
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert!(
        client
            .pool_get_alive(&["tls://dead:6262".to_string()])
            .is_none(),
        "a dead pooled channel is never handed back out"
    );
    assert_eq!(
        client.pooled_channel_count(),
        0,
        "the dead entry is lazily evicted on the failed get"
    );

    // An ALIVE pooled channel (router end held) is reused, by Arc identity.
    let (live_ch, _live_router) = fake_channel();
    let a = client.pool_store_or_reuse("tls://live:6262".to_string(), live_ch);
    let got = client
        .pool_get_alive(&["tls://live:6262".to_string()])
        .expect("alive channel reused");
    assert!(
        Arc::ptr_eq(&a, &got),
        "an alive pooled channel is reused by identity"
    );
}

// ----- latency scoring (slice scoring (A)): pool_get_alive picks lowest mean -----

/// `pool_get_alive` (scoring): among >=2 ALIVE pooled channels for a session's routers, the LOWEST
/// mean-latency one wins — the oracle's Phase-1 pick (`getEdgeRouterConn` `ziti.go:1689-1701`), NOT
/// first-alive. Seeds give each pooled channel a distinct mean. RED under a first-alive (or
/// `max_by_key`) pick.
#[tokio::test]
async fn pool_get_alive_picks_lowest_mean_latency() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    let (slow, _rs) = fake_channel();
    slow.seed_latency(500_000); // 0.5ms mean
    let _slow = client.pool_store_or_reuse("tls://slow:6262".to_string(), slow);
    let (fast, _rf) = fake_channel();
    fast.seed_latency(100_000); // 0.1ms mean — the winner
    let fast_ptr = client.pool_store_or_reuse("tls://fast:6262".to_string(), fast);

    // Addr order [slow, fast]: first-seen is the SLOW one, but fast has the lower mean → fast wins.
    let got = client
        .pool_get_alive(&["tls://slow:6262".to_string(), "tls://fast:6262".to_string()])
        .expect("an alive channel is returned");
    assert!(
        Arc::ptr_eq(&got, &fast_ptr),
        "the lowest-mean-latency channel wins, not the first-seen"
    );
}

/// `pool_get_alive`: equal means keep the FIRST-SEEN (addr order) — the oracle's strict `<` does not
/// replace `bestER` on a tie (`min_by_key` returns the first element on ties).
#[tokio::test]
async fn pool_get_alive_ties_keep_first_seen() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    let (a, _ra) = fake_channel();
    a.seed_latency(200_000);
    let a_ptr = client.pool_store_or_reuse("tls://a:6262".to_string(), a);
    let (b, _rb) = fake_channel();
    b.seed_latency(200_000); // equal mean
    let _b = client.pool_store_or_reuse("tls://b:6262".to_string(), b);

    let got = client
        .pool_get_alive(&["tls://a:6262".to_string(), "tls://b:6262".to_string()])
        .expect("an alive channel is returned");
    assert!(
        Arc::ptr_eq(&got, &a_ptr),
        "equal means keep the first-seen (addr order)"
    );
}

/// `pool_get_alive`: a single alive-but-UNSAMPLED channel (`mean == u64::MAX`) is still returned, not
/// dropped to a spurious re-dial. Pins the Option-form pick (a `best=MAX; strict <` form would fail
/// `MAX < MAX` and return `None`). In practice every pooled channel is seeded, but the form is robust.
#[tokio::test]
async fn pool_get_alive_single_unsampled_is_returned() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    let (ch, _r) = fake_channel(); // NOT seeded → mean == u64::MAX
    let ptr = client.pool_store_or_reuse("tls://only:6262".to_string(), ch);
    let got = client
        .pool_get_alive(&["tls://only:6262".to_string()])
        .expect("a single alive (even unsampled) channel is returned");
    assert!(Arc::ptr_eq(&got, &ptr));
}

/// `pool_get_alive`: full scan — a DEAD session-router entry is evicted (not scored) and the
/// lowest-mean ALIVE one among the rest wins. Combines lazy eviction with the scoring pick.
#[tokio::test]
async fn pool_get_alive_evicts_dead_and_scores_the_alive() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    // Dead entry (router end dropped → rx-loop EOFs).
    let (dead, dead_router) = fake_channel();
    dead.seed_latency(1); // a tiny mean — but it is DEAD, so it must NOT win
    let _dead = client.pool_store_or_reuse("tls://dead:6262".to_string(), dead);
    drop(dead_router);
    // Two alive entries with distinct means.
    let (slow, _rs) = fake_channel();
    slow.seed_latency(900_000);
    let _slow = client.pool_store_or_reuse("tls://slow:6262".to_string(), slow);
    let (fast, _rf) = fake_channel();
    fast.seed_latency(300_000);
    let fast_ptr = client.pool_store_or_reuse("tls://fast:6262".to_string(), fast);
    tokio::time::sleep(std::time::Duration::from_millis(30)).await; // let the dead rx-loop finish

    let got = client
        .pool_get_alive(&[
            "tls://dead:6262".to_string(),
            "tls://slow:6262".to_string(),
            "tls://fast:6262".to_string(),
        ])
        .expect("an alive channel is returned");
    assert!(
        Arc::ptr_eq(&got, &fast_ptr),
        "the dead (tiny-mean) entry is evicted; the lowest-mean ALIVE one wins"
    );
    assert_eq!(
        client.pooled_channel_count(),
        2,
        "the dead entry is lazily evicted, leaving the two alive ones"
    );
}

/// `open_or_reuse_pooled_channel`: on a POOL HIT it returns the pooled channel WITHOUT opening a new
/// TLS channel (the non-vacuous reuse property, observed via `tls_channel_opens()`). Deterministic
/// (no live router needed — the pool is pre-seeded, so the dial path is never taken).
#[tokio::test]
async fn open_or_reuse_returns_pooled_channel_without_dialing() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    let (ch, _router) = fake_channel();
    let pooled = client.pool_store_or_reuse("tls://r1:6262".to_string(), ch);
    assert_eq!(
        client.tls_channel_opens(),
        0,
        "no handshake recorded for a pre-seeded entry"
    );

    // A session whose `tls` router is the pre-seeded address ⇒ a pool HIT.
    let d = detail_with(vec![er("r1", Some("tls://r1:6262"))]);
    let got = client
        .open_or_reuse_pooled_channel(&d)
        .await
        .expect("pool hit reuses");
    assert!(
        Arc::ptr_eq(&pooled, &got),
        "a pool hit returns the pooled channel"
    );
    assert_eq!(
        client.tls_channel_opens(),
        0,
        "a pool hit opens NO new TLS channel (reuse is non-vacuous)"
    );
}

// ----- slice 4c (2nd half): the FAN-OUT ALSO RUNS ON A CACHE HIT (oracle `ziti.go:1708-1714` ≺ `:1716`)
//
// The oracle spawns `go handleConnectEdgeRouter` for every UNCONNECTED router of the session on EVERY
// dial — the hit-return at `:1716` comes AFTER — with a nil `ch` (fire-and-forget), so each opener still
// runs `connectEdgeRouter` + `Upsert` (`:1746`, `:1874`). Without that, a router that is not pooled while
// ANOTHER router of the session is alive would NEVER be pooled: no failover redundancy, no scoring
// candidates.
//
// OBSERVATION SEAM (offline, no TLS server exists in this crate): a live TCP listener at the router's
// address. The background opener's TLS handshake against it necessarily fails, but the ACCEPT is the
// STATE observable that proves the dial was ATTEMPTED — precisely the discriminant of the bug (before:
// the router was never dialed on a hit). The POOLING of a successful background dial is the shared tail
// of `open_and_pool_router` (`pool_store_or_reuse_into`), pinned deterministically by
// `spawn_router_openers_pools_every_addr_fire_and_forget` below and by
// `fan_out_pools_every_success_not_just_the_winner`. Synchronization is by SIGNAL (a oneshot from the
// accept task), never by sleeping and hoping.

/// `pool_unconnected` (the oracle's `unconnected` accumulator, `ziti.go:1697-1699`): a router with an
/// ALIVE pooled channel is CONNECTED (excluded); one with no entry at all is UNCONNECTED (included).
/// The set the cache-hit fan-out spawns over. MUTATION → RED: return every addr (drop the pool check).
#[tokio::test]
async fn pool_unconnected_excludes_the_routers_with_an_alive_pooled_channel() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    let (ch, _io) = fake_channel();
    let _pooled = client.pool_store_or_reuse("tls:pooled:1".to_string(), ch);
    assert_eq!(
        client.pool_unconnected(&["tls:pooled:1".to_string(), "tls:absent:2".to_string()]),
        vec!["tls:absent:2".to_string()],
        "only the router without an alive pooled channel is (re)opened"
    );
}

/// `pool_unconnected`: a router whose pooled channel is DEAD counts as UNCONNECTED — so the cache-hit
/// fan-out RE-OPENS it (the whole point: an evicted dead router must not stay unpooled forever while
/// another router of the session lives). MUTATION → RED: key on mere PRESENCE in the pool (the oracle's
/// own `routerConnections.Get`, `ziti.go:1691`) ⇒ the dead router is never re-dialed.
#[tokio::test]
async fn pool_unconnected_counts_a_dead_pooled_channel_as_unconnected() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    let (ch, io) = fake_channel();
    let arc = client.pool_store_or_reuse("tls:dead:1".to_string(), ch);
    drop(io); // the rx-loop EOFs → the channel dies
    for _ in 0..500u32 {
        if !arc.is_alive() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert!(!arc.is_alive(), "fixture: the pooled channel must be dead");
    assert_eq!(
        client.pool_unconnected(&["tls:dead:1".to_string()]),
        vec!["tls:dead:1".to_string()],
        "a DEAD pooled channel does not count as connected: its router must be re-opened"
    );
}

/// A local TCP listener standing in for an edge router that is NOT in the pool. Returns its `tls:` addr
/// and a receiver that fires on the first accepted connection.
async fn accept_probe() -> (String, tokio::sync::oneshot::Receiver<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a probe listener");
    let addr = listener.local_addr().expect("probe local addr");
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = tx.send(());
            drop(stream); // the opener's TLS handshake then fails — we only prove it DIALED
        }
    });
    (format!("tls:{}:{}", addr.ip(), addr.port()), rx)
}

/// The window an ABSENCE assertion waits before concluding "not dialed". A localhost TCP connect from a
/// spawned task lands in well under a millisecond, so a second is ~3 orders of magnitude of headroom.
const NO_DIAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

/// ★ ACCEPTANCE: a session `{R1, R2}` whose R1 is ALREADY pooled (e.g. by another service's connect)
/// still gets R2 opened — the hit returns R1's channel, and the background fan-out DIALS R2 (the oracle's
/// `:1708-1714` running BEFORE the hit-return of `:1716`, with a nil `ch`). Before this fix the early
/// return meant R2 was NEVER pooled while R1 lived: a permanent degradation to one router.
/// MUTATION → RED: restore the bare early return (`if let Some(c) = pool_get_alive(..) { return Ok(c) }`)
/// ⇒ nothing ever dials R2 ⇒ the probe never accepts ⇒ the timeout fires.
#[tokio::test]
async fn pool_hit_still_fans_out_to_the_sessions_unconnected_routers() {
    let client = EdgeClient::for_test_with_cert_identity("http://x/edge/client/v1", "API-TOK");
    // R1: already pooled and alive → the scoring pick, and the HIT.
    let (ch, _r1_io) = fake_channel();
    ch.seed_latency(100_000);
    let pooled = client.pool_store_or_reuse("tls:r1:1".to_string(), ch);
    // R2: NOT pooled — the probe records the background opener's dial.
    let (r2_addr, dialed) = accept_probe().await;

    let d = detail_with(vec![er("r1", Some("tls:r1:1")), er("r2", Some(&r2_addr))]);
    let got = client
        .open_or_reuse_pooled_channel(&d)
        .await
        .expect("the pool hit returns a channel");

    assert!(
        Arc::ptr_eq(&pooled, &got),
        "the hit still returns the pooled channel (the fan-out must not change WHAT is returned)"
    );
    assert_eq!(
        client.tls_channel_opens(),
        0,
        "the hit does not WAIT for any handshake: the openers are fire-and-forget"
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), dialed)
        .await
        .expect(
            "the background fan-out must DIAL the session's unpooled router R2 (oracle :1708-1714)",
        )
        .expect("the probe's accept task signals before it drops");
}

/// ★ ACCEPTANCE (2nd reachable case): a session `{R_dead, R_alive}` whose R_dead's channel DIED — the
/// scoring evicts it lazily and serves the hit from R_alive — must RE-OPEN R_dead in the background.
/// Before the fix, R_dead stayed unpooled forever (as long as R_alive lived): the session silently
/// degraded to a single router. MUTATION → RED: bare early return ⇒ the dead router is never re-dialed.
#[tokio::test]
async fn pool_hit_reopens_a_router_whose_pooled_channel_died() {
    let client = EdgeClient::for_test_with_cert_identity("http://x/edge/client/v1", "API-TOK");
    // R_dead: pooled at the probe's address, then its router end drops ⇒ the rx-loop EOFs ⇒ dead.
    let (dead_addr, dialed) = accept_probe().await;
    let (dead, dead_io) = fake_channel();
    dead.seed_latency(100_000); // the LOWEST mean — but dead, so it must not win
    let dead_arc = client.pool_store_or_reuse(dead_addr.clone(), dead);
    drop(dead_io);
    // Sync on STATE (not a sleep): wait until the fixture's channel really is dead.
    for _ in 0..500u32 {
        if !dead_arc.is_alive() {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    assert!(
        !dead_arc.is_alive(),
        "fixture: the pooled channel must actually be dead"
    );
    // R_alive: the survivor that serves the hit.
    let (alive, _alive_io) = fake_channel();
    alive.seed_latency(900_000);
    let alive_ptr = client.pool_store_or_reuse("tls:alive:1".to_string(), alive);

    let d = detail_with(vec![
        er("dead", Some(&dead_addr)),
        er("alive", Some("tls:alive:1")),
    ]);
    let got = client
        .open_or_reuse_pooled_channel(&d)
        .await
        .expect("the surviving router serves the hit");
    assert!(
        Arc::ptr_eq(&got, &alive_ptr),
        "the dead entry is evicted and the ALIVE router serves the hit"
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), dialed)
        .await
        .expect("the evicted dead router must be RE-DIALED in the background, not abandoned")
        .expect("the probe's accept task signals before it drops");
}

/// ★ POSITIVE CONTROL (anti-no-op) of the two tests above: the new fan-out must not change WHAT a hit
/// returns, must not duplicate pool entries, and must not dial a router it already has. With BOTH of the
/// session's routers pooled and alive the oracle's `unconnected` is empty ⇒ nothing is dialed, and the
/// SCORING is unchanged — the LOWEST-mean-latency pooled channel still wins, though it is not first-seen.
///
/// Falsifiability of each assert (MEASURED, not assumed):
/// - the SCORING assert reddens under a `max_by_key`/first-alive pick in `pool_get_alive`;
/// - the "no re-dial" asserts (`pooled_channel_count` + the silent probe) are DOUBLE-guarded: by
///   `pool_unconnected` (pinned single-mutation by `pool_unconnected_*`, below) AND by
///   `open_and_pool_router`'s get-first reuse (the oracle's `ziti.go:1749`). Fanning out over ALL `addrs`
///   ALONE leaves them GREEN (the get-first absorbs it — verified); they go RED under the conjunction
///   (fan out over all `addrs` + drop the get-first) — verified. So: defense-in-depth against exactly the
///   refactor that removes both ("the dedup is redundant"), not the primary pin of `pool_unconnected`.
#[tokio::test]
async fn pool_hit_does_not_redial_the_already_pooled_routers() {
    let client = EdgeClient::for_test_with_cert_identity("http://x/edge/client/v1", "API-TOK");
    // The FAST router is pooled AND has a live probe at its address: a redundant dial would be recorded.
    let (fast_addr, dialed) = accept_probe().await;
    let (fast, _fast_io) = fake_channel();
    fast.seed_latency(100_000);
    let fast_ptr = client.pool_store_or_reuse(fast_addr.clone(), fast);
    let (slow, _slow_io) = fake_channel();
    slow.seed_latency(900_000);
    let _slow = client.pool_store_or_reuse("tls:slow:1".to_string(), slow);

    // Addr order [slow, fast]: first-seen is the SLOW one, but the FAST one has the lower mean.
    let d = detail_with(vec![
        er("slow", Some("tls:slow:1")),
        er("fast", Some(&fast_addr)),
    ]);
    let got = client
        .open_or_reuse_pooled_channel(&d)
        .await
        .expect("the pool hit returns a channel");
    assert!(
        Arc::ptr_eq(&got, &fast_ptr),
        "scoring is unchanged: the lowest-mean-latency pooled channel wins, not the first-seen"
    );
    assert_eq!(
        client.pooled_channel_count(),
        2,
        "no duplicate pool entry for an already-pooled router"
    );
    assert_eq!(
        client.tls_channel_opens(),
        0,
        "no TLS handshake is attempted"
    );
    assert!(
        tokio::time::timeout(NO_DIAL_WINDOW, dialed).await.is_err(),
        "an already-pooled ALIVE router must NOT be re-dialed (the fan-out covers the UNCONNECTED only)"
    );
}

/// The `EdgeRouterUrlFilter` gates the CACHE-HIT fan-out too — the oracle's filter sits ON the
/// unconnected-router loop (`isEdgeRouterUrlAccepted`, `:1710`), which is exactly this loop. A rejected
/// R2 is never dialed, and the hit still returns R1. MUTATION → RED: drop the `.filter(..)` from
/// `tls_addrs` (or fan out over the UNFILTERED session routers) ⇒ the rejected probe accepts a dial.
#[tokio::test]
async fn pool_hit_fan_out_honors_the_url_filter() {
    let mut client = EdgeClient::for_test_with_cert_identity("http://x/edge/client/v1", "API-TOK");
    let (ch, _r1_io) = fake_channel();
    ch.seed_latency(100_000);
    let pooled = client.pool_store_or_reuse("tls:r1:1".to_string(), ch);
    let (r2_addr, dialed) = accept_probe().await;
    client.set_edge_router_url_filter(Some(reject_url(r2_addr.clone())));

    let d = detail_with(vec![er("r1", Some("tls:r1:1")), er("r2", Some(&r2_addr))]);
    let got = client
        .open_or_reuse_pooled_channel(&d)
        .await
        .expect("the pool hit returns a channel");
    assert!(
        Arc::ptr_eq(&pooled, &got),
        "the accepted router still serves the hit"
    );
    assert!(
        tokio::time::timeout(NO_DIAL_WINDOW, dialed).await.is_err(),
        "a filter-REJECTED router must not be dialed by the cache-hit fan-out either (:1710)"
    );
}

/// `open_or_reuse_pooled_channel` with no `tls` router ⇒ `NoTlsEdgeRouter` (before any dial).
#[tokio::test]
async fn open_or_reuse_no_tls_router_is_error() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "TOK");
    let d = detail_with(vec![er("r1", None)]);
    let err = client
        .open_or_reuse_pooled_channel(&d)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, EdgeError::NoTlsEdgeRouter));
}
