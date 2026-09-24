//! Fan-out de openers detached del connect: `RouterOpenerCtx`, `open_and_pool_router`,
//! `fan_out_first_ok` (first-OK; los perdedores corren hasta el final y se poolean) y
//! `spawn_router_openers` (fire-and-forget del cache-HIT), acotados por `ROUTER_DIAL_TIMEOUT`.
//! (F6 tramo 6: movido verbatim del monolito de `edge/channel`.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::channel::address::parse_tls_address;
use crate::edge::data::EdgeChannel;
use crate::edge::error::EdgeError;

use super::dial::dial_handshake;

/// Per-router dial timeout for the connect fan-out's detached opener tasks (slice (B)). Mirror of the
/// oracle's `options.ConnectTimeout = 15 * time.Second` applied to EVERY `connectEdgeRouter` goroutine
/// (`ziti.go:1810-1811`, threaded into `dialer.CreateWithHeaders` / `NewChannelWithUnderlay`). Load-
/// bearing: a `tokio::spawn`ed loser ESCAPES `connect_inner`'s outer connect-timeout (which cancels only
/// the foreground flow), so without this per-dial cap a router that completes TCP+TLS but withholds the
/// channel Result would hang the detached task forever — pinning the pool's `Arc` clones (and every
/// healthy pooled channel's rx-loop+probe+socket) past `EdgeClient` drop. Applied in `fan_out_first_ok`
/// (wrapping each opener), NOT inside `dial_handshake` — so `bind`'s validated 60s `bind_with_timeout`
/// per-dial budget (via `open_channel`→`open_channel_to`→`dial_handshake`, which never goes through the
/// fan-out) is unchanged.
pub(super) const ROUTER_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// `'static` context for a detached per-router opener task (slice (B) Phase-2 fan-out-and-pool-all).
/// Every field is owned/`Arc` so the task can run AFTER the winning connect returns — the oracle's
/// `go handleConnectEdgeRouter` goroutine (`ziti.go:1711`), which `Upsert`s its channel regardless of the
/// select winner. The mTLS `ClientConfig` + leaf CN + token are computed ONCE per connect (they are
/// per-CLIENT, not per-router — the oracle's `GetIdentity` returns the same identity for every router) and
/// shared by clone, so each loser does NOT recompute the (possibly network-bound `updb`) config.
#[derive(Clone)]
pub(crate) struct RouterOpenerCtx {
    pub(crate) cc: Arc<rustls::ClientConfig>,
    pub(crate) cn: String,
    pub(crate) token: String,
    pub(crate) channel_pool: Arc<Mutex<HashMap<String, Arc<EdgeChannel>>>>,
    pub(crate) live_channels: crate::edge::refresh::LiveChannels,
    pub(crate) tls_opens: Arc<std::sync::atomic::AtomicUsize>,
}

/// Open and POOL one router — the body of the oracle's `connectEdgeRouter` (`ziti.go:1746`): a Get-first
/// reuse check (`:1749`), then the mTLS+Hello dial, then a first-writer-wins `Upsert` into the pool
/// (`:1874-1886`). `Send + 'static` (borrows no `&EdgeClient`), so it is `tokio::spawn`able as a detached
/// background task that pools itself even after the winning connect has returned.
pub(crate) async fn open_and_pool_router(
    ctx: RouterOpenerCtx,
    addr: String,
) -> Result<Arc<EdgeChannel>, EdgeError> {
    // Get-first: another connect may have pooled this addr meanwhile → reuse without dialing (oracle
    // `connectEdgeRouter` `routerConnections.Get` + `!IsClosed()`, `ziti.go:1749`).
    if let Some(existing) = crate::edge::client::pool_get_alive_one(&ctx.channel_pool, &addr) {
        return Ok(existing);
    }
    let (host, port) = parse_tls_address(&addr)?;
    // The dial is bounded by the per-router timeout in `fan_out_first_ok` (which wraps this whole opener):
    // a DETACHED loser ESCAPES `connect_inner`'s outer connect-timeout, so the per-router cap is what keeps
    // "let the losers finish" bounded (no TLS-stall hang / pool-Arc leak). On a timeout the fan-out cancels
    // this future, dropping any partial `EdgeChannel` (whose `Drop` aborts its rx-loop).
    let channel = dial_handshake(
        &host,
        port,
        ctx.cc.clone(),
        &ctx.cn,
        &ctx.token,
        &ctx.tls_opens,
    )
    .await?;
    Ok(crate::edge::client::pool_store_or_reuse_into(
        &ctx.channel_pool,
        &ctx.live_channels,
        addr,
        channel,
    ))
}

/// Fan out `open_one` over EVERY `addr` as a detached `tokio::spawn` task and return the FIRST `Ok` — the
/// oracle's `getEdgeRouterConn` select on `ch` (`ziti.go:1722-1731`). The losers are NOT cancelled: each
/// task runs to completion in the background (the oracle's per-router `go handleConnectEdgeRouter`
/// goroutine, which `Upsert`s its channel regardless of who won the select). Detached is the FAITHFUL port:
/// the oracle's goroutines outlive both the select winner AND the outer connect timeout, running to
/// completion + `Upsert`; a late task holds `Arc` clones, pools into a pool kept alive by its own clone,
/// and when it finishes the last `Arc` drops → `EdgeChannel::Drop` reaps its rx-loop+probe. A detached
/// task ESCAPES `connect_inner`'s outer connect-timeout (which cancels only the foreground flow), so each
/// opener is bounded INDIVIDUALLY by the per-router [`ROUTER_DIAL_TIMEOUT`] inside `open_and_pool_router`
/// (the oracle's per-goroutine `options.ConnectTimeout`, `ziti.go:1810-1811`) — that, not the connect-timeout,
/// is what makes "let the losers finish" bounded (no unbounded hang / pool-Arc leak). Each genuine
/// per-router failure logs `warn!` (slice O3; now EVERY router's
/// failure logs, not only those completing before the winner). On all-fail returns the LAST error received
/// (slice 10c; the connect-timeout, slice 10b, bounds the wait — WHICH error is "last" is now
/// nondeterministic across the concurrent tasks, a conscious widening of 10c's deterministic last-error,
/// same class as 10c's own deviation from the oracle's block-until-deadline). Empty `addrs` →
/// [`EdgeError::NoTlsEdgeRouter`]. Each opener is bounded by `dial_timeout` ([`ROUTER_DIAL_TIMEOUT`] in
/// production = the oracle's per-goroutine `options.ConnectTimeout`, `ziti.go:1810-1811`): the load-bearing cap
/// that keeps a DETACHED loser from hanging forever (it escapes `connect_inner`'s outer connect-timeout) —
/// on a per-router timeout the opener future is cancelled (dropping any partial channel) and reported as a
/// dial failure. `open_one` and its future must be `Send + 'static` so the losers outlive this call.
/// Generic over the future so the fan-out logic is unit-testable with fake openers (no TLS).
pub(crate) async fn fan_out_first_ok<T, F, O>(
    addrs: Vec<String>,
    open_one: O,
    dial_timeout: std::time::Duration,
) -> Result<T, EdgeError>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, EdgeError>> + Send + 'static,
    O: Fn(String) -> F,
{
    if addrs.is_empty() {
        return Err(EdgeError::NoTlsEdgeRouter);
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<T, EdgeError>>(addrs.len());
    for addr in addrs {
        // Build the future EAGERLY (every router is dialed) then move it into a detached task.
        let fut = open_one(addr.clone());
        let tx = tx.clone();
        tokio::spawn(async move {
            // Per-router timeout: a TLS-stall router (TCP+TLS up, Result withheld) would otherwise hang
            // this detached task forever (it escapes the outer connect-timeout) and pin the pool's `Arc`
            // clones past `EdgeClient` drop. On elapse `fut` is dropped (cancelling the dial, any partial
            // channel's `Drop` aborting its rx-loop) and we report a per-router dial failure.
            let r = match tokio::time::timeout(dial_timeout, fut).await {
                Ok(r) => r,
                Err(_) => Err(EdgeError::ChannelTls(format!(
                    "router dial timed out after {dial_timeout:?}"
                ))),
            };
            if let Err(e) = &r {
                tracing::warn!(router = %addr, error = %e, "edge router connect failed");
            }
            let _ = tx.send(r).await; // a winner-already-returned drop of `rx` just fails this send
        });
    }
    drop(tx); // so `rx` closes once every task has reported
    let mut last_err = None;
    while let Some(r) = rx.recv().await {
        match r {
            // First success wins; the remaining tasks keep running and pool themselves in the background.
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(EdgeError::NoTlsEdgeRouter))
}

/// Fire-and-forget fan-out: `tokio::spawn` one DETACHED opener per `addr` and return IMMEDIATELY, with NO
/// result channel — the oracle's `go handleConnectEdgeRouter(name, addr, ch)` with a **nil `ch`**
/// (`ziti.go:1711` when `bestER != nil` ⇒ `ch` was never made, `:1703-1706`), whose `if ret != nil` guard
/// (`:1738`) then discards the result: the goroutine still runs `connectEdgeRouter` + `Upsert`
/// (`:1746`, `:1874`), so the router IS pooled, nobody waits for it, and its failure is only logged.
/// The sibling of [`fan_out_first_ok`] for the CACHE-HIT path of [`EdgeClient::open_or_reuse_pooled_channel`](crate::edge::client::EdgeClient::open_or_reuse_pooled_channel):
/// same per-router bound (`dial_timeout` = [`ROUTER_DIAL_TIMEOUT`], the oracle's per-goroutine
/// `options.ConnectTimeout`, `ziti.go:1810-1811` — load-bearing, a detached opener escapes the connect-timeout),
/// same `Send + 'static` opener, same self-pooling ([`open_and_pool_router`]) — only the winner-select is
/// gone, because on a hit there is no winner to wait for. Generic over the opener so the spawn/pool
/// behavior is unit-testable without TLS.
pub(crate) fn spawn_router_openers<T, F, O>(
    addrs: Vec<String>,
    open_one: O,
    dial_timeout: std::time::Duration,
) where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, EdgeError>> + Send + 'static,
    O: Fn(String) -> F,
{
    for addr in addrs {
        let fut = open_one(addr.clone());
        tokio::spawn(async move {
            let r = match tokio::time::timeout(dial_timeout, fut).await {
                Ok(r) => r.map(|_| ()),
                Err(_) => Err(EdgeError::ChannelTls(format!(
                    "router dial timed out after {dial_timeout:?}"
                ))),
            };
            if let Err(e) = r {
                // Distinct from the fan-out's "edge router connect failed": nobody is waiting on this dial,
                // so its failure is NOT the reason any `connect()` failed — it only means one router of the
                // session stays unpooled (and will be retried by the next dial's fan-out).
                tracing::warn!(router = %addr, error = %e, "background edge-router connect failed");
            }
        });
    }
}
