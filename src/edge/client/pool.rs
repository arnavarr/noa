use super::EdgeClient;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Reuse an alive pooled channel for ONE `addr`, lazily evicting a dead entry — the oracle's
/// `connectEdgeRouter` Get-first reuse (`routerConnections.Get(ingressUrl)` + `!IsClosed()`,
/// `ziti.go:1749`). Free-function form (pool handle, not `&self`) so the connect fan-out's detached
/// per-router opener tasks (slice (B) Phase-2) can run it without borrowing `&EdgeClient`.
pub(crate) fn pool_get_alive_one(
    pool: &Mutex<HashMap<String, Arc<crate::edge::data::EdgeChannel>>>,
    addr: &str,
) -> Option<Arc<crate::edge::data::EdgeChannel>> {
    let mut guard = pool.lock().expect("channel-pool mutex poisoned");
    match guard.get(addr) {
        Some(c) if c.is_alive() => Some(c.clone()),
        Some(_) => {
            guard.remove(addr);
            None
        }
        None => None,
    }
}

/// Free-function form of `EdgeClient::pool_store_or_reuse` (first-writer-wins `Upsert`,
/// `ziti.go:1874-1886`), taking the pool + OIDC-2 registry handles so the connect fan-out's detached
/// opener tasks (slice (B) Phase-2) can pool themselves without `&EdgeClient`. Registers a NEW entry in
/// the live-channel registry exactly once (never on reuse). The `std::sync::Mutex` guard is
/// synchronous-only (no `.await` under the lock); the redundant duplicate is dropped after release.
pub(crate) fn pool_store_or_reuse_into(
    pool: &Mutex<HashMap<String, Arc<crate::edge::data::EdgeChannel>>>,
    live: &crate::edge::refresh::LiveChannels,
    addr: String,
    channel: crate::edge::data::EdgeChannel,
) -> Arc<crate::edge::data::EdgeChannel> {
    let mut guard = pool.lock().expect("channel-pool mutex poisoned");
    if let Some(existing) = guard.get(&addr).filter(|c| c.is_alive()).cloned() {
        drop(guard);
        drop(channel); // our duplicate's rx-loop aborts now (lock already released)
        return existing;
    }
    let arc = Arc::new(channel);
    guard.insert(addr, arc.clone());
    drop(guard);
    register_live_channel_into(live, arc.state_weak());
    arc
}

/// Free-function form of [`EdgeClient::register_live_channel`] (OIDC-2 registry): prune dead `Weak`s
/// and push the new one. Taken by the detached opener tasks (slice (B) Phase-2).
pub(crate) fn register_live_channel_into(
    live: &crate::edge::refresh::LiveChannels,
    channel: Weak<crate::edge::data::ChannelState>,
) {
    let mut guard = live.lock().expect("live-channels mutex poisoned");
    guard.retain(|w| w.strong_count() > 0);
    guard.push(channel);
}

impl EdgeClient {
    /// Register a freshly-established channel in the live-channel registry (OIDC-2). Called from
    /// `pool_store_or_reuse` (connect path — the instant a channel is NEWLY pooled, never on a pool
    /// reuse, so a channel is registered exactly once and a 10c race LOSER, dropped inside the race, is
    /// never registered) and from `bind_with_timeout` (bind path, the instant the bind succeeds). Prunes
    /// dead `Weak`s while inserting so a long-lived client doing many connects between refreshes does not
    /// grow the registry unboundedly. Synchronous (the guard never crosses an await).
    ///
    /// NOTE (registry vs pool liveness): the registry prunes by `Weak::strong_count`, NOT by
    /// [`crate::edge::data::EdgeChannel::is_alive`]/`state.closed`. A pooled channel the latency probe has declared dead
    /// (`state.closed` set) still has a live `ChannelState` `Arc` while the pool holds its
    /// `EdgeChannel`, so its `Weak` still upgrades and it stays registered — an OIDC token push in that
    /// window would target a dead channel and time out, but OIDC-2 collects per-channel push errors
    /// without aborting (`update_token` failures are non-fatal). The zombie leaves the registry once the
    /// pool LAZILY EVICTS it (`pool_get_alive`/`pool_store_or_reuse` drop the `EdgeChannel` → its
    /// `ChannelState` `Arc` drops → the `Weak` no longer upgrades → pruned on the next insert).
    pub(crate) fn register_live_channel(&self, channel: Weak<crate::edge::data::ChannelState>) {
        register_live_channel_into(&self.live_channels, channel);
    }

    /// The number of edge-router channels currently in the connection pool. The faithful analogue of
    /// the oracle's `GetRouterConnections` (`ziti.go:341`): one entry per router protocol-address with
    /// a live (or not-yet-lazily-evicted) channel. Useful for diagnostics and for asserting reuse: two
    /// `connect()`s to the same router leave this at 1.
    #[must_use]
    pub fn pooled_channel_count(&self) -> usize {
        self.channel_pool
            .lock()
            .expect("channel-pool mutex poisoned")
            .len()
    }

    /// Diagnostic: the lowest mean latency (nanoseconds) among the currently-pooled channels, or
    /// `None` if the pool is empty — the scoring key the pool minimizes (`pool_get_alive`). After a
    /// `connect()`, the chosen channel is seeded with its handshake RTT (`connectTime`), so this is
    /// finite and > 0; the non-vacuous live observable for the connectTime seed.
    #[must_use]
    pub fn pooled_min_mean_latency_nanos(&self) -> Option<u64> {
        self.channel_pool
            .lock()
            .expect("channel-pool mutex poisoned")
            .values()
            .map(|c| c.mean_latency_nanos())
            .min()
    }

    /// Diagnostic: the largest latency-sample count among the pooled channels, or `None` if the pool
    /// is empty. A pooled channel starts at 1 (the connectTime seed) and gains one sample per latency
    /// probe round-trip (or slow-probe timeout penalty); the non-vacuous live observable for the
    /// probe's RTT recording (>= 2 after at least one probe round).
    #[must_use]
    pub fn pooled_max_latency_sample_count(&self) -> Option<u64> {
        self.channel_pool
            .lock()
            .expect("channel-pool mutex poisoned")
            .values()
            .map(|c| c.latency_sample_count())
            .max()
    }

    /// Scan `addrs` (a session's `tls` router addresses) for pooled alive channels and return the one
    /// with the LOWEST mean latency — the oracle's Phase-1 scoring pick in `getEdgeRouterConn`
    /// (`ziti.go:1689-1701`): among the session's already-connected routers, prefer the lowest-mean
    /// latency one (strict `<`, first-seen wins ties). The per-channel mean is a running mean of the
    /// connectTime seed + latency-probe round-trips + slow-probe timeout penalties (design spec §4;
    /// a conscious simplification of the oracle's decaying-reservoir `Mean()`). LAZY eviction: a pooled
    /// entry whose channel is dead (`!is_alive()`, i.e. `state.closed` is set — by an rx-loop EOF/error
    /// exit OR the latency probe's death-close of a black-holed router) is removed in passing and not a
    /// candidate — the exact mirror of the oracle's get-time `!conn.IsClosed()` check in
    /// `connectEdgeRouter` (`ziti.go:1749`), so a dead router conn is never handed back out. Full scan
    /// (no early break): every dead session-router entry is evicted, then the min picked. The
    /// `std::sync::Mutex` guard is synchronous-only (no `.await` under the lock; `mean_latency_nanos`
    /// is two relaxed atomic loads). Used by [`EdgeClient::open_or_reuse_pooled_channel`].
    ///
    /// SCOPE (scoring slice = (A)): this picks among ALREADY-pooled routers. The pool currently holds at
    /// most one channel per router that has won a race, so >=2 candidates arise when a multi-router
    /// service's router set shares routers already pooled by other services' connects. Pooling EVERY
    /// successful dial on a miss (the oracle's Phase-2 fan-out, which widens how often scoring fires) is
    /// the named follow-up (B) — it needs the detached-spawn refactor of the `select_ok` race.
    pub(crate) fn pool_get_alive(
        &self,
        addrs: &[String],
    ) -> Option<Arc<crate::edge::data::EdgeChannel>> {
        let mut pool = self
            .channel_pool
            .lock()
            .expect("channel-pool mutex poisoned");
        let mut dead: Vec<String> = Vec::new();
        let mut candidates: Vec<(u64, Arc<crate::edge::data::EdgeChannel>)> = Vec::new();
        for addr in addrs {
            if let Some(channel) = pool.get(addr) {
                if channel.is_alive() {
                    candidates.push((channel.mean_latency_nanos(), channel.clone()));
                } else {
                    dead.push(addr.clone());
                }
            }
        }
        for addr in &dead {
            pool.remove(addr);
        }
        // `min_by_key` returns the FIRST element on ties → first-seen (addr order) wins, matching the
        // oracle's strict `h.Mean() < bestLatency`. Option-form (not `best=MAX; strict <`) so a single
        // alive-but-unsampled candidate (mean==MAX — never in practice, pooled channels are seeded) is
        // still returned rather than dropped to a spurious re-dial.
        candidates
            .into_iter()
            .min_by_key(|(mean, _)| *mean)
            .map(|(_, channel)| channel)
    }

    /// The session router addresses with NO alive pooled channel — the oracle's `unconnected` accumulator
    /// in `getEdgeRouterConn` (the `else` arm of its scoring walk, `ziti.go:1697-1699`), i.e. the set it
    /// fans out over on EVERY dial, cache-hit included (`:1708-1714`, before the hit-return at `:1716`).
    /// Called right AFTER [`Self::pool_get_alive`], whose lazy eviction has already removed the dead
    /// entries, so "absent or dead" == "must be (re)opened": a router whose channel died is REOPENED, which
    /// is what keeps a multi-router session from degrading permanently to its one surviving router.
    ///
    /// DEVIATION (in our favor, same class as `pool_get_alive`'s lazy eviction): the oracle's walk keys on
    /// mere PRESENCE in `routerConnections` (`ziti.go:1691`), so a CLOSED-but-still-mapped conn counts as
    /// connected and is neither scored out nor re-dialed; we treat a dead entry as unconnected. No
    /// authorization impact — a channel is not access (every dial/bind carries its session token).
    pub(crate) fn pool_unconnected(&self, addrs: &[String]) -> Vec<String> {
        let pool = self
            .channel_pool
            .lock()
            .expect("channel-pool mutex poisoned");
        addrs
            .iter()
            .filter(|addr| !pool.get(addr.as_str()).is_some_and(|c| c.is_alive()))
            .cloned()
            .collect()
    }

    /// Store a freshly-raced winner channel in the pool keyed by `addr`, with FIRST-WRITER-WINS dedup
    /// (the oracle's `Upsert` callback, `ziti.go:1874-1886`): if a concurrent `connect()` already
    /// pooled an alive channel for `addr`, REUSE theirs and drop ours (its rx-loop aborts once the lock
    /// is released), so at most one live channel per router exists. On a genuine insert (absent, or
    /// replacing a lazily-detected dead entry) the channel is registered in the live-channel registry
    /// (OIDC-2) — ONLY on new insertion, never on reuse, so a reused channel is not re-registered and a
    /// rotated token is not pushed to it twice (the registry iterates unique pool entries once). The
    /// guard is synchronous-only; any redundant channel is dropped AFTER the lock is released.
    ///
    /// Test-only convenience wrapper: production now pools through the free [`pool_store_or_reuse_into`]
    /// (the connect fan-out's detached opener tasks cannot borrow `&EdgeClient`); the pool unit tests
    /// still drive it through `&EdgeClient`, so this delegates.
    #[cfg(test)]
    pub(crate) fn pool_store_or_reuse(
        &self,
        addr: String,
        channel: crate::edge::data::EdgeChannel,
    ) -> Arc<crate::edge::data::EdgeChannel> {
        pool_store_or_reuse_into(&self.channel_pool, &self.live_channels, addr, channel)
    }

    /// The number of edge-router channels this client has opened (TLS handshakes completed). With the
    /// connection pool, reuse keeps this BELOW the number of `connect()` calls — two connects to one
    /// router open exactly one channel. The non-vacuous observable for the pool's reuse.
    #[must_use]
    pub fn tls_channel_opens(&self) -> usize {
        self.tls_opens.load(Ordering::Relaxed)
    }

    /// Install (or clear, with `None`) the edge-router URL filter — the oracle's
    /// `Options.EdgeRouterUrlFilter` (`options.go:47`), which noa-sdk exposes as a setter because it has
    /// no `Options` struct (building one would be alien scope). Consulted wherever a session's router
    /// URLs are enumerated for a dial or a bind; **`None` (the default, and the oracle's `nil`) accepts
    /// every URL** (`isEdgeRouterUrlAccepted`, `options.go:50-51`). The filter is handed the
    /// POST-sanitize form `tls:host:port`, not the `tls://host:port` the controller emits — see
    /// [`crate::edge::router_filter::EdgeRouterUrlFilter`], which OWNS that contract. A filter can only
    /// ever REMOVE routers from the candidate set — it never grants access to one that would otherwise
    /// be unusable, and it is not an authorization boundary (the controller authorizes, via
    /// `POST /sessions`).
    pub fn set_edge_router_url_filter(
        &mut self,
        filter: Option<crate::edge::router_filter::EdgeRouterUrlFilter>,
    ) {
        self.edge_router_url_filter = filter;
    }

    /// The installed edge-router URL filter, if any (the oracle's `context.options`, read at each
    /// enumeration site). Borrowed, not cloned: the router-selection paths consult it synchronously.
    pub(crate) fn edge_router_url_filter(
        &self,
    ) -> Option<&crate::edge::router_filter::EdgeRouterUrlFilter> {
        self.edge_router_url_filter.as_ref()
    }

    /// Clone of the channel-pool handle, for the connect fan-out's detached `'static` opener tasks
    /// (slice (B) Phase-2 — they cannot borrow `&EdgeClient`, so they own `Arc` clones of the shared
    /// state via [`crate::edge::channel::RouterOpenerCtx`]).
    pub(crate) fn channel_pool_handle(
        &self,
    ) -> Arc<Mutex<HashMap<String, Arc<crate::edge::data::EdgeChannel>>>> {
        self.channel_pool.clone()
    }

    /// Clone of the OIDC-2 live-channel registry handle, for the connect fan-out's detached opener tasks.
    pub(crate) fn live_channels_handle(&self) -> crate::edge::refresh::LiveChannels {
        self.live_channels.clone()
    }

    /// Clone of the TLS-open counter handle, so a detached opener task can bump it on a completed
    /// handshake (the sole handshake site is `dial_handshake`, used by both `open_channel_to` and the
    /// fan-out). Relaxed ordering: a monotone diagnostic counter, no happens-before is needed.
    pub(crate) fn tls_opens_handle(&self) -> Arc<AtomicUsize> {
        self.tls_opens.clone()
    }

    /// Test-only count of entries in the live-channel registry (OIDC-2), to assert that a POOL reuse
    /// does NOT re-register a channel (no duplicate token pushes).
    #[cfg(test)]
    pub(crate) fn live_channel_count(&self) -> usize {
        self.live_channels
            .lock()
            .expect("live-channels mutex poisoned")
            .len()
    }
}
