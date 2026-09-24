//! `impl ChannelState`: the shared channel state's behaviour (mux registration, sequence/conn-id
//! allocation, latency-probe send, update-token push, best-effort dial-failed). The struct
//! definition and its fields live in the parent [`super`] module (`data/mod.rs`); these methods see
//! the private fields by descendance. Split out of the monolithic `edge/data` module (F6 tramo 1b),
//! byte-identical.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};

use crate::channel::connect::write_message;
use crate::channel::message::{HDR_REPLY_FOR, Message};
use crate::edge::bind::build_dial_failed;
use crate::edge::error::EdgeError;

use super::wire::{
    build_latency_probe, build_update_token, classify_update_token_reply, elapsed_millis,
};
use super::{BoxWrite, ChannelState, ProbeOutcome};

/// Lower bound of the conn-id range, EXCLUSIVE of nothing: the oracle's `mux.minId`
/// (`ziti/edge/msg_mux.go:315`), which is NEVER written — `NewChannelConnMapMux` assigns only
/// `maxId` (`:302`), so `minId` keeps its zero-value. It is also the rewind DESTINATION
/// (`atomic.StoreUint32(&mux.nextId, mux.minId)`, `:345`).
pub(super) const MIN_CONN_ID: u32 = 0;

/// Upper bound (EXCLUSIVE) of the conn-id range: the oracle's `maxId: (math.MaxUint32 / 2) - 1`
/// (`ziti/edge/msg_mux.go:302`) = `2^31-2`. A candidate `>= MAX_CONN_ID` rewinds, so the SDK's ids
/// live in `[1, 2^31-3]` (plus the `0` reachable only by the counter wrapping — see
/// [`alloc_conn_id`]), disjoint from the router's `[2^31, 2^32-1]`.
pub(super) const MAX_CONN_ID: u32 = (u32::MAX / 2) - 1;

/// Port 1:1 of the oracle's `ConnMuxImpl.GetNextId` (`ziti/edge/msg_mux.go:337-352`): allocate the
/// next conn-id, SKIPPING ids already in use and REWINDING the counter to `min_id` when the
/// candidate leaves `[min_id, max_id)`. The three loop branches, in the oracle's order:
/// (i) `in_use` ⇒ advance; (ii) out of range ⇒ `store(min_id)` + advance; (iii) ⇒ return.
///
/// `atomic.AddUint32` returns the NEW value and WRAPS (Go's modular arithmetic), so the port uses
/// `wrapping_add(1)`: with the counter at `u32::MAX` the candidate is `0`, which IS in range and is
/// returned (golden cell `C-09`) — a bare `+ 1` would PANIC in debug.
///
/// `min_id`/`max_id` travel as PARAMETERS, not as constants inlined in the comparison (deviation
/// `D-2` of the slice spec): with `const MIN_ID: u32 = 0` the faithful transcription
/// `next < MIN_ID || next >= MAX_ID` is REJECTED by the repo's clippy gate
/// (`absurd_extreme_comparisons` + `manual_range_contains`), and the oracle itself holds them as
/// FIELDS of the mux, not as constants. `Ordering::Relaxed` where Go's `sync/atomic` is seq-cst
/// (`D-1`): id uniqueness comes from the atomic RMW under ANY ordering, and the "in use" lookups
/// take a `Mutex`, which supplies acquire/release.
///
/// ⚠ Loops forever if EVERY id in `[min_id, max_id)` is in use — exactly like the oracle
/// (`D-5`): ~2^31 live conns on one channel, unreachable within any memory budget.
pub(super) fn alloc_conn_id(
    counter: &AtomicU32,
    min_id: u32,
    max_id: u32,
    in_use: impl Fn(u32) -> bool,
) -> u32 {
    let mut next_id = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    loop {
        if in_use(next_id) {
            // (i) in use ⇒ try the next one (`msg_mux.go:340-342`).
            next_id = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        } else if next_id < min_id || next_id >= max_id {
            // (ii) free but out of the valid range ⇒ reset to the beginning of the range
            // (`msg_mux.go:343-346`, con el `Store` en `:345`).
            counter.store(min_id, Ordering::Relaxed);
            next_id = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        } else {
            // (iii) free AND in range ⇒ return it (`msg_mux.go:347-350`).
            return next_id;
        }
    }
}

impl ChannelState {
    pub(crate) fn new(write: BoxWrite) -> Self {
        Self {
            write: AsyncMutex::new(write),
            waiters: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            binds: Mutex::new(HashMap::new()),
            seq: AtomicI32::new(0),
            next_conn_id: AtomicU32::new(0),
            base: Instant::now(),
            last_read: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
            latency_sum_nanos: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
        }
    }

    /// Record one latency sample (nanoseconds) into the running-mean accumulator used by the
    /// router-pool scoring pick. Called at channel creation with the handshake RTT (`connectTime`
    /// seed), by [`Self::send_latency_probe`] with each probe round-trip, and by [`super::wire::run_latency_probe`]
    /// with the full timeout on a slow-but-not-dead probe. Lock-free; monotone. Mirrors the oracle's
    /// `h.Update(...)` (`ziti.go:1888`/`ResultHandler`/`TimeoutHandler` else-branch).
    pub(crate) fn record_latency(&self, nanos: u64) {
        self.latency_sum_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Mean recorded latency in nanoseconds (the scoring key). `u64::MAX` for an unsampled channel
    /// (`count==0`) so it sorts last — a pooled channel is always seeded with its `connectTime`, so
    /// in practice `count>=1`. The two relaxed loads are not a single atomic snapshot; a transiently
    /// stale mean is harmless for one selection. Mirrors the oracle's `metrics.Histogram.Mean()`,
    /// simplified to a running mean (design spec §4).
    pub(crate) fn mean_latency_nanos(&self) -> u64 {
        let count = self.latency_count.load(Ordering::Relaxed);
        if count == 0 {
            return u64::MAX;
        }
        self.latency_sum_nanos.load(Ordering::Relaxed) / count
    }

    /// Number of latency samples recorded (seed + probe rounds). Test/diagnostic observability for
    /// the scoring slice (the connectTime seed is sample 1; each probe round adds one).
    pub(crate) fn latency_sample_count(&self) -> u64 {
        self.latency_count.load(Ordering::Relaxed)
    }

    /// Record that a frame was just read off the transport (called by [`super::rxloop::rx_loop`] after each successful
    /// `read_message`). Lock-free; monotonic. Feeds the latency probe's read-idle death check.
    pub(super) fn note_read(&self) {
        self.last_read
            .store(elapsed_millis(self.base), Ordering::Relaxed);
    }

    /// Milliseconds since the last successful transport read. Mirrors `GetTimeSinceLastRead`
    /// (`channel/v4 impl.go:492`). Used by the probe to decide "no read progress → close".
    pub(super) fn millis_since_last_read(&self) -> u64 {
        elapsed_millis(self.base).saturating_sub(self.last_read.load(Ordering::Relaxed))
    }

    /// Whether this channel has been torn down (the `closed` teardown flag is set). The exact analogue
    /// of the oracle's `Channel.IsClosed()`. Set once by [`ChannelState::mark_closed`] on every death
    /// path (rx-loop EOF exit, `close`, `Drop`, the latency probe's two death paths). Used by the
    /// OIDC-2 token-push to SKIP a dead-but-still-registered channel: the router connection pool holds a
    /// strong `Arc<EdgeChannel>` (hence a live `ChannelState` `Arc`) for a pooled channel that has died,
    /// so its registry `Weak` still upgrades — pushing a rotated token to it would write into the
    /// half-closed transport and then block the full `UPDATE_TOKEN_TIMEOUT` waiting a reply the gone
    /// rx-loop can never deliver. (Also the basis for [`super::EdgeChannel::is_alive`].)
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Mark the channel closed: clear the mux maps (dropping the per-conn/bind senders → every parked
    /// `read()`/`accept()` EOFs) AND wake the [`super::rxloop::rx_loop`] if it is parked on a backpressured dispatch
    /// (via `close_notify`). Idempotent (CAS on `closed`). This is the single teardown primitive shared
    /// by `EdgeChannel::close`/`Drop`, the rx-loop's own EOF path, and the latency probe's death close.
    ///
    /// Both effects matter: clearing the map alone does NOT release a dispatch-stalled rx-loop (it holds
    /// a *clone* of the stalled conn's sender from the dispatch site, so the receiver is still alive and
    /// `send().await` keeps blocking); the `close_notify` is what releases it.
    pub(super) fn mark_closed(&self) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.close_notify.notify_waiters();
            self.waiters.lock().unwrap().clear();
            self.conns.lock().unwrap().clear();
            self.binds.lock().unwrap().clear();
        }
    }

    /// Send a latency probe (`CT_LATENCY`=3) and await the router's reply, correlated by `HDR_REPLY_FOR`
    /// (the router replies with a `Result` carrying `ReplyTo(seq)`; we match by sequence so the reply
    /// content type is irrelevant). Reuses the dial/update-token reply-waiter path with NO change to
    /// `rx_loop`'s reply routing. On a reply this records the round-trip time into the scoring
    /// accumulator (`record_latency`, the lowest-mean pool pick's input) — the mirror of the oracle's
    /// `ResultHandler(resultNanos)` (`ziti.go:1890`). We measure the RTT locally with the monotonic
    /// `base.elapsed()` rather than reading back the reflected `probeTime` header (header id 128, which
    /// the router DOES echo); the two are value-equal. Oracle: `latency.ProbeLatencyConfigurable`
    /// (`channel/v4 latency/latency.go:82-95`).
    pub(super) async fn send_latency_probe(&self, timeout: Duration) -> ProbeOutcome {
        let seq = self.next_seq();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.waiters.lock().unwrap().insert(seq, reply_tx);

        // Monotonic, infallible probe time, captured BEFORE the send so the reply arm can compute the
        // RTT (`base.elapsed() - now_nanos`) for the scoring accumulator. The router DOES reflect this
        // header back (id 128 has the reflected bit `1<<7`, so the reply's `ReplyTo` copies it —
        // `channel/v4 message.go` `ReflectedHeaderBitMask`); we measure the RTT locally instead of
        // reading the echo (value-equal). Sent for wire fidelity with the oracle's `probeTime` header
        // (we use monotonic `base.elapsed()` nanos; the oracle uses wall-clock — same value, no skew).
        let now_nanos = u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let mut msg = build_latency_probe(now_nanos);
        msg.sequence = seq;
        // Bound the ENTIRE acquire+write, not just the reply wait: a black-holed transport write — or a
        // concurrent bulk writer wedged on the write `AsyncMutex` (so we never even acquire it) — would
        // otherwise park the probe here forever, defeating the death detector and re-introducing the very
        // hang this slice fixes. On timeout we drop the inner future (releasing any acquired lock) and
        // report `WriteError` → teardown. The oracle's separate txer goroutine carries an analogous
        // `WriteTimeout` (`channel/v4 impl.go`).
        let send = tokio::time::timeout(timeout, async {
            let mut w = self.write.lock().await;
            write_message(&mut *w, &msg).await
        })
        .await;
        // `Err(Elapsed)` (wedged send) and `Ok(Err)` (transport error) are both death → `WriteError`.
        if !matches!(send, Ok(Ok(()))) {
            self.waiters.lock().unwrap().remove(&seq);
            return ProbeOutcome::WriteError;
        }

        match tokio::time::timeout(timeout, reply_rx).await {
            // Any reply (matched by sequence) means the channel is making progress → alive.
            Ok(Ok(_reply)) => {
                // Round-trip time for the router-pool scoring accumulator: the elapsed since the
                // probe was sent (monotonic `base.elapsed()`; equals the oracle's reflected-`probeTime`
                // `now - sentTime` in value). Mirrors `ResultHandler(resultNanos)` (`ziti.go:1890`).
                let rtt = u64::try_from(self.base.elapsed().as_nanos())
                    .unwrap_or(u64::MAX)
                    .saturating_sub(now_nanos);
                self.record_latency(rtt);
                ProbeOutcome::Alive
            }
            // The channel closed (rx-loop cleared the waiters) before a reply.
            Ok(Err(_)) => ProbeOutcome::Closed,
            // No reply within the budget: drop the stale waiter and report a timeout.
            Err(_elapsed) => {
                self.waiters.lock().unwrap().remove(&seq);
                ProbeOutcome::Timeout
            }
        }
    }

    /// Register a connection's inbound queue under its id. Called by `dial` (production)
    /// and directly by tests that wire up `rx_loop` without going through `dial`.
    ///
    /// No-op if the channel is already closing: `mark_closed` sets `closed` BEFORE taking the map lock,
    /// so checking `closed` while holding the lock makes a registration that races a teardown either be
    /// dropped here (→ the new conn's `tx` is dropped → its `read()` EOFs immediately) or land before the
    /// `mark_closed` clear (which then drops it). Closes the post-teardown orphan race the probe enlarges.
    pub(crate) fn register_conn(&self, conn_id: u32, tx: mpsc::Sender<Message>) {
        let mut conns = self.conns.lock().unwrap();
        if !self.closed.load(Ordering::Acquire) {
            conns.insert(conn_id, tx);
        }
    }

    /// Register a bind's accept queue under its conn-id. Called by `send_bind` (production) and
    /// by tests that exercise `rx_loop` routing directly. No-op if the channel is already closing (same
    /// race-closing rationale as [`Self::register_conn`]).
    pub(crate) fn register_bind(&self, conn_id: u32, tx: mpsc::Sender<Message>) {
        let mut binds = self.binds.lock().unwrap();
        if !self.closed.load(Ordering::Acquire) {
            binds.insert(conn_id, tx);
        }
    }

    /// Number of connections currently registered in the mux. Test-only observability for the
    /// tunneler splice's "both directions done → deregister exactly once" invariant.
    #[cfg(test)]
    pub(crate) fn conn_count(&self) -> usize {
        self.conns.lock().unwrap().len()
    }

    pub(crate) fn next_seq(&self) -> i32 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Whether `id` is already taken by this channel's mux — the port's equivalent of the oracle's
    /// `mux.sinks.Get(id)` (`ziti/edge/msg_mux.go:340`, el lookup DENTRO de `GetNextId`). The oracle keeps ONE sink map holding dial
    /// conns (`factory.go:139`), bind conns (`factory.go:201`) and accepted children
    /// (`hosting_conn.go:347`) at once; the port splits them into `conns` and `binds`, so the
    /// equivalent predicate is their UNION, not either half. `conns` first — the same tie-break
    /// [`super::inspect::classify_conn_inspect`] and the rx-loop's `CT_STATE_CLOSED` already use.
    ///
    /// The `||` does NOT nest the two locks: each operand of `||` is its own temporary scope, so the
    /// first guard is dropped before the second `lock()` runs (MEASURED on the repo's toolchain).
    pub(super) fn conn_id_in_use(&self, id: u32) -> bool {
        self.conns.lock().unwrap().contains_key(&id) || self.binds.lock().unwrap().contains_key(&id)
    }

    /// Allocate this channel's next conn-id with the oracle's clamped, skip-in-use generator
    /// ([`alloc_conn_id`] = `ConnMuxImpl.GetNextId`, `ziti/edge/msg_mux.go:337-352`). The three
    /// oracle call-sites map here: `NewDialConn` (`factory.go:118`), `NewListenConn`
    /// (`factory.go:179`) and the accept's generate branch (`hosting_conn.go:294`).
    pub(crate) fn next_conn_id(&self) -> u32 {
        alloc_conn_id(&self.next_conn_id, MIN_CONN_ID, MAX_CONN_ID, |id| {
            self.conn_id_in_use(id)
        })
    }

    /// Push a rotated api-session token to the router behind this channel (`UpdateToken`, ct 60803),
    /// awaiting the router's `UpdateTokenSuccess`/`UpdateTokenFailure` reply (correlated by sequence
    /// via `ReplyFor`, the SAME reply-waiter path Bind/Dial use — so the rx-loop routes the reply with
    /// NO change). Bounded by `timeout` so a non-responding router cannot hang the caller. Oracle:
    /// `routerConn.UpdateToken(token, 10s)` (`ziti/edge/network/factory.go:157`).
    ///
    /// # Errors
    /// - [`EdgeError::UpdateTokenFailed`] if the router replies `UpdateTokenFailure` (reason = body),
    ///   the reply does not arrive within `timeout`, or the reply has an unexpected content type.
    /// - [`EdgeError::ChannelClosed`] if the channel closes before a reply.
    /// - [`EdgeError::Channel`] on a frame/IO write error.
    pub(crate) async fn update_token(
        &self,
        new_token: &str,
        timeout: Duration,
    ) -> Result<(), EdgeError> {
        let seq = self.next_seq();
        let (reply_tx, reply_rx) = oneshot::channel();
        // Register the reply-waiter BEFORE sending (avoids the reply-before-registration race), exactly
        // like `dial`/`send_bind`.
        self.waiters.lock().unwrap().insert(seq, reply_tx);

        let mut msg = build_update_token(new_token.as_bytes());
        msg.sequence = seq;
        let send = {
            let mut w = self.write.lock().await;
            write_message(&mut *w, &msg).await
        };
        if let Err(e) = send {
            self.waiters.lock().unwrap().remove(&seq);
            return Err(e.into());
        }

        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(reply)) => classify_update_token_reply(&reply),
            // The channel closed (rx-loop cleared the waiters on EOF) before a reply.
            Ok(Err(_)) => Err(EdgeError::ChannelClosed),
            // The router never replied within the budget: drop the now-stale waiter and report.
            Err(_elapsed) => {
                self.waiters.lock().unwrap().remove(&seq);
                Err(EdgeError::UpdateTokenFailed {
                    reason: "timed out waiting for UpdateToken reply".to_string(),
                })
            }
        }
    }

    /// Best-effort `DialFailed` reply (the oracle sends it fire-and-forget; on a closing channel the
    /// write may legitimately fail). Rejects a dial without killing the listener. Lives on
    /// `ChannelState` (not `EdgeChannel`) so `accept_pending` (pre-target rejects),
    /// [`super::PendingAccept::complete_failed`] (target-unreachable) and
    /// [`super::PendingAccept::complete_success`]'s start-handshake failure (all holding only an
    /// `Arc<ChannelState>`) reach it.
    ///
    /// ⚠ `conn_id` is NOT always the bind's: the oracle's two producers disagree ON PURPOSE.
    /// `dialFailed` (the `complete_failed` path) uses the BIND (`self.conn.Id()` with `self.conn` =
    /// the `edgeHostConn`, `conn.go:971`); `CompleteAcceptSuccess`'s failure reply uses the CHILD
    /// (`conn.Id()` with `conn` = the child `edgeConn` the handler hangs off, `conn.go:902` +
    /// `hosting_conn.go:385`). This helper just puts whatever `u32` it is given in the `ConnId`.
    pub(super) async fn send_dial_failed(&self, conn_id: u32, dial_seq: i32, reason: &str) {
        let mut msg = build_dial_failed(conn_id, reason);
        msg.headers
            .insert(HDR_REPLY_FOR, dial_seq.to_le_bytes().to_vec());
        msg.sequence = self.next_seq();
        let mut w = self.write.lock().await;
        let _ = write_message(&mut *w, &msg).await;
    }
}
