//! Async edge data channel runtime: a background rx-loop, a ConnId mux, and the
//! per-connection read/write (EdgeConn). Oracle: channel/impl.go rxer + edge msg_mux.go.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};

use crate::channel::message::Message;
use crate::edge::crypto::{Decryptor, Encryptor, STREAM_HEADER_BYTES, SessionKey};

mod accept;
mod channel;
mod channel_state;
mod conn;
mod inspect;
mod rxloop;
mod wire;

pub(crate) use conn::server_crypto_setup;
pub use wire::{build_latency_probe, build_update_token};

#[cfg(test)]
mod tests_accept;
#[cfg(test)]
mod tests_channel;
#[cfg(test)]
mod tests_channel_state;
#[cfg(test)]
mod tests_conn;
#[cfg(test)]
mod tests_inspect;
#[cfg(test)]
mod tests_wire;
#[cfg(test)]
mod testsupport;

/// Boxed stream halves: keeps `ChannelState`/`EdgeConn`/`EdgeChannel` concrete (not
/// generic) while staying testable over `tokio::io::duplex` halves.
pub(crate) type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub(crate) type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Shared channel state: the write half, the reply-waiter map, the ConnId mux, and
/// the per-channel sequence / conn-id allocators (both pre-increment from 0).
pub(crate) struct ChannelState {
    write: AsyncMutex<BoxWrite>,
    waiters: Mutex<HashMap<i32, oneshot::Sender<Message>>>,
    conns: Mutex<HashMap<u32, mpsc::Sender<Message>>>,
    /// Accept queues for registered binds (this identity hosting). Keyed by the bind conn-id;
    /// the rx-loop routes inbound `Dial`/bind-`StateClosed` here. Disjoint from `conns`, and the
    /// disjointness is one of RANGES, NOT of provenance: an accepted child's conn-id is the
    /// router's when the `Dial` carries `RouterProvidedConnId`, and OURS when it does not
    /// (`hosting_conn.go:290-296`), so "child ids come from the router" no longer holds. What does
    /// hold — and structurally, not by margin — is the range split: the router seeds its ids in
    /// `[2^31, 2^32-1]`, and OUR allocator now CLAMPS its own to `[1, 2^31-3]` exactly like the
    /// oracle, rewinding at `maxId = (MaxUint32/2)-1 = 2^31-2` (`ziti/edge/msg_mux.go:302,337-352`;
    /// port: [`self::channel_state::alloc_conn_id`]). The measured argument with its oracle
    /// citations lives on [`self::inspect::classify_conn_inspect`].
    binds: Mutex<HashMap<u32, mpsc::Sender<Message>>>,
    seq: AtomicI32,
    next_conn_id: AtomicU32,
    /// Liveness substrate for the latency probe (the independent death detector). `base` is a monotonic
    /// origin captured at channel creation; `last_read` stores `base.elapsed().as_millis()` of the most
    /// recent successful `read_message` in [`self::rxloop::rx_loop`]. The probe closes the channel when no read has
    /// progressed for longer than the probe interval. Oracle: `channel.lastRead` + `GetTimeSinceLastRead`
    /// (`channel/v4 impl.go:345,492`), consumed by `TimeoutHandler` (`ziti.go:1899`).
    base: Instant,
    last_read: AtomicU64,
    /// One-shot "channel is closing" gate. `closed` is the CAS'd terminal flag; `close_notify` wakes the
    /// SINGLE [`self::rxloop::rx_loop`] task when it is parked on a backpressured per-conn dispatch (`tx.send().await`),
    /// so it stops masking router death. The healthy siblings are woken instead by [`Self::mark_closed`]
    /// clearing the maps (dropping their senders → EOF) — BOTH effects are load-bearing. Oracle: the
    /// per-conn sequencer's `select` over `externalCloseNotify` (`sdk-golang .../network/seq.go:51-57`).
    closed: AtomicBool,
    close_notify: Notify,
    /// Per-channel latency accumulator for the router-pool scoring pick (`pool_get_alive` chooses
    /// the lowest-mean-latency alive channel among a session's routers). Seeded at channel creation
    /// with the handshake RTT (`connectTime`), updated by the latency probe with each round-trip and
    /// penalized with the full timeout on a slow-but-not-dead probe. A running mean (`sum/count`,
    /// equal weight over this channel's lifetime) — a conscious simplification of the oracle's
    /// decaying-reservoir `Mean()` (`ExpDecaySample(128, 0.015)`); see the scoring design spec §4.
    /// This accumulator is per-`ChannelState`, so it RESETS when a router is re-dialed; the oracle's
    /// histogram is addr-keyed in `context.metrics` and persists across channel generations (it is
    /// ref-counted and never net-disposed while scoring keeps `Get`-ing it), carrying recency-decayed
    /// cross-generation samples — a second, benign deviation noted in §4. Relaxed atomics: a monotone
    /// heuristic; the two reads are not a single snapshot but a transiently-stale mean is harmless
    /// for one selection. Oracle: the `latency.<addr>` histogram (`ziti.go:1689-1701`/`:1888-1903`).
    latency_sum_nanos: AtomicU64,
    latency_count: AtomicU64,
}

/// `UpdateToken` content type (60803): a control message that hands a router a freshly-rotated
/// api-session token so a long-lived channel does not go stale when the token rotates (OIDC refresh).
/// Body = the raw token BYTES (`GetToken()`), NO headers. Oracle: `ContentTypeUpdateToken`
/// (`ziti/edge/messages.go:65`), `NewUpdateTokenMsg` (`:529`).
pub const CT_UPDATE_TOKEN: i32 = 60803;
/// `UpdateTokenSuccess` (60801): the router accepted the rotated token. Oracle `:66`.
pub const CT_UPDATE_TOKEN_SUCCESS: i32 = 60801;
/// `UpdateTokenFailure` (60802): the router rejected the rotated token (body = the reason). Oracle `:67`.
pub const CT_UPDATE_TOKEN_FAILURE: i32 = 60802;

/// The per-channel `UpdateToken` reply budget: the oracle calls `erConn.UpdateToken(token, 10*time.Second)`
/// (`ziti.go:981`) — a 10s timeout on `SendForReply`. Bounds a router that reads the push but never
/// replies (without it the push would hang the refresh / proactive timer).
pub const UPDATE_TOKEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Default latency-probe cadence (oracle `ziti.go:74-75`): probe every 30s, await the reply 10s.
/// A HOL-stall (a non-draining sibling parks the rx-loop's dispatch) that outlasts the interval makes
/// the read-idle check fire and tears the channel down — faithful (the oracle's single rxer is starved
/// the same way), bounded at ~interval(+timeout).
pub(crate) const LATENCY_CHECK_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const LATENCY_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of one latency-probe round (see [`ChannelState::send_latency_probe`]).
enum ProbeOutcome {
    /// A reply arrived (correlated by sequence) → the channel is making read progress.
    Alive,
    /// No reply within the timeout → the caller checks read-idle to decide on teardown.
    Timeout,
    /// The probe write failed (transport dead) → death; the caller closes.
    WriteError,
    /// The channel closed (waiters cleared) before the reply → already torn down.
    Closed,
}

/// Per-connection e2e crypto state. `sender` encrypts writes; `decryptor` is built lazily
/// from the first inbound 24-byte Data frame (the host's stream header), consuming `rx_key`.
pub(crate) struct ConnCrypto {
    pub(crate) sender: Encryptor,
    pub(crate) decryptor: Option<Decryptor>,
    pub(crate) rx_key: Option<SessionKey>,
}

/// Read-side e2e crypto: the lazily-built `decryptor` and the `rx_key` consumed by the first
/// inbound 24-byte stream-header frame. The write-side `sender` lives in [`EdgeWriteHalf`]. This is
/// exactly the read-side of [`ConnCrypto`], split out so the read half is self-contained.
struct ReadCrypto {
    decryptor: Option<Decryptor>,
    rx_key: Option<SessionKey>,
}

/// The read half of a split [`EdgeConn`]: the inbound queue + EOF latch + the read-side crypto.
/// Disjoint from [`EdgeWriteHalf`] so a tunneler splice can read one direction while writing the
/// other concurrently (the oracle's two-goroutine `myCopy`). Obtained via [`EdgeConn::into_split`].
pub struct EdgeReadHalf {
    conn_id: u32,
    rx: mpsc::Receiver<Message>,
    read_eof: bool,
    /// `None` = plaintext conn; `Some` is the read-side of [`ConnCrypto`].
    crypto: Option<ReadCrypto>,
    /// The oracle's `sentFIN` (`ziti/edge/network/conn.go:111-113`), SHARED with [`EdgeWriteHalf`]
    /// (same `Arc`). The read half STORES it when it processes an inbound `StateClosed`
    /// (`AcceptMessage` `:361`: the conn is dead ⇒ no more writes), and NEVER for a FIN (`:761`
    /// sets only `readFIN`) nor an rx-hangup (`:751` = sequencer closed, `readFIN` only). This is the
    /// FIN-vs-`StateClosed` discriminant: the write half consults the same flag and fails after a
    /// `StateClosed`, but keeps working after a FIN (half-close).
    sent_fin: Arc<AtomicBool>,
}

/// The write half of a split [`EdgeConn`]: the shared channel state + the write-side crypto
/// (`sender`) + the FIN latch. Disjoint from [`EdgeReadHalf`]. Obtained via [`EdgeConn::into_split`].
pub struct EdgeWriteHalf {
    conn_id: u32,
    state: Arc<ChannelState>,
    first_write: bool,
    /// `None` = plaintext conn; `Some` is the write-side of [`ConnCrypto`].
    sender: Option<Encryptor>,
    /// The oracle's `sentFIN` (`ziti/edge/network/conn.go:111-113`, "no more data can be sent"),
    /// SHARED with [`EdgeReadHalf`] (same `Arc`, so a `StateClosed` observed by the read half is
    /// seen here). THREE setters, mirroring the oracle: our `close_write` (the compare-and-set that
    /// makes it an idempotent half-close latch, `CloseWrite` `:243`), our `close` (`:862`), and the
    /// read half on an inbound `StateClosed` (`AcceptMessage` `:361`). `write` CONSULTS it (load) and
    /// returns [`EdgeError::WriteAfterClose`](crate::edge::error::EdgeError::WriteAfterClose) BEFORE
    /// serializing if set (`Write` `:216-220`). An `Arc<AtomicBool>` (not a plain `bool`) so both
    /// halves share one flag AND `close_write`/`close` take `&self` — the splice's per-direction task
    /// can half-close the peer without owning `&mut self`.
    sent_fin: Arc<AtomicBool>,
}

/// One virtual connection over the channel. Read pulls Data from the conn's queue;
/// write sends Data frames over the shared write half; close sends StateClosed. Holds a
/// [`EdgeReadHalf`] + [`EdgeWriteHalf`]; the public read/write/close methods delegate to them (a
/// single source of truth), and [`EdgeConn::into_split`] hands the halves out for the tunneler
/// splice (which needs to read and write the same connection from two concurrent directions).
pub struct EdgeConn {
    circuit_id: Option<String>,
    source_identity: Option<String>,
    reader: EdgeReadHalf,
    writer: EdgeWriteHalf,
}

/// Async edge channel handle: owns the background rx-loop task and the shared state.
/// `dial` establishes a connection through the rx-loop (its StateConnected returns via
/// a reply-waiter). Oracle: the SDK runs the rxer from channel open and dials via
/// SendForReply.
pub struct EdgeChannel {
    state: Arc<ChannelState>,
    rx_task: Option<tokio::task::JoinHandle<()>>,
    /// The independent latency-probe / death-detector task (see [`self::wire::run_latency_probe`]). Aborted on
    /// `close`/`Drop` alongside `rx_task`.
    probe_task: Option<tokio::task::JoinHandle<()>>,
    /// Headers from the channel Hello/Result (slice 3): router id + hello version.
    result_headers: std::collections::BTreeMap<i32, Vec<u8>>,
}

/// A dial accepted on a bind queue but NOT yet acknowledged: validated (the token; plus a child
/// conn-id that is the router's when the `Dial` carried a readable `RouterProvidedConnId` and OURS,
/// generated, when it did not — `ziti/edge/network/hosting_conn.go:290-296`), the child registered
/// in the mux, and server crypto computed (header not yet sent). A
/// forwarding host dials its target BETWEEN accept and ack, then calls [`complete_success`] (which
/// writes DialSuccess then the host crypto stream-header) on a reachable target or [`complete_failed`]
/// (DialFailed) on an unreachable one — the faithful order (oracle
/// `CompleteAcceptSuccess`/`CompleteAcceptFailed` under `ManualStart=true`, so DialSuccess and the
/// stream-header reach the wire only when the target is reachable). Holds an `Arc<ChannelState>` clone
/// (NOT a `&mut binding` borrow), so the accept loop can pull the next dial while this child's target
/// dial is in flight.
///
/// [`complete_success`]: PendingAccept::complete_success
/// [`complete_failed`]: PendingAccept::complete_failed
pub struct PendingAccept {
    state: Arc<ChannelState>,
    bind_conn_id: u32,
    child_id: u32,
    /// Whether `child_id` came from the `Dial`'s `RouterProvidedConnId` header (`true`) or was
    /// GENERATED by us because the header was absent or not 4 bytes long (`false`). The oracle's
    /// `routerProvidedConnId`, ONE boolean that is born in `newChildConnection`
    /// (`hosting_conn.go:290`), travels in the `newConnHandler` (`:380`) and decides in
    /// `dialSucceeded` (`conn.go:992`) whether the `DialSuccess` waits for a `StateConnected`.
    router_provided: bool,
    dial_seq: i32,
    data_rx: mpsc::Receiver<Message>,
    circuit_id: Option<String>,
    source_identity: Option<String>,
    app_data: Option<Vec<u8>>,
    crypto_setup: Option<(ConnCrypto, [u8; STREAM_HEADER_BYTES])>,
}
