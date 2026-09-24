//! Proxy-UDP tunneler mode (T3): a local UDP listener whose datagrams are demultiplexed by source
//! address into per-source virtual connections, each dialing the ziti `service`. The UDP sibling of
//! T1 (proxy-TCP) — but UDP is connectionless, so there is no `splice`/half-close: instead a single
//! shared socket fans datagrams out by `srcAddr` into per-source vconns, and idle vconns are reaped.
//!
//! Oracle: `openziti/ziti` v2.0.0 `tunnel/intercept/proxy/proxy.go` (`handleUDP`,
//! `generateReadEvents`), `tunnel/udp_vconn/{manager,conn,policy}.go`, and `tunnel/tunnel.go`
//! (`Run`/`myCopy`, `halfClose=false` for UDP). `info.MaxUdpPacketSize = 65507`.
//!
//! Model (faithful to the oracle's single `manager.run()` goroutine):
//! - [`run_udp_proxy`] is the manager actor: it OWNS `conns` (no locking — single owner) and
//!   `select!`s a `recv_from` against an expiration tick.
//! - A new `srcAddr` → insert a [`Vconn`] handle + `spawn_local` a vconn task that dials ziti
//!   (via the pooled `connect()`, like T1 — the router channel is SHARED, multiplexed by conn-id)
//!   and pumps both directions.
//! - **udp→ziti**: ONE ziti `Data` frame per WHOLE datagram (≤65507) — the oracle's `WriteTo` path.
//! - **ziti→udp**: each `read()` chunk split at [`PROXY_BUF`](crate::tunnel::proxy::PROXY_BUF) (16367) into UDP datagrams — the
//!   oracle's generic `io.CopyBuffer` copyBuf path (VERIFIED: in sdk-golang v1.7.0 `edgeConn` is not an
//!   `io.WriterTo` and `udpConn` is not an `io.ReaderFrom`, so `io.CopyBuffer(udpConn, edgeConn)` falls
//!   to the generic loop; a >16367 chunk IS split — datagram boundaries are not preserved above 16367,
//!   by oracle design). Asymmetric with udp→ziti, exactly like the oracle.
//! - **Drop-on-full**: inbound delivery is a non-blocking `try_send` on a cap-[`VCONN_QUEUE_DEPTH`]
//!   (16) queue — full ⇒ DROP the datagram (oracle `udpConn.Accept`'s `default:`). UDP is lossy;
//!   there is NO backpressure (contrast T1/T2's blocking send).
//! - **halfClose=false**: no FIN. A ziti EOF cascades to a full-close of the vconn (oracle `myCopy`'s
//!   `dst.Close()` with `halfClose=false`).
//! - **Idle reaping**: a vconn idle in BOTH directions for [`VCONN_IDLE_TIMEOUT`] (5min) is reaped on
//!   the [`VCONN_POLL_INTERVAL`] (30s) tick; closed vconns are swept too. The shared socket is never
//!   closed by a vconn (oracle `sharedWriteConn=true` ⇒ `ownsWriteConn=false`).
//!
//! Conscious deviations (documented; auto-proceed):
//! 1. A `recv_from` error stops the WHOLE proxy (`?`), AND — because the bin drives this via
//!    `LocalSet::run_until(run_udp_proxy(..))` — the error unwinds out of `run_until`, the `LocalSet`
//!    drops, and ALL live `spawn_local` vconns are aborted. The oracle is softer: `manager.run()` only
//!    logs a non-`io.EOF` read error and keeps the ticker + established vconns alive (only `io.EOF`
//!    stops the loop). A bound UDP listener's `recv_from` error is effectively fatal, so "stop
//!    everything" matches the accept-error deviation [`crate::tunnel::run_tcp_proxy`] documents (the
//!    proxy's lifetime is the socket); the larger blast radius (established vconns torn down) is the
//!    honest difference.
//! 2. NOT udp4-only. The oracle `handleUDP` hard-rejects IPv6 (`To4()==nil` + `ListenUDP("udp4")`).
//!    We key by `SocketAddr` and `send_to` it back → IPv4 and IPv6 both work (strictly more general).
//! 3. On ziti-EOF teardown the udp→ziti direction FLUSHES the ≤16 buffered datagrams to the ziti conn
//!    before the StateClosed — CLOSED (was a conscious under-permit divergence). Mirrors the oracle's
//!    `udpConn.WriteTo` loop, which drains `readC` to empty after `closeNotify` (conn.go:71-97: select
//!    :76-83, `buf==nil → io.EOF` :85-87, `w.Write`+`markUsed`+abort :91-96) — the two `myCopy`
//!    goroutines are joined independently and `Close` only closes `closeNotify`, not `readC`
//!    (conn.go:162-163). The `done` arm of [`pump_udp_to_ziti`](pump::pump_udp_to_ziti) now drains a SNAPSHOT (`in_rx.len()`
//!    datagrams, one whole Data frame each, bump per datagram, abort on the first write error) via
//!    [`drain_queued_to_ziti`](pump::drain_queued_to_ziti). The EVICTION arm was ALREADY faithful and is UNTOUCHED: `in_tx` dropped →
//!    `recv()` yields `None` only once the queue is EMPTY, so the writer drains all buffered datagrams
//!    before ending. (The C tunneler has NO queue at all, so it does not arbitrate this.)
//!
//!    DV-1 (era una micro-desviación *under-permit*) — **CERRADA** (rebanada teardown-window): el flush
//!    es un SNAPSHOT (`in_rx.len()` fijo), y ahora eso NO pierde nada, porque [`mark_closed`](pump::mark_closed) pone
//!    `closed` **AL ABRIR** la ventana de derribo (espejo de conn.go:162-163: la bandera ANTES del
//!    `closeNotify` que dispara el drenado), no después del `join!`. Con `closed` puesto antes del
//!    drenado, el manager (single-threaded) YA NO entrega a la conn moribunda: la ve cerrada, la evicta
//!    (`GetWriteQueue`→nil, manager.go:83-87) y RE-DIALEA una conn fresca (`CreateWriteQueue` →
//!    `DialAndRun`, manager.go:91-116; llamante proxy.go:375-388) por la que el datagrama SÍ viaja.
//!    ⇒ nada nuevo entra en la cola moribunda ⇒ el snapshot ES, demostrablemente, la cola ENTERA ⇒
//!    equivale punto por punto al bucle "drenar hasta vaciar" del oráculo (conn.go:73-98), con la ventaja
//!    de que el conteo fijo GARANTIZA terminación.
//!
//!    The `biased;` join! (reader polled first — see [`drive_vconn`](pump::drive_vconn)) makes this DETERMINISTIC: a
//!    ziti-EOF already queued is observed BEFORE the writer pulls anything, so the writer's first action
//!    is the draining `done` arm. It used to be a COIN FLIP (the old `select!` / a plain `join!`
//!    randomize which branch is polled first). A plain `join!` cannot replace the `select!` on its own —
//!    udp→ziti never ends by itself and would hang the join — hence the local `done` signal.
//! 4. **DV-TW (teardown-window): marcamos `closed` desde AMBOS brazos; el oráculo, solo desde el brazo
//!    ziti→udp.** [`mark_closed`](pump::mark_closed) se llama al retornar CUALQUIERA de los dos pumps de [`drive_vconn`](pump::drive_vconn).
//!    En el oráculo, `Run` lanza `myCopy(clientConn, zitiConn, …)` —ziti→udp, `dst == udpConn`— y
//!    `myCopy(zitiConn, clientConn, …)` —udp→ziti, `dst == zitiConn`— (`tunnel.go:98-100`), y el `defer`
//!    de `myCopy` cierra **su `dst`** (`tunnel.go:126-135`, rama `else` porque `halfClose == false` para
//!    UDP). ⇒ el `closed` del `udpConn` (`conn.go:162`) lo pone SOLO la goroutine ziti→udp; la udp→ziti
//!    cierra la conn ZITI, y el `udpConn` se cierra después por cascada (el lector ve la conn ziti
//!    cerrada y su `defer` la cierra) o, en el límite, por el `defer` de `Run` (`tunnel.go:102-105`).
//!    **Efecto:** en el camino «error de escritura a ziti» (falla el `zw.write` de [`pump_udp_to_ziti`](pump::pump_udp_to_ziti) y
//!    ese pump retorna primero) evictamos y RE-DIALEAMOS **antes** que el oráculo. **Cota:** esa antelación (lo que el oráculo
//!    tarda en cascadear el cierre). **Dirección:** estrictamente **menos pérdida** (beyond-oracle en
//!    robustez, no en autorización) y **JAMÁS over-permit**: cada conn nueva pasa por el camino completo
//!    de dial-session (`POST /sessions` + `Connect`), no se entrega un byte sin autorizar. Se acepta y se
//!    NOMBRA (antes estaba sin registrar). La ruta ziti→udp (EOF/error de lectura/`send_to`) SÍ es espejo
//!    exacto del `dst.Close()` del oráculo.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

mod flow;
mod pump;
mod runner;
mod vconn;

#[cfg(test)]
mod tests_flow;
#[cfg(test)]
mod tests_pump;
#[cfg(test)]
mod tests_teardown;
#[cfg(test)]
mod tests_window;
#[cfg(test)]
mod testsupport;

pub use runner::run_udp_proxy;

/// Max UDP datagram payload over IPv4 (65535 − 8 UDP − 20 IP). The per-datagram read buffer size.
/// Oracle: `info.MaxUdpPacketSize` (openziti/foundation) = 65507.
pub const MAX_UDP_PACKET_SIZE: usize = 65507;

/// Per-source inbound queue depth: datagrams waiting to be forwarded to ziti. When full, a new
/// datagram is DROPPED (UDP is lossy — no backpressure). Oracle: `udpConn.readC` = `make(chan .., 16)`.
const VCONN_QUEUE_DEPTH: usize = 16;

/// Idle reaping threshold: a vconn with no traffic in EITHER direction for this long is reaped.
/// Oracle: `defaultExpirationPolicy.IsExpired` = `now − lastUsed > 5*time.Minute` (`policy.go:61`).
pub const VCONN_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Cadence of the idle-reaping sweep. Oracle: `defaultExpirationPolicy.PollFrequency` = `30*time.Second`.
pub const VCONN_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// A per-source virtual connection handle, held by the manager in its `conns` map (the oracle's
/// `connMap` value, `udp_vconn.udpConn`). The vconn TASK owns the other ends (`in_rx`, the ziti
/// halves); this handle is the manager's side.
struct Vconn {
    /// Inbound datagrams (udp→ziti). Bounded ([`VCONN_QUEUE_DEPTH`]); full ⇒ drop (oracle `Accept`).
    in_tx: mpsc::Sender<Vec<u8>>,
    /// Last activity in EITHER direction (the vconn task bumps it on each datagram drained/sent); the
    /// manager reads it in [`self::flow::drop_expired`]. Oracle: `udpConn.lastUse` (atomic), bumped in
    /// `WriteTo`/`Write`, read by `dropExpired`.
    last_use: Arc<Mutex<Instant>>,
    /// Set by the vconn task at teardown (dial failure OR ziti EOF OR write/send error). The manager
    /// treats a `closed` handle as absent (create a fresh vconn) and sweeps it. Oracle:
    /// `udpConn.closed` (atomic), checked in `GetWriteQueue`/`dropExpired`.
    closed: Arc<AtomicBool>,
}
