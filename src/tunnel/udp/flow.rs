//! El mapa de vconns del manager proxy-UDP (T3): decisión de ruteo por `srcAddr`, entrega
//! drop-on-full, reaping de ociosos y bump de actividad. (F6 tramo 3b: movido verbatim del monolito de
//! `tunnel/udp`.)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::Vconn;

/// What to do with an inbound datagram for a given source: deliver to the existing live vconn, or
/// create a new one. Mirrors the oracle's `GetWriteQueue` (`manager.go:77`): a present-but-`closed`
/// entry is evicted and treated as absent.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RouteAction {
    Deliver,
    CreateNew,
}

/// Decide how to route a datagram for `src`, evicting a closed entry as a side effect (faithful to
/// `GetWriteQueue`, which `delete`s a closed vconn and returns nil → the caller creates a new one).
pub(super) fn route_decision(
    conns: &mut HashMap<SocketAddr, Vconn>,
    src: SocketAddr,
) -> RouteAction {
    if let Some(v) = conns.get(&src) {
        if !v.closed.load(Ordering::Acquire) {
            return RouteAction::Deliver;
        }
        conns.remove(&src); // closed → evict, fall through to create
    }
    RouteAction::CreateNew
}

/// Deliver a datagram to a live vconn's inbound queue, non-blocking. A full queue DROPS the datagram
/// (oracle `udpConn.Accept`'s `default:` → `Warnf("read buffer full, dropping packet")`); a closed
/// queue (vconn already torn down, not yet swept) also drops. UDP is lossy by nature — there is NO
/// backpressure here, unlike the TCP splice's bounded blocking send.
pub(super) fn deliver(vconn: &Vconn, datagram: Vec<u8>) {
    // Ok → queued; Closed → vconn gone (not yet swept) → silently drop; Full → drop + warn.
    if let Err(mpsc::error::TrySendError::Full(_)) = vconn.in_tx.try_send(datagram) {
        tracing::warn!("udp->ziti: read buffer full, dropping packet");
    }
}

/// Reap closed and idle vconns. Dropping a handle drops its `in_tx`, so the vconn task's `in_rx`
/// returns `None` and it tears down (removal IS the close signal — the oracle's `manager.close` →
/// `conn.Close()` → `closeNotify`). Oracle: `dropExpired` (`manager.go:133`): delete closed entries,
/// `close` expired ones.
pub(super) fn drop_expired(
    conns: &mut HashMap<SocketAddr, Vconn>,
    idle_timeout: Duration,
    now: Instant,
) {
    conns.retain(|_src, v| {
        if v.closed.load(Ordering::Acquire) {
            return false;
        }
        let last = *v.last_use.lock().unwrap();
        now.duration_since(last) <= idle_timeout
    });
}

/// Bump a vconn's last-activity timestamp (oracle `markUsed`).
pub(super) fn bump(last_use: &Mutex<Instant>) {
    *last_use.lock().unwrap() = Instant::now();
}
