//! El mapa de vconns del manager UDP del intercept: decisión de ruteo por flujo, entrega, reaping
//! y bump de actividad. (F6 tramo 3a: movido verbatim del monolito de `intercept/udp`.)

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::{FlowKey, Vconn};

/// What to do with an inbound datagram for a given flow: deliver to the existing live vconn, or create a
/// new one. Mirror of T3's `GetWriteQueue`: a present-but-`closed` entry is evicted and treated as absent.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RouteAction {
    Deliver,
    CreateNew,
}

/// Decide how to route a datagram for `key`, evicting a closed entry as a side effect (faithful to the
/// oracle's `GetWriteQueue`, which deletes a closed vconn and returns nil → the caller creates a new one).
pub(super) fn route_decision(conns: &mut HashMap<FlowKey, Vconn>, key: FlowKey) -> RouteAction {
    if let Some(v) = conns.get(&key) {
        if !v.closed.load(Ordering::Acquire) {
            return RouteAction::Deliver;
        }
        conns.remove(&key); // closed → evict, fall through to create
    }
    RouteAction::CreateNew
}

/// Deliver a datagram to a live vconn's inbound queue, non-blocking. A full queue DROPS the datagram
/// (oracle `udpConn.Accept`'s `default:`); a closed queue (vconn torn down, not yet swept) also drops.
/// UDP is lossy — NO backpressure here, unlike the TCP splice's bounded blocking send.
pub(super) fn deliver(vconn: &Vconn, datagram: Vec<u8>) {
    if let Err(mpsc::error::TrySendError::Full(_)) = vconn.in_tx.try_send(datagram) {
        tracing::warn!("intercept udp->ziti: read buffer full, dropping packet");
    }
}

/// Reap closed and idle vconns. Dropping a handle drops its `in_tx`, so the vconn task's `in_rx` returns
/// `None` and it tears down (removal IS the close signal). Oracle: `dropExpired` (`manager.go:133`).
pub(super) fn drop_expired(
    conns: &mut HashMap<FlowKey, Vconn>,
    idle_timeout: Duration,
    now: Instant,
) {
    conns.retain(|_key, v| {
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
