// F6 tramo 3b troceo: tests movidos verbatim del monolito de `tunnel/udp` (mod tests).

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::tunnel::proxy::PROXY_BUF;

use super::flow::{RouteAction, deliver, drop_expired, route_decision};
use super::testsupport::*;
use super::vconn::{VconnSpawnParts, create_vconn};
use super::{
    MAX_UDP_PACKET_SIZE, VCONN_IDLE_TIMEOUT, VCONN_POLL_INTERVAL, VCONN_QUEUE_DEPTH, Vconn,
};

// ───────────────────────── constants (oracle-pinned) ─────────────────────────

#[test]
fn constants_match_the_oracle() {
    assert_eq!(MAX_UDP_PACKET_SIZE, 65507, "info.MaxUdpPacketSize");
    assert_eq!(VCONN_QUEUE_DEPTH, 16, "udpConn.readC cap");
    assert_eq!(VCONN_IDLE_TIMEOUT, Duration::from_secs(300), "5min idle");
    assert_eq!(VCONN_POLL_INTERVAL, Duration::from_secs(30), "30s poll");
    assert_eq!(PROXY_BUF, 0x4000 - 17, "copyBuf");
}

// ───────────────────────── route_decision (GetWriteQueue) ─────────────────────────

#[test]
fn route_decision_creates_for_absent_delivers_for_open_recreates_for_closed() {
    let mut conns: HashMap<SocketAddr, Vconn> = HashMap::new();
    // Absent → create.
    assert_eq!(route_decision(&mut conns, addr(1)), RouteAction::CreateNew);

    // Present + open → deliver.
    let (v, _rx, _lu, closed) = vconn_handle();
    conns.insert(addr(1), v);
    assert_eq!(route_decision(&mut conns, addr(1)), RouteAction::Deliver);
    assert!(conns.contains_key(&addr(1)), "open entry kept");

    // Present + closed → evict + create (oracle GetWriteQueue deletes the closed entry).
    closed.store(true, Ordering::Release);
    assert_eq!(route_decision(&mut conns, addr(1)), RouteAction::CreateNew);
    assert!(
        !conns.contains_key(&addr(1)),
        "closed entry evicted so a fresh vconn replaces it"
    );
}

// ───────────────────────── deliver (Accept drop-on-full) ─────────────────────────

#[test]
fn deliver_queues_until_full_then_drops() {
    let (v, mut rx, _lu, _closed) = vconn_handle();
    // The first VCONN_QUEUE_DEPTH datagrams queue; the next is DROPPED (try_send, not blocking).
    for i in 0..VCONN_QUEUE_DEPTH {
        deliver(&v, vec![u8::try_from(i).unwrap()]);
    }
    deliver(&v, vec![0xFF]); // 17th → dropped, no block, no panic
    let mut got = Vec::new();
    while let Ok(d) = rx.try_recv() {
        got.push(d[0]);
    }
    assert_eq!(
        got.len(),
        VCONN_QUEUE_DEPTH,
        "exactly the queue depth survived"
    );
    assert_eq!(
        got.last(),
        Some(&u8::try_from(VCONN_QUEUE_DEPTH - 1).unwrap())
    );
    assert!(
        !got.contains(&0xFF),
        "the over-capacity datagram was dropped"
    );
}

#[test]
fn deliver_on_closed_queue_drops_without_panicking() {
    let (v, rx, _lu, _closed) = vconn_handle();
    drop(rx); // receiver gone → try_send returns Closed
    deliver(&v, vec![1, 2, 3]); // must not panic
}

// ───────────────────────── create_vconn (CreateWriteQueue) ─────────────────────────

#[test]
fn create_vconn_inserts_handle_and_queues_first_datagram() {
    let mut conns: HashMap<SocketAddr, Vconn> = HashMap::new();
    let captured: Rc<RefCell<Option<VconnSpawnParts>>> = Rc::new(RefCell::new(None));
    let cap = Rc::clone(&captured);
    create_vconn(&mut conns, addr(5), b"first".to_vec(), move |parts| {
        *cap.borrow_mut() = Some(parts);
    });
    assert!(conns.contains_key(&addr(5)), "handle inserted into the map");
    let (s, mut in_rx, _lu, _c) = captured.borrow_mut().take().unwrap();
    assert_eq!(s, addr(5));
    assert_eq!(
        in_rx.try_recv().unwrap(),
        b"first",
        "the first datagram is queued before the dial (Accept-then-DialAndRun)"
    );
}

// ───────────────────────── drop_expired (dropExpired) ─────────────────────────

#[test]
fn drop_expired_reaps_idle_and_closed_keeps_fresh() {
    let mut conns: HashMap<SocketAddr, Vconn> = HashMap::new();
    let now = Instant::now();
    let idle = Duration::from_secs(300);

    // Fresh (just used) → kept.
    let (fresh, _rx0, _lu0, _c0) = vconn_handle();
    conns.insert(addr(1), fresh);

    // Idle past the timeout → reaped.
    let (idle_v, _rx1, lu1, _c1) = vconn_handle();
    *lu1.lock().unwrap() = now.checked_sub(Duration::from_secs(301)).unwrap();
    conns.insert(addr(2), idle_v);

    // Closed (even if recently used) → reaped.
    let (closed_v, _rx2, _lu2, c2) = vconn_handle();
    c2.store(true, Ordering::Release);
    conns.insert(addr(3), closed_v);

    drop_expired(&mut conns, idle, now);

    assert!(conns.contains_key(&addr(1)), "fresh vconn kept");
    assert!(!conns.contains_key(&addr(2)), "idle vconn reaped");
    assert!(!conns.contains_key(&addr(3)), "closed vconn swept");
}

#[test]
fn drop_expired_keeps_a_vconn_used_within_the_window() {
    let mut conns: HashMap<SocketAddr, Vconn> = HashMap::new();
    let now = Instant::now();
    let (v, _rx, lu, _c) = vconn_handle();
    *lu.lock().unwrap() = now.checked_sub(Duration::from_secs(299)).unwrap(); // just under 5min
    conns.insert(addr(1), v);
    drop_expired(&mut conns, Duration::from_secs(300), now);
    assert!(conns.contains_key(&addr(1)), "299s < 300s → kept");
}
