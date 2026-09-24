//! Tests for the FIXED host mode (T2) and the shared per-dial core.
//!
//! (F6 tramo 9: movido verbatim del monolito de `tunnel/host`.)

use super::HOST_DIAL_TIMEOUT;
use super::dial::handle_host_conn;
use super::testsupport::{
    DIAL_SEQ, TEST_CONN_ID, fake_pending, fin_frame, flags_of, tcp_echo_once,
};
use crate::channel::connect::read_message;
use crate::channel::message::{HDR_REPLY_FOR, Message};
use crate::edge::bind::{CT_DIAL_FAILED, CT_DIAL_SUCCESS};
use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, build_data};
use std::time::Duration;
use tokio::net::TcpListener;

fn reply_for_of(msg: &Message) -> Option<i32> {
    msg.headers
        .get(&HDR_REPLY_FOR)
        .map(|v| i32::from_le_bytes(v[..4].try_into().unwrap()))
}

/// Full happy path (T4a order): handle_host_conn dials the local TCP target FIRST; on success it
/// `complete_success`-es the accept (so the router sees DialSuccess), then splices — the dialer's
/// inbound bytes flow to the target and the echo flows back to ziti, a ziti-side EOF (inbound FIN)
/// is forwarded as a socket half-close, the target's EOF comes back as a FIN frame, and after both
/// directions finish the splice does the single full-close (StateClosed) and deregisters the child.
/// The CHANNEL is NOT closed (the binding owns it). Load-bearing test for the host direction.
#[tokio::test]
async fn handle_host_conn_round_trips_through_local_tcp_then_tears_down() {
    let (pending, state, data_tx, mut router) = fake_pending();
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo_listener.local_addr().unwrap().to_string();
    let echo = tokio::spawn(tcp_echo_once(echo_listener));

    let router_task = tokio::spawn(async move {
        let mut echoed = Vec::new();
        let mut saw_dial_success = false;
        let mut saw_fin = false;
        let mut saw_state_closed = false;
        loop {
            let Ok(msg) = read_message(&mut router).await else {
                break;
            };
            match msg.content_type {
                CT_DIAL_SUCCESS => saw_dial_success = true,
                CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => saw_fin = true,
                CT_DATA => echoed.extend_from_slice(&msg.body),
                CT_STATE_CLOSED => {
                    saw_state_closed = true;
                    break;
                }
                _ => {}
            }
        }
        (saw_dial_success, echoed, saw_fin, saw_state_closed)
    });

    // Inject the dialer's inbound bytes, then a FIN (ziti EOF). They wait in the mpsc until
    // complete_success builds the EdgeConn; the splice then writes "hello-host" to the target, the
    // echo returns it (observed on the router after DialSuccess), then the FIN half-closes the
    // target → its EOF → FIN back to ziti → StateClosed.
    data_tx
        .send(build_data(TEST_CONN_ID, b"hello-host", false))
        .await
        .unwrap();
    data_tx.send(fin_frame()).await.unwrap();
    drop(data_tx); // the mux still holds the registered clone; this local handle is done

    handle_host_conn(pending, target, None, HOST_DIAL_TIMEOUT).await;

    let (saw_dial_success, echoed, saw_fin, saw_state_closed) = router_task.await.unwrap();
    echo.await.unwrap();
    assert!(
        saw_dial_success,
        "complete_success sent DialSuccess AFTER the target dial succeeded"
    );
    assert_eq!(
        echoed, b"hello-host",
        "target echo round-tripped back to ziti"
    );
    assert!(
        saw_fin,
        "the target's EOF was forwarded to ziti as a FIN frame"
    );
    assert!(
        saw_state_closed,
        "the splice sent StateClosed (full close) after both directions ended"
    );
    assert_eq!(
        state.conn_count(),
        0,
        "the child was deregistered from the mux exactly once"
    );
}

/// T4a — the FLIPPED deviation (was: target-unreachable → StateClosed after an eager DialSuccess):
/// a target that is unreachable (a bound-then-dropped port → ECONNREFUSED) now makes
/// handle_host_conn send **DialFailed** (the faithful accept-then-dial order — the dialer's
/// `connect()` fails), with NO DialSuccess ever on the wire, and the child deregistered. A
/// regression to the eager-ack path would emit DialSuccess (+ StateClosed) → this goes RED.
#[tokio::test]
async fn handle_host_conn_target_unreachable_sends_dial_failed() {
    let (pending, state, _data_tx, mut router) = fake_pending();
    // A definitely-closed port: bind then drop (loopback → fast ECONNREFUSED).
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap().to_string();
    drop(l);

    let router_task = tokio::spawn(async move {
        // Collect the host's reply frames IN ORDER (bounded, so a wrong/missing ack fails cleanly,
        // not by hanging). The faithful failure wire is DialFailed THEN StateClosed; an eager-ack
        // regression would put a DialSuccess here instead → clean RED.
        let mut frames: Vec<i32> = Vec::new();
        let mut reply_for = None;
        while frames.len() < 2 {
            let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut router)).await
            else {
                break;
            };
            if msg.content_type == CT_DIAL_FAILED {
                reply_for = reply_for_of(&msg);
            }
            frames.push(msg.content_type);
        }
        (frames, reply_for)
    });

    handle_host_conn(pending, dead, None, HOST_DIAL_TIMEOUT).await;

    let (frames, reply_for) = router_task.await.unwrap();
    assert_eq!(
        frames,
        vec![CT_DIAL_FAILED, CT_STATE_CLOSED],
        "T4a: target-unreachable emits DialFailed THEN StateClosed (faithful order), not an eager DialSuccess"
    );
    assert!(
        !frames.contains(&CT_DIAL_SUCCESS),
        "no DialSuccess is ever sent for an unreachable target"
    );
    assert_eq!(
        reply_for,
        Some(DIAL_SEQ),
        "the DialFailed correlates to the inbound Dial's sequence"
    );
    assert_eq!(
        state.conn_count(),
        0,
        "the child was deregistered after the failure wire"
    );
}

/// Pins the host dial timeout to the oracle's no-config default (`hosting.go:144`
/// `GetDialTimeout(5*time.Second)`), distinct from connect's 15s and bind's 60s.
#[test]
fn host_dial_timeout_is_the_oracle_5s_default() {
    assert_eq!(HOST_DIAL_TIMEOUT, Duration::from_secs(5));
}

/// Build a LOCAL TCP target whose `connect()` hangs, without depending on the network: a loopback
/// listener with backlog 0 that never `accept()`s. Filler connections are opened (and kept alive) until
/// one of them does not complete within 100ms — from then on the accept queue is full and the kernel
/// silently drops new SYNs (Linux and the BSDs/macOS drop, they do not reset), so the next `connect()`
/// hangs in SYN retransmission. Returns the target address and the guards that must stay alive.
async fn hanging_local_target() -> (String, tokio::net::TcpListener, Vec<tokio::net::TcpStream>) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(0).unwrap();
    let addr = listener.local_addr().unwrap();
    let mut fillers = Vec::new();
    for _ in 0..64 {
        match tokio::time::timeout(
            Duration::from_millis(100),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => fillers.push(stream),
            Ok(Err(e)) => panic!("filler connect to the backlog-0 listener failed: {e}"),
            Err(_elapsed) => return (addr.to_string(), listener, fillers),
        }
    }
    panic!("the accept queue of a backlog-0 listener never filled after 64 connections");
}

/// THREADING mutation-killer (T4b-2c): `handle_host_conn` must apply its `dial_timeout` PARAM, not the
/// fixed `HOST_DIAL_TIMEOUT`. A short 150ms timeout against a LOCAL target whose `connect()` hangs
/// ([`hanging_local_target`]: loopback listener with a full accept queue, no network needed) makes the
/// elapsed branch fire in ~150ms and send DialFailed `"target dial timed out"`; the whole call completes
/// well under the 1s outer bound. A mutant that ignored the param and used the 5s default would NOT
/// complete within 1s → the first assertion goes RED. (Pairs with the `get_dial_timeout` value tests in
/// `resolve/tests_timeout.rs`, which prove the resolved value; this proves the value is the one actually applied.)
#[tokio::test]
async fn handle_host_conn_uses_the_configured_dial_timeout_not_the_default() {
    let (target, _listener, _fillers) = hanging_local_target().await;
    let (pending, state, _data_tx, mut router) = fake_pending();

    let router_task = tokio::spawn(async move {
        let mut reason: Option<String> = None;
        for _ in 0..2 {
            let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut router)).await
            else {
                break;
            };
            if msg.content_type == CT_DIAL_FAILED {
                reason = Some(String::from_utf8_lossy(&msg.body).into_owned());
            }
        }
        reason
    });

    let completed = tokio::time::timeout(
        Duration::from_secs(1),
        handle_host_conn(pending, target, None, Duration::from_millis(150)),
    )
    .await;

    assert!(
        completed.is_ok(),
        "the configured 150ms dial_timeout (not the 5s HOST_DIAL_TIMEOUT default) bounded the dial"
    );
    assert_eq!(
        router_task.await.unwrap().as_deref(),
        Some("target dial timed out"),
        "the short timeout fired the elapsed branch → DialFailed 'target dial timed out'"
    );
    assert_eq!(
        state.conn_count(),
        0,
        "the child was deregistered after the timeout failure"
    );
}
