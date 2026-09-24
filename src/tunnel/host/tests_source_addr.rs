//! Tests for the per-dial `source_addr` socket bind (T4b-2d-2), a capability that spans
//! resolver → forward → dial.
//!
//! (F6 tramo 9: movido verbatim del monolito de `tunnel/host`.)

use super::HOST_DIAL_TIMEOUT;
use super::dial::handle_host_conn;
use super::forward::handle_host_forward_conn;
use super::testsupport::{
    TEST_CONN_ID, fake_pending, fake_pending_with_app_data, fin_frame, flags_of, fwd_cfg,
};
use crate::channel::connect::read_message;
use crate::edge::bind::{CT_DIAL_FAILED, CT_DIAL_SUCCESS};
use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, build_app_data, build_data};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ----- T4b-2d-2: per-dial source_addr socket bind -----

/// T4b-2d-2 END-TO-END through the forwarding host: the inbound dial's appData carries a `source_addr`
/// (`127.0.0.1:<reserved port>`), so the host binds its outbound dial's LOCAL end to that port
/// (`net.Dialer{LocalAddr}`). The in-process echo records the connecting peer and asserts its PORT ==
/// the requested source port — proving the bind fired (a default-source connect would show a random
/// ephemeral port → a mutant dropping `source_bind` goes RED). The source IP is loopback either way
/// (`127.0.0.2` is not bindable on macOS without aliasing `lo0`, and the host runs on the Mac), so the
/// PORT is the observable that distinguishes the bind from a default connect.
#[tokio::test]
async fn handle_host_forward_conn_binds_the_requested_source_port() {
    // Reserve a free loopback port for the SOURCE bind: bind a listener to :0, take its port, drop it.
    // A never-accepted listening socket frees its port with no TIME_WAIT, so reusing it as a source
    // bind is reliable.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let src_port = probe.local_addr().unwrap().port();
    drop(probe);

    // The echo (the resolved dial target) records the connecting peer's address via a oneshot.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    let echo = tokio::spawn(async move {
        if let Ok((mut sock, peer)) = echo_listener.accept().await {
            let _ = peer_tx.send(peer);
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => {
                        let _ = sock.shutdown().await;
                        return;
                    }
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        }
    });

    // appData: dst_ip/dst_port → the echo; source_addr → 127.0.0.1:<src_port>.
    let app = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        None,
        Some(&format!("127.0.0.1:{src_port}")),
    );
    let (pending, state, data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut echoed = Vec::new();
        let mut saw_dial_success = false;
        let mut saw_state_closed = false;
        loop {
            let Ok(msg) = read_message(&mut router).await else {
                break;
            };
            match msg.content_type {
                CT_DIAL_SUCCESS => saw_dial_success = true,
                CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => {}
                CT_DATA => echoed.extend_from_slice(&msg.body),
                CT_STATE_CLOSED => {
                    saw_state_closed = true;
                    break;
                }
                _ => {}
            }
        }
        (saw_dial_success, echoed, saw_state_closed)
    });

    data_tx
        .send(build_data(TEST_CONN_ID, b"hello-srcbind", false))
        .await
        .unwrap();
    data_tx.send(fin_frame()).await.unwrap();
    drop(data_tx);

    handle_host_forward_conn(pending, &fwd_cfg(), &[], HOST_DIAL_TIMEOUT).await;

    let peer = peer_rx.await.expect("echo observed a connecting peer");
    assert_eq!(
        peer.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "the source bound to loopback"
    );
    assert_eq!(
        peer.port(),
        src_port,
        "the dial's local end was bound to the requested source_addr port (not a random ephemeral one)"
    );

    let (saw_dial_success, echoed, saw_state_closed) = router_task.await.unwrap();
    echo.await.unwrap();
    assert!(
        saw_dial_success,
        "source-bound dial reached the target → DialSuccess"
    );
    assert_eq!(
        echoed, b"hello-srcbind",
        "round-trip via the source-bound dial"
    );
    assert!(saw_state_closed, "splice tore down after both directions");
    assert_eq!(state.conn_count(), 0, "child deregistered exactly once");
}

/// T4b-2d-2 bind FAILURE surfaces as DialFailed: a `source_addr` whose IP is not a local address
/// (`203.0.113.1`, RFC 5737 TEST-NET-3 — never assigned to this host) makes `TcpSocket::bind` fail
/// (EADDRNOTAVAIL) BEFORE connecting, so the host sends DialFailed (the faithful `dialer.Dial` error →
/// DialFailed via the `Ok(Err)` arm) and deregisters the child — never a default-source dial. The
/// target is a real, reachable local listener, so ONLY the source bind can fail: a mutant that dropped
/// `source` would connect fine → no DialFailed → RED.
#[tokio::test]
async fn handle_host_conn_unbindable_source_ip_sends_dial_failed() {
    // A reachable target: a live listener we never accept (the connect would succeed if not for the
    // source bind). Kept alive for the whole test.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo_listener.local_addr().unwrap().to_string();
    let _keep_target_alive = echo_listener;
    let (pending, state, _data_tx, mut router) = fake_pending();

    let router_task = tokio::spawn(async move {
        let mut frames: Vec<i32> = Vec::new();
        let mut reason: Option<String> = None;
        while frames.len() < 2 {
            let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut router)).await
            else {
                break;
            };
            if msg.content_type == CT_DIAL_FAILED {
                reason = Some(String::from_utf8_lossy(&msg.body).into_owned());
            }
            frames.push(msg.content_type);
        }
        (frames, reason)
    });

    let source = "203.0.113.1:0".parse::<std::net::SocketAddr>().unwrap();
    handle_host_conn(pending, target, Some(source), HOST_DIAL_TIMEOUT).await;

    let (frames, reason) = router_task.await.unwrap();
    assert_eq!(
        frames,
        vec![CT_DIAL_FAILED, CT_STATE_CLOSED],
        "an unbindable source_addr → DialFailed THEN StateClosed (no DialSuccess)"
    );
    assert!(!frames.contains(&CT_DIAL_SUCCESS));
    assert!(
        reason.is_some_and(|r| r.starts_with("target dial failed:")),
        "the bind failure is carried in the DialFailed body via the Ok(Err) arm"
    );
    assert_eq!(
        state.conn_count(),
        0,
        "child deregistered after the bind failure"
    );
}
