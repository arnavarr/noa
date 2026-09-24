//! Shared test fixtures for the `host` module's test files.
//!
//! (F6 tramo 9: movido verbatim del monolito de `tunnel/host`.)

use crate::channel::message::Message;
use crate::edge::data::{ChannelState, PendingAccept};
use crate::edge::dial::{FLAG_FIN, HDR_FLAGS, build_data};
use crate::edge::model::{HostV1Config, PortRange};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

pub(super) const TEST_CONN_ID: u32 = 7;
const BIND_CONN_ID: u32 = 3;
pub(super) const DIAL_SEQ: i32 = 42;

pub(super) fn flags_of(msg: &Message) -> u32 {
    msg.headers
        .get(&HDR_FLAGS)
        .map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()))
}

pub(super) fn fin_frame() -> Message {
    let mut fin = build_data(TEST_CONN_ID, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    fin
}

/// A fake PENDING accept (T4a: the host now dials the target BETWEEN accept and ack): a plaintext
/// `PendingAccept` over a duplex-backed channel with the child pre-registered, plus a `state`
/// handle to assert deregister, a `data_tx` to INJECT inbound (ziti→socket) frames (no rx-loop in
/// the test), and the router-side duplex end carrying what `complete_success`/`complete_failed` +
/// the splice WRITE (DialSuccess/DialFailed + socket→ziti Data + FIN + StateClosed).
pub(super) fn fake_pending() -> (
    PendingAccept,
    Arc<ChannelState>,
    mpsc::Sender<Message>,
    tokio::io::DuplexStream,
) {
    let (cw, router) = tokio::io::duplex(64 * 1024);
    let state = Arc::new(ChannelState::new(Box::new(cw)));
    let (data_tx, data_rx) = mpsc::channel(64);
    state.register_conn(TEST_CONN_ID, data_tx.clone());
    let pending =
        PendingAccept::new_for_test(state.clone(), BIND_CONN_ID, TEST_CONN_ID, DIAL_SEQ, data_rx);
    (pending, state, data_tx, router)
}

/// Like [`fake_pending`] but with appData attached, for the forwarding-host (T4b-1) tests.
pub(super) fn fake_pending_with_app_data(
    app_data: Vec<u8>,
) -> (
    PendingAccept,
    Arc<ChannelState>,
    mpsc::Sender<Message>,
    tokio::io::DuplexStream,
) {
    let (pending, state, data_tx, router) = fake_pending();
    (pending.with_app_data(app_data), state, data_tx, router)
}

/// A `forwardAddress`+`forwardPort` host.v1 with a flat CIDR allow-list + a port range that
/// includes the local echo's port (host runs on 127.0.0.1, so allow loopback /32 + a wide range).
pub(super) fn fwd_cfg() -> HostV1Config {
    HostV1Config {
        protocol: "tcp".to_string(),
        forward_address: true,
        allowed_addresses: vec!["127.0.0.1/32".to_string()],
        forward_port: true,
        allowed_port_ranges: vec![PortRange {
            low: 1,
            high: 65535,
        }],
        ..Default::default()
    }
}

/// A one-shot TCP echo (the host's local `target`): accept one conn, echo every chunk, and on the
/// peer's EOF half-close our write side (like `/bin/cat`). Lets the splice round-trip + observe
/// the half-close from the socket side.
pub(super) async fn tcp_echo_once(listener: TcpListener) {
    if let Ok((mut sock, _)) = listener.accept().await {
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
}
