//! Shared test fixtures for the split `data` test modules.
//!
//! Re-export hub for the sibling `tests_*` modules, so it deliberately re-exports names some of
//! them do not each use.
#![allow(unused_imports)]

pub(crate) use super::accept::*;
pub(crate) use super::channel::*;
pub(crate) use super::channel_state::*;
pub(crate) use super::conn::*;
pub(crate) use super::rxloop::*;
pub(crate) use super::wire::*;
pub(crate) use super::*;

// The union of the original `edge/data` module-level imports (which the monolithic `mod tests`
// saw via `use super::*`) and the test module's own imports. Re-exported so the split `tests_*`
// files resolve every name exactly as before the troceo.
pub(crate) use std::collections::HashMap;
pub(crate) use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
pub(crate) use std::sync::{Arc, Mutex, Weak};
pub(crate) use std::time::{Duration, Instant};

pub(crate) use tokio::io::{AsyncRead, AsyncWrite};
pub(crate) use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};

pub(crate) use crate::channel::connect::{read_message, write_message};
pub(crate) use crate::channel::message::{
    CT_LATENCY, CT_RESULT, HDR_PROBE_TIME, HDR_REPLY_FOR, HDR_REPLY_FOR as MSG_HDR_REPLY_FOR,
    Message,
};
pub(crate) use crate::edge::bind::{
    CT_DIAL, HDR_ROUTER_PROVIDED_CONN_ID, build_bind, build_dial_failed, build_dial_success,
    build_unbind, classify_bind_reply,
};
pub(crate) use crate::edge::crypto::{Decryptor, Encryptor, STREAM_HEADER_BYTES, SessionKey};
pub(crate) use crate::edge::dial::{
    CRYPTO_METHOD_LIBSODIUM, CT_DATA, CT_STATE_CLOSED, CT_STATE_CONNECTED, FLAG_FIN,
    FLAG_MULTIPART, HDR_APPDATA, HDR_CALLER_ID, HDR_CIRCUIT_ID, HDR_CONN_ID, HDR_CRYPTO_METHOD,
    HDR_FLAGS, HDR_PUBLIC_KEY, build_connect, build_data, build_state_closed, classify_dial_reply,
    new_marker,
};
pub(crate) use crate::edge::error::EdgeError;
pub(crate) use crate::edge::model::{SessionDetail, SessionEdgeRouter, SessionType};

pub(crate) use tracing_test::traced_test;

pub(crate) fn detail() -> SessionDetail {
    SessionDetail {
        id: "s".into(),
        token: "jwt-tok".into(),
        service_id: "svc".into(),
        session_type: SessionType::Dial,
        api_session_id: String::new(),
        identity_id: String::new(),
        edge_routers: vec![SessionEdgeRouter::default()],
    }
}

// Build a ChannelState whose write half is one end of a duplex; return the state,
// the rx-loop handle, and the OTHER duplex end (the fake router).
pub(crate) fn rig() -> (
    Arc<ChannelState>,
    tokio::task::JoinHandle<()>,
    tokio::io::DuplexStream,
) {
    let (client, router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let state = Arc::new(ChannelState::new(Box::new(cw)));
    let task = tokio::spawn(rx_loop(Box::new(cr), state.clone()));
    (state, task, router)
}

/// Fill conn A's cap-4 queue so the rx-loop parks on the dispatch to it (a non-draining sibling).
/// Writes 6 Data frames for `conn_id` to `router` (4 buffer, the 5th parks the loop; the 6th never
/// read). The caller must keep A's receiver alive (un-drained) so the queue stays full.
pub(crate) async fn stall_rx_loop_on(router: &mut tokio::io::DuplexStream, conn_id: u32) {
    for _ in 0..6 {
        let mut d = Message::new(CT_DATA, b"x".to_vec());
        d.headers
            .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
        write_message(router, &d).await.unwrap();
    }
    // Give the rx-loop a moment to drain the duplex and park on the full queue.
    tokio::time::sleep(Duration::from_millis(20)).await;
}

/// A write half whose writes NEVER complete (poll_write -> Pending) — models a black-holed transport
/// or a wedged bulk writer holding the write lock.
pub(crate) struct BlackHoleWrite;
impl tokio::io::AsyncWrite for BlackHoleWrite {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Drive the bind handshake (send_bind + a concurrent responder that replies StateConnected),
/// returning the bound channel + the bind conn-id headers + the router END (kept here, NOT in a
/// long-lived task, so the split tests can assert the wire themselves).
pub(crate) async fn bound_channel_with_router() -> (
    EdgeChannel,
    u32,
    Vec<u8>,
    mpsc::Receiver<Message>,
    tokio::io::DuplexStream,
) {
    let (client, router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let mut router = router;
    let bind_fut = ch.send_bind("bind-jwt", "lid-split", None);
    let responder = async {
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        bind_conn_id
    };
    let (bind_res, bind_conn_id_hdr) = tokio::join!(bind_fut, responder);
    let (bind_id, bind_rx) = bind_res.expect("bind ok");
    (ch, bind_id, bind_conn_id_hdr, bind_rx, router)
}

/// Send an inbound Dial for the bound conn-id (child id 42, seq 99) onto the router.
pub(crate) async fn send_inbound_dial(
    router: &mut tokio::io::DuplexStream,
    bind_conn_id_hdr: &[u8],
) {
    let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"bind-jwt".to_vec());
    dial.headers.insert(HDR_CONN_ID, bind_conn_id_hdr.to_vec());
    dial.headers.insert(
        crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
        42u32.to_le_bytes().to_vec(),
    );
    dial.sequence = 99;
    write_message(router, &dial).await.unwrap();
}
