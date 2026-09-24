//! Fixtures compartidos por los `tests_*` del proxy-UDP (T3). (F6 tramo 3b troceo.)

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;

use crate::channel::message::Message;
use crate::edge::data::{ChannelState, EdgeConn, EdgeReadHalf, EdgeWriteHalf};
use crate::edge::dial::HDR_FLAGS;

use super::{VCONN_QUEUE_DEPTH, Vconn};

pub(super) const TEST_CONN_ID: u32 = 7;

pub(super) fn flags_of(msg: &Message) -> u32 {
    msg.headers
        .get(&HDR_FLAGS)
        .map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()))
}

/// A fake ziti connection split into halves (mirrors `proxy::tests::fake_conn`): a `state` handle
/// to assert deregister; a `data_tx` to INJECT inbound (ziti→udp) frames (no rx-loop in the test);
/// and the router-side duplex end carrying the frames the vconn WRITES to ziti (udp→ziti Data +
/// StateClosed).
pub(super) fn fake_conn() -> (
    EdgeReadHalf,
    EdgeWriteHalf,
    Arc<ChannelState>,
    mpsc::Sender<Message>,
    tokio::io::DuplexStream,
) {
    fake_conn_sized(256 * 1024)
}

/// [`fake_conn`] con el buffer del canal parametrizado: uno DIMINUTO aparca el `write_all` de un
/// frame grande a mitad, que es como se ejerce el invariante (ii).
pub(super) fn fake_conn_sized(
    chan_buf: usize,
) -> (
    EdgeReadHalf,
    EdgeWriteHalf,
    Arc<ChannelState>,
    mpsc::Sender<Message>,
    tokio::io::DuplexStream,
) {
    let (cw, router) = tokio::io::duplex(chan_buf);
    let state = Arc::new(ChannelState::new(Box::new(cw)));
    let (data_tx, data_rx) = mpsc::channel(64);
    state.register_conn(TEST_CONN_ID, data_tx.clone());
    let conn = EdgeConn::new_for_test(TEST_CONN_ID, data_rx, state.clone());
    let (zr, zw) = conn.into_split();
    (zr, zw, state, data_tx, router)
}

/// A `Vconn` handle plus the owned ends a test drives it through (mirror of [`VconnSpawnParts`]
/// but with the handle, and minus the `src` the test supplies separately).
pub(super) type VconnHandleParts = (
    Vconn,
    mpsc::Receiver<Vec<u8>>,
    Arc<Mutex<Instant>>,
    Arc<AtomicBool>,
);

pub(super) fn vconn_handle() -> VconnHandleParts {
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));
    let v = Vconn {
        in_tx,
        last_use: Arc::clone(&last_use),
        closed: Arc::clone(&closed),
    };
    (v, in_rx, last_use, closed)
}

pub(super) fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}
