//! El loop del manager proxy-UDP (T3) y su entrada pública: demultiplexa `recv_from` por `srcAddr`
//! contra el tick de reaping. (F6 tramo 3b: movido verbatim del monolito de `tunnel/udp`.)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::MissedTickBehavior;

use crate::edge::client::EdgeClient;

use super::flow::drop_expired;
use super::vconn::route_datagram;
use super::{MAX_UDP_PACKET_SIZE, VCONN_IDLE_TIMEOUT, VCONN_POLL_INTERVAL, Vconn};

/// Run a proxy-UDP listener on a bound `socket`: demultiplex inbound datagrams by source address
/// into per-source vconns, each dialing the ziti `service`, and reap idle vconns. The manager actor —
/// it owns `conns` and `select!`s `recv_from` against the reaping tick (faithful to the oracle's
/// single `manager.run()` goroutine).
///
/// Per-source vconn work runs under `tokio::task::spawn_local` (so this MUST be driven inside a
/// `tokio::task::LocalSet`): [`EdgeClient::connect`] is `!Send` (slice 10c). The socket is shared
/// (`Arc`) so vconns `send_to` it concurrently with the manager's `recv_from` (tokio `UdpSocket`
/// recv/send both take `&self`).
///
/// # Errors
/// Returns the `io::Error` from `recv_from` (CONSCIOUS DEVIATION: this stops the whole proxy — see
/// the module docs — vs the oracle logging a non-EOF read error and keeping existing vconns alive).
pub async fn run_udp_proxy(
    client: Rc<EdgeClient>,
    socket: UdpSocket,
    service: String,
) -> io::Result<()> {
    run_udp_proxy_with(
        client,
        socket,
        service,
        VCONN_IDLE_TIMEOUT,
        VCONN_POLL_INTERVAL,
    )
    .await
}

/// [`run_udp_proxy`] with the idle timeout + poll interval injected, so a live/integration harness
/// can use the oracle defaults while a test could drive a fast cadence. Production passes
/// [`VCONN_IDLE_TIMEOUT`]/[`VCONN_POLL_INTERVAL`].
async fn run_udp_proxy_with(
    client: Rc<EdgeClient>,
    socket: UdpSocket,
    service: String,
    idle_timeout: Duration,
    poll_interval: Duration,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut conns: HashMap<SocketAddr, Vconn> = HashMap::new();
    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                let (n, src) = r?; // deviation: a read error stops the whole proxy
                let datagram = buf[..n].to_vec();
                route_datagram(&mut conns, &client, &service, &socket, src, datagram);
            }
            _ = ticker.tick() => {
                drop_expired(&mut conns, idle_timeout, Instant::now());
            }
        }
    }
}
