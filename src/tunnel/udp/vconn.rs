//! Alta de un vconn del proxy-UDP (T3): las piezas que el manager cede a la task, la creación del
//! flujo (`CreateWriteQueue`), el dial del servicio ziti y el ruteo de un datagrama a su vconn.
//! (F6 tramo 3b: movido verbatim del monolito de `tunnel/udp`.)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::edge::client::EdgeClient;

use super::flow::{RouteAction, deliver, route_decision};
use super::pump::drive_vconn;
use super::{VCONN_QUEUE_DEPTH, Vconn};

/// The owned ends handed to a vconn's spawn callback: `(src, inbound queue, last-use, closed flag)`.
/// The spawn callback drives the dial + both-direction pump (production: `spawn_local(run_vconn(..))`).
pub(super) type VconnSpawnParts = (
    SocketAddr,
    mpsc::Receiver<Vec<u8>>,
    Arc<Mutex<Instant>>,
    Arc<AtomicBool>,
);

/// Create a new vconn for `src`: insert its handle, queue the first datagram (the queue is fresh, so
/// the `try_send` cannot be full), then hand the other ends to `spawn` (production: `spawn_local` the
/// dial+pump task). Faithful to `CreateWriteQueue` (`manager.go:91`): insert FIRST, then
/// `go DialAndRun` — so the first datagram waits in the queue until the dial completes.
pub(super) fn create_vconn(
    conns: &mut HashMap<SocketAddr, Vconn>,
    src: SocketAddr,
    first: Vec<u8>,
    spawn: impl FnOnce(VconnSpawnParts),
) {
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));
    conns.insert(
        src,
        Vconn {
            in_tx: in_tx.clone(),
            last_use: Arc::clone(&last_use),
            closed: Arc::clone(&closed),
        },
    );
    let _ = in_tx.try_send(first); // fresh cap-16 queue → never full
    spawn((src, in_rx, last_use, closed));
}

/// Dial the ziti `service` and run the vconn (like T1's `handle_conn`; since the pool slice the router
/// channel is SHARED, multiplexed by conn-id). On a dial failure, mark `closed` (so the next datagram
/// for `src` creates a fresh vconn) and return. On success, pump both directions ([`drive_vconn`]) then
/// release the shared channel `Arc` (the oracle's `Run` defer closes the conn; the channel stays in the
/// pool for reuse — NOT force-closed, unlike the slice-4b one-conn-per-channel model).
async fn run_vconn(
    client: Rc<EdgeClient>,
    service: String,
    src: SocketAddr,
    socket: Arc<UdpSocket>,
    in_rx: mpsc::Receiver<Vec<u8>>,
    last_use: Arc<Mutex<Instant>>,
    closed: Arc<AtomicBool>,
) {
    let svc = match client.connect(&service).await {
        Ok(svc) => svc,
        Err(e) => {
            tracing::warn!(error = %e, %src, service = %service, "udp proxy: ziti connect failed");
            closed.store(true, Ordering::Release);
            return;
        }
    };
    let (zr, zw, channel) = svc.into_parts();
    drive_vconn(zr, zw, socket, src, in_rx, last_use, closed).await;
    // The conn-level full-close (StateClosed + deregister this conn-id) already happened inside
    // `drive_vconn` (`zw.close()`). Do NOT close the CHANNEL: since the pool slice it is a SHARED
    // `Arc<EdgeChannel>` owned by the connection pool and kept for reuse — a sibling vconn may ride
    // the same channel. Our `Arc` clone just drops here (the rx-loop is aborted only at the LAST
    // `Arc`). Was a force-close in the one-conn-per-channel model.
    //
    // HOL-coupling (pool slice): vconns to the same router share ONE rx-loop, so a slow vconn that lets
    // its bounded inbound queue fill backpressure-parks the shared rx-loop, briefly HOL-stalling sibling
    // vconns until the latency probe tears the channel down (~one interval). FAITHFUL — the oracle's
    // channel rxer is a single sequenced reader (`PutSequenced`, seq.go:51-57); one-conn-per-channel was
    // over-isolated relative to the oracle.
    drop(channel);
}

/// Route one inbound datagram: deliver to the live vconn for `src`, or create a new one (dialing the
/// ziti service in a `spawn_local` task). The production wiring of [`route_decision`] + [`deliver`] +
/// [`create_vconn`].
pub(super) fn route_datagram(
    conns: &mut HashMap<SocketAddr, Vconn>,
    client: &Rc<EdgeClient>,
    service: &str,
    socket: &Arc<UdpSocket>,
    src: SocketAddr,
    datagram: Vec<u8>,
) {
    match route_decision(conns, src) {
        RouteAction::Deliver => {
            if let Some(v) = conns.get(&src) {
                deliver(v, datagram);
            }
        }
        RouteAction::CreateNew => {
            let client = Rc::clone(client);
            let service = service.to_string();
            let socket = Arc::clone(socket);
            create_vconn(
                conns,
                src,
                datagram,
                move |(src, in_rx, last_use, closed)| {
                    tokio::task::spawn_local(run_vconn(
                        client, service, src, socket, in_rx, last_use, closed,
                    ));
                },
            );
        }
    }
}
