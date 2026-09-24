//! Alta de un flujo UDP interceptado: el `AppData` del destino, el dial del servicio resuelto y el
//! ruteo de un datagrama a su vconn. (F6 tramo 3a: movido verbatim del monolito de `intercept/udp`.)

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::edge::client::EdgeClient;
use crate::edge::dial::build_app_data;
use crate::tunnel::intercept::flows::FlowRegistry;
use crate::tunnel::intercept::resolve::{InterceptResolver, Protocol};
use crate::tunnel::intercept::stack::UdpReplySender;

use super::flow::{RouteAction, deliver, route_decision};
use super::pump::drive_vconn;
use super::{FlowKey, VCONN_QUEUE_DEPTH, Vconn};

/// The resolver's owned output for a new flow: which ziti service to dial, its dial-timeout, and the
/// destination's DNS hostname (reverse-lookup at dispatch time, `None` for a pure-IP intercept).
/// Grouped so the per-vconn fns stay within the argument budget and the resolved values travel
/// together — OWNED, so no resolver borrow enters the vconn task.
struct Dial {
    service: String,
    timeout: Duration,
    dst_hostname: Option<String>,
}

/// Construye el `AppData` (mapa `dst_*` JSON, header 1011) de un flujo UDP interceptado hacia `dst`.
/// DELTA CERO con el emisor TCP ([`intercept_tcp_appdata`](crate::tunnel::intercept::tcp::intercept_tcp_appdata)) salvo
/// el string de protocolo `"udp"` — REUSA [`build_app_data`] (NO un emisor paralelo: la clase de
/// over-permits que el differential cazó 5× viene de emisores paralelos).
///
/// `dst_hostname` = reverse-lookup del destino contra el DNS embebido, espejo del `get_app_data` del
/// tunneler C, que lo emite para TODO dial interceptado — UDP incluido
/// (`ziti_dns_reverse_lookup(dst_ip)`, `ziti_tunnel_cbs.c:255-259`). **Desviación consciente
/// Go-vs-C, resuelta a favor del C:** el `udp_vconn.Manager` del tunneler Go NO tiene resolver DNS y
/// hardcodea `dstHostname=""` (`manager.go:112`) — pero el DNS embebido del Go es Linux-only y su
/// path UDP jamás ve una IP sintética; el oráculo REAL de la composición DNS+intercept de este arco
/// es el C (decisión establecida en M3-DNS wiring), cuyo emisor es compartido entre protocolos. Un
/// flujo UDP hacia una IP sintética (p. ej. DNS-resuelto bajo `*.dominio`) emite el hostname, como
/// ziti-edge-tunnel; un flujo por-IP puro no tiene entrada DNS → `None` → omitido (omit-empty de
/// ambos oráculos). `source_addr` sigue DIFERIDO — el oráculo UDP SÍ lo computa (`GetSourceAddr`,
/// `manager.go:111`) y lo emitiría con una plantilla `sourceIp`. **Divergencia nombrada Go-vs-C
/// (mantenida a favor del Go):** el C emite además `src_protocol`/`src_ip`/`src_port`
/// (`get_app_data`, `ziti_tunnel_cbs.c:262-265`); pineamos el mapa del `GetAppInfo` Go (el oráculo
/// PRIMARIO del emisor AppData, differential T4b) que no los tiene — observable solo por un host con
/// plantilla `$src_ip`-style, misma clase que `source_addr` (diferido).
#[must_use]
pub(crate) fn intercept_udp_appdata(dst: SocketAddr, dst_hostname: Option<&str>) -> Vec<u8> {
    build_app_data(
        "udp",
        &dst.ip().to_string(),
        &dst.port().to_string(),
        dst_hostname.filter(|h| !h.is_empty()),
        None,
    )
}

/// Dial the resolved ziti `service` with the intercepted destination's `AppData` and run the vconn. On a
/// dial failure, mark `closed` (so the next datagram for the flow creates a fresh vconn) and return. On
/// success, pump both directions then release the SHARED channel `Arc` (the pool keeps it for reuse —
/// NOT force-closed). Mirror of T3's `run_vconn`, but dialing via [`EdgeClient::connect_with_appdata`]
/// with [`intercept_udp_appdata`] instead of the fixed-service [`EdgeClient::connect`].
///
/// `kill` (kill-active) llega ya registrado por [`create_vconn`] y se MUEVE a este future (invariante
/// de vida del [`FlowRegistry`]): si el dial falla, el `Arc` se dropea aquí → su `Weak` muere → la poda
/// amortizada lo retira del registro. Si el kill disparó con el dial en vuelo, [`drive_vconn`] lo
/// observa en el primer poll de `pump_udp_to_ziti` (token nivel-disparado + `biased`) — el dial NO se
/// cancela (DV-5).
#[allow(clippy::too_many_arguments)] // el estado completo de un vconn (dial + pumps + kill)
async fn run_vconn(
    client: Rc<EdgeClient>,
    dial: Dial,
    flow: FlowKey,
    reply: UdpReplySender,
    in_rx: mpsc::Receiver<Vec<u8>>,
    last_use: Arc<Mutex<Instant>>,
    closed: Arc<AtomicBool>,
    kill: Arc<CancellationToken>,
) {
    let (src, dst) = flow;
    let appdata = intercept_udp_appdata(dst, dial.dst_hostname.as_deref());
    let svc = match client
        .connect_with_appdata(&dial.service, dial.timeout, Some(&appdata))
        .await
    {
        Ok(svc) => svc,
        Err(e) => {
            tracing::warn!(error = %e, %dst, %src, service = %dial.service, "intercept udp: ziti connect failed");
            closed.store(true, Ordering::Release);
            return; // `kill` dropea aquí → el registro lo poda (sin deregister explícito)
        }
    };
    let (zr, zw, channel) = svc.into_parts();
    drive_vconn(zr, zw, reply, flow, in_rx, last_use, closed, kill).await;
    // The conn-level full-close (StateClosed + deregister this conn-id) already happened inside
    // `drive_vconn` (`zw.close()`). Do NOT close the CHANNEL: it is a SHARED `Arc<EdgeChannel>` owned by
    // the pool and kept for reuse — our `Arc` clone just drops here. (Mirror of T3's `run_vconn`.)
    drop(channel);
}

/// Create a new vconn for `key`: insert its handle, queue the first datagram (fresh queue → never full),
/// then `spawn_local` the dial+pump task. Faithful to the oracle's `CreateWriteQueue`: insert FIRST, then
/// `go DialAndRun` — so the first datagram waits in the queue until the dial completes.
///
/// **Kill-active:** el alta en `flows` ocurre AQUÍ, en la creación y ANTES del dial — espejo del
/// `udp_recv(npcb, on_udp_client_data, io)` que el oráculo instala en `tunnel_udp.c:169` antes del
/// `zdial` de `:171` (su comentario de `:207`, "recv_arg contains io_context after dial completes",
/// contradice a ese código; manda el código). Así un `Removed` que llegue con el dial en vuelo ya
/// encuentra este flujo. El `borrow_mut` de `flows` es síncrono y no cruza `await`; anida con el
/// `resolver.borrow()` vivo de [`route_datagram`], pero son celdas DISTINTAS (ver el doc de
/// `serve_dns_datagram` sobre esa misma disciplina).
fn create_vconn(
    conns: &mut HashMap<FlowKey, Vconn>,
    client: &Rc<EdgeClient>,
    reply: &UdpReplySender,
    flows: &Rc<RefCell<FlowRegistry>>,
    dial: Dial,
    flow: FlowKey,
    first: Vec<u8>,
) {
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));
    conns.insert(
        flow,
        Vconn {
            in_tx: in_tx.clone(),
            last_use: Arc::clone(&last_use),
            closed: Arc::clone(&closed),
        },
    );
    let _ = in_tx.try_send(first); // fresh cap-16 queue → never full
    let (src, dst) = flow;
    // El `Arc` devuelto se MUEVE al future del vconn y no se clona fuera de él (invariante de vida).
    let kill = flows
        .borrow_mut()
        .register(&dial.service, Protocol::Udp, src, dst);
    let client = Rc::clone(client);
    let reply = reply.clone();
    // The dial (`connect_with_appdata`) is `!Send` (the `Rc<EdgeClient>` of slice 10c) → `spawn_local`
    // (this MUST be driven inside a `LocalSet`). Like T3, the whole vconn (dial + pump) runs in the
    // `LocalSet`; the scale-spike MT-split of the ESTABLISHED pump is a TCP-splice-specific refinement
    // (T3 itself runs the established UDP pump in the `LocalSet`) — named-deferred for UDP.
    tokio::task::spawn_local(run_vconn(
        client, dial, flow, reply, in_rx, last_use, closed, kill,
    ));
}

/// Route one inbound datagram: deliver to the live vconn for `(src, dst)`, or — on a new flow — resolve
/// `dst`→service and create a vconn (or DROP the datagram if no service intercepts the destination,
/// faithful to [`run_tcp_intercept`](crate::tunnel::intercept::tcp::run_tcp_intercept)'s no-match close).
#[allow(clippy::too_many_arguments)] // el seam completo del routing per-datagrama (+ registro de flujos)
pub(super) fn route_datagram(
    conns: &mut HashMap<FlowKey, Vconn>,
    client: &Rc<EdgeClient>,
    resolver: &InterceptResolver,
    reply: &UdpReplySender,
    flows: &Rc<RefCell<FlowRegistry>>,
    dst: SocketAddr,
    src: SocketAddr,
    datagram: Vec<u8>,
) {
    let key = (src, dst);
    match route_decision(conns, key) {
        RouteAction::Deliver => {
            if let Some(v) = conns.get(&key) {
                deliver(v, datagram);
            }
        }
        RouteAction::CreateNew => {
            // Resolve the REAL destination to a service (per new flow; synchronous, no await). No match →
            // DROP the datagram (do not create a vconn) — a non-intercepted destination is not routed.
            let Some(m) = resolver.lookup(dst.ip(), dst.port(), Protocol::Udp, src.ip()) else {
                tracing::debug!(%dst, %src, "intercept udp: ningún servicio intercepta el destino; datagrama descartado");
                return;
            };
            // Reverse-lookup del destino AL despachar (espejo del `get_app_data` del C sobre el
            // mismo `ziti_dns`): owned en `Dial`, así el borrow del resolver no entra al vconn.
            let dst_hostname = match dst.ip() {
                IpAddr::V4(v4) => resolver.dns().reverse_lookup(v4).map(str::to_string),
                IpAddr::V6(_) => None,
            };
            let dial = Dial {
                service: m.service.to_string(),
                timeout: m.dial_timeout,
                dst_hostname,
            };
            create_vconn(conns, client, reply, flows, dial, key, datagram);
        }
    }
}
