//! Fixtures compartidos por los `tests_*` del manager UDP del intercept (F6 tramo 3a troceo).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use std::collections::BTreeMap;

use tokio::sync::mpsc;

use crate::edge::data::{EdgeReadHalf, EdgeWriteHalf};
use crate::tunnel::intercept::dns::{DnsMatcher, RegisterOutcome};

use super::{VCONN_QUEUE_DEPTH, Vconn};

/// Parsea el `AppData` emitido a un mapa `String→String` (como `json.Unmarshal` del host).
pub(super) fn parse(appdata: &[u8]) -> BTreeMap<String, String> {
    serde_json::from_slice(appdata).expect("el AppData es un objeto JSON string→string")
}

pub(super) fn vconn_handle() -> (Vconn, mpsc::Receiver<Vec<u8>>, Arc<AtomicBool>) {
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));
    (
        Vconn {
            in_tx,
            last_use,
            closed: Arc::clone(&closed),
        },
        in_rx,
        closed,
    )
}

// ───────── kill-active: rig de vconn falso (conn ziti + reply-egress observables) ─────────

pub(super) const KILL_CONN_ID: u32 = 11;
pub(super) const KILL_TIMEOUT: Duration = Duration::from_secs(5);

/// Conexión ziti falsa partida en halves, con el buffer del canal PARAMETRIZADO: un buffer diminuto
/// hace que `zw.write` se aparque a medias (backpressure) — así el test 8b pone al pump escritor
/// MID-FRAME antes de disparar el kill.
pub(super) fn kill_fake_conn(
    chan_buf: usize,
) -> (
    EdgeReadHalf,
    EdgeWriteHalf,
    Arc<crate::edge::data::ChannelState>,
    mpsc::Sender<crate::channel::message::Message>,
    tokio::io::DuplexStream,
) {
    let (cw, router) = tokio::io::duplex(chan_buf);
    let state = Arc::new(crate::edge::data::ChannelState::new(Box::new(cw)));
    let (data_tx, data_rx) = mpsc::channel(64);
    state.register_conn(KILL_CONN_ID, data_tx.clone());
    let conn = crate::edge::data::EdgeConn::new_for_test(KILL_CONN_ID, data_rx, state.clone());
    let (zr, zw) = conn.into_split();
    (zr, zw, state, data_tx, router)
}

/// Drena el lado router de un vconn falso contando Data y StateClosed, y acumulando los payloads.
/// Que `read_message` NO cuelgue ES la aserción de framing: un frame partido lo dejaría esperando
/// bytes que no llegan. Genérico sobre el lector para aceptar también un `Chain` (ver el
/// rendezvous determinista del test 8b).
pub(super) async fn drain_router<R: tokio::io::AsyncRead + Unpin>(
    router: &mut R,
) -> (Vec<u8>, usize, usize) {
    use crate::channel::connect::read_message;
    use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED};
    let (mut body, mut datas, mut closeds) = (Vec::new(), 0usize, 0usize);
    loop {
        let Ok(msg) = tokio::time::timeout(KILL_TIMEOUT, read_message(router))
            .await
            .expect("read_message no cuelga ⇒ todos los frames están completos")
        else {
            break; // EOF del canal
        };
        match msg.content_type {
            CT_DATA => {
                datas += 1;
                body.extend_from_slice(&msg.body);
            }
            CT_STATE_CLOSED => {
                closeds += 1;
                break;
            }
            _ => {}
        }
    }
    (body, datas, closeds)
}

// ──────────── drive_vconn: ningún pump se dropea a mitad de un `zw.write` (§7 del spec) ────────────

const SIBLING_CONN_ID: u32 = 12;

/// Frame `Data` vacío con FIN = el EOF de ziti tal como lo emite el peer (`edgeConn.CloseWrite`).
pub(super) fn fin_frame(conn_id: u32) -> crate::channel::message::Message {
    use crate::edge::dial::{FLAG_FIN, HDR_FLAGS, build_data};
    let mut fin = build_data(conn_id, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    fin
}

/// Frame `StateClosed` = la conn ENTERA murió (el router la tiró), NO un half-close por FIN. Gemelo
/// de [`fin_frame`] para el discriminante DV-11-SC: el lector lo mapea a EOF Y pone `sent_fin`, de
/// modo que el siguiente `zw.write` FALLA (a diferencia de un FIN, que deja `write` funcionando).
pub(super) fn state_closed_frame(conn_id: u32) -> crate::channel::message::Message {
    crate::edge::dial::build_state_closed(conn_id)
}

/// Una SEGUNDA conn registrada en el MISMO [`crate::edge::data::ChannelState`]: mismo mutex de
/// escritura, mismo underlay. Es el "flujo de otro servicio" cuyo framing corrompería un frame
/// partido del vecino.
pub(super) fn sibling_write_half(state: &Arc<crate::edge::data::ChannelState>) -> EdgeWriteHalf {
    let (tx, rx) = mpsc::channel(64);
    state.register_conn(SIBLING_CONN_ID, tx);
    let conn = crate::edge::data::EdgeConn::new_for_test(SIBLING_CONN_ID, rx, state.clone());
    let (_zr, zw) = conn.into_split();
    zw
}

/// Lee EXACTAMENTE `n` frames COMPLETOS. Colgarse o fallar el parseo **es** la aserción: significa
/// que alguien dejó un frame partido en el canal compartido.
pub(super) async fn collect_n_messages<R: tokio::io::AsyncRead + Unpin>(
    router: &mut R,
    n: usize,
) -> Vec<crate::channel::message::Message> {
    use crate::channel::connect::read_message;
    let mut out = Vec::new();
    for i in 0..n {
        let msg = tokio::time::timeout(KILL_TIMEOUT, read_message(router))
            .await
            .unwrap_or_else(|_| {
                panic!("read_message #{i} se colgó ⇒ frame PARTIDO en el canal compartido")
            })
            .unwrap_or_else(|e| panic!("read_message #{i} falló ({e:?}) ⇒ framing corrupto"));
        out.push(msg);
    }
    out
}

/// Lee frames y, tras el `StateClosed`, **sigue leyendo** con un tope corto en vez de PARAR.
///
/// ⚠ Es la diferencia con [`drain_router`], y es load-bearing: aquél **rompe el bucle en el primer
/// `StateClosed`**, así que un `assert_eq!(closeds, 1)` sobre su salida es **INOBSERVABLE** (una
/// mutación que emitiera DOS seguiría verde). Ése es exactamente el assert vacío que la review de la
/// opción 5 cazó en el gemelo T3; no lo repetimos aquí. Devuelve `(payloads, datas, closeds, saw_fin)`.
///
/// ⚠ **Honestidad del detector:** tras el cierre espera un presupuesto ACOTADO (250 ms), así que
/// prueba «no salió un 2.º StateClosed *pronto*», no la ausencia absoluta. Es un detector con
/// presupuesto, no una prueba de ausencia — mejor que `drain_router` (que no detectaba nada), pero
/// no lo vendas como más de lo que es.
pub(super) async fn drain_router_strict<R: tokio::io::AsyncRead + Unpin>(
    router: &mut R,
) -> (Vec<Vec<u8>>, usize, usize, bool) {
    use crate::channel::connect::read_message;
    use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, HDR_FLAGS};

    let (mut bodies, mut datas, mut closeds, mut saw_fin) = (Vec::new(), 0, 0, false);
    loop {
        // Antes del cierre esperamos de verdad (una regresión debe dar ROJO, no colgar); DESPUÉS del
        // cierre basta un tope corto: si saliera un 2.º StateClosed o un FIN tardío, lo veríamos.
        let budget = if closeds == 0 {
            KILL_TIMEOUT
        } else {
            Duration::from_millis(250)
        };
        let Ok(read) = tokio::time::timeout(budget, read_message(router)).await else {
            break; // no llegan más frames
        };
        let Ok(msg) = read else { break }; // EOF del canal
        let flags = msg
            .headers
            .get(&HDR_FLAGS)
            .map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()));
        saw_fin |= flags & FLAG_FIN != 0;
        match msg.content_type {
            CT_DATA => {
                datas += 1;
                bodies.push(msg.body);
            }
            CT_STATE_CLOSED => closeds += 1,
            _ => {}
        }
    }
    (bodies, datas, closeds, saw_fin)
}

pub(super) fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
}

// ───────────────────────── servidor DNS embebido (M3-DNS, diferido #4) ─────────────────────────

pub(super) const DNS_SRV_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

/// Construye una query A DNS válida para `name`.
pub(super) fn dns_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in name.split('.') {
        pkt.push(u8::try_from(label.len()).unwrap());
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

pub(super) fn dns_matcher_with(addr: &str) -> DnsMatcher {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("100.64.0.0/24"));
    m.reserve(Ipv4Addr::new(100, 64, 0, 1)); // utun
    m.reserve(DNS_SRV_IP); // el propio resolver
    assert!(!matches!(m.register(addr, "i"), RegisterOutcome::Rejected));
    m
}

// ───────────────────── upstream DNS forwarding (M3-DNS #1) ─────────────────────

pub(super) const TEST_TIMEOUT: Duration = Duration::from_secs(3);
