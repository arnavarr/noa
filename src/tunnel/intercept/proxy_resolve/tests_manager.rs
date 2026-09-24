//! Los tests del manager (estado síncrono, sin conn real): completion por evento, dedup, TTL de
//! pendientes, eviction del handle por cambio de dueño y el ciclo con el dial fallando. F6 tramo
//! 12: movidos verbatim del `mod tests` del monolito de `intercept/proxy_resolve`.

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::edge::client::EdgeClient;
use crate::tunnel::intercept::dns_server::{DNS_SERVFAIL, ProxyQuery};

use super::manager::{PROXY_PENDING_TIMEOUT, ProxyDns, ProxyEvent, ProxyPending};

// ───────────────────────── manager (estado síncrono, sin conn real) ─────────────────────────

fn pending_for(id: u16) -> (Vec<u8>, usize) {
    // Una query MX real bajo un dominio (mismo shape que el harness).
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for lab in ["mail", "svc", "example", "com"] {
        pkt.push(u8::try_from(lab.len()).unwrap());
        pkt.extend_from_slice(lab.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&15u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    let strlen = "mail.svc.example.com".len();
    (pkt, strlen)
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([100, 64, 0, 2], port))
}

fn insert_pending(proxy: &mut ProxyDns, id: u16) {
    let (packet, name_strlen) = pending_for(id);
    proxy.pending.insert(
        id,
        ProxyPending {
            packet,
            name_strlen,
            server_addr: addr(53),
            client_addr: addr(50000),
            at: Instant::now(),
        },
    );
}

/// `WriteFailed` completa el pendiente con SERVFAIL (espejo `on_proxy_write` con error) y lo
/// consume; un segundo evento con el mismo id ya no encuentra pendiente.
#[test]
fn write_failed_completes_pending_with_servfail_once() {
    let (mut proxy, _rx) = ProxyDns::new();
    insert_pending(&mut proxy, 0x1234);

    let (bytes, dst, src) = proxy
        .on_event(ProxyEvent::WriteFailed(0x1234), true)
        .expect("pendiente registrado → completa");
    assert_eq!(bytes[3] & 0x0f, DNS_SERVFAIL, "rcode SERVFAIL");
    assert_eq!(bytes[3] & 0x80, 0x80, "RA con upstream activo");
    assert_eq!(&bytes[0..2], &[0x12, 0x34], "el id del request");
    assert_eq!(dst, addr(53));
    assert_eq!(src, addr(50000));

    assert!(
        proxy
            .on_event(ProxyEvent::WriteFailed(0x1234), true)
            .is_none(),
        "el pendiente se consumió (complete_dns_req lo borra del mapa)"
    );
}

/// `Data` con una respuesta del peer completa el pendiente casado por id, injertando SOLO los
/// answers (status del peer IGNORADO — el fixture dice REFUSED y la respuesta sale NOERROR);
/// un id sin pendiente se descarta (respuesta tardía/espuria, espejo del `if (req)`).
#[test]
fn data_completes_matching_pending_and_ignores_peer_status() {
    let (mut proxy, _rx) = ProxyDns::new();
    insert_pending(&mut proxy, 0x2001);

    // id 0x2001 = 8193; el peer contesta REFUSED (5) CON un answer MX.
    let peer = br#"{"status":5,"id":8193,"question":[{"name":"mail.svc.example.com","type":15}],"answer":[{"type":15,"ttl":300,"priority":10,"data":"mx1.example.com"}]}"#;
    let (bytes, _, _) = proxy
        .on_event(ProxyEvent::Data(peer.to_vec()), false)
        .expect("id casado → completa");
    assert_eq!(bytes[3] & 0x0f, 0, "NOERROR: el status del peer se IGNORA");
    assert_eq!(bytes[3] & 0x80, 0, "sin upstream, RA nunca");
    assert_eq!(
        u16::from_be_bytes([bytes[6], bytes[7]]),
        1,
        "ANCOUNT=1: el answer injertado"
    );

    // Un id que no casa nada: descartado.
    let spurious = br#"{"id":4660,"answer":[]}"#;
    assert!(
        proxy
            .on_event(ProxyEvent::Data(spurious.to_vec()), false)
            .is_none(),
        "respuesta espuria (id sin pendiente) → drop"
    );
}

/// Un chunk que no parsea (JSON roto) se descarta SIN consumir ningún pendiente (la conn
/// sigue viva; divergencia drop-vs-wedge nombrada en el doc del módulo).
#[test]
fn malformed_chunk_drops_without_touching_pendings() {
    let (mut proxy, _rx) = ProxyDns::new();
    insert_pending(&mut proxy, 0x3001);
    assert!(
        proxy
            .on_event(ProxyEvent::Data(b"not json".to_vec()), true)
            .is_none()
    );
    assert!(
        proxy.pending.contains_key(&0x3001),
        "el pendiente sigue registrado (solo el chunk se descartó)"
    );
}

/// El TTL de pendientes ([`PROXY_PENDING_TIMEOUT`]): el barrido evicta los viejos; una
/// respuesta que llega después ya no casa (se descarta como espuria) — la divergencia TTL
/// nombrada (el oráculo liga la vida al cliente DNS, idle 5s: mismo horizonte).
#[test]
fn evict_expired_drops_stale_pendings() {
    let (mut proxy, _rx) = ProxyDns::new();
    insert_pending(&mut proxy, 0x4001);
    proxy.pending.get_mut(&0x4001).unwrap().at = Instant::now()
        .checked_sub(PROXY_PENDING_TIMEOUT + Duration::from_secs(1))
        .expect("el reloj del test lleva más de 6 s de uptime");
    insert_pending(&mut proxy, 0x4002);

    proxy.evict_expired(Instant::now());
    assert!(!proxy.pending.contains_key(&0x4001), "el viejo se evicta");
    assert!(proxy.pending.contains_key(&0x4002), "el fresco sobrevive");
}

/// Dedup del camino proxy: un `handle_forward` con un id YA pendiente se descarta en silencio
/// (None) sin re-encolar ni tocar el pendiente original — espejo por-camino del dedup global
/// del oráculo (`on_dns_req:792-799`, "just drop new request").
#[tokio::test(flavor = "current_thread")]
async fn duplicate_in_flight_id_is_dropped_silently() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut proxy, _rx) = ProxyDns::new();
            let client = Rc::new(EdgeClient::from_identity_for_test());
            insert_pending(&mut proxy, 0x5001);
            let (packet, name_strlen) = pending_for(0x5001);
            let out = proxy.handle_forward(
                &client,
                Some(("svc".to_string(), Duration::from_secs(1))),
                ProxyQuery {
                    domain: "svc.example.com".to_string(),
                    id: 0x5001,
                    name_strlen,
                    json: b"{}".to_vec(),
                },
                packet,
                addr(53),
                addr(50000),
                true,
            );
            assert!(out.is_none(), "dup → drop silencioso");
            assert!(
                proxy.conns.is_empty(),
                "el dup ni siquiera abre conn (cortocircuito antes del dial)"
            );
        })
        .await;
}

/// El cache de conns va keyed por DOMINIO pero el dueño puede cambiar (eviction #5 +
/// re-registro del mismo sufijo por OTRO servicio): `live_handle` debe tratar un handle de OTRO
/// servicio como ausente (evict + task fresca al dueño ACTUAL) — espejo del `resolv_proxy ==
/// NULL` del `dns_domain_t` re-creado del oráculo (`ziti_dns.c:436-445` evicta el struct;
/// `ziti_dns_register_hostname:462-468` crea uno nuevo zeroed). Sin el guard `h.service !=
/// service`, la query del dominio re-reclamado se respondería por la conn del servicio RETIRADO
/// (over-dispatch que el oráculo no comete).
#[tokio::test(flavor = "current_thread")]
async fn live_handle_evicts_a_conn_whose_service_no_longer_owns_the_domain() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut proxy, _rx) = ProxyDns::new();
            let client = Rc::new(EdgeClient::from_identity_for_test());
            let domain = "svc.example.com".to_string();
            let (first_marker, first_service) = {
                let h = proxy.live_handle(
                    &client,
                    "svc-a".to_string(),
                    Duration::from_secs(1),
                    domain.clone(),
                );
                (Arc::as_ptr(&h.closed) as usize, h.service.clone())
            };
            assert_eq!(first_service, "svc-a");
            // El dominio cambió de dueño: el handle de svc-a se evicta, task fresca a svc-b.
            let (second_marker, second_service) = {
                let h = proxy.live_handle(
                    &client,
                    "svc-b".to_string(),
                    Duration::from_secs(1),
                    domain.clone(),
                );
                (Arc::as_ptr(&h.closed) as usize, h.service.clone())
            };
            assert_eq!(second_service, "svc-b", "el handle es del dueño ACTUAL");
            assert_ne!(
                second_marker, first_marker,
                "handle/task FRESCOS — no la conn del servicio retirado"
            );
            // Mismo dueño → SÍ se reusa (el caso normal: resolv_proxy cacheado del oráculo).
            let third_marker = {
                let h =
                    proxy.live_handle(&client, "svc-b".to_string(), Duration::from_secs(1), domain);
                Arc::as_ptr(&h.closed) as usize
            };
            assert_eq!(
                third_marker, second_marker,
                "el mismo dueño reusa su conn viva"
            );
        })
        .await;
}

/// Sin servicio para el dominio (resolver inconsistente / dominio evictado) → SERVFAIL
/// SÍNCRONO (espejo del quick-fail State A del oráculo, `resolv_proxy == NULL` tras
/// `intercept_resolve_connect` fallando, `ziti_dns.c:755-756`), sin registrar pendiente.
#[tokio::test(flavor = "current_thread")]
async fn missing_service_answers_servfail_synchronously() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut proxy, _rx) = ProxyDns::new();
            let client = Rc::new(EdgeClient::from_identity_for_test());
            let (packet, name_strlen) = pending_for(0x6001);
            let out = proxy
                .handle_forward(
                    &client,
                    None,
                    ProxyQuery {
                        domain: "svc.example.com".to_string(),
                        id: 0x6001,
                        name_strlen,
                        json: b"{}".to_vec(),
                    },
                    packet,
                    addr(53),
                    addr(50000),
                    false,
                )
                .expect("sin servicio → respuesta síncrona");
            assert_eq!(out[3] & 0x0f, DNS_SERVFAIL);
            assert!(proxy.pending.is_empty(), "nada queda pendiente");
        })
        .await;
}

/// El ciclo completo con la conn REAL fallando el dial (EdgeClient de test, sin red): un
/// `handle_forward` registra el pendiente y spawnea la task; el dial falla → la task drena el
/// job como `WriteFailed` → `on_event` completa con SERVFAIL — el observable EXACTO del
/// oráculo cuando la conexión resolver no puede establecerse (`on_proxy_connect` error →
/// writes encolados fallan → `on_proxy_write` → SERVFAIL). También deja `closed`: el
/// siguiente request re-dial-ea (evict-on-closed).
#[tokio::test(flavor = "current_thread")]
async fn dial_failure_completes_pending_with_servfail_via_events() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut proxy, mut rx) = ProxyDns::new();
            let client = Rc::new(EdgeClient::from_identity_for_test());
            let (packet, name_strlen) = pending_for(0x7001);
            let out = proxy.handle_forward(
                &client,
                Some(("unreachable-svc".to_string(), Duration::from_millis(200))),
                ProxyQuery {
                    domain: "svc.example.com".to_string(),
                    id: 0x7001,
                    name_strlen,
                    json: b"{\"status\":0,\"id\":28673}".to_vec(),
                },
                packet,
                addr(53),
                addr(50000),
                true,
            );
            assert!(out.is_none(), "registrado async");

            let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("la task debe fallar el dial dentro del timeout")
                .expect("el manager retiene un tx: recv nunca da None");
            let (bytes, dst, src) = proxy
                .on_event(ev, true)
                .expect("WriteFailed casa el pendiente");
            assert_eq!(bytes[3] & 0x0f, DNS_SERVFAIL, "dial caído → SERVFAIL");
            assert_eq!(dst, addr(53));
            assert_eq!(src, addr(50000));
        })
        .await;
}
