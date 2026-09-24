//! Fixtures compartidos por los `tests_*` de [`super`] (F6 tramo 13 troceo): 7 de los 15 helpers son
//! 2-way/3-way compartidos entre los 3 "Ciclos" de test, con un grafo de dependencia entre
//! "exclusivos" y "compartidos" que impide partirlos sin duplicación o imports ilegales entre
//! hermanos (precedente `intercept/udp/testsupport.rs`, F6 tramo 3a).

use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::channel::message::Message;
use crate::edge::client::EdgeClient;
use crate::edge::data::{ChannelState, EdgeConn, EdgeReadHalf, EdgeWriteHalf};
use crate::edge::model::Service;
use crate::tunnel::intercept::dns::{DnsMatcher, RegisterOutcome};
use crate::tunnel::intercept::dns_server::{DnsAction, handle_query};
use crate::tunnel::intercept::resolve::InterceptResolver;

pub(super) const CONN_ID: u32 = 7;

/// Cliente edge de test (dial siempre falla rápido, sin red): los paths LOCAL/forward no lo usan;
/// el path proxy lo usa solo para el caso dial-fail (la completion con conn viva se prueba
/// llamando `complete_proxy_over_conn` directo sobre halves de test).
pub(super) fn test_client() -> Rc<EdgeClient> {
    Rc::new(EdgeClient::from_identity_for_test())
}

/// Sin upstreams → RA=0, byte-igual a #4.
pub(super) fn no_upstream() -> Rc<[SocketAddr]> {
    Rc::from(Vec::new())
}

/// Upstreams configurados (para el bit RA; un hit LOCAL nunca los contacta).
pub(super) fn some_upstream(servers: Vec<SocketAddr>) -> Rc<[SocketAddr]> {
    Rc::from(servers)
}

/// Resolver con un hostname EXACTO registrado (`svc.example.com` → IP sintética /32) y sin
/// servicios: basta para el servidor DNS embebido (que consulta `dns.lookup`, no la tabla de
/// dispatch). Determinista (seed + registro en el mismo orden → la MISMA IP), así dos builds
/// idénticos producen la misma respuesta → sirve de oráculo local del payload.
pub(super) fn dns_resolver() -> InterceptResolver {
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("100.64.0.0/24"));
    assert!(matches!(
        dns.register("svc.example.com", "i"),
        RegisterOutcome::Hostname(_)
    ));
    InterceptResolver::from_services_with_dns(&[], dns)
}

/// Un `Service` Dial-permitido cuyo `intercept.v1` intercepta `*.example.com` en tcp+udp:80
/// (espejo del helper de `combined/`/`intercept/resolve/testsupport.rs`).
pub(super) fn wildcard_service() -> Service {
    let config: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
        r#"{"intercept.v1":{"protocols":["tcp","udp"],"addresses":["*.example.com"],
            "portRanges":[{"low":80,"high":80}]}}"#,
    )
    .unwrap();
    Service {
        id: "id-wildcard-svc".into(),
        name: "wildcard-svc".into(),
        encryption_required: false,
        permissions: vec!["Dial".into()],
        config,
        configs: vec![],
    }
}

/// Resolver con el servicio wildcard `*.example.com`: `matched_domain("mail.example.com")` →
/// `example.com` y `proxy_service("example.com")` → `wildcard-svc` (el dueño del dominio).
pub(super) fn domain_resolver() -> InterceptResolver {
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("100.64.0.0/24"));
    dns.reserve("100.64.0.1".parse().unwrap());
    dns.reserve("100.64.0.2".parse().unwrap());
    InterceptResolver::from_services_with_dns(&[wildcard_service()], dns)
}

/// Resolver con un DOMINIO registrado en el matcher pero SIN servicio que lo reclame: un estado
/// inconsistente (matcher/resolver desalineados) que fuerza `matched_domain` Some + `proxy_service`
/// None → el path State-A SERVFAIL. Alcanzable en producción si el dominio se evicta entre el match
/// y el routing.
pub(super) fn orphan_domain_resolver() -> InterceptResolver {
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("100.64.0.0/24"));
    assert!(matches!(
        dns.register("*.orphan.com", "i"),
        RegisterOutcome::Domain
    ));
    InterceptResolver::from_services_with_dns(&[], dns)
}

/// Query A DNS válida para `name` (espejo del helper de `combined/`/`intercept/udp/testsupport.rs`).
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

/// Query DNS con RD=0 (sin recursión pedida) — para el gate de forward (`query_upstream:853`).
pub(super) fn dns_a_query_no_rd(id: u16, name: &str) -> Vec<u8> {
    let mut pkt = dns_a_query(id, name);
    pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // limpia el bit RD
    pkt
}

/// Query DNS con tipo arbitrario (MX/PTR/…) para `name`, espejo de `dns_a_query`.
pub(super) fn dns_typed_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = dns_a_query(id, name);
    let n = pkt.len();
    pkt[n - 4..n - 2].copy_from_slice(&qtype.to_be_bytes());
    pkt
}

/// Escribe un mensaje DNS-over-TCP enmarcado (prefijo de longitud 2B BE + cuerpo).
pub(super) async fn write_framed<S: tokio::io::AsyncWrite + Unpin>(s: &mut S, body: &[u8]) {
    let len = u16::try_from(body.len()).unwrap();
    s.write_all(&len.to_be_bytes()).await.unwrap();
    s.write_all(body).await.unwrap();
    s.flush().await.unwrap();
}

/// Lee un mensaje DNS-over-TCP enmarcado → `(prefijo, cuerpo)`.
pub(super) async fn read_framed<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> ([u8; 2], Vec<u8>) {
    let mut prefix = [0u8; 2];
    s.read_exact(&mut prefix).await.unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(prefix) as usize];
    s.read_exact(&mut body).await.unwrap();
    (prefix, body)
}

/// La respuesta local del path UDP para `query` con `(upstream_available, proxy_available)`
/// dados (el MISMO `handle_query`), el oráculo local byte-exacto que DNS-over-TCP reproduce.
pub(super) fn udp_local_response(query: &[u8], upstream_available: bool) -> Vec<u8> {
    match handle_query(dns_resolver().dns_mut(), query, upstream_available, true) {
        DnsAction::Respond(bytes) => bytes,
        other => panic!("se esperaba Respond del path local, {other:?}"),
    }
}

/// Una conn ziti falsa partida en halves (espejo del `fake_conn` de `tcp.rs`/`proxy.rs`): `zw`
/// escribe al duplex `router`; `data_tx` INYECTA frames inbound (ziti→socket) que `zr.read()`
/// entrega. Retiene `state`/`router` vivos para que el mux no cierre.
pub(super) fn fake_conn() -> (
    EdgeReadHalf,
    EdgeWriteHalf,
    Arc<ChannelState>,
    mpsc::Sender<Message>,
    tokio::io::DuplexStream,
) {
    let (cw, router) = tokio::io::duplex(64 * 1024);
    let state = Arc::new(ChannelState::new(Box::new(cw)));
    let (data_tx, data_rx) = mpsc::channel(64);
    state.register_conn(CONN_ID, data_tx.clone());
    let conn = EdgeConn::new_for_test(CONN_ID, data_rx, state.clone());
    let (zr, zw) = conn.into_split();
    (zr, zw, state, data_tx, router)
}
