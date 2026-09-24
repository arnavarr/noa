//! Tests 2-7: el runner combinado REAL sirviendo UDP-DNS (serve/forward/servfail/not_impl) y el
//! teardown (limpio/ruidoso/requires-udp), in-process — F6 tramo 17 troceo.

use super::testsupport::*;
use super::*;

use std::io;
use std::net::Ipv4Addr;
use std::rc::Rc;

use netstack_smoltcp::smoltcp::phy::ChecksumCapabilities;
use netstack_smoltcp::smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv4Repr};

use crate::edge::client::EdgeClient;
use crate::tunnel::intercept::stack::InterceptStack;

/// El runner combinado REAL, in-process y sin overlay: montado sobre la pila con UDP + el resolver
/// de la rig, una query A de un cliente (paquete IP crudo por el device) a `(DNS_IP, 53)` recibe
/// su respuesta NOERROR DESDE `(DNS_IP, 53)` con la IP sintética asignada — la reachability de
/// producción que esta rebanada existe para entregar (server DNS MONTADO en el camino del
/// subcomando, no solo alcanzable por tests del manager). El runner sigue VIVO tras servirla
/// (select! no terminó: ninguno de los dos loops cayó). El camino DNS no dial-ea el overlay, así
/// que el `EdgeClient` de test (sin red) jamás se usa — cualquier dial fallaría rápido y el test
/// no lo ejercita.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_serves_dns_at_dns_ip_53_in_process() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let client = Rc::new(EdgeClient::from_identity_for_test());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let runner = tokio::task::spawn_local(run_combined_intercept(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                Vec::new(),
                None,
            ));

            // Un cliente real: datagrama UDP crudo a (DNS_IP, 53) con una query A wildcard.
            host.ingress_tx
                .send(build_udp_pkt(
                    client_addr(),
                    dns_server_addr(),
                    &dns_a_query(0x1234, "app.example.com"),
                ))
                .expect("inyectar la query DNS");

            let (esrc, edst, payload) = host.recv_udp_egress().await;
            assert_eq!(
                esrc,
                dns_server_addr(),
                "la respuesta sale DESDE (dns_ip, 53) — el server está montado ahí"
            );
            assert_eq!(edst, client_addr(), "la respuesta vuelve al cliente");
            assert_eq!(payload[0..2], 0x1234u16.to_be_bytes(), "mismo ID de query");
            assert_eq!(payload[3] & 0x0f, 0, "NOERROR");
            assert_eq!(
                answered_ip(&payload),
                Ipv4Addr::new(100, 64, 0, 3),
                "la IP sintética asignada (1ª libre tras utun+dns)"
            );

            assert!(
                !runner.is_finished(),
                "el runner combinado sigue vivo tras servir la query (ningún loop cayó)"
            );
            runner.abort();
        })
        .await;
}

/// El runner combinado REAL con upstream DNS (M3-DNS #1), in-process: una query de un cliente por
/// un nombre NO interceptado (RD=1) a `(DNS_IP, 53)` se REENVÍA a un upstream FALSO local, cuya
/// respuesta hace passthrough VERBATIM de vuelta al cliente desde `(DNS_IP, 53)`. Prueba el
/// cableado entero server→forward→upstream→passthrough por el runner de producción (no solo las
/// piezas). El upstream falso vive en v6 loopback (el socket de `UpstreamDns` bindea `[::]:0`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_forwards_a_miss_to_upstream_and_passes_the_response_through() {
    let fake_upstream = tokio::net::UdpSocket::bind("[::1]:0")
        .await
        .expect("bind fake upstream");
    let up_addr = fake_upstream.local_addr().unwrap();

    // El fake upstream: por cada request recibido, responde con el MISMO ID + un marcador.
    let responder = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (n, from) = fake_upstream
            .recv_from(&mut buf)
            .await
            .expect("recv upstream");
        // Copia el ID (bytes 0-1), pone QR+RA (0x8180) y un cuerpo distintivo.
        let mut resp = vec![buf[0], buf[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        resp.extend_from_slice(b"UPSTREAM-ANSWER");
        fake_upstream
            .send_to(&resp, from)
            .await
            .expect("send upstream resp");
        (buf[..n].to_vec(), from)
    });

    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let client = Rc::new(EdgeClient::from_identity_for_test());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let runner = tokio::task::spawn_local(run_combined_intercept(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                vec![up_addr],
                None,
            ));

            // Query recursiva por un nombre NO interceptado → miss → forward a upstream.
            host.ingress_tx
                .send(build_udp_pkt(
                    client_addr(),
                    dns_server_addr(),
                    &dns_a_query(0x5AFE, "notlocal.example.org"),
                ))
                .expect("inyectar la query DNS");

            let (esrc, edst, payload) = host.recv_udp_egress().await;
            assert_eq!(
                esrc,
                dns_server_addr(),
                "la respuesta sale DESDE (dns_ip, 53)"
            );
            assert_eq!(edst, client_addr(), "y va al cliente");
            assert_eq!(payload[0..2], 0x5AFEu16.to_be_bytes(), "mismo ID de query");
            assert!(
                payload.ends_with(b"UPSTREAM-ANSWER"),
                "el cuerpo es el de la respuesta upstream (passthrough verbatim)"
            );

            let (fwd_req, _) = responder.await.expect("el responder hace join");
            assert_eq!(
                fwd_req[0..2],
                0x5AFEu16.to_be_bytes(),
                "el upstream recibió el request con el ID original"
            );
            runner.abort();
        })
        .await;
}

/// Query DNS válida para `name` con tipo arbitrario (MX/PTR/…), espejo de `dns_a_query`.
fn dns_typed_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = dns_a_query(id, name);
    let n = pkt.len();
    pkt[n - 4..n - 2].copy_from_slice(&qtype.to_be_bytes());
    pkt
}

/// El runner combinado REAL con PROXY-RESOLVE (M3-DNS #2), in-process y sin overlay: una query
/// MX bajo el dominio interceptado dispara el ciclo de producción ENTERO — handle_query →
/// ForwardProxy → ProxyDns (conn por-dominio, dial REAL de `wildcard-svc` con el EdgeClient de
/// test) → el dial FALLA (sin red) → WriteFailed → SERVFAIL al cliente DESDE `(dns_ip, 53)` —
/// el observable EXACTO del oráculo cuando la conexión resolver no puede establecerse
/// (`on_proxy_connect` error → el write encolado falla → `on_proxy_write` → SERVFAIL,
/// `ziti_dns.c:736-741`). El runner sigue VIVO (la conn proxy muerta no tumba ningún loop).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_answers_servfail_when_proxy_resolve_dial_fails() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let client = Rc::new(EdgeClient::from_identity_for_test());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let runner = tokio::task::spawn_local(run_combined_intercept(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                Vec::new(),
                None,
            ));

            host.ingress_tx
                .send(build_udp_pkt(
                    client_addr(),
                    dns_server_addr(),
                    &dns_typed_query(0x4d58, "mail.example.com", 15), // MX bajo *.example.com
                ))
                .expect("inyectar la query MX");

            let (esrc, edst, payload) = host.recv_udp_egress().await;
            assert_eq!(
                esrc,
                dns_server_addr(),
                "la respuesta sale DESDE (dns_ip, 53)"
            );
            assert_eq!(edst, client_addr(), "y va al cliente");
            assert_eq!(payload[0..2], 0x4d58u16.to_be_bytes(), "mismo ID de query");
            assert_eq!(
                payload[3] & 0x0f,
                2,
                "SERVFAIL: el dial del proxy-resolve falló (espejo on_proxy_write)"
            );
            assert!(
                !runner.is_finished(),
                "el runner sigue vivo: una conn proxy muerta no tumba el tunneler"
            );
            runner.abort();
        })
        .await;
}

/// Un tipo que el proxy nunca sirve (PTR) bajo el dominio, por el runner REAL → NOT_IMPL
/// SÍNCRONO (`proxy_domain_req:779-780`) — sin esperar a ningún dial (la conn se inicia de
/// lado, espejo `:748-753`, y su suerte no afecta a esta respuesta).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_answers_not_impl_for_unsupported_type_under_domain() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let client = Rc::new(EdgeClient::from_identity_for_test());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let runner = tokio::task::spawn_local(run_combined_intercept(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                Vec::new(),
                None,
            ));

            host.ingress_tx
                .send(build_udp_pkt(
                    client_addr(),
                    dns_server_addr(),
                    &dns_typed_query(0x5054, "p.example.com", 12), // PTR bajo *.example.com
                ))
                .expect("inyectar la query PTR");

            let (esrc, _, payload) = host.recv_udp_egress().await;
            assert_eq!(esrc, dns_server_addr());
            assert_eq!(payload[0..2], 0x5054u16.to_be_bytes());
            assert_eq!(
                payload[3] & 0x0f,
                4,
                "NOT_IMPL síncrono para PTR bajo dominio"
            );
            runner.abort();
        })
        .await;
}

/// Paquete IPv4 VÁLIDO con proto=UDP pero payload UDP truncado (4 bytes < los 8 de la cabecera
/// UDP): pasa la validación IP de la ingress de netstack y hace que el read-half UDP dé
/// `Poll::Ready(None)` — el colapso transitorio documentado en `InterceptStack::recv_from`.
fn build_malformed_udp_pkt(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let ip = Ipv4Repr {
        src_addr: src,
        dst_addr: dst,
        next_header: IpProtocol::Udp,
        payload_len: 4,
        hop_limit: 64,
    };
    let mut buf = vec![0u8; ip.buffer_len() + 4];
    let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
    ip.emit(&mut p, &caps);
    buf
}

/// Regresión del teardown RUIDOSO (hallazgo confirmado 3/3 de la review reforzada): una ráfaga de
/// exactamente [`MAX_CONSECUTIVE_RECV_NONE`] datagramas UDP-malformados-en-IP-válido (sin
/// datagrama válido intercalado) agota el bounded-continue del manager → el runner combinado
/// ENTERO termina con `Err(UnexpectedEof)` — NUNCA `Ok` (que main.rs convertiría en exit 0
/// silencioso y un supervisor confundiría con cierre limpio). El oráculo no tiene ningún camino
/// paquete→shutdown; este heurístico acotado es la desviación consciente documentada en
/// `MAX_CONSECUTIVE_RECV_NONE`, y su contrato es que si dispara, dispara COMO FALLO. Mutación-RED:
/// revertir `Stop → Err` a `Stop → break Ok` hace que el runner devuelva `Ok` y el test caiga.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_udp_burst_tears_down_loudly_with_unexpected_eof() {
    use crate::tunnel::intercept::udp::MAX_CONSECUTIVE_RECV_NONE;

    let (dev, host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let client = Rc::new(EdgeClient::from_identity_for_test());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let runner = tokio::task::spawn_local(run_combined_intercept(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                Vec::new(),
                None,
            ));

            for _ in 0..MAX_CONSECUTIVE_RECV_NONE {
                host.ingress_tx
                    .send(build_malformed_udp_pkt(
                        Ipv4Addr::new(100, 64, 0, 200),
                        Ipv4Addr::new(100, 64, 0, 7),
                    ))
                    .expect("inyectar datagrama malformado");
            }

            let res = tokio::time::timeout(TEST_TIMEOUT, runner)
                .await
                .expect("el runner debe terminar tras la ráfaga (bounded-continue agotado)")
                .expect("la task del runner hace join");
            let err = res.expect_err("el teardown por ráfaga malformada es Err, nunca Ok");
            assert_eq!(
                err.kind(),
                io::ErrorKind::UnexpectedEof,
                "el error señala la presunción de pila cerrada"
            );
            drop(host);
        })
        .await;
}

/// Una pila TCP-only no puede correr el runner combinado: `InvalidInput` fail-loud (sin surface
/// UDP no hay manager UDP ni DNS montable), espejo del gate de `run_udp_intercept`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_requires_a_udp_enabled_stack() {
    let (dev, _host) = MockDevice::new();
    let stack = InterceptStack::new(dev).expect("montar pila TCP-only");
    let client = Rc::new(EdgeClient::from_identity_for_test());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let err =
                run_combined_intercept(client, stack, rig_resolver(), DNS_IP, Vec::new(), None)
                    .await
                    .expect_err("TCP-only debe rehusar el runner combinado");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        })
        .await;
}
