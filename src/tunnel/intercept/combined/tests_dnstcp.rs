//! Test 12: DNS-over-TCP threading del `DnsTcpContext` por `run_combined_intercept` — F6 tramo 17 troceo.

use super::testsupport::*;
use super::*;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;

use netstack_smoltcp::smoltcp::wire::TcpControl;

use crate::edge::client::EdgeClient;
use crate::tunnel::intercept::stack::InterceptStack;

/// **Ciclo 4 (#4b): el pin del threading del `DnsTcpContext` por `run_combined_intercept`.** Un
/// cliente TCP hace el handshake con `(DNS_IP, 53)` por el device y envía una query A enmarcada bajo
/// `*.example.com`, con el runner arrancado CON un upstream configurado (non-empty, nunca contactado
/// en un hit local). La respuesta DNS-over-TCP: NOERROR + IP sintética + **RA=1**. El RA=1 SOLO
/// aparece si `!upstream_servers.is_empty()` llegó a `handle_query` → pinea el hilo `upstream_servers`;
/// recibir CUALQUIER respuesta enmarcada pinea el hilo `server_ip` (si no, TCP:53 se trataría como un
/// intercept normal y se dropearía → timeout). Ambos hilos del `DnsTcpContext` que los unit de
/// `dns_tcp/` no ven, en un solo gate.
///
/// Mutación-RED: cablear el contexto con RA=0 (upstreams no threaded) rompe el assert de RA; no
/// construir/pasar el contexto (TCP:53 se dropea) → `recv_framed_dns_over_tcp` hace timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_serves_dns_over_tcp_threads_upstream_context() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let client = Rc::new(EdgeClient::from_identity_for_test());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            // upstream NON-EMPTY (127.0.0.1:9 discard; nunca contactado en un hit local) → RA=1.
            let upstream = SocketAddr::from(([127, 0, 0, 1], 9));
            let runner = tokio::task::spawn_local(run_combined_intercept(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                vec![upstream],
                None,
            ));

            let cli = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 200), 40_000);
            let dns_tcp = SocketAddrV4::new(DNS_IP, 53);
            let isn = 1000;

            // Handshake: SYN → SYN-ACK → ACK.
            host.ingress_tx
                .send(build_tcp_pkt(cli, dns_tcp, TcpControl::Syn, isn, None, &[]))
                .expect("SYN");
            let synack = host.recv_tcp_egress_matching(|p| p.syn && p.ack).await;
            assert_eq!(synack.src, dns_tcp, "el SYN-ACK sale de (DNS_IP, 53)");
            let server_isn = synack.seq;
            host.ingress_tx
                .send(build_tcp_pkt(
                    cli,
                    dns_tcp,
                    TcpControl::None,
                    isn + 1,
                    Some(server_isn + 1),
                    &[],
                ))
                .expect("ACK");

            // Query A enmarcada bajo *.example.com (hit local que asigna una IP sintética).
            let query = dns_a_query(0x1234, "app.example.com");
            let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&query);
            host.ingress_tx
                .send(build_tcp_pkt(
                    cli,
                    dns_tcp,
                    TcpControl::Psh,
                    isn + 1,
                    Some(server_isn + 1),
                    &framed,
                ))
                .expect("query enmarcada");

            // La respuesta DNS-over-TCP enmarcada, DESDE (DNS_IP, 53). El cliente falso ACKea cada
            // segmento (si no, Nagle retiene el cuerpo tras el prefijo — ver el doc del helper).
            let client_seq = isn + 1 + i32::try_from(framed.len()).unwrap();
            let resp = host
                .recv_framed_dns_over_tcp(dns_tcp, cli, client_seq)
                .await;
            assert_eq!(&resp[0..2], &0x1234u16.to_be_bytes(), "id de la query");
            assert_eq!(resp[3] & 0x0f, 0, "NOERROR (hit A bajo *.example.com)");
            assert_eq!(
                resp[3] & 0x80,
                0x80,
                "RA=1: el upstream configurado llegó a handle_query (hilo upstream_servers)"
            );
            assert_eq!(
                answered_ip(&resp),
                Ipv4Addr::new(100, 64, 0, 3),
                "IP sintética asignada (1ª libre tras utun+dns)"
            );

            runner.abort();
        })
        .await;
}
