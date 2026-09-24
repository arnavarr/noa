//! Ciclo 3: proxy-resolve sobre TCP. F6 tramo 13: movidos verbatim del `mod tests` del monolito de
//! `intercept/dns_tcp`.

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::LocalSet;

use crate::edge::data::{ChannelState, EdgeConn, EdgeReadHalf, EdgeWriteHalf};
use crate::edge::dial::build_data;
use crate::tunnel::intercept::dns_server::{DnsAction, ProxyQuery, handle_query};
use crate::tunnel::intercept::proxy_resolve::{ProxyDns, ProxyEvent};

use super::proxy_conn::complete_proxy_over_conn;
use super::testsupport::*;
use super::*;

// ───────────────────────── Ciclo 3: proxy-resolve sobre TCP ─────────────────────────

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([100, 64, 0, 2], port))
}

/// Un writer que SIEMPRE falla el `poll_write` (espejo del `AlwaysErrWriter` de `stack/`): modela
/// el lado de escritura del overlay caído → `zw.write` da error → completion `Ok(None)`.
struct AlwaysErrWriter;
impl tokio::io::AsyncWrite for AlwaysErrWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "overlay caído",
        )))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Halves de una conn cuyo `zw.write` SIEMPRE falla (overlay caído).
fn fake_conn_write_err() -> (EdgeReadHalf, EdgeWriteHalf) {
    let state = Arc::new(ChannelState::new(Box::new(AlwaysErrWriter)));
    let (data_tx, data_rx) = mpsc::channel(8);
    state.register_conn(CONN_ID, data_tx.clone());
    let conn = EdgeConn::new_for_test(CONN_ID, data_rx, state);
    conn.into_split()
}

/// **El pin de byte-identidad (la lección T4b):** la MISMA respuesta del peer, completada por (a)
/// el manager UDP real (`ProxyDns::handle_forward` registra pending + `on_event(Data)`) y por (b)
/// [`complete_proxy_over_conn`] sobre halves `fake_conn`, produce bytes IDÉNTICOS — porque ambos
/// reusan [`parse_peer_response`] + `format_resp_answers(DNS_NO_ERROR, answers, UNSPECIFIED, ra)`
/// (cero emisor/parser paralelo). Cubre: answers MX presentes · answer ausente (`None`) ·
/// presente-vacío (`Some([])`) · status del peer ≠0 (IGNORADO).
#[tokio::test(flavor = "current_thread")]
async fn proxy_completion_over_tcp_is_byte_identical_to_udp_manager() {
    LocalSet::new()
        .run_until(async {
            let packet = dns_typed_query(0x2001, "mail.svc.example.com", 15);
            let name_strlen = "mail.svc.example.com".len();
            let cases: &[(&str, &[u8], bool)] = &[
                (
                    "mx_answers",
                    br#"{"status":5,"id":8193,"answer":[{"type":15,"ttl":300,"priority":10,"data":"mx1.example.com"}]}"#,
                    true,
                ),
                ("answer_absent", br#"{"status":0,"id":8193}"#, true),
                ("answer_empty", br#"{"status":0,"id":8193,"answer":[]}"#, false),
                (
                    "peer_status_nonzero",
                    br#"{"status":3,"id":8193,"answer":[{"type":16,"ttl":60,"data":"hello"}]}"#,
                    true,
                ),
            ];
            for (label, peer_json, ra) in cases {
                let q = ProxyQuery {
                    domain: "svc.example.com".to_string(),
                    id: 0x2001,
                    name_strlen,
                    json: b"{}".to_vec(),
                };
                // (a) manager UDP real.
                let (mut proxy, _rx) = ProxyDns::new();
                proxy.handle_forward(
                    &test_client(),
                    Some(("svc".to_string(), Duration::from_secs(1))),
                    q.clone(),
                    packet.clone(),
                    addr(53),
                    addr(50000),
                    *ra,
                );
                let (bytes_a, _, _) = proxy
                    .on_event(ProxyEvent::Data(peer_json.to_vec()), *ra)
                    .expect("el manager completa el pendiente");
                // (b) TCP: complete_proxy_over_conn sobre halves fake_conn con el peer scripted.
                let (mut zr, mut zw, _state, data_tx, _router) = fake_conn();
                data_tx
                    .send(build_data(CONN_ID, peer_json, false))
                    .await
                    .unwrap();
                let bytes_b = complete_proxy_over_conn(
                    &mut zr,
                    &mut zw,
                    &q,
                    &packet,
                    *ra,
                    Duration::from_secs(5),
                )
                .await
                .expect("sin error")
                .expect("completa con answers injertados");
                assert_eq!(
                    bytes_a, bytes_b,
                    "caso '{label}': la completion TCP es byte-idéntica al manager UDP"
                );
            }
        })
        .await;
}

/// Un chunk no-parseable se DESCARTA (espejo del drop-del-chunk del manager) y el siguiente válido
/// completa. (Mutación: abortar la conn al primer chunk malo.)
#[tokio::test(flavor = "current_thread")]
async fn proxy_malformed_chunk_then_valid_completes() {
    LocalSet::new()
        .run_until(async {
            let packet = dns_typed_query(0x2001, "mail.svc.example.com", 15);
            let q = ProxyQuery {
                domain: "svc.example.com".to_string(),
                id: 0x2001,
                name_strlen: "mail.svc.example.com".len(),
                json: b"{}".to_vec(),
            };
            let (mut zr, mut zw, _state, data_tx, _router) = fake_conn();
            data_tx
                .send(build_data(CONN_ID, b"not json at all", false))
                .await
                .unwrap();
            data_tx
                .send(build_data(
                    CONN_ID,
                    br#"{"status":0,"id":8193,"answer":[{"type":15,"ttl":300,"priority":10,"data":"m.example.com"}]}"#,
                    false,
                ))
                .await
                .unwrap();
            let bytes = complete_proxy_over_conn(
                &mut zr,
                &mut zw,
                &q,
                &packet,
                true,
                Duration::from_secs(5),
            )
            .await
            .expect("sin error")
            .expect("el 2º chunk (válido) completa");
            assert_eq!(bytes[3] & 0x0f, 0, "NOERROR (answers injertados)");
            assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1, "ANCOUNT=1");
        })
        .await;
}

/// El write del JSON falla (overlay caído) → `Ok(None)` (el llamante responde SERVFAIL, espejo de
/// `on_proxy_write`).
#[tokio::test(flavor = "current_thread")]
async fn proxy_write_fail_completes_none() {
    LocalSet::new()
        .run_until(async {
            let packet = dns_typed_query(0x2001, "mail.svc.example.com", 15);
            let q = ProxyQuery {
                domain: "svc.example.com".to_string(),
                id: 0x2001,
                name_strlen: "mail.svc.example.com".len(),
                json: b"{}".to_vec(),
            };
            let (mut zr, mut zw) = fake_conn_write_err();
            let outcome = complete_proxy_over_conn(
                &mut zr,
                &mut zw,
                &q,
                &packet,
                true,
                Duration::from_secs(5),
            )
            .await;
            assert_eq!(
                outcome,
                Ok(None),
                "write del JSON fallido → Ok(None) (→ SERVFAIL)"
            );
        })
        .await;
}

/// El peer no contesta + timeout diminuto → `Err(())` (el llamante cierra la conn del CLIENTE,
/// §7.7). Timeout por parámetro con I/O real (los halves nunca reciben Data), no reloj pausado.
#[tokio::test(flavor = "current_thread")]
async fn proxy_peer_silence_closes_client_conn() {
    LocalSet::new()
        .run_until(async {
            let packet = dns_typed_query(0x2001, "mail.svc.example.com", 15);
            let q = ProxyQuery {
                domain: "svc.example.com".to_string(),
                id: 0x2001,
                name_strlen: "mail.svc.example.com".len(),
                json: b"{}".to_vec(),
            };
            // Retenemos `_data_tx` → `zr.read()` bloquea (sin EOF) → el timeout diminuto dispara.
            let (mut zr, mut zw, _state, _data_tx, _router) = fake_conn();
            let outcome = complete_proxy_over_conn(
                &mut zr,
                &mut zw,
                &q,
                &packet,
                true,
                Duration::from_millis(80),
            )
            .await;
            assert_eq!(
                outcome,
                Err(()),
                "peer silencioso → Err(()) (cierra la conn del cliente)"
            );
        })
        .await;
}

/// Dial del proxy fallido (`EdgeClient` de test, sin red) por el `serve_dns_over_tcp` REAL → SERVFAIL
/// enmarcado; la conn del cliente SIGUE viva (una 2ª query se sirve). Espejo del observable del
/// oráculo cuando la conn resolver no se establece (`on_proxy_connect` error → SERVFAIL).
#[tokio::test(flavor = "current_thread")]
async fn proxy_dial_failure_answers_servfail_and_conn_survives() {
    LocalSet::new()
        .run_until(async {
            let (mut client, server) = tokio::io::duplex(4096);
            let serve = serve_dns_over_tcp(
                server,
                Rc::new(RefCell::new(domain_resolver())),
                test_client(),
                no_upstream(),
            );
            let drive = async move {
                let q = dns_typed_query(0x4d58, "mail.example.com", 15); // MX bajo *.example.com
                write_framed(&mut client, &q).await;
                let (_p, r) = read_framed(&mut client).await;
                assert_eq!(r[3] & 0x0f, 2, "SERVFAIL: el dial del proxy-resolve falló");
                assert_eq!(&r[0..2], &q[0..2], "id de la query");
                let q2 = dns_typed_query(0x4d59, "other.example.com", 15);
                write_framed(&mut client, &q2).await;
                let (_p2, r2) = read_framed(&mut client).await;
                assert_eq!(
                    r2[3] & 0x0f,
                    2,
                    "conn viva: 2ª query también servida (SERVFAIL)"
                );
                drop(client);
            };
            tokio::join!(serve, drive);
        })
        .await;
}

/// Un dominio interceptado SIN servicio dueño (evictado / resolver inconsistente) → SERVFAIL
/// inmediato SIN dial (espejo del quick-fail State A, `ziti_dns.c:755-756`). (Mutación: dial-ear
/// sin dueño → panic/hang.)
#[tokio::test(flavor = "current_thread")]
async fn proxy_no_service_for_domain_servfails() {
    LocalSet::new()
        .run_until(async {
            let (mut client, server) = tokio::io::duplex(4096);
            let serve = serve_dns_over_tcp(
                server,
                Rc::new(RefCell::new(orphan_domain_resolver())),
                test_client(),
                no_upstream(),
            );
            let drive = async move {
                let q = dns_typed_query(0x6001, "mail.orphan.com", 15); // MX bajo *.orphan.com (sin servicio)
                write_framed(&mut client, &q).await;
                let (_p, r) = read_framed(&mut client).await;
                assert_eq!(
                    r[3] & 0x0f,
                    2,
                    "SERVFAIL inmediato (State A: proxy_service None)"
                );
                drop(client);
            };
            tokio::join!(serve, drive);
        })
        .await;
}

/// Un tipo que el proxy nunca sirve (PTR) bajo un dominio → NOT_IMPL enmarcado byte-idéntico al
/// path UDP, SIN side-dial (§7.6); la conn sigue viva. (Mutación: replicar el side-dial del UDP.)
#[tokio::test(flavor = "current_thread")]
async fn ptr_under_domain_not_impl_without_side_dial() {
    LocalSet::new()
        .run_until(async {
            let q = dns_typed_query(0x5054, "p.example.com", 12); // PTR bajo *.example.com
            // El NOT_IMPL que el path UDP produciría (RespondAndConnectProxy.response).
            let expected = match handle_query(domain_resolver().dns_mut(), &q, false, true) {
                DnsAction::RespondAndConnectProxy { response, .. } => response,
                other => panic!("se esperaba RespondAndConnectProxy, fue {other:?}"),
            };
            let (mut client, server) = tokio::io::duplex(4096);
            let serve = serve_dns_over_tcp(
                server,
                Rc::new(RefCell::new(domain_resolver())),
                test_client(),
                no_upstream(),
            );
            let drive = async move {
                write_framed(&mut client, &q).await;
                let (_p, r) = read_framed(&mut client).await;
                assert_eq!(r[3] & 0x0f, 4, "NOT_IMPL para PTR bajo dominio");
                assert_eq!(r, expected, "byte-idéntico al NOT_IMPL del path UDP");
                // La conn sigue viva (no colgó en un side-dial): 2ª query servida.
                let q2 = dns_typed_query(0x5055, "q.example.com", 12);
                write_framed(&mut client, &q2).await;
                let (_p2, r2) = read_framed(&mut client).await;
                assert_eq!(r2[3] & 0x0f, 4, "conn viva: 2ª PTR también NOT_IMPL");
                drop(client);
            };
            tokio::join!(serve, drive);
        })
        .await;
}
