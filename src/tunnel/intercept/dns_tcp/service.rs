//! **El servicio**: [`DnsTcpContext`] + [`serve_dns_over_tcp`], el loop que lee un mensaje, calcula la
//! `DnsAction` (mismo `handle_query` que UDP) y despacha a framing/forward/proxy.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;

use crate::edge::client::EdgeClient;
use crate::tunnel::intercept::dns_server::{DnsAction, handle_query};
use crate::tunnel::intercept::resolve::InterceptResolver;
use crate::tunnel::intercept::udp::DNS_UPSTREAM_TIMEOUT;

use super::forward_tcp::forward_upstream_tcp;
use super::framing::{DNS_TCP_IDLE_TIMEOUT, read_tcp_dns_msg, write_framed_response};
use super::proxy_conn::resolve_proxy_over_tcp;

/// El contexto del servicio DNS-over-TCP que el runner combinado inyecta al accept-loop TCP
/// ([`crate::tunnel::intercept::tcp::tcp_intercept_loop`]): la IP del resolver embebido y los upstreams a los que
/// reenviar (M3-DNS #1 sobre TCP). Reemplaza el antiguo `dns_server_ip: Option<Ipv4Addr>` — el
/// standalone TCP-only pasa `None` (no sirve DNS), el combinado `Some`.
pub(crate) struct DnsTcpContext {
    /// La IP del servidor DNS embebido (`(server_ip, 53)`): un flujo TCP a esa dirección se sirve
    /// como DNS-over-TCP en vez de dial-earse al overlay.
    pub(crate) server_ip: Ipv4Addr,
    /// Los MISMOS upstreams que `UpstreamDns::bind` recibe (`--dns-upstream`); VACÍO = sin forward
    /// (RA=0, byte-igual a #4). `Rc<[SocketAddr]>` para clonar barato a cada task de conexión.
    pub(crate) upstream_servers: Rc<[SocketAddr]>,
}

/// Sirve **DNS-over-TCP** (RFC 7766) sobre `stream` para el servidor DNS embebido: un cliente que cae
/// a TCP:53 (`dig +tcp`, o un retry tras una respuesta UDP truncada) contra `(dns_ip, 53)`. Espejo
/// del path UDP ([`crate::tunnel::intercept::udp::udp_intercept_loop`]) con el framing de RFC 7766: cada mensaje va
/// precedido de su longitud en 2 bytes big-endian (RFC 1035 §4.2.2), en AMBAS direcciones. Sirve
/// queries SECUENCIALES sobre la misma conexión (reuse, RFC 7766 §6.2.1) hasta EOF limpio, error,
/// idle timeout ([`DNS_TCP_IDLE_TIMEOUT`]), o un mensaje malformado/sobredimensionado.
///
/// **`upstream_available` = `!upstream_servers.is_empty()`** gobierna, EXACTAMENTE como en el path UDP,
/// tanto el forward de un miss recursivo como el bit RA de TODA respuesta local (`format_resp`,
/// `ziti_dns.c:539-542`). **`proxy_available = true` SIEMPRE** en este path: el servicio DNS-over-TCP
/// solo existe bajo el runner combinado con el DNS montado — el mismo "intrínseco al server embebido"
/// que el loop UDP expresa con `proxy.is_some()` (`intercept/udp/runner.rs`: construye `ProxyDns` sii `dns_server_ip`
/// es `Some`). `handle_query(dns, msg, upstream_available, true)` → las 5 acciones:
///  - [`DnsAction::Respond`] → write enmarcado (RA ya correcto);
///  - [`DnsAction::Drop`] → cierra la conexión (paquete malformado, RFC 7766 §6.2.4);
///  - [`DnsAction::ForwardUpstream`] → [`forward_upstream_tcp`] (failover secuencial); `None` → el
///    `on_send_failure` pre-formateado por `handle_query` (REFUSED, RA=1);
///  - [`DnsAction::ForwardProxy`] → dial `RESOLVE_APP_DATA` + [`crate::tunnel::intercept::dns_tcp::proxy_conn::complete_proxy_over_conn`]; sin
///    servicio / dial-fail / write-fail → SERVFAIL (byte-igual al manager UDP); timeout/EOF sin
///    completion → cierra la conn del CLIENTE (§7.7);
///  - [`DnsAction::RespondAndConnectProxy`] → write enmarcado de la respuesta NOT_IMPL, **SIN** el
///    side-dial del path UDP (§7.6: aquí sería dial-and-drop sin función; under-emit de un side-effect,
///    payload byte-idéntico).
///
/// **Disciplina de borrow (load-bearing, ver el runner combinado):** el `borrow_mut`/`borrow` del
/// resolver (para `handle_query` y `proxy_service`) es SÍNCRONO y muere ANTES de todo `await` (I/O a
/// upstream, dial/read del overlay) — igual que los otros consumidores del hilo del `LocalSet`, un
/// borrow vivo a través de un `await` paniquearía al manager UDP que comparte el MISMO `RefCell`.
pub(crate) async fn serve_dns_over_tcp<S>(
    mut stream: S,
    resolver: Rc<RefCell<InterceptResolver>>,
    client: Rc<EdgeClient>,
    upstream_servers: Rc<[SocketAddr]>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let upstream_available = !upstream_servers.is_empty();
    loop {
        // Lee UN mensaje enmarcado, acotado por el idle timeout (cubre la espera entre queries Y un
        // cuerpo que no llega — slow-loris). Cualquier no-`Some` cierra la conexión: `Ok(Ok(None))` =
        // EOF LIMPIO entre queries (cierre normal, no es error); `Ok(Err(_))` = I/O error / mensaje
        // truncado / sobredimensionado; `Err(_)` = idle timeout.
        let Ok(Ok(Some(msg))) =
            tokio::time::timeout(DNS_TCP_IDLE_TIMEOUT, read_tcp_dns_msg(&mut stream)).await
        else {
            return;
        };
        // Borrow SÍNCRONO: computa la acción y SUELTA el borrow antes de cualquier await.
        let action = {
            let mut r = resolver.borrow_mut();
            handle_query(r.dns_mut(), &msg, upstream_available, true)
        };
        match action {
            DnsAction::Respond(response) => {
                if write_framed_response(&mut stream, &response).await.is_err() {
                    return;
                }
            }
            DnsAction::Drop => {
                // Paquete malformado → cierra la conexión (RFC 7766 §6.2.4), sin responder.
                return;
            }
            DnsAction::ForwardUpstream { on_send_failure } => {
                // Failover secuencial a los upstreams SOBRE TCP; ningún upstream respondió → el
                // REFUSED (RA=1) que `handle_query` ya formateó — bytes idénticos al path UDP.
                let response = forward_upstream_tcp(&upstream_servers, &msg, DNS_UPSTREAM_TIMEOUT)
                    .await
                    .unwrap_or(on_send_failure);
                if write_framed_response(&mut stream, &response).await.is_err() {
                    return;
                }
            }
            DnsAction::ForwardProxy(q) => {
                // El dial + completion viven en `resolve_proxy_over_tcp` (mantiene `serve` bajo el
                // límite de líneas): `Ok(bytes)` = escribir enmarcado (completion o SERVFAIL);
                // `Err(())` = cerrar la conn del CLIENTE sin responder (§7.7).
                match resolve_proxy_over_tcp(&resolver, &client, &q, &msg, upstream_available).await
                {
                    Ok(response) => {
                        if write_framed_response(&mut stream, &response).await.is_err() {
                            return;
                        }
                    }
                    Err(()) => return,
                }
            }
            DnsAction::RespondAndConnectProxy { response, .. } => {
                // NOT_IMPL síncrono para un tipo que el proxy nunca sirve. SIN side-dial (§7.6): el
                // path UDP espeja el quirk del oráculo (dial ANTES del gate de tipo) porque su cache
                // tiene consumidor futuro; aquí sería dial-and-drop sin función (ruido host-visible).
                if write_framed_response(&mut stream, &response).await.is_err() {
                    return;
                }
            }
        }
    }
}
