//! La rama DNS del manager UDP del intercept: el discriminante del servidor embebido y el dispatch
//! de un datagrama a local / upstream / proxy-resolve. (F6 tramo 3a: movido verbatim del monolito de
//! `intercept/udp`.)

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;

use crate::edge::client::EdgeClient;
use crate::tunnel::intercept::dns_server::{DnsAction, handle_query};
use crate::tunnel::intercept::proxy_resolve::ProxyDns;
use crate::tunnel::intercept::resolve::InterceptResolver;
use crate::tunnel::intercept::stack::UdpReplySender;

use super::UpstreamDns;

/// El puerto del servidor DNS embebido (`ziti_dns_setup`: `intercept_ctx_add_port_range(.., 53, 53)`,
/// `ziti_dns.c:189`).
const DNS_SERVER_PORT: u16 = 53;

/// ¿El datagrama va al servidor DNS embebido `(dns_server_ip, 53)` en vez de a un servicio overlay?
/// Espejo del intercept `ziti:dns-resolver` del oráculo (`ziti_dns_setup`, `ziti_dns.c:185-192`),
/// que registra `(dns_addr, 53, udp)` con callbacks propios en vez de un dial: un datagrama a esa
/// dirección lo maneja el DNS embebido, no el resolver dst→servicio. `dns_server_ip == None` (sin
/// servidor DNS configurado) → siempre `false` (comportamiento previo intacto). El puerto DEBE ser
/// exactamente 53 (`intercept_ctx_add_port_range(.., 53, 53)`).
pub(super) fn is_dns_server_datagram(dst: SocketAddr, dns_server_ip: Option<Ipv4Addr>) -> bool {
    match dns_server_ip {
        Some(ip) => dst.ip() == IpAddr::V4(ip) && dst.port() == DNS_SERVER_PORT,
        None => false,
    }
}

/// Produce la respuesta DNS LOCAL a un datagrama dirigido al servidor embebido (modo SIN upstream),
/// o `None` para descartarlo (parse inválido / camino UB fail-closed, ver [`crate::tunnel::intercept::dns_server`]).
/// Helper de tests/seam: el loop de producción llama [`handle_query`] DIRECTAMENTE con el estado real
/// de upstream (para poder ver [`DnsAction::ForwardUpstream`], que este helper nunca produce por pasar
/// `upstream_available = false`). `dns` es `&mut` porque una query bajo un dominio wildcard ASIGNA
/// una IP (efecto del oráculo `ziti_dns_lookup`). Solo-tests: los tests del runner combinado
/// (`combined`) pinean el seam resolver-compartido con EXACTAMENTE esta llamada (el loop de
/// producción llama `handle_query` directo para poder ver `ForwardUpstream`).
#[cfg(test)]
pub(crate) fn dns_response(
    dns: &mut crate::tunnel::intercept::dns::DnsMatcher,
    payload: &[u8],
) -> Option<Vec<u8>> {
    match handle_query(dns, payload, false, false) {
        DnsAction::Respond(bytes) => Some(bytes),
        DnsAction::Drop
        | DnsAction::ForwardUpstream { .. }
        | DnsAction::ForwardProxy(_)
        | DnsAction::RespondAndConnectProxy { .. } => None,
    }
}

/// Sirve UN datagrama dirigido al servidor DNS embebido `(dns_ip, 53)`: resolver localmente y
/// responder DESDE esa dirección AL cliente (send_to swap), reenviar a upstream (M3-DNS #1), o
/// proxy-resolver por el overlay (M3-DNS #2). Extraído del loop para mantenerlo legible; TODO es
/// síncrono/no-bloqueante (el manager JAMÁS se aparca — el invariante HOL: respuestas por
/// `try_send_to`, forward por `try_send_to` del socket upstream, y el trabajo async del proxy vive
/// en sus tasks por-dominio). Los `borrow`/`borrow_mut` del resolver van HOISTED a su propio `let`:
/// mueren en el `;` — inlinearlos en un scrutinee los mantendría vivos durante el bloque en
/// edition 2024 y un accept TCP concurrente paniquearía en `resolver.borrow()`.
///
/// `Break` = la cola de reply-egress se cerró (pila desmontada) → el llamante rompe el loop.
#[allow(clippy::too_many_arguments)] // el seam completo del dispatch DNS del manager (8 piezas)
pub(super) fn serve_dns_datagram(
    client: &Rc<EdgeClient>,
    resolver: &RefCell<InterceptResolver>,
    reply: &UdpReplySender,
    upstream: &mut Option<UpstreamDns>,
    proxy: &mut Option<ProxyDns>,
    payload: Vec<u8>,
    dst: SocketAddr,
    src: SocketAddr,
) -> std::ops::ControlFlow<()> {
    let action = handle_query(
        resolver.borrow_mut().dns_mut(),
        &payload,
        upstream.is_some(),
        proxy.is_some(),
    );
    match action {
        DnsAction::Respond(bytes) => send_dns_reply(reply, bytes, dst, src),
        DnsAction::Drop => std::ops::ControlFlow::Continue(()),
        DnsAction::ForwardUpstream { on_send_failure } => {
            // `upstream.is_some()` lo garantiza (handle_query solo produce Forward con
            // upstream_available). Si NINGÚN upstream aceptó el envío → devuelve el REFUSED de
            // fallback al cliente (espejo de query_upstream→DNS_REFUSE→format+complete).
            let up = upstream.as_mut().expect("Forward ⇒ upstream configurado");
            if up.forward(&payload, dst, src) {
                std::ops::ControlFlow::Continue(())
            } else {
                send_dns_reply(reply, on_send_failure, dst, src)
            }
        }
        DnsAction::ForwardProxy(q) => {
            // MX/SRV/TXT bajo dominio (M3-DNS #2): el manager asegura la conn del dominio, encola
            // el JSON y registra el pendiente — todo síncrono (el dial vive en la task
            // por-dominio). `Some(..)` = completó síncrono (SERVFAIL sin servicio, espejo State A).
            let p = proxy.as_mut().expect("ForwardProxy ⇒ proxy cableado");
            let service = resolver
                .borrow()
                .proxy_service(&q.domain)
                .map(|m| (m.service.to_string(), m.dial_timeout));
            match p.handle_forward(client, service, q, payload, dst, src, upstream.is_some()) {
                Some(now_resp) => send_dns_reply(reply, now_resp, dst, src),
                None => std::ops::ControlFlow::Continue(()),
            }
        }
        DnsAction::RespondAndConnectProxy { response, domain } => {
            // Tipo no-A/AAAA que el proxy nunca sirve, bajo dominio: NOT_IMPL YA + la conn del
            // dominio se inicia igual (el oráculo dial-ea ANTES del gate de tipo,
            // proxy_domain_req:748-753).
            let p = proxy
                .as_mut()
                .expect("RespondAndConnectProxy ⇒ proxy cableado");
            let service = resolver
                .borrow()
                .proxy_service(&domain)
                .map(|m| (m.service.to_string(), m.dial_timeout));
            if let Some((service, timeout)) = service {
                p.ensure_conn(client, service, timeout, domain);
            }
            send_dns_reply(reply, response, dst, src)
        }
    }
}

/// Encola una respuesta DNS al cliente NO-bloqueante (`try_send_to`, ver el invariante HOL del
/// manager). `Break` = la cola de reply-egress se cerró (pila desmontada) → el llamante rompe el
/// loop; `Continue` = encolada o descartada-por-llena (DNS-sobre-UDP es lossy, el stub reintenta).
pub(super) fn send_dns_reply(
    reply: &UdpReplySender,
    bytes: Vec<u8>,
    dst: SocketAddr,
    src: SocketAddr,
) -> std::ops::ControlFlow<()> {
    match reply.try_send_to(bytes, dst, src) {
        Ok(true) => std::ops::ControlFlow::Continue(()),
        Ok(false) => {
            tracing::warn!("intercept dns: cola de respuestas llena; respuesta DNS descartada");
            std::ops::ControlFlow::Continue(())
        }
        Err(_) => {
            tracing::warn!("intercept dns: reply egress cerrado");
            std::ops::ControlFlow::Break(())
        }
    }
}
