//! Servidor **DNS-over-TCP** (RFC 7766) del resolver embebido (M3-DNS, diferido #4 → **#4b**): un
//! cliente que cae a TCP:53 (`dig +tcp`, o el retry tras una respuesta UDP truncada TC=1) contra
//! `(dns_ip, 53)` se sirve aquí, con el framing de RFC 7766 (cada mensaje precedido de su longitud en
//! 2 bytes big-endian, RFC 1035 §4.2.2, en AMBAS direcciones).
//!
//! Módulo extraído de [`super::tcp`] al crecer éste (>800 líneas): el gate de dispatch `is_dns_tcp` y
//! el spawn de la task de servicio siguen en `tcp.rs`; aquí viven el servicio en sí
//! ([`serve_dns_over_tcp`]), el forward a upstream sobre TCP ([`crate::tunnel::intercept::dns_tcp::forward_tcp::forward_upstream_tcp`]) y la completion
//! de proxy-resolve sobre el overlay ([`crate::tunnel::intercept::dns_tcp::proxy_conn::complete_proxy_over_conn`]).
//!
//! **Alcance (beyond-oracle — el oráculo NO sirve DNS-over-TCP: registra el intercept del resolver
//! embebido SOLO con protocolo `"udp"`, `ziti_dns.c:190`, y su campo `is_tcp` de `ziti_dns_client_t`
//! (`ziti_dns.c:43`) es vestigial; su TCP:53 observable es handshake-then-close).** El diferido #4
//! entregó la mitad LOCAL (solo [`crate::tunnel::intercept::dns_server::DnsAction::Respond`]/[`crate::tunnel::intercept::dns_server::DnsAction::Drop`]); **#4b** cierra las dos
//! acciones ASYNC — forward a upstream SOBRE TCP ([`crate::tunnel::intercept::dns_server::DnsAction::ForwardUpstream`]) y proxy-resolve por
//! el overlay ([`crate::tunnel::intercept::dns_server::DnsAction::ForwardProxy`]/[`crate::tunnel::intercept::dns_server::DnsAction::RespondAndConnectProxy`]) — con el bit RA
//! correcto (espejo de `format_resp`, `ziti_dns.c:539-542`), reusando los MISMOS emisor/parser/
//! serializador del path UDP (cero emisor paralelo: la lección T4b). Ver
//! `docs/superpowers/specs/2026-07-08-m3dns-4b-tcp-upstream-proxy-design.md`.
//!
//! **Arquitectura (Opción A, spec §5.1): las acciones async se sirven EN la task de conexión**, con
//! recursos PROPIOS por conexión/por query — NO comparte el socket `UpstreamDns` ni el manager
//! `ProxyDns` del loop UDP (cero mutación de los paths validados en vivo; ids con scope por-conexión
//! como manda RFC 7766; la task por-conexión PUEDE aparcarse en awaits acotados, cosa que el manager
//! UDP tiene prohibida por su invariante HOL). Disciplina de borrow: ningún borrow del
//! `Rc<RefCell<InterceptResolver>>` compartido cruza un `await` (los dos accesos —`handle_query`,
//! `proxy_service`— van hoisted a su `let` y copian a owned antes de todo await).

mod forward_tcp;
mod framing;
mod proxy_conn;
mod service;

#[cfg(test)]
mod tests_forward_tcp;
#[cfg(test)]
mod tests_proxy_conn;
#[cfg(test)]
mod tests_service;
#[cfg(test)]
mod testsupport;

pub(crate) use service::{DnsTcpContext, serve_dns_over_tcp};
