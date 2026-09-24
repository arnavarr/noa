//! El router: `handle_query`, el único punto de entrada público — decide
//! LOCAL/Drop/ForwardUpstream/ForwardProxy/RespondAndConnectProxy combinando
//! parser+serializer+matcher.

use crate::tunnel::intercept::dns::DnsMatcher;

use super::parser::parse_query;
use super::serializer::format_resp;
use super::types::{
    DNS_NO_ERROR, DNS_NOT_IMPL, DNS_REFUSE, DNS_SERVFAIL, DnsAction, NS_T_A, NS_T_AAAA, NS_T_MX,
    NS_T_SRV, NS_T_TXT, ProxyQuery,
};

/// Procesa UN datagrama dirigido al resolver embebido `(dns_ip, 53)` y produce la respuesta, el
/// descarte, o el reenvío a upstream. Espejo del routing de `on_dns_req` (`ziti_dns.c:825-844`) +
/// `process_host_req` + `query_upstream` (`:850-868`). `upstream_available` = ¿hay socket upstream
/// activo? (espejo de `uv_is_active(&ziti_dns.upstream)`): gobierna tanto el forward de un miss
/// recursivo ([`crate::tunnel::intercept::dns_server::DnsAction::ForwardUpstream`]) como el bit RA de TODA respuesta local — con `false`
/// el comportamiento es BYTE-IDÉNTICO al pre-upstream (miss → REFUSE, RA nunca; el ground truth de
/// 32 casos pinea exactamente ese modo). `dns` es `&mut` porque un match de dominio wildcard ASIGNA
/// una IP fresca dentro de [`DnsMatcher::lookup`] — el efecto que alimenta el dispatch per-paquete
/// de wildcards (diferido #6, CERRADO en `0211810`; ver
/// [`crate::tunnel::intercept::resolve::InterceptResolver::dns_mut`]).
/// `proxy_available` = ¿está cableado el proxy-resolve por el overlay (M3-DNS #2)? En producción
/// SIEMPRE `true` cuando el servidor DNS embebido corre bajo el manager UDP (el oráculo no tiene
/// este estado: sus ziti contexts existen siempre que el DNS corre); `false` es el modo pineado
/// pre-proxy (State-B-fail: MX/SRV/TXT → SERVFAIL, resto → NOT_IMPL — el ground truth de 32 casos
/// y el runner standalone sin manager lo conservan byte-idéntico).
#[must_use]
pub fn handle_query(
    dns: &mut DnsMatcher,
    packet: &[u8],
    upstream_available: bool,
    proxy_available: bool,
) -> DnsAction {
    let Some(q) = parse_query(packet) else {
        return DnsAction::Drop;
    };
    // query_upstream (ziti_dns.c:853): el forward exige upstream activo Y RD=1 en el request.
    let forwards = upstream_available && q.recursive;

    // El nombre a CASAR es el que ve `check_name` del oráculo: los bytes crudos TRUNCADOS en el
    // primer NUL (`ziti_dns.c:324`, `while (*hp != '\0')` — un C-string). `name_strlen` es esa
    // posición (ya computada en el parseo). NO usar `q.name` completo: un label con un `0x00`
    // embebido (p. ej. `app\0.svc.example.com`) haría que `find_domain` casara el sufijo
    // `svc.example.com` y ASIGNARA una IP que el oráculo (que corta en `app`) REFUSE — un
    // OVER-PERMIT (cazado por la revisión reforzada, manifestación A1). Con el corte, el nombre
    // casado es `app` → sin match → REFUSE, byte-fiel al oráculo. Idéntico para el sufijo-NUL
    // (`app.example.com\0x` → `app.example.com` → HIT, manifestación A2).
    let matched = std::str::from_utf8(&q.name[..q.name_strlen]).ok();
    let (status, a_answer) = if q.qtype == NS_T_A || q.qtype == NS_T_AAAA {
        // process_host_req: A y AAAA consultan (y pueden ASIGNAR, vía dominio) igual; solo la
        // emisión del registro difiere (AAAA hit = NOERROR sin registros). Un miss va a upstream
        // (`:666-673`) si el forward procede; si no, REFUSE (query_upstream → DNS_REFUSE).
        match matched.and_then(|n| dns.lookup(n)) {
            Some(m) => (DNS_NO_ERROR, (q.qtype == NS_T_A).then_some(m.ip)),
            None if forwards => {
                return DnsAction::ForwardUpstream {
                    on_send_failure: format_resp(packet, q.name_strlen, DNS_REFUSE, None, true),
                };
            }
            None => (DNS_REFUSE, None),
        }
    } else if let Some(domain) = matched.and_then(|n| dns.matched_domain(n)) {
        // proxy_domain_req (`ziti_dns.c:747-785`), M3-DNS #2. Con el proxy CABLEADO
        // (`proxy_available`): MX/SRV/TXT → ForwardProxy (el manager dial-ea/encola/completa
        // async); el resto → NOT_IMPL síncrono (`:779-780`) PERO asegurando la conn igual (el
        // oráculo la inicia ANTES del gate de tipo, `:748-753`). El JSON lleva el nombre CRUDO
        // NUL-cortado con su case original (`req->msg.question[0]->name` como C-string) — la
        // normalización de `matched_domain` es solo del matching.
        if proxy_available {
            if q.qtype == NS_T_MX || q.qtype == NS_T_SRV || q.qtype == NS_T_TXT {
                let id = u16::from_be_bytes([packet[0], packet[1]]);
                return DnsAction::ForwardProxy(ProxyQuery {
                    domain,
                    id,
                    name_strlen: q.name_strlen,
                    json: crate::tunnel::intercept::proxy_resolve::emit_dns_message_json(
                        id,
                        q.recursive,
                        &q.name[..q.name_strlen],
                        q.qtype,
                    ),
                });
            }
            return DnsAction::RespondAndConnectProxy {
                response: format_resp(
                    packet,
                    q.name_strlen,
                    DNS_NOT_IMPL,
                    None,
                    upstream_available,
                ),
                domain,
            };
        }
        // Modo pineado SIN proxy cableado (pre-#2, lo conservan el ground truth de 32 casos y el
        // runner standalone sin manager): los rcodes del State-B-fail del oráculo — la conexión al
        // overlay quick-fallando (sin api-session válida, `ziti_dns.c:765-767`): MX/SRV/TXT toman
        // la rama async (`:757-772`) cuyo write falla → `on_proxy_write` pone SERVFAIL (`:738`);
        // el resto de tipos → NOT_IMPL SÍNCRONO (`:779-780`).
        if q.qtype == NS_T_MX || q.qtype == NS_T_SRV || q.qtype == NS_T_TXT {
            (DNS_SERVFAIL, None) // State-B write-fail: on_proxy_write (ziti_dns.c:738)
        } else {
            (DNS_NOT_IMPL, None) // State-B síncrono para tipos que el proxy nunca sirve (:779-780)
        }
    } else if forwards {
        // sin dominio (on_dns_req:836-843): query_upstream — el forward procede.
        return DnsAction::ForwardUpstream {
            on_send_failure: format_resp(packet, q.name_strlen, DNS_REFUSE, None, true),
        };
    } else {
        (DNS_REFUSE, None) // sin dominio, sin upstream (o RD=0) → DNS_REFUSE
    };

    DnsAction::Respond(format_resp(
        packet,
        q.name_strlen,
        status,
        a_answer,
        upstream_available,
    ))
}
