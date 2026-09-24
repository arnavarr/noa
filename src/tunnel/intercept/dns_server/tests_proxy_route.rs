//! Banner 3 del autor: "otros tipos (proxy diferido #2; upstream #1 cerrado)" — F6 tramo 14
//! troceo: movidos verbatim del `mod tests` del monolito de `intercept/dns_server`.

use crate::tunnel::intercept::dns::DnsMatcher;

use super::testsupport::*;
use super::types::{DNS_NOT_IMPL, DNS_REFUSE, DNS_SERVFAIL, NS_T_A, NS_T_MX, NS_T_SRV, NS_T_TXT};
use super::*;

// ─────────────── otros tipos (proxy diferido #2; upstream #1 CERRADO, aquí sin configurar) ───────────────

/// El modo pineado SIN proxy cableado (`proxy_available == false`, State-B-fail del oráculo):
/// MX/SRV/TXT bajo un dominio registrado → SERVFAIL; otros tipos bajo dominio → NOT_IMPL;
/// cualquier tipo SIN dominio → REFUSED (query_upstream en modo sin-upstream — el routing a
/// upstream, M3-DNS #1, se cubre en `a_miss_forwards_only_with_rd_and_upstream`; el CABLEADO,
/// M3-DNS #2, en `mx_under_domain_with_proxy_forwards_to_proxy_with_the_request_json`).
#[test]
fn non_a_types_route_by_domain_membership() {
    let mut m = matcher_with(&["*.svc.example.com", "app.example.com"]);
    for qtype in [NS_T_MX, NS_T_SRV, NS_T_TXT] {
        let resp = respond(&mut m, &std_query("mail.svc.example.com", qtype));
        assert_eq!(
            rcode(&resp),
            DNS_SERVFAIL,
            "tipo {qtype} bajo dominio → SERVFAIL (modo sin proxy cableado)"
        );
    }
    // PTR (12) bajo dominio → NOT_IMPL.
    let resp = respond(&mut m, &std_query("mail.svc.example.com", 12));
    assert_eq!(rcode(&resp), DNS_NOT_IMPL);
    // MX de un hostname exacto (NO dominio): find_domain no casa hostnames → REFUSED.
    let resp = respond(&mut m, &std_query("app.example.com", NS_T_MX));
    assert_eq!(rcode(&resp), DNS_REFUSE);
    // MX de un nombre cualquiera sin dominio → REFUSED.
    let resp = respond(&mut m, &std_query("nope.example.org", NS_T_MX));
    assert_eq!(rcode(&resp), DNS_REFUSE);
}

/// Como [`respond`] pero con los flags explícitos (upstream, proxy).
fn respond_with(
    m: &mut DnsMatcher,
    pkt: &[u8],
    upstream_available: bool,
    proxy_available: bool,
) -> Vec<u8> {
    match handle_query(m, pkt, upstream_available, proxy_available) {
        DnsAction::Respond(bytes) => bytes,
        other => panic!("se esperaba una respuesta, fue {other:?}"),
    }
}

/// Con el proxy CABLEADO (M3-DNS #2): MX/SRV/TXT bajo dominio → [`DnsAction::ForwardProxy`]
/// con el dominio casado (el sufijo normalizado, clave de la conn), el id del request, y el
/// JSON compacto del `dns_message` (nombre CRUDO con su case original — la normalización es
/// solo del matching). Espejo del gate de `proxy_domain_req:757` — la completion es del
/// manager. Mutación-RED: rutar MX a upstream (o responder síncrono) rompe este pin.
#[test]
fn mx_under_domain_with_proxy_forwards_to_proxy_with_the_request_json() {
    let mut m = matcher_with(&["*.svc.example.com"]);
    for qtype in [NS_T_MX, NS_T_SRV, NS_T_TXT] {
        let pkt = query(0x2001, 0x0100, "Mail.SVC.example.com", qtype, 1);
        match handle_query(&mut m, &pkt, false, true) {
            DnsAction::ForwardProxy(q) => {
                assert_eq!(q.domain, "svc.example.com", "el SUFIJO casado, normalizado");
                assert_eq!(q.id, 0x2001);
                assert_eq!(q.name_strlen, "Mail.SVC.example.com".len());
                assert_eq!(
                    String::from_utf8(q.json).unwrap(),
                    format!(
                        "{{\"status\":0,\"id\":8193,\"recursive\":1,\"question\":[{{\"name\":\"Mail.SVC.example.com\",\"type\":{qtype}}}]}}"
                    ),
                    "el JSON lleva el nombre VERBATIM (case original) y el tipo de la query"
                );
            }
            other => {
                panic!("tipo {qtype} bajo dominio con proxy debe ForwardProxy, fue {other:?}")
            }
        }
    }
}

/// Con el proxy cableado, un tipo que el proxy nunca sirve (PTR) bajo dominio →
/// [`DnsAction::RespondAndConnectProxy`]: NOT_IMPL YA (`:779-780`) pero la conn del dominio se
/// inicia igual (el oráculo dial-ea ANTES del gate de tipo, `:748-753`). Y el gate de dominio
/// sigue mandando: MX SIN dominio va a upstream/REFUSE aunque el proxy esté cableado; el
/// camino A/AAAA no cambia con el proxy.
#[test]
fn unsupported_type_under_domain_responds_not_impl_and_connects() {
    let mut m = matcher_with(&["*.svc.example.com"]);
    match handle_query(&mut m, &std_query("p.svc.example.com", 12), false, true) {
        DnsAction::RespondAndConnectProxy { response, domain } => {
            assert_eq!(rcode(&response), DNS_NOT_IMPL);
            assert_eq!(domain, "svc.example.com");
        }
        other => {
            panic!("PTR bajo dominio con proxy debe RespondAndConnectProxy, fue {other:?}")
        }
    }
    // MX sin dominio que case: REFUSE local (sin upstream) — el proxy no aplica.
    let resp = respond_with(&mut m, &std_query("nope.example.org", NS_T_MX), false, true);
    assert_eq!(rcode(&resp), DNS_REFUSE);
    // A/AAAA: el proxy no toca su camino (hit local idéntico byte a byte).
    let mut m2 = matcher_with(&["app.example.com"]);
    let with_proxy = respond_with(&mut m2, &std_query("app.example.com", NS_T_A), false, true);
    let mut m3 = matcher_with(&["app.example.com"]);
    let without = respond_with(&mut m3, &std_query("app.example.com", NS_T_A), false, false);
    assert_eq!(
        with_proxy, without,
        "proxy_available no altera el camino A/AAAA"
    );
}
