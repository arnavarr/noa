//! G1: el `#[test]` síncrono del resolver-seam compartido (sin runner ni pila) — F6 tramo 17 troceo.

use super::testsupport::*;

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};

use crate::tunnel::intercept::resolve::Protocol;
use crate::tunnel::intercept::udp::dns_response;

// ───── EL SEAM del resolver compartido (el crux de la rebanada, sin runner ni pila) ─────

/// **El pin del estado compartido.** Con el MISMO `RefCell<InterceptResolver>` que el runner
/// combinado construye: (1) el camino UDP sirve una query bajo `*.example.com` con el seam de
/// test `dns_response(resolver.borrow_mut().dns_mut(), …)` — que envuelve
/// `handle_query(dns, payload, false)`, la MISMA llamada local del manager de producción con
/// upstream ausente (el manager real llama `handle_query` directo para poder ver `ForwardUpstream`)
/// → asigna una IP sintética; (2) el camino TCP despacha un flujo a ESA IP con EXACTAMENTE la
/// llamada del
/// accept-loop (`resolver.borrow().lookup(…, Protocol::Tcp, …)`) → el servicio dueño del dominio.
/// Mutación-RED: si el runner diese a cada loop un CLON del resolver (dos estados), la asignación
/// del paso 1 no existiría en el resolver del paso 2 → `lookup` daría `None` (under-dispatch
/// divergente del `ziti_dns` global único del oráculo).
#[test]
fn shared_resolver_udp_dns_assign_feeds_tcp_dispatch() {
    let resolver = RefCell::new(rig_resolver());
    let src = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 200));

    // (1) Camino UDP (la llamada literal del manager): query A bajo el dominio wildcard.
    let resp = dns_response(
        resolver.borrow_mut().dns_mut(),
        &dns_a_query(0x77, "app.example.com"),
    )
    .expect("query bajo *.example.com → respuesta");
    assert_eq!(resp[3] & 0x0f, 0, "NOERROR");
    let ip = answered_ip(&resp);
    assert_eq!(
        ip,
        Ipv4Addr::new(100, 64, 0, 3),
        "1ª IP libre tras las reservas"
    );

    // (2) Camino TCP (la llamada literal del accept-loop): un flujo a esa IP:80 despacha al
    // servicio dueño del dominio, EN EL MISMO resolver compartido.
    let r = resolver.borrow();
    let m = r
        .lookup(IpAddr::V4(ip), 80, Protocol::Tcp, src)
        .expect("la IP asignada por la query DESPACHA vía el fallback wildcard");
    assert_eq!(m.service, "wildcard-svc");

    // Contraste: una IP del pool NO asignada por ninguna query no despacha (under-dispatch).
    assert!(
        r.lookup(
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
            80,
            Protocol::Tcp,
            src
        )
        .is_none(),
        "una IP no asignada no despacha"
    );
}
