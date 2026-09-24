//! Banner 5 del autor: "routing a upstream (M3-DNS #1)" — F6 tramo 14 troceo: movidos verbatim
//! del `mod tests` del monolito de `intercept/dns_server`.

use super::testsupport::*;
use super::types::{NS_T_A, NS_T_TXT};
use super::*;

// ───────────────────── routing a upstream (M3-DNS #1, query_upstream) ─────────────────────

/// EL gate del forward (`query_upstream`, `ziti_dns.c:850-868`): un miss A con RD=1 y upstream
/// activo → [`DnsAction::ForwardUpstream`] (el manager reenvía el request VERBATIM); el MISMO
/// paquete sin upstream → REFUSED local (byte-idéntico al pineado pre-upstream); y con upstream
/// pero RD=0 → REFUSED local también (`avail && req->msg.recursive`) — con RA puesto (el socket
/// está activo, `format_resp:539-542`). Mutación-RED: ignorar RD (forward incondicional) rompe
/// el caso RD=0; ignorar upstream_available rompe el ground truth de 32 casos.
#[test]
fn a_miss_forwards_only_with_rd_and_upstream() {
    let mut m = matcher_with(&["app.example.com"]);

    // RD=1 + upstream → Forward (con la respuesta REFUSED de fallback pre-formateada + RA).
    match handle_query(
        &mut m,
        &std_query("unknown.example.org", NS_T_A),
        true,
        false,
    ) {
        DnsAction::ForwardUpstream { on_send_failure } => {
            assert_eq!(
                rcode(&on_send_failure),
                5,
                "el fallback de fallo de envío es REFUSED"
            );
            assert_eq!(on_send_failure[3] & 0x80, 0x80, "con RA (socket activo)");
        }
        other => panic!("miss recursivo con upstream debe reenviar, fue {other:?}"),
    }
    // RD=1 sin upstream → REFUSED local (comportamiento pre-upstream intacto).
    let resp = respond(&mut m, &std_query("unknown.example.org", NS_T_A));
    assert_eq!(rcode(&resp), 5, "sin upstream, miss = REFUSED");
    assert_eq!(resp[3] & 0x80, 0, "sin upstream, RA nunca");
    // RD=0 + upstream → REFUSED local CON RA (query_upstream corto-circuita en recursive).
    let no_rd = query(0x2222, 0x0000, "unknown.example.org", NS_T_A, 1);
    match handle_query(&mut m, &no_rd, true, false) {
        DnsAction::Respond(resp) => {
            assert_eq!(rcode(&resp), 5, "RD=0: no se reenvía, REFUSED local");
            assert_eq!(
                resp[3] & 0x80,
                0x80,
                "upstream activo → RA en la respuesta local"
            );
        }
        other => panic!("RD=0 debe responder localmente, fue {other:?}"),
    }
}

/// Un tipo no-A/AAAA SIN dominio que lo casé también va a upstream con RD=1 (`on_dns_req:836-843`);
/// y uno BAJO un dominio registrado NUNCA va a upstream (el camino proxy, `:833-835`), aunque
/// haya upstream — su rcode State-B-fail lleva ahora RA (socket activo).
#[test]
fn non_a_routes_upstream_only_without_matching_domain() {
    let mut m = matcher_with(&["*.wild.example.com"]);

    // TXT sin dominio → Forward (con RD=1 + upstream).
    assert!(matches!(
        handle_query(
            &mut m,
            &std_query("other.example.org", NS_T_TXT),
            true,
            false
        ),
        DnsAction::ForwardUpstream { .. }
    ));
    // TXT BAJO el dominio → proxy path (SERVFAIL State-B-fail), NUNCA upstream; RA presente.
    match handle_query(
        &mut m,
        &std_query("a.wild.example.com", NS_T_TXT),
        true,
        false,
    ) {
        DnsAction::Respond(resp) => {
            assert_eq!(
                rcode(&resp),
                2,
                "dominio casado → proxy SERVFAIL, no upstream"
            );
            assert_eq!(resp[3] & 0x80, 0x80, "RA con upstream activo");
        }
        other => panic!("dominio casado debe responder localmente, fue {other:?}"),
    }
}

/// Un HIT local nunca se reenvía (aunque RD=1 + upstream): responde NOERROR con el registro y
/// el bit RA — la respuesta es BYTE-idéntica a la del modo sin-upstream salvo EXACTAMENTE el
/// bit RA (0x80 del byte 3). Pinea que `upstream_available` no altera nada más del serializador.
#[test]
fn local_hit_answers_with_ra_and_is_otherwise_byte_identical() {
    let mut m = matcher_with(&["app.example.com"]);
    let pkt = std_query("app.example.com", NS_T_A);

    let without = respond(&mut m, &pkt);
    let with = match handle_query(&mut m, &pkt, true, false) {
        DnsAction::Respond(bytes) => bytes,
        other => panic!("hit local debe responder, fue {other:?}"),
    };
    assert_eq!(rcode(&with), 0, "hit → NOERROR");
    assert_eq!(ancount(&with), 1, "con el registro A");
    assert_eq!(with[3] & 0x80, 0x80, "RA puesto con upstream");
    assert_eq!(without[3] & 0x80, 0, "RA ausente sin upstream");
    let mut with_ra_cleared = with.clone();
    with_ra_cleared[3] &= !0x80;
    assert_eq!(
        with_ra_cleared, without,
        "salvo el bit RA, la respuesta es byte-idéntica en ambos modos"
    );
}

/// Los caminos Drop (parse inválido / UB fail-closed) son Drop TAMBIÉN con upstream: un paquete
/// que no parsea jamás se reenvía (el oráculo ni llega a query_upstream — `on_dns_req:807-813`
/// descarta antes).
#[test]
fn malformed_packets_drop_even_with_upstream() {
    let mut m = matcher_with(&["app.example.com"]);
    let mut qr = std_query("app.example.com", NS_T_A);
    qr[2] |= 0x80; // QR=1: una respuesta
    assert_eq!(handle_query(&mut m, &qr, true, false), DnsAction::Drop);
    assert_eq!(
        handle_query(&mut m, &[0u8; 4], true, false),
        DnsAction::Drop
    );
}
