//! Banner 1 del autor: "forma de la respuesta (espejo `format_resp`)" — F6 tramo 14 troceo: movidos
//! verbatim del `mod tests` del monolito de `intercept/dns_server`.

use std::net::Ipv4Addr;

use super::testsupport::*;
use super::types::{DNS_A_TTL, DNS_OPT, DNS_REFUSE, NS_T_A, NS_T_AAAA};
use super::*;

// ───────────────────────── forma de la respuesta (espejo format_resp) ─────────────────────────

/// Query A de un hostname registrado: la respuesta completa, byte a byte — cabecera copiada
/// del request con QR puesto, pregunta eco, UN registro A (ptr c00c, IN, TTL 60, rdlen 4, la
/// IP sintética), ARCOUNT=1 + OPT de 11 bytes al final.
#[test]
fn a_query_hit_full_response_shape() {
    let mut m = matcher_with(&["app.example.com"]);
    let pkt = std_query("app.example.com", NS_T_A);
    let resp = respond(&mut m, &pkt);

    // Cabecera: id copiado; flags = request | QR; QDCOUNT/NSCOUNT del request; ANCOUNT=1.
    assert_eq!(&resp[0..2], &pkt[0..2], "id copiado del request");
    assert_eq!(
        resp[2],
        pkt[2] | 0x80,
        "QR puesto, resto del byte 2 intacto (RD incluido)"
    );
    assert_eq!(
        resp[3], pkt[3],
        "NOERROR: byte 3 intacto (sin RA: este test corre en modo sin-upstream)"
    );
    assert_eq!(ancount(&resp), 1);
    assert_eq!(&resp[8..10], &pkt[8..10], "NSCOUNT passthrough");
    assert_eq!(
        u16::from_be_bytes([resp[10], resp[11]]),
        1,
        "ARCOUNT=1 SIEMPRE"
    );

    // Pregunta eco (strlen+2+4 = la pregunta entera para un nombre normal).
    let qlen = "app.example.com".len() + 2 + 4;
    assert_eq!(
        &resp[12..12 + qlen],
        &pkt[12..12 + qlen],
        "pregunta eco verbatim"
    );

    // Registro A: c0 0c | tipo 1 | clase 1 | TTL 60 | rdlen 4 | IP.
    let a = &resp[12 + qlen..];
    assert_eq!(&a[0..2], &[0xc0, 0x0c]);
    assert_eq!(u16::from_be_bytes([a[2], a[3]]), NS_T_A);
    assert_eq!(u16::from_be_bytes([a[4], a[5]]), 1);
    assert_eq!(u32::from_be_bytes([a[6], a[7], a[8], a[9]]), DNS_A_TTL);
    assert_eq!(u16::from_be_bytes([a[10], a[11]]), 4);
    assert_eq!(
        Ipv4Addr::new(a[12], a[13], a[14], a[15]),
        Ipv4Addr::new(100, 64, 0, 3),
        "la IP sintética asignada (tras las 2 reservas)"
    );
    // OPT al final.
    assert_eq!(&a[16..27], &DNS_OPT);
    assert_eq!(resp.len(), 12 + qlen + 16 + 11, "nada más tras el OPT");
}

/// Query A de un nombre NO registrado → REFUSED (query_upstream sin upstream), sin registros,
/// ANCOUNT passthrough del request (el bloque de respuesta no se toca) y OPT presente.
#[test]
fn a_query_miss_is_refused_not_nxdomain() {
    let mut m = matcher_with(&["app.example.com"]);
    let resp = respond(&mut m, &std_query("other.example.com", NS_T_A));
    assert_eq!(
        rcode(&resp),
        DNS_REFUSE,
        "miss = REFUSED (el oráculo nunca emite NXDOMAIN)"
    );
    assert_eq!(ancount(&resp), 0, "ANCOUNT del request (0) passthrough");
    assert_eq!(&resp[resp.len() - 11..], &DNS_OPT, "OPT también en errores");
}

/// AAAA de un nombre registrado → NOERROR con CERO registros ("existe, no tiene AAAA") — el
/// bloque de respuesta no se emite (answer NULL en el oráculo) y ANCOUNT queda el del request.
#[test]
fn aaaa_query_hit_is_noerror_with_no_records() {
    let mut m = matcher_with(&["app.example.com"]);
    let resp = respond(&mut m, &std_query("app.example.com", NS_T_AAAA));
    assert_eq!(rcode(&resp), DNS_NO_ERROR);
    assert_eq!(ancount(&resp), 0);
    let qlen = "app.example.com".len() + 2 + 4;
    assert_eq!(
        resp.len(),
        12 + qlen + 11,
        "pregunta eco + OPT, sin registros"
    );
}

/// AAAA de un nombre no registrado → REFUSED (mismo camino upstream que A).
#[test]
fn aaaa_query_miss_is_refused() {
    let mut m = matcher_with(&["app.example.com"]);
    let resp = respond(&mut m, &std_query("nope.example.com", NS_T_AAAA));
    assert_eq!(rcode(&resp), DNS_REFUSE);
}
