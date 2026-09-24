//! Banner 2 del autor: "asignación vía dominio (diferido #6)" — F6 tramo 14 troceo: movidos
//! verbatim del `mod tests` del monolito de `intercept/dns_server`.

use super::testsupport::*;
use super::types::{DNS_REFUSE, NS_T_A, NS_T_AAAA};
use super::*;

// ───────────────────────── asignación vía dominio (lo que alimenta el diferido #6) ─────────────────────────

/// Una query A bajo un dominio wildcard ASIGNA una IP fresca (ziti_dns_lookup →
/// new_ipv4_entry) y la respuesta la lleva; la MISMA query después responde la MISMA IP
/// (cacheada); un subdominio DISTINTO recibe OTRA.
#[test]
fn a_query_under_wildcard_domain_assigns_and_caches_an_ip() {
    let mut m = matcher_with(&["*.svc.example.com"]);
    let r1 = respond(&mut m, &std_query("a.svc.example.com", NS_T_A));
    assert_eq!(rcode(&r1), DNS_NO_ERROR);
    let ip1 = &r1[r1.len() - 11 - 4..r1.len() - 11];
    assert_eq!(ip1, &[100, 64, 0, 3], "primera IP libre tras las reservas");

    let r2 = respond(&mut m, &std_query("a.svc.example.com", NS_T_A));
    assert_eq!(
        &r2[r2.len() - 11 - 4..r2.len() - 11],
        ip1,
        "misma IP cacheada"
    );

    let r3 = respond(&mut m, &std_query("b.svc.example.com", NS_T_A));
    assert_eq!(
        &r3[r3.len() - 11 - 4..r3.len() - 11],
        &[100, 64, 0, 4],
        "otro subdominio, otra IP"
    );
}

/// TAMBIÉN una query AAAA bajo un dominio asigna la IP (ziti_dns_lookup es agnóstico al tipo
/// — espejo exacto), aunque la respuesta AAAA no lleve registros: la A posterior del MISMO
/// nombre devuelve la IP que la AAAA ya asignó.
#[test]
fn aaaa_query_under_wildcard_domain_also_assigns_the_ip() {
    let mut m = matcher_with(&["*.svc.example.com"]);
    let r_aaaa = respond(&mut m, &std_query("x.svc.example.com", NS_T_AAAA));
    assert_eq!(rcode(&r_aaaa), DNS_NO_ERROR);
    assert_eq!(ancount(&r_aaaa), 0);

    let r_a = respond(&mut m, &std_query("x.svc.example.com", NS_T_A));
    assert_eq!(
        &r_a[r_a.len() - 11 - 4..r_a.len() - 11],
        &[100, 64, 0, 3],
        "la AAAA ya consumió/asignó la IP; la A la devuelve"
    );
}

/// Case-insensitive con eco de la pregunta EN SU CASE ORIGINAL: el matcher normaliza a
/// lowercase, pero la sección de pregunta de la respuesta es la copia verbatim del request.
#[test]
fn mixed_case_query_matches_and_echoes_original_case() {
    let mut m = matcher_with(&["app.example.com"]);
    let pkt = std_query("APP.Example.COM", NS_T_A);
    let resp = respond(&mut m, &pkt);
    assert_eq!(rcode(&resp), DNS_NO_ERROR);
    let qlen = "APP.Example.COM".len() + 2 + 4;
    assert_eq!(
        &resp[12..12 + qlen],
        &pkt[12..12 + qlen],
        "eco con el case original"
    );
}

/// Una query con forma de wildcard (`*.foo`) en tipo A se RECHAZA en el lookup
/// (`ziti_dns_lookup:383`) → REFUSED, sin asignar nada.
#[test]
fn wildcard_form_a_query_is_refused() {
    let mut m = matcher_with(&["*.svc.example.com"]);
    let resp = respond(&mut m, &std_query("*.svc.example.com", NS_T_A));
    assert_eq!(rcode(&resp), DNS_REFUSE);
}
