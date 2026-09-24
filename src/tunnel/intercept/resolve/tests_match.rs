// F6 tramo 2b troceo: tests movidos verbatim del monolito de `intercept/resolve` (mod tests).

use std::time::Duration;

use super::testsupport::*;
use super::{InterceptResolver, Protocol};

#[test]
fn lookup_matches_cidr_port_and_protocol() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    let m = r
        .lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
        .expect("debe casar");
    assert_eq!(m.service, "svc");
    assert_eq!(m.dial_timeout, Duration::from_secs(5));
}

#[test]
fn lookup_misses_outside_cidr_port_or_protocol() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    assert!(
        r.lookup(ip("10.0.1.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "fuera del CIDR"
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 81, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "fuera del rango"
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Udp, ANY_SRC)
            .is_none(),
        "protocolo distinto"
    );
}

#[test]
fn protocol_match_is_case_sensitive() {
    // El oráculo usa stringz.Contains (== exacto). Un "TCP" en el config NO casa un flujo tcp.
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["TCP"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "protocolo case-sensitive: 'TCP' != 'tcp'"
    );
}

#[test]
fn port_range_is_inclusive_both_ends() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":90}]}}"#,
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_some(),
        "low inclusive"
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 90, Protocol::Tcp, ANY_SRC)
            .is_some(),
        "high inclusive"
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 79, Protocol::Tcp, ANY_SRC)
            .is_none()
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 91, Protocol::Tcp, ANY_SRC)
            .is_none()
    );
}

#[test]
fn bare_ip_address_is_host_route() {
    // Una dirección IP desnuda → /32 (GetCidr) → solo ESE IP casa.
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["1.2.3.4"],"portRanges":[{"low":443,"high":443}]}}"#,
    );
    assert!(
        r.lookup(ip("1.2.3.4"), 443, Protocol::Tcp, ANY_SRC)
            .is_some()
    );
    assert!(
        r.lookup(ip("1.2.3.5"), 443, Protocol::Tcp, ANY_SRC)
            .is_none()
    );
}

#[test]
fn ipv6_cidr_matches() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["fd00::/8"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    assert!(
        r.lookup(ip("fd00::1"), 80, Protocol::Tcp, ANY_SRC)
            .is_some()
    );
    assert!(
        r.lookup(ip("fe00::1"), 80, Protocol::Tcp, ANY_SRC)
            .is_none()
    );
    // cross-family: un v4 no casa un CIDR v6.
    assert!(
        r.lookup(ip("10.0.0.1"), 80, Protocol::Tcp, ANY_SRC)
            .is_none()
    );
}

// ───────────────────────── permiso Dial (svcpoll.go:191) ─────────────────────────

#[test]
fn bind_only_service_is_not_intercepted() {
    let s = svc_perms(
        "bindonly",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
        &["Bind"],
    );
    let r = InterceptResolver::from_services(&[s]);
    assert!(
        r.is_empty(),
        "un servicio Bind-only no construye entradas de intercept"
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none()
    );
}

#[test]
fn dial_permitted_among_perms_is_intercepted() {
    let s = svc_perms(
        "both",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
        &["Bind", "Dial"],
    );
    let r = InterceptResolver::from_services(&[s]);
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_some()
    );
}

// ───────────────────────── allowedSourceAddresses (LOAD-BEARING, no over-permit) ─────────────────────────

#[test]
fn source_whitelist_restricts_to_listed_sources() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}],
                "allowedSourceAddresses":["192.168.0.0/16"]}}"#,
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ip("192.168.1.1"))
            .is_some(),
        "origen en la whitelist → intercepta"
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ip("172.16.0.1"))
            .is_none(),
        "origen FUERA de la whitelist → NO intercepta (ignorar esto sería over-permit)"
    );
}

#[test]
fn empty_source_whitelist_allows_any_source() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ip("8.8.8.8"))
            .is_some()
    );
}

/// El gate LOAD-BEARING (catch del advisor): una whitelist de SOLO-hostnames (parsea a `[]`) debe
/// casar con NINGÚN origen (UNDER-permit seguro), JAMÁS degradar a "permitir cualquiera". Una
/// implementación que keyease `restrict` en el set PARSEADO (vacío → allow-any) convertiría la
/// restricción en un over-permit; este test la mata.
#[test]
fn source_whitelist_of_only_hostnames_matches_no_source_not_all() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}],
                "allowedSourceAddresses":["only-a-hostname.example.com","*.wild.example.com"]}}"#,
    );
    // La lista NO está vacía (era restringida) pero todas las entradas son hostname/wildcard (DNS,
    // M3) → set parseado vacío → casa con ningún origen.
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ip("192.168.1.1"))
            .is_none(),
        "whitelist de solo-hostnames → ningún origen casa (NO allow-any)"
    );
}

#[test]
fn source_whitelist_mixed_keeps_parsed_cidrs() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}],
                "allowedSourceAddresses":["a-hostname.example.com","192.168.0.0/16"]}}"#,
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ip("192.168.1.1"))
            .is_some(),
        "el CIDR parseado sigue restringiendo"
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ip("172.16.0.1"))
            .is_none()
    );
}

// ───────────────────────── precedencia first-match ─────────────────────────

#[test]
fn overlap_returns_first_service_in_list_order() {
    let a = svc(
        "alpha",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/8"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    let b = svc(
        "beta",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    let r = InterceptResolver::from_services(&[a, b]);
    // Ambos interceptan 10.0.0.5:80; first-match en orden de lista → alpha (NO el más específico).
    assert_eq!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "alpha"
    );
}

// ───────────────────────── hostname/wildcard direcciones (M3-DNS wiring) ─────────────────────────

#[test]
fn hostname_without_pool_produces_no_literal_entry_and_wildcard_is_non_dispatchable() {
    // `from_services` (el constructor SIN M3-DNS) usa un DnsMatcher vacío/sin sembrar. Un hostname
    // EXACTO no puede asignarse IP (`IpUnavailable`) → sin entrada literal `/32`. Un dominio
    // wildcard SÍ produce una `WildcardEntry` (el oráculo registra `match_addr` incondicional,
    // independiente del pool), PERO es no-dispatchable sin pool: ninguna query puede asignar una IP
    // bajo el dominio (`allocate_ip` → None), así que el fallback nunca dispara. Ver
    // `exact_hostname_with_seeded_pool_produces_a_dispatchable_entry` para el camino CON pool.
    let mut r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com","*.svc.example.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
    );
    // No hay ninguna entrada literal /32 (el hostname exacto no obtuvo IP).
    assert!(
        r.lookup(ip("10.99.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "sin pool: el hostname exacto no produce entrada /32 dispatchable"
    );
    // Sin pool, una query bajo el dominio wildcard NO asigna IP → el fallback no puede disparar.
    assert!(
        r.dns_mut().lookup("app.svc.example.com").is_none(),
        "sin pool sembrado, una query wildcard no puede asignar IP (allocate_ip → None)"
    );
}

#[test]
fn mixed_addresses_keep_only_ip_cidr_entries() {
    let r = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24","app.example.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
    );
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_some(),
        "el CIDR sí intercepta"
    );
}
