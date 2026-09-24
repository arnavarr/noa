//! b4: comportamiento nuevo de la rebanada 2 (register/lookup con IP) (F6 tramo 15 troceo).

use super::*;

// ───────────────────── comportamiento nuevo de esta rebanada (register/lookup con IP) ─────────────────────

/// Registro EAGER de un hostname exacto: recibe IP al registrarse, no al buscarse (espejo de
/// `ziti_dns_register_hostname:472-483`); re-registrar el MISMO nombre reusa la IP sin consumir
/// el pool otra vez (idempotente, espejo de `ziti_dns.c:473-474`).
#[test]
fn register_hostname_assigns_ip_eagerly_and_is_idempotent() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29"));
    let RegisterOutcome::Hostname(ip1) = m.register("svc.example.com", "i") else {
        panic!("hostname exacto debe recibir IP")
    };
    assert_eq!(ip1.to_string(), "10.0.0.1");

    // Re-registrar el mismo nombre: MISMA ip, el pool no avanza (el siguiente hostname nuevo
    // recibe .2, no .3).
    let RegisterOutcome::Hostname(ip1_again) = m.register("svc.example.com", "i") else {
        panic!("re-registro debe seguir siendo Hostname")
    };
    assert_eq!(ip1_again, ip1);

    let RegisterOutcome::Hostname(ip2) = m.register("other.example.com", "i") else {
        panic!("segundo hostname debe recibir IP")
    };
    assert_eq!(ip2.to_string(), "10.0.0.2");
}

/// Un dominio wildcard nunca recibe IP propia al registrarse (`Domain`, sin `Ipv4Addr`) — la IP
/// se asigna LAZY, por subdominio concreto, en `lookup` (espejo de `ziti_dns_lookup:395`).
#[test]
fn lookup_assigns_ip_lazily_for_domain_matches_and_caches_it() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29"));
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);

    let first = m.lookup("a.example.com").expect("debe casar por dominio");
    assert_eq!(first.kind, DnsMatchKind::Domain);
    assert_eq!(first.ip.to_string(), "10.0.0.1");

    // Repetir la MISMA query: misma IP cacheada, el pool NO avanza para ella; el kind persiste
    // como Domain (ver el doc del módulo).
    let repeat = m
        .lookup("a.example.com")
        .expect("debe seguir casando (cacheado)");
    assert_eq!(repeat, first);

    // Un subdominio DISTINTO bajo el mismo wildcard consume una IP fresca.
    let second = m.lookup("b.example.com").expect("otro subdominio, otra IP");
    assert_eq!(second.kind, DnsMatchKind::Domain);
    assert_eq!(second.ip.to_string(), "10.0.0.2");
}

/// Re-registrar explícitamente un nombre YA cacheado vía un match de dominio reusa la entrada
/// SIN limpiar su `domain` — sigue reportando `Domain` en lookups posteriores (espejo de
/// `ziti_dns.c:473-474`: el oráculo reusa la `entry` existente sin tocar su campo `domain`).
#[test]
fn explicit_register_of_a_domain_cached_name_keeps_domain_kind() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29"));
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);
    let cached = m.lookup("a.example.com").expect("debe casar por dominio");
    assert_eq!(cached.kind, DnsMatchKind::Domain);

    let RegisterOutcome::Hostname(ip_again) = m.register("a.example.com", "i") else {
        panic!("re-registro explícito de un nombre ya cacheado sigue siendo Hostname(ip)")
    };
    assert_eq!(ip_again, cached.ip, "misma IP, el pool no avanza");
    assert_eq!(
        m.lookup("a.example.com").map(|r| r.kind),
        Some(DnsMatchKind::Domain),
        "el kind sigue siendo Domain: el oráculo no limpia entry->domain al reusar"
    );
}

/// Agotamiento del pool: un hostname exacto nuevo no puede registrarse (`IpUnavailable`, espejo
/// de `new_ipv4_entry` devolviendo `NULL`); un match de dominio nuevo tampoco (`lookup` = `None`,
/// como si la query no hubiera casado nada, espejo de `ziti_dns_lookup:395-398`). Las entradas
/// YA asignadas antes del agotamiento no se ven afectadas.
#[test]
fn pool_exhaustion_fails_new_assignments_without_disturbing_existing_ones() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29")); // capacidad 6
    for i in 0..6 {
        let RegisterOutcome::Hostname(_) = m.register(&format!("h{i}.example.com"), "i") else {
            panic!("debe asignar mientras haya capacidad")
        };
    }
    assert_eq!(
        m.register("overflow.example.com", "i"),
        RegisterOutcome::IpUnavailable,
        "7º hostname exacto: pool agotado, espejo de new_ipv4_entry -> NULL"
    );

    assert_eq!(
        m.register("*.wild.example.com", "i"),
        RegisterOutcome::Domain
    );
    assert_eq!(
        m.lookup("new.wild.example.com"),
        None,
        "match de dominio nuevo con el pool agotado: la query entera falla, como el oráculo"
    );

    // Las 6 entradas previas siguen resolviendo a su IP original.
    let RegisterOutcome::Hostname(ip0) = m.register("h0.example.com", "i") else {
        panic!("hostname ya existente sigue resolviendo")
    };
    assert_eq!(ip0.to_string(), "10.0.0.1");
}

/// Sin pool sembrado: un hostname exacto no puede registrarse (`IpUnavailable`); un dominio SÍ
/// se registra (nunca toca el pool), pero un match de dominio en `lookup` falla (no hay IP que
/// asignar). Esto no tiene equivalente observable en el oráculo real (`ziti_dns_setup` siempre
/// siembra antes de registrar nada) — es puramente ergonomía de pruebas en Rust.
#[test]
fn unseeded_pool_rejects_hostname_ip_assignment() {
    let mut m = DnsMatcher::new();
    assert_eq!(
        m.register("svc.example.com", "i"),
        RegisterOutcome::IpUnavailable
    );
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);
    assert_eq!(m.lookup("a.example.com"), None);
}

/// [`DnsMatcher::reverse_lookup`]: la IP asignada resuelve de vuelta al hostname exacto (espejo
/// de `ziti_dns_reverse_lookup`, `ziti_dns.c:362-368`) — para hostnames explícitos, para
/// subdominios cacheados vía dominio, y `None` para una IP nunca asignada.
#[test]
fn reverse_lookup_mirrors_ziti_dns_reverse_lookup() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29"));
    let RegisterOutcome::Hostname(ip) = m.register("svc.example.com", "i") else {
        panic!("debe asignar IP")
    };
    assert_eq!(m.reverse_lookup(ip), Some("svc.example.com"));

    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);
    let via_domain = m.lookup("a.example.com").expect("debe casar por dominio");
    assert_eq!(m.reverse_lookup(via_domain.ip), Some("a.example.com"));

    assert_eq!(m.reverse_lookup("10.0.0.6".parse().unwrap()), None);
}
