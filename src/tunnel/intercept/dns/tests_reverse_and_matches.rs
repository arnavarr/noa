//! b6: `reverse_lookup_domain` (diferido #6) + `matches_domain` (camino no-A/AAAA) (F6 tramo
//! 15 troceo).

use std::net::Ipv4Addr;

use super::*;

// ───────────────── reverse_lookup_domain (diferido #6) + matches_domain (camino no-A/AAAA) ─────────────────

/// [`DnsMatcher::reverse_lookup_domain`] (espejo de `ziti_dns_reverse_lookup_domain`,
/// `ziti_dns.c:354-360`): SOLO una IP asignada vía un match de dominio wildcard devuelve su
/// patrón (`entry->domain != NULL`); un hostname explícito, una IP reservada (entrada zeroed) y
/// una IP nunca asignada devuelven `None` — exactamente los tres `NULL` del oráculo.
#[test]
fn reverse_lookup_domain_returns_the_domain_only_for_domain_derived_entries() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/24"));
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);

    let via_domain = m.lookup("a.example.com").expect("debe casar por dominio");
    assert_eq!(
        m.reverse_lookup_domain(via_domain.ip),
        Some("example.com"),
        "IP derivada de un dominio: devuelve el sufijo del patrón que casó"
    );

    let RegisterOutcome::Hostname(explicit_ip) = m.register("svc.example.org", "i") else {
        panic!("hostname exacto debe asignar IP")
    };
    assert_eq!(
        m.reverse_lookup_domain(explicit_ip),
        None,
        "hostname explícito: entry->domain == NULL en el oráculo"
    );

    let reserved = "10.0.0.99".parse().unwrap();
    m.reserve(reserved);
    assert_eq!(
        m.reverse_lookup_domain(reserved),
        None,
        "IP reservada: entrada zeroed, sin dominio"
    );
    assert_eq!(
        m.reverse_lookup_domain("10.0.0.200".parse().unwrap()),
        None,
        "IP nunca asignada"
    );
}

/// El sufijo devuelto es el del dominio QUE CASÓ, no el hostname de la query — y una entrada
/// creada vía dominio lo CONSERVA aunque el mismo nombre se re-registre explícitamente después
/// (el oráculo no limpia `entry->domain` al reusar la entrada, `ziti_dns.c:473-474`).
#[test]
fn reverse_lookup_domain_persists_after_an_explicit_reregister() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/24"));
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);
    let cached = m.lookup("a.example.com").expect("debe casar por dominio");

    let RegisterOutcome::Hostname(same_ip) = m.register("a.example.com", "i") else {
        panic!("re-registro explícito reusa la entrada")
    };
    assert_eq!(same_ip, cached.ip);
    assert_eq!(
        m.reverse_lookup_domain(cached.ip),
        Some("example.com"),
        "el dominio persiste tras el re-registro explícito"
    );
}

/// Regresión (revisión reforzada del slice #6, over-permit cazado 3/3): una IP RESERVADA
/// (utun/DNS-resolver, guardada bajo la cadena `""`) NO debe heredar el `domain` de una entrada de
/// query del nombre vacío `""` (creada por un servicio `"*."` + una query de `""`). El oráculo keyea
/// `ip_addresses` IP→entry directo, así que la IP reservada resuelve a su entrada zeroed
/// (`entry->domain == NULL`) → `NULL`. El guard `entry.ip == ip` de `reverse_lookup_domain` lo
/// restaura pese a que ambas IPs comparten la clave reversa `""`.
#[test]
fn reverse_lookup_domain_of_a_reserved_ip_is_none_despite_empty_name_collision() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.99.0.0/24"));
    let reserved: Ipv4Addr = "10.99.0.1".parse().unwrap();
    m.reserve(reserved); // p.ej. el utun/DNS-resolver → ip_addresses[reserved] = ""
    assert_eq!(m.register("*.", "i"), RegisterOutcome::Domain); // dominio degenerado ""
    let assigned = m
        .lookup("")
        .expect("una query del nombre vacío casa el dominio \"\"");
    assert_ne!(
        assigned.ip, reserved,
        "la query obtiene una IP distinta de la reservada"
    );
    // La IP reservada NO hereda el dominio "" de la entrada de la query (over-permit del oráculo).
    assert_eq!(
        m.reverse_lookup_domain(reserved),
        None,
        "una IP reservada resuelve a su propia entrada (domain NULL en el oráculo), no a la de \"\""
    );
    // La IP de la query SÍ resuelve a su dominio "".
    assert_eq!(m.reverse_lookup_domain(assigned.ip), Some(""));
}

/// [`DnsMatcher::matches_domain`] (el gate no-A/AAAA de `on_dns_req`): casa por sufijo SIN
/// asignar IP ni crear entrada, incluidos los dos quirks del call site del oráculo (retorno de
/// `check_name` ignorado → overflow busca `""`; query con forma de wildcard NO rechazada).
#[test]
fn matches_domain_mirrors_the_non_a_query_gate_without_allocating() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29")); // capacidad 6: probamos que NO se consume ninguna
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);

    assert!(m.matches_domain("mail.example.com"), "subdominio casa");
    assert!(
        m.matches_domain("example.com"),
        "quirk dominio desnudo casa"
    );
    assert!(m.matches_domain("MAIL.EXAMPLE.COM"), "case-insensitive");
    assert!(!m.matches_domain("otherdomain.org"), "no registrado");
    assert!(
        m.matches_domain("*.example.com"),
        "quirk: una query con forma de wildcard NO se rechaza en este call site (is_domain=NULL) \
             y el walk de sufijos la casa"
    );

    // Nada de lo anterior asignó IP: el pool sigue intacto (el primer hostname recibe .1).
    let RegisterOutcome::Hostname(first) = m.register("h.example.org", "i") else {
        panic!("debe asignar")
    };
    assert_eq!(
        first,
        Ipv4Addr::new(10, 0, 0, 1),
        "matches_domain no consume el pool ni crea entradas"
    );
}

/// [`DnsMatcher::matched_domain`] (M3-DNS #2): el MISMO gate que `matches_domain` pero
/// devolviendo el SUFIJO de dominio que casó — el nombre del `dns_domain_t` que
/// `proxy_domain_req` recibe (`find_domain` devuelve el dominio, no la query,
/// `ziti_dns.c:833-835`). Mismos quirks del call site (overflow → `""`, wildcard-form no
/// rechazada) porque delega en la MISMA normalización. `matches_domain` y `matched_domain`
/// deben ser consistentes por construcción (uno delega en el otro).
#[test]
fn matched_domain_returns_the_suffix_that_find_domain_matched() {
    let mut m = DnsMatcher::new();
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);
    assert_eq!(m.register("*.svc.wild.org", "i"), RegisterOutcome::Domain);

    assert_eq!(
        m.matched_domain("mail.example.com").as_deref(),
        Some("example.com"),
        "subdominio → el sufijo del dominio, no la query"
    );
    assert_eq!(
        m.matched_domain("a.b.svc.wild.org").as_deref(),
        Some("svc.wild.org"),
        "el walk recorta etiqueta a etiqueta hasta el dominio registrado"
    );
    assert_eq!(
        m.matched_domain("example.com").as_deref(),
        Some("example.com"),
        "quirk dominio desnudo: casa su propio wildcard"
    );
    assert_eq!(
        m.matched_domain("MAIL.Example.COM").as_deref(),
        Some("example.com"),
        "el sufijo devuelto es el NORMALIZADO (lowercase), el shape de `domains`"
    );
    assert_eq!(m.matched_domain("other.org"), None, "sin dominio → None");
    // Consistencia por construcción con matches_domain.
    assert_eq!(
        m.matches_domain("mail.example.com"),
        m.matched_domain("mail.example.com").is_some()
    );
}

/// Quirk de overflow del call site no-A/AAAA: el retorno de `check_name` se IGNORA y el nombre
/// desbordado queda `""` — que SÍ casa si el dominio `""` está registrado (dirección literal
/// `"*."`), y no casa en un matcher normal. Espejo exacto, no un rechazo nuestro.
#[test]
fn matches_domain_overflow_falls_back_to_the_empty_name_like_the_oracle() {
    let mut m = DnsMatcher::new();
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);
    let overlong = "a".repeat(300);
    assert!(
        !m.matches_domain(&overlong),
        "overflow → nombre \"\" → sin dominio \"\" registrado → no casa"
    );

    let mut m2 = DnsMatcher::new();
    assert_eq!(
        m2.register("*.", "i"),
        RegisterOutcome::Domain,
        "la dirección literal \"*.\" registra el dominio \"\""
    );
    assert!(
        m2.matches_domain(&overlong),
        "overflow → nombre \"\" → casa el dominio \"\" (quirk del oráculo, replicado)"
    );
}

/// `wildcard_suffix` devuelve EXACTAMENTE el mismo string que `register` guarda en `domains`
/// (`clean[2..]`, lowercase, sin `"*."`), o `None` para un no-wildcard o un desbordamiento — así
/// la entrada de dispatch por-dominio del resolver casa su propio dominio sin divergencia de forma.
#[test]
fn wildcard_suffix_equals_the_stored_domain_form() {
    assert_eq!(
        DnsMatcher::wildcard_suffix("*.Example.COM").as_deref(),
        Some("example.com"),
        "lowercase, sin \"*.\" — mismo shape que domains"
    );
    assert_eq!(
        DnsMatcher::wildcard_suffix("*.").as_deref(),
        Some(""),
        "el literal \"*.\" normaliza al sufijo vacío (dominio \"\")"
    );
    assert_eq!(
        DnsMatcher::wildcard_suffix("app.example.com"),
        None,
        "un hostname exacto no es wildcard"
    );
    assert_eq!(
        DnsMatcher::wildcard_suffix("*foo.com"),
        None,
        "un '*' sin punto inmediato no es wildcard (espejo check_name)"
    );
    assert_eq!(
        DnsMatcher::wildcard_suffix(&format!("*.{}", "a".repeat(300))),
        None,
        "un nombre que desborda MAX_DNS_NAME → None (coherente con el Rejected de register)"
    );
    // Consistencia con lo que `domains` guarda: registrar y confirmar que el sufijo casa una query.
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/8"));
    assert_eq!(m.register("*.example.com", "i"), RegisterOutcome::Domain);
    let suffix = DnsMatcher::wildcard_suffix("*.example.com").unwrap();
    let assigned = m.lookup("host.example.com").unwrap();
    assert_eq!(
        m.reverse_lookup_domain(assigned.ip),
        Some(suffix.as_str()),
        "reverse_lookup_domain devuelve el MISMO sufijo que wildcard_suffix"
    );
}
