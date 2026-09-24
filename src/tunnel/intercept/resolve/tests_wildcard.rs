// F6 tramo 2b troceo: tests movidos verbatim del monolito de `intercept/resolve` (mod tests).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::tunnel::intercept::dns::{DnsMatcher, RegisterOutcome};

use super::testsupport::*;
use super::{InterceptResolver, Protocol, WildcardEntry};

/// Wiring M3-DNS (espejo `intercept_addr_from_cfg_addr`, `ziti_tunnel_cbs.c:533-540`): un
/// hostname EXACTO con un pool sembrado recibe una IP sintética que se despacha COMO CUALQUIER
/// OTRA dirección `/32` — mismo mecanismo `lookup`, cero lógica nueva.
#[test]
fn exact_hostname_with_seeded_pool_produces_a_dispatchable_entry() {
    let mut dns = seeded_dns();
    let ip_before = match dns.register("app.example.com", "probe") {
        RegisterOutcome::Hostname(ip) => ip,
        other => panic!("debe asignar IP: {other:?}"),
    };
    let dns2 = seeded_dns(); // mismo CIDR, contador fresco → misma IP que ip_before
    let r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
        dns2,
    );
    let m = r
        .lookup(IpAddr::V4(ip_before), 80, Protocol::Tcp, ANY_SRC)
        .expect("la IP sintética del hostname debe despachar como cualquier /32");
    assert_eq!(m.service, "svc");
    // Un vecino en el mismo /24 pero NO la IP asignada no casa: confirma que es un /32, no un
    // over-permit accidental del CIDR entero.
    let neighbor = Ipv4Addr::from(u32::from(ip_before) + 1);
    assert!(
        r.lookup(IpAddr::V4(neighbor), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "solo la IP exacta asignada al hostname despacha, no todo el /24"
    );
}

/// M3-DNS #6: un dominio wildcard produce una entrada de dispatch por-dominio ([`WildcardEntry`]),
/// así que el resolver YA NO cuenta como vacío. Pero SIN una query DNS que asigne una IP bajo ese
/// dominio, un paquete a una IP arbitraria no despacha (el fallback exige un `reverse_lookup_domain`
/// con éxito — under-dispatch seguro).
#[test]
fn wildcard_domain_produces_a_fallback_entry_but_needs_a_query_to_dispatch() {
    let r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.svc.example.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
        seeded_dns(),
    );
    assert!(
        !r.is_empty(),
        "wildcard con pool sembrado: produce una WildcardEntry de dispatch (M3-DNS #6)"
    );
    // Sin query previa, ninguna IP del rango DNS está asignada a un dominio → sin fallback.
    assert!(
        r.lookup(ip("10.99.0.2"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "sin una query DNS que asigne la IP bajo el dominio, no hay reverse-lookup → sin dispatch"
    );
}

/// EL camino end-to-end de M3-DNS #6, todo IN-PROCESS (sin root/live): una query DNS bajo un
/// dominio wildcard ASIGNA una IP sintética (vía el mismo `DnsMatcher` que comparte el server), y un
/// paquete a ESA IP despacha al servicio dueño del dominio por el fallback `intercept_match_addr`.
/// Es la prueba de que el mecanismo real (server → asignación → reverse-lookup → fallback) funciona,
/// no un estado fabricado a mano.
#[test]
fn wildcard_query_assigns_ip_then_packet_dispatches_end_to_end() {
    let mut r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.svc.example.com"],
                "portRanges":[{"low":443,"high":443}]}}"#,
        seeded_dns(),
    );
    // Paso 1: una query (lo que haría el servidor DNS embebido) asigna la IP LAZY bajo el dominio.
    let m = r
        .dns_mut()
        .lookup("app.svc.example.com")
        .expect("query bajo el dominio wildcard debe casar y asignar una IP");
    let assigned = m.ip;
    // Paso 2: un paquete a esa IP despacha al servicio por el fallback wildcard.
    let hit = r
        .lookup(IpAddr::V4(assigned), 443, Protocol::Tcp, ANY_SRC)
        .expect("un paquete a la IP asignada-por-dominio debe despachar (intercept_match_addr)");
    assert_eq!(hit.service, "svc");
}

/// El fallback wildcard aplica protocolo Y rango de puerto (espejo de `protocol_match`/`port_match`
/// sobre el mismo intercept, `intercept.c`): la IP está asignada, pero un proto/puerto que no casa
/// devuelve `None` (nunca despacha de más).
#[test]
fn wildcard_fallback_respects_protocol_and_port() {
    let mut r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.svc.example.com"],
                "portRanges":[{"low":443,"high":443}]}}"#,
        seeded_dns(),
    );
    let assigned = r.dns_mut().lookup("app.svc.example.com").unwrap().ip;
    let dst = IpAddr::V4(assigned);
    assert!(
        r.lookup(dst, 443, Protocol::Tcp, ANY_SRC).is_some(),
        "tcp/443 casa"
    );
    assert!(
        r.lookup(dst, 80, Protocol::Tcp, ANY_SRC).is_none(),
        "puerto fuera de rango no casa"
    );
    assert!(
        r.lookup(dst, 443, Protocol::Udp, ANY_SRC).is_none(),
        "protocolo distinto no casa"
    );
}

/// El fallback wildcard aplica la whitelist `allowedSourceAddresses` (igual que una entrada
/// literal): un origen fuera de la whitelist no despacha, aunque el dominio/proto/puerto casen.
#[test]
fn wildcard_fallback_respects_source_whitelist() {
    let mut r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.svc.example.com"],
                "portRanges":[{"low":443,"high":443}],"allowedSourceAddresses":["192.168.0.0/16"]}}"#,
        seeded_dns(),
    );
    let assigned = r.dns_mut().lookup("app.svc.example.com").unwrap().ip;
    let dst = IpAddr::V4(assigned);
    assert_eq!(
        r.lookup(dst, 443, Protocol::Tcp, ip("192.168.1.1"))
            .unwrap()
            .service,
        "svc",
        "origen dentro de la whitelist despacha"
    );
    assert!(
        r.lookup(dst, 443, Protocol::Tcp, ip("10.0.0.1")).is_none(),
        "origen fuera de la whitelist no despacha (nunca amplía la whitelist)"
    );
}

/// [`InterceptResolver::proxy_service`] (M3-DNS #2): el servicio a dial-ear para la conexión
/// proxy-resolve de un DOMINIO — espejo de `proxy_domain_req` tomando el PRIMER intercept del
/// `domain->intercepts` del oráculo (`ziti_dns.c:749-752`). La clave es el sufijo EXACTO que
/// `matched_domain` devolvió (el shape de `DnsMatcher::domains`), NO una query: aquí no hay walk
/// de sufijos. Dos servicios sobre el MISMO dominio → el primero registrado (interpretación
/// determinista del "primer elemento del model_map" del oráculo, cuyo orden de iteración es de
/// hash — ambigüedad resuelta por orden de registro, documentada). El timeout devuelto es el
/// dial-timeout del intercept (el seam disponible; el `ziti_dial_with_options` del oráculo no
/// fija timeout propio).
#[test]
fn proxy_service_returns_the_first_service_that_claims_the_domain() {
    let a = svc(
        "svc-a",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.svc.example.com"],
                "portRanges":[{"low":443,"high":443}],
                "dialOptions":{"connectTimeoutSeconds":7}}}"#,
    );
    let b = svc(
        "svc-b",
        r#"{"intercept.v1":{"protocols":["udp"],"addresses":["*.svc.example.com","*.other.org"],
                "portRanges":[{"low":53,"high":53}]}}"#,
    );
    let r = InterceptResolver::from_services_with_dns(&[a, b], seeded_dns());

    let m = r
        .proxy_service("svc.example.com")
        .expect("dominio reclamado por dos servicios → el primero registrado");
    assert_eq!(m.service, "svc-a");
    assert_eq!(
        m.dial_timeout,
        Duration::from_secs(7),
        "lleva el dial-timeout del intercept del servicio elegido"
    );

    let other = r
        .proxy_service("other.org")
        .expect("dominio reclamado solo por svc-b");
    assert_eq!(other.service, "svc-b");

    assert!(
        r.proxy_service("unclaimed.example.net").is_none(),
        "dominio sin wildcard → None (el llamante degrada a SERVFAIL, espejo State A)"
    );
    assert!(
        r.proxy_service("app.svc.example.com").is_none(),
        "la clave es el SUFIJO exacto de matched_domain, no una query: sin walk aquí"
    );
}

/// Un match LITERAL gana al fallback wildcard sobre la misma IP (espejo del scoring del oráculo:
/// `address_match` por delante de `match_addr`). Un servicio con un CIDR que cubre el rango DNS
/// entero intercepta la IP asignada-por-dominio ANTES de que se consulte el fallback.
#[test]
fn literal_match_beats_wildcard_fallback() {
    // `cidr_svc` cubre TODO el /24 del pool DNS; `wild_svc` reclama el dominio. La IP asignada cae
    // dentro del /24 → el match literal de `cidr_svc` (paso 1) gana.
    let cidr_svc = svc(
        "cidr_svc",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.99.0.0/24"],"portRanges":[{"low":443,"high":443}]}}"#,
    );
    let wild_svc = svc(
        "wild_svc",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.svc.example.com"],"portRanges":[{"low":443,"high":443}]}}"#,
    );
    let mut r = InterceptResolver::from_services_with_dns(&[cidr_svc, wild_svc], seeded_dns());
    let assigned = r.dns_mut().lookup("app.svc.example.com").unwrap().ip;
    let hit = r
        .lookup(IpAddr::V4(assigned), 443, Protocol::Tcp, ANY_SRC)
        .expect("la IP está en el /24 literal");
    assert_eq!(
        hit.service, "cidr_svc",
        "un match literal (CIDR) gana al fallback wildcard sobre la misma IP"
    );
}

/// Precedencia de sufijos: dos servicios wildcard, uno específico (`*.sub.example.com`) y uno
/// general (`*.example.com`). Una query bajo el subdominio se ASIGNA al dominio MÁS específico
/// (`find_domain`), y AMBOS servicios lo reclaman (el oráculo les da a los dos el score fijo 1) →
/// first-match en orden de lista lo resuelve (misma clase de desviación documentada que el
/// first-match literal). Una query fuera del subdominio SÓLO la reclama el general — el gate de
/// sufijos discrimina bien (no over-permit del específico).
#[test]
fn wildcard_suffix_precedence_specific_and_general() {
    let specific = svc(
        "specific",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.sub.example.com"],"portRanges":[{"low":443,"high":443}]}}"#,
    );
    let general = svc(
        "general",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.example.com"],"portRanges":[{"low":443,"high":443}]}}"#,
    );
    let mut r = InterceptResolver::from_services_with_dns(&[specific, general], seeded_dns());

    // Query bajo el subdominio → dominio asignado = "sub.example.com"; ambos reclaman, first-match
    // (specific va primero en la lista) gana.
    let ip_sub = r.dns_mut().lookup("a.sub.example.com").unwrap().ip;
    assert_eq!(
        r.lookup(IpAddr::V4(ip_sub), 443, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "specific",
        "ambos reclaman el subdominio; first-match (specific primero) gana"
    );

    // Query fuera del subdominio → dominio = "example.com"; SÓLO el general reclama (el específico
    // exige que el dominio termine en \".sub.example.com\", y \"example.com\" no).
    let ip_top = r.dns_mut().lookup("b.example.com").unwrap().ip;
    assert_eq!(
        r.lookup(IpAddr::V4(ip_top), 443, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "general",
        "un dominio que no cae bajo el subdominio SÓLO lo reclama el wildcard general"
    );
}

/// El fallback wildcard nunca dispara para: una IP v6 (el pool es v4), una IP no asignada, o una IP
/// RESERVADA (utun/DNS-resolver — `entry->domain == NULL` en el oráculo). Todos → `None`
/// (under-dispatch seguro; nunca despachamos una IP que el oráculo no rutearía por dominio).
#[test]
fn wildcard_fallback_ignores_v6_unassigned_and_reserved() {
    let mut dns = seeded_dns();
    dns.reserve("10.99.0.1".parse().unwrap()); // p.ej. el utun/DNS-resolver
    let mut r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.svc.example.com"],
                "portRanges":[{"low":443,"high":443}]}}"#,
        dns,
    );
    // Una query real para tener AL MENOS una IP asignada (aísla que el rechazo es por la IP, no por
    // un resolver sin dominios).
    let _assigned = r.dns_mut().lookup("app.svc.example.com").unwrap().ip;
    assert!(
        r.lookup("::1".parse().unwrap(), 443, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "una IP v6 no tiene reverse-lookup de dominio (pool v4) → sin fallback"
    );
    assert!(
        r.lookup(ip("10.99.0.200"), 443, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "una IP v4 del rango pero NO asignada a ningún dominio → sin fallback"
    );
    assert!(
        r.lookup(ip("10.99.0.1"), 443, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "una IP RESERVADA (domain == None) → sin fallback"
    );
}

/// Regresión (revisión reforzada del slice #6, over-permit 3/3): un servicio con la dirección
/// wildcard DEGENERADA `"*."` (sufijo `""`) + una query del nombre vacío `""` NO debe hacer que un
/// paquete a una IP RESERVADA (utun/DNS-resolver) despache a ese servicio. La IP reservada y la
/// entrada de la query `""` comparten la clave reversa `""`; sin el guard `entry.ip == ip` de
/// `reverse_lookup_domain`, la IP reservada heredaría el dominio `""` y `WildcardEntry{suffix:""}`
/// la reclamaría (`"" == ""`). El oráculo devuelve NULL para la IP reservada (`entry->domain == NULL`).
#[test]
fn reserved_ip_does_not_dispatch_to_a_degenerate_star_dot_service() {
    let mut dns = seeded_dns();
    let reserved = ip("10.99.0.1");
    dns.reserve("10.99.0.1".parse().unwrap());
    let mut r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*."],
                "portRanges":[{"low":443,"high":443}]}}"#,
        dns,
    );
    // La query del nombre vacío crea la entrada hostnames[""] que colisiona en el mapa reverso.
    let assigned = r
        .dns_mut()
        .lookup("")
        .expect("\"\" casa el dominio degenerado \"\"");
    assert_ne!(IpAddr::V4(assigned.ip), reserved);
    // La IP reservada NO despacha (el oráculo la rehúsa; el fallback wildcard tampoco debe rutearla).
    assert!(
        r.lookup(reserved, 443, Protocol::Tcp, ANY_SRC).is_none(),
        "una IP reservada nunca despacha al servicio \"*.\" pese a la colisión de la clave \"\""
    );
    // La IP realmente asignada por la query SÍ despacha (el mecanismo sigue funcionando).
    assert_eq!(
        r.lookup(IpAddr::V4(assigned.ip), 443, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "svc"
    );
}

/// Una IP de HOSTNAME EXACTO no dispara el fallback wildcard aunque exista un servicio wildcard del
/// mismo dominio: su `entry->domain == NULL` → `reverse_lookup_domain` da `None`, y de todos modos
/// despacha por su `/32` literal al servicio EXACTO (no al wildcard). Sin contaminación cruzada.
#[test]
fn exact_hostname_ip_dispatches_to_its_own_service_not_the_wildcard() {
    let exact = svc(
        "exact",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com"],"portRanges":[{"low":443,"high":443}]}}"#,
    );
    let wild = svc(
        "wild",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.example.com"],"portRanges":[{"low":443,"high":443}]}}"#,
    );
    let mut dns = seeded_dns();
    let exact_ip = match dns.register("app.example.com", "probe") {
        RegisterOutcome::Hostname(ip) => ip,
        other => panic!("{other:?}"),
    };
    // Reconstruir el resolver con un pool fresco para que las IPs coincidan con el orden de
    // registro interno.
    let mut r = InterceptResolver::from_services_with_dns(&[exact, wild], seeded_dns());
    // La IP exacta (misma que `exact_ip`: mismo CIDR/contador/orden) despacha al servicio EXACTO.
    assert_eq!(
        r.lookup(IpAddr::V4(exact_ip), 443, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "exact",
        "la IP del hostname exacto despacha por su /32 al servicio exacto, no al wildcard"
    );
    // Y una query wildcard bajo el mismo dominio despacha al servicio WILDCARD (IP distinta).
    let wild_ip = r.dns_mut().lookup("other.example.com").unwrap().ip;
    assert_ne!(wild_ip, exact_ip);
    assert_eq!(
        r.lookup(IpAddr::V4(wild_ip), 443, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "wild"
    );
}

/// El núcleo de fidelidad de `intercept_match_addr`: [`WildcardEntry::suffix_matches`] espeja
/// `ziti_address_match(parse("*.D"), "*.W")` EXACTO. Pin de casos byte-a-byte contra el walk del
/// oráculo (`internal_model.c:327-360`), incluyendo la frontera de etiqueta y el sufijo vacío del
/// literal `"*."`.
#[test]
fn suffix_matches_mirrors_ziti_address_match() {
    let we = |suffix: &str| WildcardEntry {
        suffix: suffix.to_string(),
        low_port: 0,
        high_port: 0,
        protocol: "tcp".into(),
        service: "s".into(),
        dial_timeout: Duration::from_secs(5),
        allowed_sources: None,
    };
    // W == D (incluye el quirk dominio-desnudo del oráculo).
    assert!(we("example.com").suffix_matches("example.com"));
    // D termina en ".W" (frontera de etiqueta) — score 2/6 en el oráculo, ambos >= 0.
    assert!(we("example.com").suffix_matches("sub.example.com"));
    assert!(we("example.com").suffix_matches("a.b.example.com"));
    // Sufijo NO en frontera de etiqueta: el walk del oráculo sólo avanza tras un punto.
    assert!(!we("xample.com").suffix_matches("example.com"));
    assert!(!we("ample.com").suffix_matches("example.com"));
    // W más largo que D, o dominio distinto → no casa.
    assert!(!we("sub.example.com").suffix_matches("example.com"));
    assert!(!we("other.com").suffix_matches("example.com"));
    // Sufijo vacío (dirección literal "*.", `range+2 == ""`): casa D == "" o D que termina en '.'
    // (fiel al walk del oráculo que alcanza "" tras el último punto), NADA más.
    assert!(we("").suffix_matches(""));
    assert!(we("").suffix_matches("foo."));
    assert!(!we("").suffix_matches("example.com"));
}

/// Differential EMPÍRICO byte-a-byte contra un harness C con extracción VERBATIM de
/// `parse_ziti_address_str`+`ziti_address_match`+`ziti_address_match_s` (`internal_model.c`,
/// `clang -O2`; scratch NO comiteado, mismo patrón que las rebanadas 1/2 de M3-DNS). Cada par
/// `(D, W)` reconstruye las formas `"*."`-prefijadas que `intercept_match_addr` pasa al oráculo
/// (`ziti_address_match_s("*."+D, range "*."+W)`) y el `verdict` es el `>= 0` del oráculo. Ambos
/// lados YA lowercased en producción (`check_name`/`wildcard_suffix`/`reverse_lookup_domain`), así
/// que el `strcasecmp` del oráculo (case-INSENSITIVE en el match) equivale a nuestro match
/// case-sensitive tras la normalización upstream — el caso `EXAMPLE.COM` del harness se cubre en
/// `dns::tests::wildcard_suffix_equals_the_stored_domain_form`, no aquí. **0 divergencias.**
#[test]
fn suffix_matches_differential_vs_ziti_address_match_c_oracle() {
    let we = |suffix: &str| WildcardEntry {
        suffix: suffix.to_string(),
        low_port: 0,
        high_port: 0,
        protocol: "tcp".into(),
        service: "s".into(),
        dial_timeout: Duration::from_secs(5),
        allowed_sources: None,
    };
    // (D_suffix, W_suffix, oracle verdict `ziti_address_match_s("*."+D, "*."+W) >= 0`).
    let ground_truth: &[(&str, &str, bool)] = &[
        ("example.com", "example.com", true),
        ("sub.example.com", "example.com", true),
        ("a.b.example.com", "example.com", true),
        ("sub.example.com", "sub.example.com", true),
        ("example.com", "sub.example.com", false),
        ("example.com", "xample.com", false),
        ("example.com", "ample.com", false),
        ("example.com", "other.com", false),
        ("com", "com", true),
        ("example.com", "com", true),
        ("foo.example.com", "foo.example.com", true),
        ("x.foo.example.com", "foo.example.com", true),
        ("foo.example.com", "oo.example.com", false),
        ("", "", true),
        ("foo.", "", true),
        ("example.com", "", false),
        ("", "example.com", false),
        ("a.example.com", "a.example.com", true),
        ("aa.example.com", "a.example.com", false),
    ];
    for (d, w, expected) in ground_truth {
        assert_eq!(
            we(w).suffix_matches(d),
            *expected,
            "suffix_matches(W={w:?}, D={d:?}) debe casar el verdicto del oráculo C"
        );
    }
}

/// Regresión (revisión reforzada): un `*` NO seguido INMEDIATAMENTE de un punto (p. ej.
/// `"*foo.com"`) NO es un patrón de dominio — `check_name`/el oráculo lo registran como hostname
/// LITERAL (ver el doc de `dns/`, quirk ya differential-testeado en la rebanada del matcher).
/// El gate de este bucle debe espejar EXACTO `"*."`, no un `starts_with('*')` más laxo, o esta
/// clase de hostname pierde su entrada de dispatch en silencio (bug real cazado empíricamente).
#[test]
fn star_without_immediate_dot_is_a_literal_hostname_not_a_domain() {
    let r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*foo.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
        seeded_dns(),
    );
    assert!(
        !r.is_empty(),
        "\"*foo.com\" (sin punto tras el '*') debe producir una entrada /32 dispatchable, \
             igual que el oráculo"
    );
    assert_eq!(
        r.lookup(ip("10.99.0.1"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "svc"
    );
}

/// DOS servicios con hostnames EXACTOS distintos reciben IPs sintéticas DISTINTAS (el pool
/// compartido no las colisiona) y cada una despacha a SU PROPIO servicio — ninguna interferencia
/// cruzada entre servicios que comparten el mismo `DnsMatcher`.
#[test]
fn two_services_with_distinct_hostnames_get_distinct_ips_and_dispatch_correctly() {
    let mut dns = seeded_dns();
    let ip_a = match dns.register("a.example.com", "probe") {
        RegisterOutcome::Hostname(ip) => ip,
        other => panic!("{other:?}"),
    };
    let ip_b = match dns.register("b.example.com", "probe") {
        RegisterOutcome::Hostname(ip) => ip,
        other => panic!("{other:?}"),
    };
    assert_ne!(ip_a, ip_b);

    let a = svc(
        "alpha",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["a.example.com"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    let b = svc(
        "beta",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["b.example.com"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    // El orden de registro dentro de `from_services_with_dns` sigue el orden de `services`, así
    // que las IPs asignadas coinciden con `ip_a`/`ip_b` de arriba (mismo CIDR, mismo contador
    // fresco, mismo orden alpha→beta).
    let r = InterceptResolver::from_services_with_dns(&[a, b], seeded_dns());

    assert_eq!(
        r.lookup(IpAddr::V4(ip_a), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "alpha"
    );
    assert_eq!(
        r.lookup(IpAddr::V4(ip_b), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "beta"
    );
}

/// Un hostname exacto que colisionaría con una IP ya RESERVADA (espejo del utun/DNS-resolver de
/// `main.rs`) recibe la SIGUIENTE IP libre, nunca la reservada — confirma que
/// `from_services_with_dns` respeta un `DnsMatcher` pre-poblado por el llamante, no solo uno
/// recién sembrado.
#[test]
fn exact_hostname_skips_ips_reserved_before_wiring() {
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("10.99.0.0/24"));
    dns.reserve("10.99.0.1".parse().unwrap()); // p. ej. la IP del propio utun
    let r = one_svc_resolver_with_dns(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
        dns,
    );
    assert!(
        r.lookup(ip("10.99.0.1"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "la IP reservada nunca se asigna a un hostname"
    );
    assert_eq!(
        r.lookup(ip("10.99.0.2"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "svc",
        "el hostname recibe la siguiente IP libre tras la reservada"
    );
}
