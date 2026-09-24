// F6 tramo 2b troceo: tests movidos verbatim del monolito de `intercept/resolve` (mod tests).

use std::net::IpAddr;

use ipnet::IpNet;

use crate::edge::services::ServiceEvent;
use crate::tunnel::intercept::dns::RegisterOutcome;

use super::testsupport::*;
use super::{InterceptResolver, Protocol};

#[test]
fn intercept_cidrs_returns_distinct_cidrs_in_first_seen_order() {
    // Dos servicios comparten `10.0.0.0/24`; un tercer address aporta `192.168.5.0/24`. Cada
    // servicio expande protocolos×puertos en varias entradas con la MISMA cidr → el accessor debe
    // colapsar a CIDRs distintas (el refcount del oráculo `route.c:40`, colapsado a un conjunto).
    let resolver = InterceptResolver::from_services(&[
        svc(
            "a",
            r#"{"intercept.v1":{"protocols":["tcp","udp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":81}]}}"#,
        ),
        svc(
            "b",
            r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24","192.168.5.0/24"],"portRanges":[{"low":443,"high":443}]}}"#,
        ),
    ]);
    assert_eq!(
        resolver.intercept_cidrs(),
        vec![
            "10.0.0.0/24".parse::<IpNet>().unwrap(),
            "192.168.5.0/24".parse::<IpNet>().unwrap(),
        ],
        "CIDRs distintas en orden de primera aparición; el /24 compartido aparece UNA sola vez"
    );
}

#[test]
fn intercept_cidrs_omits_hostname_addresses() {
    // Una dirección hostname NO produce entrada IP (su ruteo es M3-DNS, vía IP sintética), así que
    // NO aparece como CIDR a rutear; solo el CIDR IP del mismo servicio se rutea.
    let resolver = InterceptResolver::from_services(&[svc(
        "h",
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com","10.1.0.0/16"],"portRanges":[{"low":80,"high":80}]}}"#,
    )]);
    assert_eq!(
        resolver.intercept_cidrs(),
        vec!["10.1.0.0/16".parse::<IpNet>().unwrap()],
        "el hostname se omite (M3-DNS); solo el CIDR IP se rutea"
    );
}

// ───── Reconciliación por-servicio (svc-poller re-feed T5 + #5 eviction + RUTAS OS) ─────
// Espejo de `ziti_sdk_c_on_service` (`ziti_tunnel_cbs.c:615`): reconciliar la tabla de MATCH ante
// eventos Added/Changed/Removed del ServiceWatcher, liberando también el estado DNS del servicio
// retirado (#5 eviction cerró la Opción B; ver el doc de add_service/remove_service) y devolviendo
// el RouteDelta de cada mutación (rebanada RUTAS OS: el RouteLifecycle refcounted lo aplica —
// wiring vivo en combined/runner.rs::svc_poll_loop, arranque en main.rs).

/// `add_service` sobre un resolver vacío instala el intercept (status ZITI_OK, alta).
#[test]
fn add_service_installs_a_new_intercept() {
    let mut r = InterceptResolver::from_services(&[]);
    assert!(r.is_empty());
    r.add_service(&svc("a", CIDR_A));
    assert_eq!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "a"
    );
}

/// `remove_service` retira TODO el match de ese nombre y SOLO ese: tras él ningún paquete despacha al
/// servicio retirado; los demás intactos (espejo `stop_intercept` menos las rutas OS).
#[test]
fn remove_service_stops_only_that_services_dispatch() {
    let mut r = InterceptResolver::from_services(&[svc("a", CIDR_A), svc("b", CIDR_B)]);
    assert_eq!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "a"
    );
    r.remove_service("a");
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "a retirado → no despacha"
    );
    assert_eq!(
        r.lookup(ip("10.1.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "b",
        "b intacto"
    );
}

/// El fold de `add_service` reproduce EXACTAMENTE la construcción del snapshot, incluida la ORDEN de
/// asignación de IP sintética (el guard clave del refactor): host-a antes que host-b → IPs en ese
/// orden, idéntico a un `register` secuencial independiente. Un refactor que perturbe la orden haría
/// diverger las IPs.
#[test]
fn folding_add_service_preserves_snapshot_ip_assignment_order() {
    let services = [
        svc(
            "a",
            r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["host-a.example.com"],"portRanges":[{"low":80,"high":80}]}}"#,
        ),
        svc(
            "b",
            r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["host-b.example.com"],"portRanges":[{"low":80,"high":80}]}}"#,
        ),
    ];
    // Oráculo del orden, independiente del resolver: registrar los hostnames en orden en un pool fresco.
    let mut probe = seeded_dns();
    let ip_a = match probe.register("host-a.example.com", "a") {
        RegisterOutcome::Hostname(x) => x,
        o => panic!("host-a debe asignar IP: {o:?}"),
    };
    let ip_b = match probe.register("host-b.example.com", "b") {
        RegisterOutcome::Hostname(x) => x,
        o => panic!("host-b debe asignar IP: {o:?}"),
    };
    assert_ne!(ip_a, ip_b);

    let snap = InterceptResolver::from_services_with_dns(&services, seeded_dns());
    let mut fold = InterceptResolver::from_services_with_dns(&[], seeded_dns());
    for s in &services {
        fold.add_service(s);
    }
    for r in [&snap, &fold] {
        assert_eq!(
            r.lookup(IpAddr::V4(ip_a), 80, Protocol::Tcp, ANY_SRC)
                .unwrap()
                .service,
            "a"
        );
        assert_eq!(
            r.lookup(IpAddr::V4(ip_b), 80, Protocol::Tcp, ANY_SRC)
                .unwrap()
                .service,
            "b"
        );
    }
}

/// `apply_event(Added)` = alta: instala el intercept.
#[test]
fn apply_event_added_installs() {
    let mut r = InterceptResolver::from_services(&[]);
    r.apply_event(&ServiceEvent::Added(svc("a", CIDR_A)));
    assert_eq!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "a"
    );
}

/// `apply_event(Changed)` con `intercept.v1` VÁLIDO nuevo = REEMPLAZA (status ZITI_OK, curr_i existe
/// → stop old + install new, `ziti_tunnel_cbs.c:632-639`): las direcciones VIEJAS dejan de despachar,
/// las NUEVAS despachan. Discrimina un mutante "Changed→add sin remove" (dejaría ambas).
#[test]
fn apply_event_changed_valid_replaces_addresses() {
    let mut r = InterceptResolver::from_services(&[svc("a", CIDR_A)]);
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_some()
    );
    r.apply_event(&ServiceEvent::Changed(svc("a", CIDR_B))); // mismo nombre, nuevo CIDR
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "la dirección VIEJA (10.0.0.0/24) ya no despacha tras el replace"
    );
    assert_eq!(
        r.lookup(ip("10.1.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "a",
        "la dirección NUEVA (10.1.0.0/24) despacha"
    );
}

/// `apply_event(Changed)` que PIERDE el permiso `Dial` = RETIRA (status ZITI_OK + !CAN_DIAL →
/// stop_intercept si curr_i, `ziti_tunnel_cbs.c:624-626`). Llega como Changed, NO como Removed — es
/// la rama que un naive "Changed→add_service que sobre no-Dial no hace nada" dejaría viva.
#[test]
fn apply_event_changed_losing_dial_removes() {
    let mut r = InterceptResolver::from_services(&[svc("a", CIDR_A)]);
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_some()
    );
    // Mismo servicio, misma config de intercept, pero YA NO puede Dial (Bind-only).
    r.apply_event(&ServiceEvent::Changed(svc_perms("a", CIDR_A, &["Bind"])));
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "perder Dial retira el intercept (llega como Changed, no Removed)"
    );
}

/// `apply_event(Changed)` con `Dial` pero SIN `intercept.v1` válido nuevo = CONSERVA el intercept
/// anterior (`new_ziti_intercept`→NULL → el oráculo mantiene curr_i, `ziti_tunnel_cbs.c:641-644`). LA
/// rama sutil: discrimina un mutante "Changed→replace que rebuild-ea desde config-vacío" que RETIRARÍA
/// el intercept vivo.
#[test]
fn apply_event_changed_dial_without_intercept_v1_keeps_old() {
    let mut r = InterceptResolver::from_services(&[svc("a", CIDR_A)]);
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_some()
    );
    // Dial-permitido, pero el nuevo config no tiene intercept.v1 (solo host.v1) → keep-old.
    r.apply_event(&ServiceEvent::Changed(svc(
        "a",
        r#"{"host.v1":{"address":"x","port":1,"protocol":"tcp"}}"#,
    )));
    assert_eq!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "a",
        "sin intercept.v1 válido nuevo, se CONSERVA el intercept anterior (no se retira)"
    );
}

/// `apply_event(Removed)` = baja (status ZITI_SERVICE_UNAVAILABLE, `ziti_tunnel_cbs.c:677-682`): retira.
#[test]
fn apply_event_removed_retires() {
    let mut r = InterceptResolver::from_services(&[svc("a", CIDR_A)]);
    r.apply_event(&ServiceEvent::Removed(svc("a", CIDR_A)));
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none()
    );
}

/// EL corner shared-domain del MATCH: dos servicios reclaman `*.example.com`; retirar UNO deja al
/// superviviente despachando el dominio (en el match, la WildcardEntry del otro sigue; en el DNS,
/// el refcount por-dominio real de #5 lo conserva — ver
/// `shared_domain_keeps_lazy_entries_while_a_claimant_remains`). Garantiza que retirar un servicio
/// NO under-dispatchea a otro que aún reclama el dominio compartido.
#[test]
fn removing_one_of_two_services_sharing_a_wildcard_domain_keeps_the_survivor() {
    let cfg = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.example.com"],"portRanges":[{"low":80,"high":80}]}}"#;
    let mut r =
        InterceptResolver::from_services_with_dns(&[svc("a", cfg), svc("b", cfg)], seeded_dns());
    // Una query asigna una IP bajo el dominio compartido.
    let assigned = r.dns_mut().lookup("host.example.com").unwrap().ip;
    let dst = IpAddr::V4(assigned);
    // first-match en orden de registro: "a" (primer servicio) gana el fallback wildcard.
    assert_eq!(
        r.lookup(dst, 80, Protocol::Tcp, ANY_SRC).unwrap().service,
        "a"
    );
    r.remove_service("a");
    assert_eq!(
        r.lookup(dst, 80, Protocol::Tcp, ANY_SRC).unwrap().service,
        "b",
        "el superviviente que aún reclama *.example.com despacha (no under-dispatch)"
    );
}

/// El corner name-reuse: un servicio se retira y se re-da de alta bajo el MISMO nombre con OTRA
/// dirección. La reconciliación por-nombre deja despachando SOLO la config nueva.
#[test]
fn name_reuse_readd_dispatches_the_new_config_only() {
    let mut r = InterceptResolver::from_services(&[svc("a", CIDR_A)]);
    r.apply_event(&ServiceEvent::Removed(svc("a", CIDR_A)));
    r.apply_event(&ServiceEvent::Added(svc("a", CIDR_B)));
    assert!(
        r.lookup(ip("10.0.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "la dirección vieja no despacha"
    );
    assert_eq!(
        r.lookup(ip("10.1.0.5"), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "a",
        "la dirección nueva del servicio re-dado-de-alta despacha"
    );
}

/// #5 eviction (cierra la desviación de la Opción B): tras `remove_service`, el estado DNS del
/// servicio retirado se LIBERA entero — el dominio deja de casar (una query posterior es un miss
/// → REFUSED, como el oráculo tras `ziti_dns_deregister_intercept`), sus entradas lazy se evictan
/// (la IP asignada deja de reverse-resolver) y, por supuesto, ningún paquete despacha.
#[test]
fn removed_service_releases_domain_lazy_entries_and_ips() {
    let cfg = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.example.com"],"portRanges":[{"low":80,"high":80}]}}"#;
    let mut r = one_svc_resolver_with_dns(cfg, seeded_dns());
    let assigned = r.dns_mut().lookup("host.example.com").unwrap().ip;
    assert_eq!(
        r.lookup(IpAddr::V4(assigned), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "svc"
    );
    r.remove_service("svc");
    // (a) el dominio se evictó (pasada 3): una query posterior no casa → el server REFUSA.
    assert!(
        !r.dns().matches_domain("other.example.com"),
        "el dominio del servicio retirado se deregistra (ziti_dns_deregister_intercept :436-445)"
    );
    // (b) la entrada lazy se evictó con su IP (pasada 2): ni forward ni reverse.
    assert!(
        r.dns_mut().lookup("host.example.com").is_none(),
        "el hostname lazy bajo el dominio evictado ya no resuelve"
    );
    assert!(
        r.dns().reverse_lookup(assigned).is_none(),
        "la IP sintética se liberó de ip_addresses (:428)"
    );
    // (c) y un paquete a la IP vieja no despacha (tabla de match limpia + DNS liberado).
    assert!(
        r.lookup(IpAddr::V4(assigned), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "ningún paquete despacha al servicio retirado"
    );
}

/// Refcount de HOSTNAME EXACTO compartido: dos servicios registran el MISMO hostname; retirar UNO
/// conserva la entrada (misma IP, sigue resolviendo y despachando al superviviente); retirar el
/// SEGUNDO la evicta con su IP. Pin de la condición de la pasada 2 (`ziti_dns.c:426`) en ambas
/// direcciones para entradas con refcount propio.
#[test]
fn shared_exact_hostname_survives_until_the_last_service_deregisters() {
    let cfg = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com"],"portRanges":[{"low":80,"high":80}]}}"#;
    let mut r =
        InterceptResolver::from_services_with_dns(&[svc("a", cfg), svc("b", cfg)], seeded_dns());
    let ip = r.dns_mut().lookup("app.example.com").unwrap().ip;
    r.remove_service("a");
    assert_eq!(
        r.dns_mut().lookup("app.example.com").unwrap().ip,
        ip,
        "la entrada compartida sobrevive con la MISMA IP mientras quede un reclamante"
    );
    assert_eq!(
        r.lookup(IpAddr::V4(ip), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "b",
        "despacha al superviviente"
    );
    r.remove_service("b");
    assert!(
        r.dns_mut().lookup("app.example.com").is_none(),
        "el último deregistro evicta la entrada"
    );
    assert!(
        r.dns().reverse_lookup(ip).is_none(),
        "y libera la IP (:428)"
    );
}

/// Dominio COMPARTIDO: retirar uno de dos servicios que reclaman `*.example.com` conserva el
/// dominio Y sus entradas lazy (refcount del dominio > 0 → la pasada 2 las mantiene): la IP ya
/// asignada sigue resolviendo y despachando al superviviente. Complemento DNS del test de
/// match `removing_one_of_two_services_sharing_a_wildcard_domain_keeps_the_survivor`.
#[test]
fn shared_domain_keeps_lazy_entries_while_a_claimant_remains() {
    let cfg = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["*.example.com"],"portRanges":[{"low":80,"high":80}]}}"#;
    let mut r =
        InterceptResolver::from_services_with_dns(&[svc("a", cfg), svc("b", cfg)], seeded_dns());
    let assigned = r.dns_mut().lookup("host.example.com").unwrap().ip;
    r.remove_service("a");
    assert!(
        r.dns().matches_domain("other.example.com"),
        "el dominio sigue activo (refcount del superviviente)"
    );
    assert_eq!(
        r.dns_mut().lookup("host.example.com").unwrap().ip,
        assigned,
        "la entrada lazy sobrevive con la MISMA IP (pasada 2: dominio activo)"
    );
    assert_eq!(
        r.lookup(IpAddr::V4(assigned), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "b",
        "y despacha al superviviente"
    );
}

/// El gate keep-unchanged (`compare()==0`, `ziti_tunnel_cbs.c:449-455`): un `Changed` cuyo
/// `intercept.v1` NO cambió (aquí: solo cambian las permissions, que `service_details_equal`
/// SÍ diffea → el evento es real) CONSERVA el intercept instalado — la IP sintética del hostname
/// NO cambia, el estado DNS no se toca y el dispatch sigue. Discrimina el mutante
/// "Changed→rebuild ciego", que post-#5 deregistraría+re-registraría (IP nueva, churn que el
/// oráculo evita devolviendo NULL de `new_ziti_intercept` sin `stop_intercept`).
#[test]
fn changed_with_identical_intercept_v1_keeps_dns_state_stable() {
    let cfg = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com","*.wild.example.com"],"portRanges":[{"low":80,"high":80}]}}"#;
    let mut r = one_svc_resolver_with_dns(cfg, seeded_dns());
    let host_ip = r.dns_mut().lookup("app.example.com").unwrap().ip;
    let lazy_ip = r.dns_mut().lookup("x.wild.example.com").unwrap().ip;
    // Changed real (permissions añaden Bind) con intercept.v1 byte-idéntico.
    r.apply_event(&ServiceEvent::Changed(svc_perms(
        "svc",
        cfg,
        &["Dial", "Bind"],
    )));
    assert_eq!(
        r.dns_mut().lookup("app.example.com").map(|x| x.ip),
        Some(host_ip),
        "la IP del hostname NO cambia (keep-unchanged, sin deregistro/re-registro)"
    );
    assert_eq!(
        r.dns_mut().lookup("x.wild.example.com").map(|x| x.ip),
        Some(lazy_ip),
        "la entrada lazy del wildcard sobrevive intacta"
    );
    assert_eq!(
        r.lookup(IpAddr::V4(host_ip), 80, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "svc",
        "y el dispatch sigue"
    );
}

/// Un REPLACE (`Changed` con config válido DISTINTO) deregistra el config saliente ANTES de
/// re-registrar (espejo `ziti_sdk_c_on_service`: `stop_intercept` `:634` → `new_intercept_ctx`
/// `:638`), así que la IP sintética de un hostname NO compartido CAMBIA (el contador del pool
/// avanzó y el registro fresco asigna la siguiente): la IP vieja queda liberada (ni resuelve ni
/// despacha) y la nueva resuelve y despacha. Pin del comportamiento observable del oráculo — un
/// cliente re-resuelve tras el TTL y alcanza la IP nueva.
#[test]
fn replace_reassigns_the_synthetic_ip_of_an_unshared_hostname() {
    let cfg = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com"],"portRanges":[{"low":80,"high":80}]}}"#;
    let mut r = one_svc_resolver_with_dns(cfg, seeded_dns());
    let old_ip = r.dns_mut().lookup("app.example.com").unwrap().ip;
    // Mismo servicio, config válido (puerto distinto) → REPLACE.
    r.apply_event(&ServiceEvent::Changed(svc(
            "svc",
            r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["app.example.com"],"portRanges":[{"low":81,"high":81}]}}"#,
        )));
    let new_ip = r.dns_mut().lookup("app.example.com").unwrap().ip;
    assert_ne!(
        new_ip, old_ip,
        "el hostname re-registrado tras el deregistro del REPLACE recibe una IP NUEVA"
    );
    assert!(
        r.dns().reverse_lookup(old_ip).is_none(),
        "la IP vieja quedó liberada"
    );
    assert!(
        r.lookup(IpAddr::V4(old_ip), 81, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "la IP vieja no despacha"
    );
    assert_eq!(
        r.lookup(IpAddr::V4(new_ip), 81, Protocol::Tcp, ANY_SRC)
            .unwrap()
            .service,
        "svc",
        "la IP nueva despacha al servicio"
    );
}

/// El delta de un alta reporta SOLO las direcciones literales (IP/CIDR), en orden de config y
/// con duplicados (la lista de `i_ctx->addresses` que `ziti_tunneler_intercept` recorre con
/// `add_route`, `ziti_tunnel.c:428-430`); hostname y wildcard quedan fuera (desviación
/// documentada en [`RouteDelta`]: su ruteo es la subred on-link del utun).
#[test]
fn add_service_delta_reports_literal_addresses_in_config_order_with_duplicates() {
    let mut r = InterceptResolver::from_services_with_dns(&[], seeded_dns());
    let delta = r
            .add_service(&svc(
                "a",
                r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.7.0.0/24","app.example.com","*.wild.example.com","192.168.9.9","10.7.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#,
            ))
            .routes;
    assert!(delta.removed.is_empty(), "alta pura: nada saliente");
    assert_eq!(
        delta.added,
        vec![
            cidr("10.7.0.0/24"),
            cidr("192.168.9.9/32"),
            cidr("10.7.0.0/24")
        ],
        "literales en orden de config, duplicado incluido (refcuenta 2 como el C); hostname/wildcard fuera"
    );
}

/// `remove_service` devuelve las direcciones del config INSTALADO (la lista que
/// `ziti_tunneler_stop_intercepting` recorre con `delete_route`, `ziti_tunnel.c:500-503`);
/// un nombre sin intercept instalado devuelve vacío (`curr_i == NULL` → sin stop_intercept).
#[test]
fn remove_service_delta_returns_the_installed_addresses() {
    let mut r = InterceptResolver::from_services(&[svc("a", CIDR_A)]);
    assert_eq!(r.remove_service("a"), vec![cidr("10.0.0.0/24")]);
    assert!(
        r.remove_service("a").is_empty(),
        "ya retirado: sin direcciones que devolver"
    );
    assert!(r.remove_service("nunca-instalado").is_empty());
}

/// El ciclo completo de deltas por rama de `apply_event`, espejo de los caminos de
/// `ziti_sdk_c_on_service`: replace = removed(viejo)+added(nuevo) (delete-then-add, `:634`/`:638`);
/// keep-unchanged y keep-old = delta VACÍO (sin stop ni intercept); lost-dial y Removed =
/// removed solo (`:626`/`:681`).
#[test]
fn apply_event_deltas_mirror_the_on_service_route_branches() {
    let mut r = InterceptResolver::from_services(&[]);
    // Alta.
    let d = r.apply_event(&ServiceEvent::Added(svc("a", CIDR_A))).routes;
    assert_eq!(
        (d.removed.clone(), d.added.clone()),
        (vec![], vec![cidr("10.0.0.0/24")])
    );
    // Changed con intercept.v1 IDÉNTICO (solo permissions) → keep-unchanged → vacío.
    let d = r
        .apply_event(&ServiceEvent::Changed(svc_perms(
            "a",
            CIDR_A,
            &["Dial", "Bind"],
        )))
        .routes;
    assert!(
        d.is_empty(),
        "keep-unchanged: el C ni para ni re-instala → 0 rutas"
    );
    // Changed con config INVÁLIDO (keep-old) → vacío.
    let d = r
        .apply_event(&ServiceEvent::Changed(svc(
            "a",
            r#"{"host.v1":{"address":"x","port":1,"protocol":"tcp"}}"#,
        )))
        .routes;
    assert!(d.is_empty(), "keep-old: sin stop_intercept → 0 rutas");
    // REPLACE (config válido distinto) → removed(viejo) + added(nuevo), en ese orden.
    let d = r
        .apply_event(&ServiceEvent::Changed(svc("a", CIDR_B)))
        .routes;
    assert_eq!(d.removed, vec![cidr("10.0.0.0/24")], "el config saliente");
    assert_eq!(d.added, vec![cidr("10.1.0.0/24")], "el config entrante");
    // Changed que PIERDE Dial → removed solo.
    let d = r
        .apply_event(&ServiceEvent::Changed(svc_perms("a", CIDR_B, &["Bind"])))
        .routes;
    assert_eq!(
        (d.removed.clone(), d.added.clone()),
        (vec![cidr("10.1.0.0/24")], vec![])
    );
    // Re-alta + Removed → removed solo.
    let _ = r.apply_event(&ServiceEvent::Added(svc("a", CIDR_B)));
    let d = r
        .apply_event(&ServiceEvent::Removed(svc("a", CIDR_B)))
        .routes;
    assert_eq!((d.removed, d.added), (vec![cidr("10.1.0.0/24")], vec![]));
}

/// **Test 10 (kill-active §4.3): la tabla de verdad de `kill_active`, espejo EXACTO de las ramas de
/// `ziti_sdk_c_on_service` que llaman `stop_intercept`** (y, con él,
/// `ziti_tunneler_stop_intercepting` → `tunneler_kill_active`, `ziti_tunnel.c:493`/`:510`).
///
/// Las 6 filas: alta fresca (`curr_i == NULL`) → false · REPLACE (`:632`) → true · keep-unchanged
/// (`compare()==0` → NULL → sin stop, `:449-455`+`:641-643`) → false · keep-old (config inválido →
/// NULL) → false · pierde-Dial con instalado (`:624`) → true · pierde-Dial SIN instalado → false ·
/// `Removed` → true SIEMPRE (DV-1: incondicional; el bucket vacío lo hace no-op).
///
/// **Pin anti-derivación (load-bearing):** un `intercept.v1` de SOLO-hostname da `RouteDelta`
/// VACÍO y aun así mata. Una implementación que dedujese `kill_active` del delta (`!routes
/// .is_empty()`) pasaría todas las filas CIDR y fallaría ESTAS dos → under-kill silencioso.
#[test]
fn apply_event_kill_active_truth_table() {
    // Pin anti-derivación (usado al final): dos configs SOLO-hostname ⇒ `RouteDelta` siempre vacío.
    const HOSTNAME_CFG: &str = r#"{"intercept.v1":{"addresses":["app.ziti.test"],"protocols":["tcp"],"portRanges":[{"low":80,"high":80}]}}"#;
    const HOSTNAME_CFG_B: &str = r#"{"intercept.v1":{"addresses":["other.ziti.test"],"protocols":["tcp"],"portRanges":[{"low":80,"high":80}]}}"#;

    let mut r = InterceptResolver::from_services(&[]);

    // Alta fresca: `curr_i == NULL` ⇒ sin stop ⇒ sin kill (y no puede haber flujos: `lookup`
    // nunca devolvió el servicio).
    let a = r.apply_event(&ServiceEvent::Added(svc("a", CIDR_A)));
    assert!(!a.kill_active, "alta fresca: curr_i == NULL ⇒ sin kill");

    // keep-unchanged: mismo `intercept.v1`, solo cambian permissions ⇒ NULL ⇒ sin kill.
    let a = r.apply_event(&ServiceEvent::Changed(svc_perms(
        "a",
        CIDR_A,
        &["Dial", "Bind"],
    )));
    assert!(
        !a.kill_active,
        "keep-unchanged (compare()==0): el oráculo conserva el intercept Y sus flujos"
    );

    // keep-old: `intercept.v1` ausente/inválido ⇒ `new_ziti_intercept` NULL ⇒ sin stop ⇒ sin kill.
    let a = r.apply_event(&ServiceEvent::Changed(svc(
        "a",
        r#"{"host.v1":{"address":"x","port":1,"protocol":"tcp"}}"#,
    )));
    assert!(!a.kill_active, "keep-old: conserva curr_i, no mata");

    // REPLACE: config válido DISTINTO con `curr_i` presente ⇒ `stop_intercept(curr_i)` ⇒ kill.
    let a = r.apply_event(&ServiceEvent::Changed(svc("a", CIDR_B)));
    assert!(
        a.kill_active,
        "REPLACE (:632-635): mata los flujos del viejo"
    );

    // Pierde Dial CON instalado ⇒ `stop_intercept` (`:624-626`) ⇒ kill.
    let a = r.apply_event(&ServiceEvent::Changed(svc_perms("a", CIDR_B, &["Bind"])));
    assert!(a.kill_active, "pierde-dial con curr_i (:624): mata");

    // Pierde Dial SIN instalado (ya retirado arriba) ⇒ `curr_i == NULL` ⇒ sin kill.
    let a = r.apply_event(&ServiceEvent::Changed(svc_perms("a", CIDR_B, &["Bind"])));
    assert!(
        !a.kill_active,
        "pierde-dial sin curr_i: no hay nada que parar"
    );

    // `Removed` ⇒ true SIEMPRE, incluso sin config instalado (DV-1).
    let a = r.apply_event(&ServiceEvent::Removed(svc("a", CIDR_B)));
    assert!(
        a.kill_active,
        "Removed sin instalado ⇒ kill incondicional (DV-1); bucket vacío ⇒ no-op"
    );
    assert!(a.routes.removed.is_empty(), "…y sin rutas que retirar");

    // ── Pin anti-derivación: SOLO-hostname ⇒ delta de rutas VACÍO, pero mata igual. ──
    let mut r = InterceptResolver::from_services_with_dns(&[], seeded_dns());
    let a = r.apply_event(&ServiceEvent::Added(svc("h", HOSTNAME_CFG)));
    assert!(
        a.routes.is_empty() && !a.kill_active,
        "alta hostname: sin rutas literales y sin kill"
    );
    // REPLACE de un servicio SOLO-hostname: cero rutas, kill SÍ.
    let a = r.apply_event(&ServiceEvent::Changed(svc("h", HOSTNAME_CFG_B)));
    assert!(
        a.routes.is_empty(),
        "hostname: el /32 sintético es on-link, no entra al delta"
    );
    assert!(
        a.kill_active,
        "REPLACE de solo-hostname MATA aunque el RouteDelta sea vacío \
             (kill_active NO se deriva del delta)"
    );
    // Removed de un servicio SOLO-hostname: idem.
    let a = r.apply_event(&ServiceEvent::Removed(svc("h", HOSTNAME_CFG_B)));
    assert!(
        a.routes.is_empty() && a.kill_active,
        "Removed solo-hostname"
    );
}
