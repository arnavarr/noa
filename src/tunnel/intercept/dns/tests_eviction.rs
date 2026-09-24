//! b7: #5 eviction (`ziti_dns_deregister_intercept`, `ziti_dns.c:414-446`) (F6 tramo 15
//! troceo).

use std::net::Ipv4Addr;

use super::testsupport::*;
use super::*;

// ─────────────── #5 eviction (`ziti_dns_deregister_intercept`, `ziti_dns.c:414-446`) ───────────────

/// VECTOR SANCIONADO POR UPSTREAM — espejo del test "recycle ip" del propio oráculo
/// (`ziti-tunnel-sdk-c` @ `2addfbb`, `lib/tests/dns_test.cpp:33-88`): pool `100.64.0.1/24` con
/// tun (.1) y dns (.2) reservadas; 252 hostnames lo llenan (el 1º recibe `.3`, el último `.254`
/// — ni red .0 ni broadcast .255); uno más falla; deregistrar el intercept del hostname índice
/// 100 (IP `.103`) libera EXACTAMENTE ese hueco y el siguiente registro lo reusa
/// (`CHECK_THAT(ipaddr_ntoa(ip), Catch::Equals("100.64.0.103"))`).
#[test]
fn recycle_ip_equals_upstream_dns_test() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("100.64.0.1/24"));
    m.reserve(Ipv4Addr::new(100, 64, 0, 1)); // tun
    m.reserve(Ipv4Addr::new(100, 64, 0, 2)); // dns
    // El test upstream itera `pool_size = 2^8 - 4` (red, broadcast, tun, dns) = 252 y TODAS
    // asignan (los huecos reales son exactamente `.3`-`.254`); el CHECK upstream pide que la
    // última (`ips[pool_size-1]`) haya recibido IP.
    let mut ips = Vec::new();
    for i in 0..252 {
        match m.register(&format!("host{i:03}."), &format!("svc{i:03}")) {
            RegisterOutcome::Hostname(ip) => ips.push(ip),
            RegisterOutcome::IpUnavailable => break,
            other => panic!("registro {i}: {other:?}"),
        }
    }
    assert_eq!(ips.len(), 252, "los 252 huecos reales (.3-.254) asignan");
    assert_eq!(
        ips[0],
        Ipv4Addr::new(100, 64, 0, 3),
        "el 1º no pisa tun/dns"
    );
    assert_eq!(
        *ips.last().unwrap(),
        Ipv4Addr::new(100, 64, 0, 254),
        "el último no es broadcast"
    );
    // Pool lleno: uno más falla (upstream: register == nullptr).
    assert_eq!(
        m.register("just.one.more", "svc-more"),
        RegisterOutcome::IpUnavailable
    );
    // Liberar el intercept del hostname índice 100 (IP .103) y reintentar: recicla ESE hueco.
    assert_eq!(ips[100], Ipv4Addr::new(100, 64, 0, 103));
    m.deregister_intercept("svc100");
    assert_eq!(
        m.register("just.one.more", "svc-more"),
        RegisterOutcome::Hostname(Ipv4Addr::new(100, 64, 0, 103)),
        "el hueco liberado se reusa — byte-igual al CHECK del test upstream"
    );
}

/// El corner de la pasada 2 en AMBAS direcciones para una entrada con refcount propio Y dominio:
/// un dominio de "b" asigna una entrada lazy; "a" registra el MISMO nombre explícitamente
/// (reusa la entrada/IP, `:473-478`). Deregistrar "b" evicta el DOMINIO pero CONSERVA la entrada
/// (su refcount propio no está vacío, `:426`) — que sigue resolviendo con la MISMA IP y conserva
/// su `domain` de origen (espejo del `entry->domain` del oráculo, que sobrevive a la eviction
/// del dominio). Deregistrar "a" después la evicta y libera la IP.
#[test]
fn explicit_entry_under_lazy_domain_survives_the_domain_owner_deregister() {
    let mut m = matcher_of(&[]);
    assert_eq!(m.register("*.foo.com", "b"), RegisterOutcome::Domain);
    let lazy_ip = m.lookup("app.foo.com").unwrap().ip;
    // "a" registra el mismo nombre explícito: reusa la entrada y su IP.
    assert_eq!(
        m.register("app.foo.com", "a"),
        RegisterOutcome::Hostname(lazy_ip)
    );
    m.deregister_intercept("b");
    assert!(
        !m.matches_domain("other.foo.com"),
        "el dominio de 'b' se evictó (pasada 3)"
    );
    assert_eq!(
        m.lookup("app.foo.com").map(|x| x.ip),
        Some(lazy_ip),
        "la entrada sobrevive por su refcount propio (pasada 2, `:426`)"
    );
    assert_eq!(
        m.reverse_lookup_domain(lazy_ip),
        Some("foo.com"),
        "conserva su domain de origen (espejo del entry->domain superviviente del oráculo)"
    );
    m.deregister_intercept("a");
    assert!(
        m.lookup("app.foo.com").is_none(),
        "el último refcount se fue → evictada"
    );
    assert!(m.reverse_lookup(lazy_ip).is_none(), "IP liberada (:428)");
}

/// Las IPs RESERVADAS (utun / DNS resolver) NUNCA se evictan: viven solo en `ip_addresses` sin
/// entrada en `hostnames`, y la pasada 2 solo barre `hostnames` — igual que el oráculo (`:422`
/// itera `ziti_dns.hostnames`; las reservas solo están en `ip_addresses`, `:194-201`).
#[test]
fn deregister_never_releases_reserved_ips() {
    let mut m = matcher_of(&[]);
    let tun = Ipv4Addr::new(10, 0, 0, 1);
    m.reserve(tun);
    assert_eq!(m.register("*.foo.com", "s"), RegisterOutcome::Domain);
    let _ = m.lookup("app.foo.com").unwrap();
    m.deregister_intercept("s");
    assert_eq!(
        m.reverse_lookup(tun),
        Some(""),
        "la reserva sobrevive al deregistro (entrada zeroed del oráculo)"
    );
    // Y sigue bloqueando el pool: un hostname nuevo no puede recibirla.
    let mut m2 = DnsMatcher::new();
    assert!(m2.seed_pool("10.0.0.0/29"));
    m2.reserve(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(m2.register("*.d.com", "s"), RegisterOutcome::Domain);
    let ip = m2.lookup("a.d.com").unwrap().ip;
    assert_ne!(ip, Ipv4Addr::new(10, 0, 0, 1));
    m2.deregister_intercept("s");
    let RegisterOutcome::Hostname(fresh) = m2.register("h.e.com", "t") else {
        panic!("debe asignar")
    };
    assert_ne!(
        fresh,
        Ipv4Addr::new(10, 0, 0, 1),
        "la reserva nunca vuelve al pool"
    );
}

/// Registrar dos veces el mismo (nombre, intercept) es UN solo refcount (set semantics, espejo
/// de `model_map_set_key` sobre la misma clave): un único deregistro lo libera del todo.
#[test]
fn double_register_by_the_same_intercept_is_one_refcount() {
    let mut m = matcher_of(&[]);
    let RegisterOutcome::Hostname(ip) = m.register("app.foo.com", "s") else {
        panic!("debe asignar")
    };
    assert_eq!(
        m.register("app.foo.com", "s"),
        RegisterOutcome::Hostname(ip)
    );
    m.deregister_intercept("s");
    assert!(
        m.lookup("app.foo.com").is_none(),
        "un deregistro basta (no hay doble-conteo)"
    );
    assert!(m.reverse_lookup(ip).is_none());
}

/// Deregistrar un intercept que nunca registró nada es un no-op inocuo (los tres barridos no
/// encuentran nada suyo) — es el camino del fold del snapshot (`add_service` llama
/// `remove_service` para nombres frescos) y del `Removed` de un servicio sin intercept.
#[test]
fn deregister_of_an_unknown_intercept_is_a_noop() {
    let mut m = matcher_of(&["app.foo.com", "*.bar.com"]);
    let ip = m.lookup("app.foo.com").unwrap().ip;
    let lazy = m.lookup("x.bar.com").unwrap().ip;
    m.deregister_intercept("nunca-registrado");
    assert_eq!(m.lookup("app.foo.com").map(|x| x.ip), Some(ip));
    assert_eq!(m.lookup("x.bar.com").map(|x| x.ip), Some(lazy));
    assert!(m.matches_domain("y.bar.com"));
}
