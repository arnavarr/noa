//! b5: reserve (`ziti_dns_setup`, wiring del utun/DNS-resolver) (F6 tramo 15 troceo).

use super::*;

// ───────────────────────── reserve (ziti_dns_setup, wiring del utun/DNS-resolver) ─────────────────────────

/// [`DnsMatcher::reserve`]: una IP reservada nunca sale de `next_ipv4` (espejo de la reserva de
/// `ziti_dns_setup:194-201`), aunque quede DENTRO del rango del pool y sea, por orden de
/// contador, el primer candidato.
#[test]
fn reserve_blocks_the_pool_from_ever_allocating_that_ip() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29")); // capacidad 6, primer candidato = 10.0.0.1
    m.reserve("10.0.0.1".parse().unwrap());

    let RegisterOutcome::Hostname(ip) = m.register("svc.example.com", "i") else {
        panic!("debe asignar IP pese a la reserva")
    };
    assert_eq!(
        ip.to_string(),
        "10.0.0.2",
        "10.0.0.1 está reservada: el primer hostname registrado debe saltarla"
    );
}

/// Reservar la MISMA IP dos veces es un no-op (idempotente) — no hay refcount que desbordar ni
/// estado que corromper.
#[test]
fn reserve_is_idempotent() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29"));
    let ip = "10.0.0.1".parse().unwrap();
    m.reserve(ip);
    m.reserve(ip); // no debe entrar en pánico ni cambiar el estado
    assert_eq!(m.reverse_lookup(ip), Some(""));
}

/// Una IP reservada resuelve hacia atrás a `""` (byte-idéntico al `dns_entry_t` calloc'd/zeroed
/// del oráculo, ver el doc de [`DnsMatcher::reserve`]) — indistinguible de un hostname `""`
/// legítimamente registrado en OTRA IP, la MISMA ambigüedad que tiene el oráculo real. Reservar
/// NO toca `hostnames`: no hay una query DNS hacia delante que resuelva a una IP reservada.
#[test]
fn reserve_reverse_lookups_to_empty_string_like_the_oracles_zeroed_entry() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("10.0.0.0/29"));
    let reserved = "10.0.0.3".parse().unwrap();
    m.reserve(reserved);
    assert_eq!(m.reverse_lookup(reserved), Some(""));
    assert_eq!(
        m.lookup(""),
        None,
        "reservar una IP no registra un hostname \"\": ninguna query hacia delante casa"
    );
}
