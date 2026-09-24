//! b3: DIFFERENTIAL empírico del pool de IP contra el harness C (F6 tramo 15 troceo).

use std::collections::HashSet;
use std::net::Ipv4Addr;

use super::pool::IpPool;

// ───────────────────── DIFFERENTIAL ziti_dns.c (frontera de seguridad, pool de IP) ─────────────────────

/// DIFFERENTIAL empírico contra un puerto verbatim de `seed_dns`+`next_ipv4`
/// (`ziti-tunnel-sdk-c` @ `2addfbbae26be597f7a51359ea6ef069f54f6c43`, `ziti_dns.c:120-179`;
/// `model_map` sustituido por un array lineal, mismo patrón que la rebanada 1). Ground truth
/// generado ejecutando el harness C compilado (`clang -O2`) con el mismo protocolo por-línea.
/// Cubre: secuencia `/29` hasta agotamiento exacto (capacity=6, 7ª llamada `NONE`).
#[test]
fn ip_pool_exhaustion_boundary_equals_c_oracle_29() {
    let mut pool = IpPool::seed("10.0.0.0/29").expect("CIDR /29 válido");
    let mut occupied: HashSet<Ipv4Addr> = HashSet::new();
    let expected: &[&str] = &[
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6",
    ];
    for want in expected {
        let got = pool
            .allocate(occupied.len(), |ip| occupied.contains(&ip))
            .expect("debe asignar mientras haya capacidad");
        assert_eq!(got.to_string(), *want);
        occupied.insert(got);
    }
    assert_eq!(
        pool.allocate(occupied.len(), |ip| occupied.contains(&ip)),
        None,
        "7ª asignación en un /29 (capacidad 6): pool agotado, igual que el oráculo"
    );
}

/// Differential: collision-skip. Dos IPs pre-ocupadas (simulando reservas fuera del pool, p.ej.
/// la IP del utun/resolver DNS del oráculo, `ziti_dns_setup:194-201` — wiring diferido) deben
/// saltarse en el MISMO orden de escaneo que el oráculo.
#[test]
fn ip_pool_collision_skip_equals_c_oracle() {
    let mut pool = IpPool::seed("10.0.0.0/29").expect("CIDR /29 válido");
    let mut occupied: HashSet<Ipv4Addr> = HashSet::new();
    occupied.insert("10.0.0.2".parse().unwrap());
    occupied.insert("10.0.0.4".parse().unwrap());
    let expected: &[&str] = &["10.0.0.1", "10.0.0.3", "10.0.0.5", "10.0.0.6"];
    for want in expected {
        let got = pool
            .allocate(occupied.len(), |ip| occupied.contains(&ip))
            .expect("debe saltarse los ocupados y asignar uno libre");
        assert_eq!(got.to_string(), *want);
        occupied.insert(got);
    }
    assert_eq!(
        pool.allocate(occupied.len(), |ip| occupied.contains(&ip)),
        None,
        "con 2 pre-ocupadas + 4 asignadas, capacidad 6 alcanzada: agotado"
    );
}

/// Differential: secuencia completa `/28` (capacity=14), sin colisiones, hasta agotamiento.
#[test]
fn ip_pool_sequential_28_equals_c_oracle() {
    let mut pool = IpPool::seed("10.0.0.0/28").expect("CIDR /28 válido");
    let mut occupied: HashSet<Ipv4Addr> = HashSet::new();
    for i in 1..=14u8 {
        let got = pool
            .allocate(occupied.len(), |ip| occupied.contains(&ip))
            .unwrap_or_else(|| panic!("debe asignar el candidato #{i}"));
        assert_eq!(got, Ipv4Addr::new(10, 0, 0, i));
        occupied.insert(got);
    }
    assert_eq!(
        pool.allocate(occupied.len(), |ip| occupied.contains(&ip)),
        None,
        "15ª asignación en un /28 (capacidad 14): pool agotado"
    );
}

/// Divergencia consciente (NO reproducida a propósito, ver el doc del módulo): el oráculo
/// descarta un candidato GENUINAMENTE libre si lo encuentra exactamente en el intento
/// `capacity`-ésimo del escaneo (bug del oráculo — su propio chequeo post-bucle dispara por
/// conteo de intentos, no por si el bucle salió por agotamiento real). Con capacidad 6 (`/29`)
/// y `.1`-`.5` pre-ocupadas, `.6` es el único libre y se encuentra en el intento i=6=capacity:
/// el oráculo devolvería `INADDR_NONE` ahí (confirmado con el mismo harness C usado arriba);
/// [`IpPool::allocate`] devuelve `Some(.6)`.
#[test]
fn ip_pool_finds_a_hole_on_the_last_scan_try_where_the_oracle_would_discard_it() {
    let mut pool = IpPool::seed("10.0.0.0/29").expect("CIDR /29 válido");
    let occupied: HashSet<Ipv4Addr> = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(
        pool.allocate(occupied.len(), |ip| occupied.contains(&ip)),
        Some(Ipv4Addr::new(10, 0, 0, 6)),
        "10.0.0.6 es el único libre, encontrado en el intento i=6=capacity: el oráculo lo \
             descartaría (INADDR_NONE) por su chequeo post-bucle basado en conteo de intentos; no \
             reproducimos ese bug a propósito"
    );
}

/// `/0` y `/32` degenerados se rechazan fail-loud (ver el doc del módulo); `/31` (capacity=0) es
/// válido pero inmediatamente agotado, comportamiento REAL del oráculo, no un rechazo.
#[test]
fn ip_pool_seed_rejects_degenerate_prefixes_but_accepts_slash_31() {
    assert!(
        IpPool::seed("10.0.0.0/0").is_none(),
        "/0 degenerado: rechazar"
    );
    assert!(
        IpPool::seed("10.0.0.0/32").is_none(),
        "/32 degenerado: rechazar"
    );
    let mut slash_31 = IpPool::seed("10.0.0.0/31").expect("/31 es válido (capacidad 0)");
    assert_eq!(
        slash_31.allocate(0, |_| false),
        None,
        "/31 tiene capacidad 0: agotado desde la primera llamada, no un rechazo de seed"
    );
}
