//! b1 (DIFFERENTIAL matcher) fusionado con b2 (coda: register overflow) — contiguos en el
//! monolito, ambos sobre el matcher y el límite de overflow, pre-IP (F6 tramo 15 troceo).

use super::testsupport::*;
use super::*;

// ───────────────────── DIFFERENTIAL ziti_dns.c (frontera de seguridad, matcher) ─────────────────────

/// DIFFERENTIAL empírico contra el oráculo C: `check_name`+`find_domain`+la decisión de match
/// de `ziti_dns_lookup` (`ziti-tunnel-sdk-c` @ `2addfbbae26be597f7a51359ea6ef069f54f6c43`,
/// `lib/ziti-tunnel-cbs/ziti_dns.c:310-334,370-378,380-411`). Heredado byte-a-byte de la
/// rebanada 1 (el ground truth del match no cambia: esta rebanada solo añade la IP asignada
/// encima del mismo veredicto kind/no-match).
#[test]
fn matcher_lookup_equals_ziti_dns_c_oracle() {
    let cases: &[(&[&str], &str, Option<DnsMatchKind>)] = &[
        (
            &["Exact.Example.COM"],
            "exact.example.com",
            Some(DnsMatchKind::Hostname),
        ),
        (
            &["Exact.Example.COM"],
            "EXACT.EXAMPLE.COM",
            Some(DnsMatchKind::Hostname),
        ),
        (&["Exact.Example.COM"], "other.example.com", None),
        (&["Exact.Example.COM"], "exact.example.com.evil.com", None),
        (
            &["*.example.com"],
            "example.com",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.example.com"],
            "www.example.com",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.example.com"],
            "a.b.example.com",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.example.com"],
            "w.x.y.z.example.com",
            Some(DnsMatchKind::Domain),
        ),
        (&["*.example.com"], "notexample.com", None),
        (&["*.example.com"], "example.com.evil.com", None),
        (
            &["*.example.com"],
            "EXAMPLE.COM",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.example.com"],
            "WWW.EXAMPLE.COM",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.com", "*.example.com"],
            "foo.example.com",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.com", "*.example.com"],
            "foo.bar.com",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.com", "*.example.com"],
            "com",
            Some(DnsMatchKind::Domain),
        ),
        (
            &["*.com", "*.example.com"],
            "example.com",
            Some(DnsMatchKind::Domain),
        ),
        (&["*.com", "*.example.com"], "org", None),
        (
            &["*foo.com", "*.reject-test.com"],
            "*foo.com",
            Some(DnsMatchKind::Hostname),
        ),
        (&["*foo.com", "*.reject-test.com"], "foo.com", None),
        (&["*foo.com", "*.reject-test.com"], "*.foo.com", None),
        (
            &["*foo.com", "*.reject-test.com"],
            "*.reject-test.com",
            None,
        ),
        (&[""], "", Some(DnsMatchKind::Hostname)),
        (&[], "", None),
    ];
    for (registrations, query, expected) in cases {
        assert_eq!(
            kind_of(registrations, query),
            *expected,
            "lookup('{query}') con registros {registrations:?} debe coincidir con ziti_dns.c (esperado {expected:?})"
        );
    }
}

/// Límite de desbordamiento (`MAX_DNS_NAME=256`) en AMBOS lados (hostname y dominio), en la
/// QUERY: bien definido en el oráculo real, SÍ es target de differential.
#[test]
fn matcher_overflow_boundary_equals_c_oracle() {
    let host_255 = "a".repeat(255);
    let host_256 = "a".repeat(256);
    let mut m = matcher_of(&[&host_255]);
    assert_eq!(
        m.lookup(&host_255).map(|r| r.kind),
        Some(DnsMatchKind::Hostname),
        "255 bytes: exactamente en el límite, debe registrar y casar"
    );
    assert_eq!(
        m.lookup(&host_256).map(|r| r.kind),
        None,
        "256 bytes: la query desborda -> no-match, aunque el hostname de 256 nunca se registró"
    );

    let domain_253 = "a".repeat(253);
    let wildcard_255 = format!("*.{domain_253}");
    let mut m = matcher_of(&[&wildcard_255]);
    assert_eq!(
        m.lookup(&domain_253).map(|r| r.kind),
        Some(DnsMatchKind::Domain),
        "dominio desnudo de un wildcard de 255 bytes totales: debe casar (quirk desnudo)"
    );
    assert_eq!(
        m.lookup(&format!("x.{domain_253}")).map(|r| r.kind),
        Some(DnsMatchKind::Domain),
        "un nivel bajo ese mismo dominio: debe casar"
    );

    let domain_254 = "a".repeat(254);
    let wildcard_256 = format!("*.{domain_254}");
    let mut m2 = DnsMatcher::new();
    assert!(
        matches!(m2.register(&wildcard_256, "i"), RegisterOutcome::Rejected),
        "\"*.\"+254 bytes = 256 total: el registro debe rechazarse (desborda)"
    );
    assert_eq!(m2.lookup(&domain_254), None, "nunca se registró: no-match");
    assert_eq!(m2.lookup(&format!("x.{domain_254}")), None);
}

// ───────────────────── desviación DELIBERADA (no differential: 2 sub-caminos, ver doc) ─────────────────────

/// El REGISTRO de un nombre que desborda (≥256 bytes) se bifurca en DOS sub-caminos del oráculo
/// real con determinismo DISTINTO (ver el doc del módulo).
#[test]
fn register_overflow_is_a_safe_deliberate_divergence() {
    let mut m = DnsMatcher::new();
    let overlong = "a".repeat(256);
    assert!(
        matches!(m.register(&overlong, "i"), RegisterOutcome::Rejected),
        "256 bytes: debe rechazarse limpio"
    );
    assert_eq!(
        m.lookup(&"a".repeat(255)),
        None,
        "nada quedó registrado tras el rechazo"
    );

    let overlong_domain = format!("*.{}", "b".repeat(300));
    assert!(
        matches!(m.register(&overlong_domain, "i"), RegisterOutcome::Rejected),
        "dominio overlong: rechazo limpio, evita la UB genuina del oráculo"
    );
}
