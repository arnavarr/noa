// F6 tramo 2b troceo: tests movidos verbatim del monolito de `intercept/resolve` (mod tests).

use crate::tunnel::resolve::parse_ip_or_cidr;

use super::Protocol;
use super::testsupport::*;

// ───────────────────────── DIFFERENTIAL Go GetCidr+Contains (frontera de seguridad) ─────────────────────────

/// DIFFERENTIAL empírico contra el oráculo Go: `utils.GetCidr(addr)` + `net.IPNet.Contains(ip)`
/// (lo que el interceptor hace en `GetInterceptAddresses`/`InterceptAddress.Contains`). El ground
/// truth se generó ejecutando un port verbatim de `GetCidr`+`Contains` en Go (go 1.x, ver el
/// resultado de la rebanada). Para CADA `(addr, probe_ip)` se comprueba que nuestro
/// `parse_ip_or_cidr(addr)` + `IpNet::contains(probe)` coincide con Go.
///
/// Cubre la CLASE de over-permits cazada 3× en T4b: leading-zero (`010.0.0.0/8`, `/08`), v4-mapped
/// con leading-zero (`::ffff:010.0.0.1/120`), prefijo leading-zero (`/00`) — Go los RECHAZA en
/// GetCidr (→ hostname/DNS, sin entrada IP), y nosotros también (`parse_ip_or_cidr` → `None`), así
/// que un `dst_ip` NO casa por esas entradas → CERO over-permit. Más fronteras de CIDR
/// (network/broadcast/justo-fuera) y cross-family.
#[test]
fn matcher_parse_set_equals_go_getcidr() {
    // (addr, parsea_a_cidr?) — `false` = Go GetCidr falla (→ DNS, sin entrada IP); debemos coincidir.
    // La clase over-permit (leading-zero `010.0.0.0/8`/`/08`, v4-mapped `::ffff:010.0.0.1/120`,
    // prefijo `/00`) la RECHAZA Go en GetCidr (→ hostname/DNS, sin entrada IP), y nosotros también
    // (`parse_ip_or_cidr` → `None`), así que un `dst_ip` NO casa por esas entradas → CERO over-permit.
    let parse_cases: &[(&str, bool)] = &[
        ("10.0.0.0/8", true),
        ("192.168.1.0/24", true),
        ("1.2.3.4", true),
        ("1.2.3.4/32", true),
        ("0.0.0.0/0", true),
        ("100.64.0.0/10", true),
        ("::1", true),
        ("fd00::/8", true),
        ("2001:db8::/32", true),
        ("10.0.0.0/24", true),
        // clase over-permit: Go GetCidr FALLA → debemos devolver None (sin entrada → sin match IP).
        ("010.0.0.0/8", false),
        ("10.0.0.0/08", false),
        ("::ffff:010.0.0.1/120", false),
        ("1.2.3.4/00", false),
        ("1.2.3.4/33", false),
        ("1.2.3.256", false),
        ("", false),
        // FIX 1 (leading-SIGN prefix, the 4th over-permit instance): `netip.ParsePrefix` rejects a
        // multi-char bits token whose first byte is not '1'..'9' ("strconv.Atoi accepts a leading
        // sign and leading zeroes, but we don't want that", netip.go:1385). Go GetCidr FALLA → None.
        // (Empirically confirmed: pre-fix Rust parsed `10.0.0.0/+8` as a whole `/8` → over-permit.)
        ("10.0.0.0/+8", false),
        ("10.0.0.0/+0", false),
        ("10.0.0.0/+08", false),
        ("1.2.3.4/+32", false),
        ("fd00::/+8", false),
        ("10.0.0.0/-8", false),
        // FIX 1 sanity: a leading '1'..'9' multi-char prefix STILL parses (the guard must not
        // over-reject); a single-char `/0`/`/8` STILL parses.
        ("10.0.0.0/24", true),
        ("fd00::/128", true),
    ];
    for (addr, go_parses) in parse_cases {
        assert_eq!(
            parse_ip_or_cidr(addr).is_some(),
            *go_parses,
            "parse de '{addr}' debe coincidir con GetCidr (Go parses={go_parses})"
        );
    }
}

/// El masking de `IpNet::contains` debe coincidir con `net.IPNet.Contains` (enmascara AMBOS
/// operandos). Ground truth del run Go. Incluye CIDRs NON-ALIGNED (host bits ≠ 0), fronteras
/// (network/broadcast/justo-fuera) y cross-family.
#[test]
fn matcher_contains_masking_equals_go() {
    // (addr, [(probe_ip, go_contains)]) — solo para los addr que parsean; `IpNet::contains` debe
    // coincidir con `net.IPNet.Contains` (el masking). Ground truth del run Go.
    let contains_cases: &[(&str, &[(&str, bool)])] = &[
        (
            "10.0.0.0/8",
            &[
                ("10.0.0.1", true),
                ("10.255.255.255", true),
                ("10.0.0.255", true),
                ("11.0.0.1", false),
                ("9.255.255.255", false),
            ],
        ),
        (
            "10.0.0.0/24",
            &[
                ("10.0.0.0", true),
                ("10.0.0.1", true),
                ("10.0.0.255", true),
                ("10.0.1.0", false),
            ],
        ),
        (
            "192.168.1.0/24",
            &[("192.168.1.1", true), ("192.168.2.1", false)],
        ),
        // NON-ALIGNED host bits (operador escribe un CIDR "sucio"): prueba que `IpNet::contains`
        // ENMASCARA `self` igual que `net.IPNet.Contains` (que enmascara AMBOS operandos). El
        // ground truth Go: `10.0.0.5/24` casa todo `10.0.0.x` (host bits del .5 enmascarados).
        (
            "10.0.0.5/24",
            &[
                ("10.0.0.99", true),
                ("10.0.0.0", true),
                ("10.0.0.255", true),
                ("10.0.1.0", false),
                ("11.0.0.5", false),
            ],
        ),
        (
            "fd00::5/8",
            &[("fd00::99", true), ("fd00::", true), ("fe00::1", false)],
        ),
        (
            "1.2.3.4/32",
            &[("1.2.3.4", true), ("1.2.3.5", false), ("1.2.3.3", false)],
        ),
        (
            "0.0.0.0/0",
            // /0 v4 contiene todo v4, NADA v6 (cross-family).
            &[
                ("0.0.0.0", true),
                ("255.255.255.255", true),
                ("8.8.8.8", true),
                ("::1", false),
                ("fd00::1", false),
            ],
        ),
        (
            "100.64.0.0/10",
            &[
                ("100.64.0.7", true),
                ("100.127.255.255", true),
                ("100.128.0.0", false),
                ("100.63.255.255", false),
            ],
        ),
        (
            "fd00::/8",
            &[
                ("fd00::1", true),
                ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
                ("fe00::1", false),
                ("10.0.0.1", false),
            ],
        ),
        (
            "2001:db8::/32",
            &[("2001:db8::1", true), ("2001:db9::1", false)],
        ),
    ];
    for (addr, probes) in contains_cases {
        let net = parse_ip_or_cidr(addr).expect("debe parsear");
        for (probe, expected) in *probes {
            assert_eq!(
                net.contains(&ip(probe)),
                *expected,
                "contains('{addr}', '{probe}') debe coincidir con net.IPNet.Contains (Go={expected})"
            );
        }
    }
}

/// FIX 2 (v4-mapped NETWORK unmapping, mirror Go `net.IPNet.Contains`'s `To4()`): a v4-mapped
/// `::ffff:a.b.c.d/n` config network is a PURE V4 network — it matches v4 destinations under the
/// low-32-bits mask (`max(0,n-96)`) and NEVER a genuine v6 destination. Differential-pinned ground
/// truth from `GetCidr`+`net.IPNet.Contains` (go1.26.3). MUTATION-KILLER for the unmap: reverting it
/// (keeping the v6 net) makes `::ffff:1.2.3.4/64` ALLOW `::1` (was the empirically-confirmed
/// over-permit) and makes the v4-match cases DENY (cross-family) → either direction reds.
#[test]
fn v4mapped_network_unmaps_to_v4_like_go() {
    // (addr, [(probe, go_allows)]) — `IpNet::contains` must equal `net.IPNet.Contains` post-unmap.
    let cases: &[(&str, &[(&str, bool)])] = &[
        (
            "::ffff:1.2.3.4/120", // -> V4 1.2.3.4/24
            &[
                ("1.2.3.4", true),
                ("1.2.3.99", true),
                ("1.2.4.1", false),
                ("2001:db8::1", false), // genuine v6: cross-family DENY (Go length-check)
            ],
        ),
        (
            "::ffff:1.2.3.4/128", // -> V4 1.2.3.4/32
            &[("1.2.3.4", true), ("1.2.3.5", false)],
        ),
        (
            "::ffff:1.2.3.4/96", // -> V4 1.2.3.4/0 (matches all v4, no v6)
            &[("8.8.8.8", true), ("1.2.3.4", true), ("2001:db8::1", false)],
        ),
        (
            "::ffff:1.2.3.4/64", // -> V4 1.2.3.4/0: genuine v6 `::1` DENIED (the closed over-permit)
            &[("::1", false), ("2001:db8::1", false), ("1.2.3.4", true)],
        ),
        (
            "::ffff:10.20.30.40", // bare -> V4 10.20.30.40/32
            &[("10.20.30.40", true), ("10.20.30.41", false)],
        ),
    ];
    for (addr, probes) in cases {
        let net = parse_ip_or_cidr(addr).expect("v4-mapped network parses (unmapped to V4)");
        for (probe, expected) in *probes {
            assert_eq!(
                net.contains(&ip(probe)),
                *expected,
                "contains('{addr}'->V4, '{probe}') debe coincidir con net.IPNet.Contains (Go={expected})"
            );
        }
    }
}

/// CONSCIOUS, SAFE-direction divergences from Go, pinned EXPLICITLY (no silent hole). Two distinct
/// classes — note the v4-mapped-DESTINATION-literal class is BIDIRECTIONAL (NOT under-permit-only,
/// as a prior version of this test wrongly claimed): Go's `Contains` `To4()`-normalizes the PROBE,
/// we parse the dst_ip with `IpAddr::from_str` (kept v6), so a v4-mapped LITERAL dst diverges. It is
/// PRE-EXISTING (not introduced by FIX 1/FIX 2 — those fix the network parse). REACHABILITY:
/// datapath-unreachable for the intercept resolver (its caller feeds `dst.ip()` from netstack —
/// canonical V4/V6, never `::ffff:` literals; verified via `InterceptStack::accept`); on the shared
/// host-side path it requires a NON-conformant dialer (a conformant dialer emits a canonical
/// `dst_ip`) plus an unusual v6-net config. DEFERRED: the only Go-faithful close is to To4-normalize
/// the probe, which is PURE widening — it closes NO over-permit on the canonical datapath (every
/// residual over-permit needs a non-canonical v4-mapped probe), so deferring keeps the change tight.
/// (NOT the same as FIX 2's network unmap, whose v4-widening is inseparable from closing a genuine
/// over-permit and so was not deferrable.)
#[test]
fn v4mapped_destination_literal_residual_class() {
    // (A) zone-id IPv6: Go GetCidr ACCEPTS `fe80::1%eth0` (/128); we reject `%` → DNS (M3).
    // UNDER-permit (network side, safe): we do not intercept fe80::1 where Go would.
    assert!(
        parse_ip_or_cidr("fe80::1%eth0").is_none(),
        "zone-id rejected (Go would accept as /128) — safe UNDER-permit"
    );
    // (B) UNDER-permit direction: a v4-mapped DESTINATION literal `::ffff:1.2.3.4` against a v4 net
    // `1.2.3.4/32`. Go To4-normalizes the probe → matches; we keep it v6 → cross-family → no match.
    let r_v4 = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["1.2.3.4/32"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    assert!(
        r_v4.lookup(ip("::ffff:1.2.3.4"), 80, Protocol::Tcp, ANY_SRC)
            .is_none(),
        "v4-mapped dst LITERAL vs v4 net: Go matches (To4), we don't — UNDER-permit (datapath-unreachable)"
    );
    // (C) OVER-permit direction (the residual the BLOCK-class hunts): a v4-mapped DESTINATION literal
    // `::ffff:1.2.3.4` against a genuine-v6 net `::/0`. Go's `Contains` length-check (post probe-To4)
    // DENIES; we keep the probe v6 → `::/0` matches → Some. PINNED HONESTLY as the documented,
    // pre-existing, datapath-unreachable residual (netstack never yields a v4-mapped dst literal).
    let r_v6 = one_svc_resolver(
        r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["::/0"],"portRanges":[{"low":80,"high":80}]}}"#,
    );
    assert!(
        r_v6.lookup(ip("::ffff:1.2.3.4"), 80, Protocol::Tcp, ANY_SRC)
            .is_some(),
        "v4-mapped dst LITERAL vs ::/0: Go denies (length-check), we match — OVER-permit (datapath-unreachable, deferred)"
    );
}
