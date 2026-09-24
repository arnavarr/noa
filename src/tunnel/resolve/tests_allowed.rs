use crate::edge::dial::build_app_data;

use super::target::resolve_target;
use super::testsupport::fwd_ip_cfg;

// ----- T4b-2a: dst_hostname string-matched path + matcher type-dispatch (the CRUX) -----
/// THE CRUX: a `dst_hostname` whose textual value is an IP literal ("1.2.3.4") is a STRING and is
/// string-matched; a `cidrAddress` (`1.2.3.4/32`) returns false for a string, so it does NOT match.
/// Faithful to the oracle's `addr.(net.IP)` type assertion (`service.go:177`). The dialer-observable
/// reject is the byte-exact not-in-allowed reason with the hostname value.
#[test]
fn dst_hostname_ip_literal_does_not_match_cidr_matcher() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["1.2.3.4/32".to_string()];
    // dst_hostname = "1.2.3.4" (a string), dst_ip also present but the hostname path wins + no fallback.
    let app = build_app_data("tcp", "1.2.3.4", "19009", Some("1.2.3.4"), None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "address '1.2.3.4' is not in allowed addresses");
}
/// The REVERSE crux: a `dst_ip` (a `net.IP`) never matches a `hostnameAddress` (string matcher). An
/// allow-list of only a hostname has no `cidrAddress`, so any `dst_ip` is not-allowed.
#[test]
fn dst_ip_does_not_match_hostname_matcher() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["example.com".to_string()];
    let app = build_app_data("tcp", "1.2.3.4", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "address '1.2.3.4' is not in allowed addresses");
}
/// A `dst_hostname` matches a `hostnameAddress` (exact). Returns the hostname as the dial address.
#[test]
fn dst_hostname_matches_hostname_allow_list_exact() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["example.com".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", Some("example.com"), None);
    let target = resolve_target(&cfg, Some(&app)).expect("dst_hostname matches hostnameAddress");
    assert_eq!(target.address, "example.com");
    assert_eq!(target.port, 19009);
}
/// `hostnameAddress` match is case-insensitive on BOTH sides (oracle lowercases the stored hostname
/// AND the incoming host, `service.go:189,214`).
#[test]
fn dst_hostname_match_is_case_insensitive() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["Example.COM".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", Some("eXaMple.com"), None);
    let target = resolve_target(&cfg, Some(&app)).expect("case-insensitive hostname match");
    assert_eq!(target.address, "eXaMple.com"); // the RAW dst_hostname is returned, unchanged.
}
/// `domainAddress` `*.example.com` matches a subdomain via the `domain[1:]` suffix `.example.com`.
#[test]
fn dst_hostname_matches_domain_wildcard_subdomain() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["*.example.com".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", Some("foo.example.com"), None);
    let target = resolve_target(&cfg, Some(&app)).expect("subdomain matches *.example.com");
    assert_eq!(target.address, "foo.example.com");
}
/// `domainAddress` `*.example.com` ALSO matches the apex `example.com` via `domain[2:]`
/// (oracle `service.go:199`: `host == self.domain[2:]`).
#[test]
fn dst_hostname_matches_domain_wildcard_apex() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["*.example.com".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", Some("example.com"), None);
    let target = resolve_target(&cfg, Some(&app)).expect("apex matches *.example.com");
    assert_eq!(target.address, "example.com");
}
/// `domainAddress` `*.example.com` does NOT match a non-suffix host (`evil.com`) nor a deceptive
/// `example.com.evil.com` (ends with `.evil.com`, not `.example.com`).
#[test]
fn dst_hostname_domain_wildcard_rejects_non_suffix() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["*.example.com".to_string()];
    for host in ["evil.com", "example.com.evil.com", "notexample.com"] {
        let app = build_app_data("tcp", "127.0.0.1", "19009", Some(host), None);
        assert_eq!(
            resolve_target(&cfg, Some(&app)).unwrap_err(),
            format!("address '{host}' is not in allowed addresses"),
            "{host} must not match *.example.com"
        );
    }
}
/// `domainAddress` `*` matches ANY string — including an IP literal as a `dst_hostname`.
#[test]
fn dst_hostname_star_domain_matches_any() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["*".to_string()];
    for host in ["anything.internal", "1.2.3.4", ""] {
        let app = serde_json::to_vec(&serde_json::json!({
            "dst_hostname": host, "dst_ip": "127.0.0.1", "dst_port": "19009",
        }))
        .unwrap();
        let target = resolve_target(&cfg, Some(&app)).expect("* matches any string");
        assert_eq!(target.address, host);
    }
}
/// PRECEDENCE: a present `dst_hostname` does NOT fall back to `dst_ip` on a no-match. Even with a
/// CIDR allow-list and a `dst_ip` that WOULD match, an unmatched present `dst_hostname` rejects
/// (oracle `GetAddress`: the `dst_ip` branch is the `else` of `dst_hostname` being absent,
/// `service.go:289-307`).
#[test]
fn present_dst_hostname_does_not_fall_back_to_dst_ip() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["10.0.0.0/8".to_string()]; // would match dst_ip 10.5.6.7
    let app = build_app_data("tcp", "10.5.6.7", "19009", Some("nope.example.com"), None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    // The hostname (not the dst_ip) is the address in the reject, and the dst_ip is NOT tried.
    assert_eq!(
        err,
        "address 'nope.example.com' is not in allowed addresses"
    );
}
/// A MIXED allow-list keeps BOTH a `cidrAddress` and a `domainAddress`: a `dst_ip` matches the CIDR,
/// a `dst_hostname` matches the domain — the type-dispatch selects per inbound value.
#[test]
fn mixed_allow_list_dispatches_ip_and_hostname_by_type() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["10.0.0.0/8".to_string(), "*.example.com".to_string()];
    // dst_ip path → matches the CIDR.
    let by_ip = build_app_data("tcp", "10.5.6.7", "19009", None, None);
    assert_eq!(
        resolve_target(&cfg, Some(&by_ip))
            .expect("ip in CIDR")
            .address,
        "10.5.6.7"
    );
    // dst_hostname path → matches the domain.
    let by_host = build_app_data("tcp", "127.0.0.1", "19009", Some("a.example.com"), None);
    assert_eq!(
        resolve_target(&cfg, Some(&by_host))
            .expect("host in domain")
            .address,
        "a.example.com"
    );
}
/// An invalid `*…` domain entry (`*foo`, no `.`) is dropped by `makeAllowedAddress` (oracle errors →
/// `log.Warn`-drops); the allow-list ends up empty, so any dst_hostname is not-allowed.
#[test]
fn invalid_star_domain_entry_is_dropped() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["*foo".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", Some("*foo"), None);
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address '*foo' is not in allowed addresses"
    );
}
/// FIDELITY (over-permit guard): an IPv6 zone-id allow-list entry (`fe80::1%eth0`) — which Go `netip`
/// ACCEPTS as a `cidrAddress` (IP-only, string-UNmatchable) but the `ipnet` crate rejects — is
/// DROPPED, not promoted to a string-matchable `Hostname`. A `dst_hostname="fe80::1%eth0"` must NOT
/// match (else it would be an over-permit vs the oracle, which returns not-allowed for the string).
#[test]
fn zone_id_entry_is_dropped_not_string_matchable() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["fe80::1%eth0".to_string()];
    let app = build_app_data("tcp", "fe80::1", "19009", Some("fe80::1%eth0"), None);
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address 'fe80::1%eth0' is not in allowed addresses"
    );
}
/// RE-REVIEW FIX (REQUIRED, security over-permit): a v4-mapped IPv6 CIDR with a leading-zero in the
/// FIRST embedded octet (`::ffff:010.0.0.1/120`) must NOT become a `Cidr` and must NOT IP-match a
/// `dst_ip`. Go `netip` (oracle `GetCidr`) REJECTS the leading-zero embedded octet → the oracle
/// builds a `hostnameAddress` that denies any `net.IP`. The pre-fix dot-split guard MISSED it (the
/// `010` was glued to `::ffff:`, whose first split element starts with `:`), so `IpNet::from_str`
/// normalized `010`→`10` → `Cidr` → ALLOWED a dst_ip the oracle denies. The strict-address parse
/// (`IpAddr::from_str`) now rejects it. Mutation-killer (was ALLOW, now DENY).
#[test]
fn v4mapped_leading_zero_cidr_does_not_match_ip() {
    for (entry, dst) in [
        ("::ffff:010.0.0.1/120", "::ffff:10.0.0.50"),
        ("::00.0.0.1/120", "::0.0.0.50"),
        ("64:ff9b::010.0.0.1/96", "64:ff9b::10.0.0.50"),
    ] {
        let mut cfg = fwd_ip_cfg();
        cfg.allowed_addresses = vec![entry.to_string()];
        let app = build_app_data("tcp", dst, "19009", None, None);
        assert_eq!(
            resolve_target(&cfg, Some(&app)).unwrap_err(),
            format!("address '{dst}' is not in allowed addresses"),
            "{entry} must NOT IP-match {dst} (oracle netip rejects -> hostnameAddress)"
        );
    }
}
/// The faithful PROMOTE side of the above: a leading-zero v4-mapped CIDR entry is a `hostnameAddress`
/// in the oracle, so a `dst_hostname` whose value equals it MATCHES (exact string). Mirrors
/// `leading_zero_cidr_string_matches_as_hostname` for the v4-mapped form.
#[test]
fn v4mapped_leading_zero_cidr_string_matches_as_hostname() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["::ffff:010.0.0.1/120".to_string()];
    let app = build_app_data(
        "tcp",
        "127.0.0.1",
        "19009",
        Some("::ffff:010.0.0.1/120"),
        None,
    );
    let target = resolve_target(&cfg, Some(&app))
        .expect("leading-zero v4-mapped entry is a hostnameAddress, string-matchable");
    assert_eq!(target.address, "::ffff:010.0.0.1/120");
}
/// FIX 2 (v4-mapped NETWORK unmapping, mirrors Go `net.IPNet.Contains`'s `To4()`): an EXPANDED
/// v4-mapped IPv6 with no leading-zero octet (`0:0:0:0:0:ffff:1.2.3.4`) is a `cidrAddress`, NOT a
/// `Hostname`. Go normalizes it to a PURE V4 network → a v4 `dst_ip` matches, a `dst_hostname`
/// (string) does NOT. `parse_ip_or_cidr` now unmaps it to V4 `1.2.3.4/32`, so a v4 `dst_ip`
/// `1.2.3.4` matches (faithful), while a genuine-v6 `dst_ip` cannot (cross-family). The v4-mapped
/// DESTINATION LITERAL `::ffff:1.2.3.4` is the documented datapath-unreachable residual: Go would
/// To4-normalize it and match, we keep it v6 → no match (a safe under-permit, see
/// `v4mapped_destination_literal_residual_class`). Mutation-killer for the unmap (was a v6 net).
#[test]
fn expanded_v4mapped_is_cidr_not_hostname() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["0:0:0:0:0:ffff:1.2.3.4".to_string()];
    // A v4 dst_ip matches the unmapped V4 host-route Cidr (oracle: cidrAddress matches v4 via To4).
    let by_ip = build_app_data("tcp", "1.2.3.4", "19009", None, None);
    assert_eq!(
        resolve_target(&cfg, Some(&by_ip))
            .expect("v4 dst_ip matches the unmapped v4-mapped cidrAddress")
            .address,
        "1.2.3.4"
    );
    // dst_hostname does NOT match a Cidr (oracle cidrAddress.Allows(string) == false).
    let by_host = build_app_data(
        "tcp",
        "127.0.0.1",
        "19009",
        Some("0:0:0:0:0:ffff:1.2.3.4"),
        None,
    );
    assert_eq!(
        resolve_target(&cfg, Some(&by_host)).unwrap_err(),
        "address '0:0:0:0:0:ffff:1.2.3.4' is not in allowed addresses"
    );
}
/// REGRESSION GUARD for the `IpNet::from_str` → `IpNet::new` switch: a CIDR with host bits SET
/// (`10.5.6.7/8`) must still match any `dst_ip` in the masked network (the oracle keeps the address
/// verbatim and masks at `Contains` time). Pins that `IpNet::new` keeps host bits like the old
/// `IpNet::from_str` and the oracle.
#[test]
fn cidr_with_host_bits_set_matches_masked_network() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["10.5.6.7/8".to_string()];
    let app = build_app_data("tcp", "10.1.2.3", "19009", None, None);
    assert_eq!(
        resolve_target(&cfg, Some(&app))
            .expect("10.1.2.3 is in 10.0.0.0/8")
            .address,
        "10.1.2.3"
    );
}
/// RE-REVIEW FIX (over-permit, NEW in T4b-2a's string matching): case-folding must be RUNE-WISE
/// (Go `strings.ToLower`), NOT Rust's context-sensitive `str::to_lowercase`. With `str::to_lowercase`
/// a stored `"ΟΔΟΣ"` lowercases to `"οδος"` (word-final sigma) and would MATCH a `dst_hostname`
/// `"οδος"` the oracle (`"οδοσ" != "οδος"`) denies. `fold_lower` stores `"οδοσ"`, so it correctly
/// DENIES. Mutation-killer (was ALLOW with `to_lowercase`, now DENY).
#[test]
fn unicode_final_sigma_does_not_over_permit() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["ΟΔΟΣ".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", Some("οδος"), None);
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address 'οδος' is not in allowed addresses"
    );
}
/// The `(Domain, Ip) => false` arm (lens test-hardening): a `*` domain admits only a STRING value
/// (`dst_hostname`); a `dst_ip` with NO `dst_hostname` is REJECTED (oracle
/// `domainAddress.Allows(net.IP)` fails the `addr.(string)` assertion → false). Kills a
/// `(Domain, Ip) => true` mutant the prior tests left alive (`*`-tests always sent a dst_hostname;
/// the mixed-list test put the CIDR first so `.any()` short-circuited).
#[test]
fn star_domain_does_not_match_dst_ip() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["*".to_string()];
    let app = build_app_data("tcp", "1.2.3.4", "19009", None, None);
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address '1.2.3.4' is not in allowed addresses"
    );
}
/// FIX #1: a PURE hostname allow-list (no CIDR) is NOT a hard reject anymore. The oracle's
/// `GetAllowedAddresses` keeps `example.com` as a `hostnameAddress` string matcher that returns
/// false for a `net.IP` (it never matches a `dst_ip`), so the IP falls through to the byte-exact
/// "not in allowed addresses" reason — still fail-loud, but the not-in-allowed reason, NOT a
/// deferred-capability reject (which over-rejected mixed lists). Oracle: `service.go:234-249`
/// (`GetAllowedAddresses` append-on-ok) + `:187-190` (`hostnameAddress.Allows`) + `:308`.
#[test]
fn pure_hostname_allow_list_rejects_ip_as_not_allowed() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["example.com".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "address '127.0.0.1' is not in allowed addresses");
}
/// FIX #1: same as above for a PURE `*.`-wildcard allow-list (a `domainAddress` string matcher,
/// false for a `net.IP`). Reject is the not-in-allowed reason, not a deferred-capability reject.
#[test]
fn pure_wildcard_allow_list_rejects_ip_as_not_allowed() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["*.example.com".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "address '127.0.0.1' is not in allowed addresses");
}
/// FIX #1 (a): a MIXED allow-list `["10.0.0.0/8","*.example.com"]` resolves a `dst_ip` that lands in
/// the CIDR — the wildcard entry is a string matcher that never matches a `net.IP`, so it is dropped
/// for IP matching (NOT a fatal reject of the whole list). The over-rejection bug fixed: the first
/// cut aborted the entire resolution at the non-IP entry BEFORE ever testing the CIDR. Oracle:
/// `GetAddress` accepts when ANY matcher `.Allows(ip)` (`service.go:302-306`).
#[test]
fn mixed_allow_list_accepts_ip_in_surviving_cidr() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["10.0.0.0/8".to_string(), "*.example.com".to_string()];
    // dst_port inside fwd_ip_cfg's 19000..=19100 range so the test exercises the ADDRESS path.
    let app = build_app_data("tcp", "10.5.6.7", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("10.5.6.7 is in the surviving 10.0.0.0/8");
    assert_eq!(target.address, "10.5.6.7");
}
/// FIX #1 (b): a MIXED allow-list still rejects (byte-exact not-in-allowed) a `dst_ip` outside every
/// surviving CIDR — the dropped non-IP entries cannot rescue it.
#[test]
fn mixed_allow_list_rejects_ip_outside_all_cidrs() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["10.0.0.0/8".to_string(), "*.example.com".to_string()];
    let app = build_app_data("tcp", "192.168.1.1", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "address '192.168.1.1' is not in allowed addresses");
}
// ----- CIDR matching (cidrAddress) + bare-IP host routes (GetCidr) -----
#[test]
fn cidr_network_allows_contained_ip() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["10.0.0.0/8".to_string()];
    let app = build_app_data("tcp", "10.5.6.7", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("10.5.6.7 is in 10.0.0.0/8");
    assert_eq!(target.address, "10.5.6.7");
}
#[test]
fn bare_ip_allow_entry_is_a_host_route() {
    // A bare IP "127.0.0.1" (no /prefix) is a /32 host route (oracle GetCidr) — only that exact IP.
    let cfg = fwd_ip_cfg(); // allowed_addresses = ["127.0.0.1/32"] but test bare form too
    let mut bare = cfg.clone();
    bare.allowed_addresses = vec!["127.0.0.1".to_string()];
    let ok = build_app_data("tcp", "127.0.0.1", "19009", None, None);
    assert!(resolve_target(&bare, Some(&ok)).is_ok());
    let no = build_app_data("tcp", "127.0.0.2", "19009", None, None);
    assert_eq!(
        resolve_target(&bare, Some(&no)).unwrap_err(),
        "address '127.0.0.2' is not in allowed addresses"
    );
}
#[test]
fn ipv6_cidr_matches() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["fd00::/8".to_string()];
    let app = build_app_data("tcp", "fd00::1", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("fd00::1 is in fd00::/8");
    assert_eq!(target.address, "fd00::1");
}
/// A leading-zero PREFIX-LENGTH token is "bad bits" to Go `netip`, so the oracle's `GetCidr` REJECTS
/// it → `makeAllowedAddress` builds a `hostnameAddress` (NOT a `cidrAddress`), which never matches a
/// `net.IP`. `ipnet` would accept `/00` as `/0` (allow-ALL) and `/08` as `/8` — an over-permit on the
/// destination allow-list — so [`parse_ip_or_cidr`] guards it OUT of `Cidr`; it falls through to
/// `Hostname`, so a `dst_ip` is not-in-allowed (the IP path is unchanged by the T4b-2a promote).
/// Oracle: `tunnel/utils/ipcalc.go:25-32` (`netip.ParsePrefix` rejects leading-zero bits).
#[test]
fn leading_zero_prefix_length_cidr_does_not_match_ip() {
    // `/00` must NOT become an allow-all `/0`.
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["1.2.3.4/00".to_string()];
    let app = build_app_data("tcp", "203.0.113.9", "19009", None, None);
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address '203.0.113.9' is not in allowed addresses"
    );
    // `/08` must NOT become `/8`.
    cfg.allowed_addresses = vec!["10.0.0.0/08".to_string()];
    let app = build_app_data("tcp", "10.5.6.7", "19009", None, None);
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address '10.5.6.7' is not in allowed addresses"
    );
}
/// A leading-zero IPv4 OCTET (`010.0.0.0`) is rejected by Go `netip` (`netip.ParseAddr`/`ParsePrefix`),
/// so the oracle builds a `hostnameAddress`, not a `cidrAddress`. `ipnet` would accept `010.0.0.0/8`
/// as `10.0.0.0/8` — an over-permit — so we guard it out of `Cidr`; it becomes a `Hostname` that
/// never matches a `net.IP` → `dst_ip` not-in-allowed.
#[test]
fn leading_zero_octet_cidr_does_not_match_ip() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["010.0.0.0/8".to_string()];
    let app = build_app_data("tcp", "10.5.6.7", "19009", None, None);
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address '10.5.6.7' is not in allowed addresses"
    );
}
/// FIDELITY (the faithful PROMOTE, asserted not just incidentally true): a leading-zero CIDR-looking
/// entry (`010.0.0.0/8`) — which Go `netip` REJECTS so the oracle builds a `hostnameAddress` — is a
/// string matcher. A `dst_hostname` whose value equals it (`"010.0.0.0/8"`) MATCHES (exact, the
/// oracle's `hostnameAddress.Allows`). Pins that the entry is promoted to `Hostname`, not dropped.
#[test]
fn leading_zero_cidr_string_matches_as_hostname() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["010.0.0.0/8".to_string()];
    let app = build_app_data("tcp", "127.0.0.1", "19009", Some("010.0.0.0/8"), None);
    let target = resolve_target(&cfg, Some(&app)).expect("leading-zero entry is a hostnameAddress");
    assert_eq!(target.address, "010.0.0.0/8");
}
/// PRESERVATION: a legitimate SINGLE-zero octet (`0.0.0.0`) and prefix (`/0`) are valid to `netip`,
/// so the leading-zero guard must NOT over-reject them. `0.0.0.0/0` is allow-all and admits any IP.
#[test]
fn legitimate_single_zero_cidr_is_kept() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_addresses = vec!["0.0.0.0/0".to_string()];
    let app = build_app_data("tcp", "203.0.113.9", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("0.0.0.0/0 admits any IP");
    assert_eq!(target.address, "203.0.113.9");
}
/// Precedence: an address/port error WINS over a present `source_addr`, mirroring the oracle's `Dial`
/// order `GetAddress`→`GetPort`→`dialAddress` (source-bind read last, `hosting.go:388-409`). A
/// not-allowed `dst_ip` surfaces the not-in-allowed reason even when a `source_addr` is present — and
/// even when that source_addr is ITSELF malformed (the address error is reached first, so the source
/// is never parsed).
#[test]
fn address_error_wins_over_present_source_addr() {
    let cfg = fwd_ip_cfg();
    let app = build_app_data("tcp", "10.0.0.5", "19009", None, Some("192.168.1.5:0"));
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "address '10.0.0.5' is not in allowed addresses"
    );
    // Even a malformed source_addr does not win over the address error.
    let bad = build_app_data("tcp", "10.0.0.5", "19009", None, Some("1.2.3.4:notaport"));
    assert_eq!(
        resolve_target(&cfg, Some(&bad)).unwrap_err(),
        "address '10.0.0.5' is not in allowed addresses"
    );
}
#[test]
fn unparseable_dst_ip_is_not_allowed() {
    // A non-IP dst_ip: oracle net.ParseIP → nil → no CIDR contains → "not in allowed addresses".
    let cfg = fwd_ip_cfg();
    let app = build_app_data("tcp", "not-an-ip", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "address 'not-an-ip' is not in allowed addresses");
}
