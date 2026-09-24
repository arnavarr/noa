use crate::edge::dial::build_app_data;
use crate::edge::model::{HostV1Config, PortRange};

use super::target::{ResolvedTarget, parse_source_bind, resolve_target};
use super::testsupport::fwd_ip_cfg;

#[test]
fn resolves_forward_address_ip_path() {
    let cfg = fwd_ip_cfg();
    let app = build_app_data("tcp", "127.0.0.1", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("resolves");
    assert_eq!(
        target,
        ResolvedTarget {
            protocol: "tcp".to_string(),
            address: "127.0.0.1".to_string(),
            port: 19009,
            source_bind: None,
        }
    );
    assert_eq!(target.socket_addr(), "127.0.0.1:19009");
}
#[test]
fn ip_outside_allowed_addresses_is_rejected_byte_exact() {
    let cfg = fwd_ip_cfg();
    let app = build_app_data("tcp", "10.0.0.5", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    // Byte-exact to GetAddress's `"address '%s' is not in allowed addresses"` (service.go:308).
    assert_eq!(err, "address '10.0.0.5' is not in allowed addresses");
}
#[test]
fn port_outside_allowed_ranges_is_rejected_byte_exact() {
    let cfg = fwd_ip_cfg();
    let app = build_app_data("tcp", "127.0.0.1", "25000", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    // Byte-exact to GetPort's `"port %d is not in allowed port ranges"` (service.go:329).
    assert_eq!(err, "port 25000 is not in allowed port ranges");
}
#[test]
fn non_numeric_port_is_rejected_with_truncated_wrapf_prefix() {
    let cfg = fwd_ip_cfg();
    // Hand-build appData with a non-numeric dst_port (build_app_data takes a string already).
    let app = build_app_data("tcp", "127.0.0.1", "notaport", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    // CONSCIOUS TRUNCATION (not byte-exact): the oracle's `errors.Wrapf(err, "invalid destination
    // port %v", portStr)` (service.go:321) appends Go's wrapped `strconv.Atoi` text
    // (`: strconv.Atoi: parsing "notaport": invalid syntax`). We emit only the Wrapf PREFIX — we do
    // not hardcode Go's internal error string on a path reachable only from a non-conformant dialer.
    assert_eq!(err, "invalid destination port notaport");
}
#[test]
fn missing_dst_ip_is_rejected_byte_exact() {
    let cfg = fwd_ip_cfg();
    // appData with only a port, no dst_ip and no dst_hostname.
    let app = serde_json::to_vec(&serde_json::json!({"dst_port": "19009"})).unwrap();
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    // Byte-exact to getValue's `"%v required but not provided"` (service.go:257) for dst_ip.
    assert_eq!(err, "dst_ip required but not provided");
}
#[test]
fn missing_dst_port_is_rejected_byte_exact() {
    let cfg = fwd_ip_cfg();
    let app = serde_json::to_vec(&serde_json::json!({"dst_ip": "127.0.0.1"})).unwrap();
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "dst_port required but not provided");
}
// ----- Fixed-address / fixed-port paths -----
#[test]
fn fixed_address_and_port_need_no_app_data() {
    let cfg = HostV1Config {
        protocol: "tcp".to_string(),
        address: "192.168.1.10".to_string(),
        port: 8080,
        ..Default::default()
    };
    let target = resolve_target(&cfg, None).expect("fixed target resolves with no appData");
    assert_eq!(target.address, "192.168.1.10");
    assert_eq!(target.port, 8080);
    assert_eq!(target.protocol, "tcp");
}
#[test]
fn forward_port_with_fixed_address_resolves() {
    // forwardPort but fixed address (a real config shape).
    let cfg = HostV1Config {
        protocol: "tcp".to_string(),
        address: "127.0.0.1".to_string(),
        forward_port: true,
        allowed_port_ranges: vec![PortRange {
            low: 1,
            high: 65535,
        }],
        ..Default::default()
    };
    let app = build_app_data("tcp", "0.0.0.0", "443", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("resolves");
    assert_eq!(target.address, "127.0.0.1"); // fixed, dst_ip ignored when forward_address=false
    assert_eq!(target.port, 443);
}
// ----- T4b-2d-2: source_addr socket bind (per-dial appData parse) + the still-deferred
// config-level allowedSourceAddresses route setup -----
/// A per-dial NON-EMPTY `source_addr` in the appData is now CARRIED into the resolved target's
/// `source_bind` (T4b-2d-2 supports it; the host binds the dial's local end to it). Checked AFTER a
/// fully-resolvable address/port (the value points at the allowed loopback target). Replaces the old
/// "rejected loudly" deferral.
#[test]
fn source_addr_in_app_data_is_carried_as_bind() {
    let cfg = fwd_ip_cfg();
    let app = build_app_data("tcp", "127.0.0.1", "19009", None, Some("192.168.1.5:5678"));
    let target = resolve_target(&cfg, Some(&app)).expect("source_addr is parsed, not rejected");
    assert_eq!(target.address, "127.0.0.1");
    assert_eq!(target.port, 19009);
    assert_eq!(
        target.source_bind,
        Some("192.168.1.5:5678".parse().unwrap()),
        "the per-dial source_addr is carried as the bind SocketAddr"
    );
}
/// An EMPTY `source_addr` is a no-op (`None`, mirroring the oracle's `if sourceAddr != ""` gate,
/// hosting.go:215) — it must NOT reject a dial that is otherwise resolvable. (We bypass
/// `build_app_data`, which omits an empty source_addr, by hand-building the map with an explicit empty
/// value.)
#[test]
fn empty_source_addr_is_a_no_op() {
    let cfg = fwd_ip_cfg();
    let app = serde_json::to_vec(&serde_json::json!({
        "dst_ip": "127.0.0.1",
        "dst_port": "19009",
        "source_addr": "",
    }))
    .unwrap();
    let target = resolve_target(&cfg, Some(&app)).expect("empty source_addr does not reject");
    assert_eq!(target.address, "127.0.0.1");
    assert_eq!(target.port, 19009);
    assert!(
        target.source_bind.is_none(),
        "an empty source_addr yields no bind"
    );
}
/// A MALFORMED per-dial `source_addr` (bad port segment) rejects loudly with the oracle's
/// `errors.Wrapf` PREFIX — surfaced as the dialer-observable DialFailed by the host. The address/port
/// here are fully resolvable, so the source parse is what fails (precedence: source parsed LAST).
#[test]
fn malformed_source_addr_rejects_with_port_reason() {
    let cfg = fwd_ip_cfg();
    let app = build_app_data("tcp", "127.0.0.1", "19009", None, Some("1.2.3.4:notaport"));
    assert_eq!(
        resolve_target(&cfg, Some(&app)).unwrap_err(),
        "failed to parse port 'notaport'"
    );
}
/// [`parse_source_bind`] unit battery: the oracle's `dialAddress` parse (`strings.Split(sourceAddr,
/// ":")` + `len==2`-gated port, `net.ParseIP`). The naive split (NOT `split_once`) is load-bearing:
/// a bare IPv6 (`::1`/`fe80::1:53`) is the whole IP with port 0.
#[test]
fn parse_source_bind_mirrors_the_oracle_split() {
    // IP only → port 0.
    assert_eq!(
        parse_source_bind("192.168.1.5").unwrap(),
        "192.168.1.5:0".parse().unwrap()
    );
    // ip:port (exactly 2 segments) → split.
    assert_eq!(
        parse_source_bind("192.168.1.5:8080").unwrap(),
        "192.168.1.5:8080".parse().unwrap()
    );
    // Bare IPv6: 3 segments → NOT split → whole is the IP, port 0.
    assert_eq!(
        parse_source_bind("::1").unwrap(),
        "[::1]:0".parse().unwrap()
    );
    // IPv6 with 4 segments → NOT split → whole string parses as the IPv6 address, port 0 (the naive
    // split CANNOT attach a port to an unbracketed IPv6, faithful to the oracle).
    assert_eq!(
        parse_source_bind("fe80::1:53").unwrap(),
        "[fe80::1:53]:0".parse().unwrap()
    );
    // Non-numeric port → reject with the oracle's `errors.Wrapf` prefix.
    assert_eq!(
        parse_source_bind("1.2.3.4:notaport").unwrap_err(),
        "failed to parse port 'notaport'"
    );
    // Out-of-u16 port → reject (the oracle would `uint16`-wrap; we are stricter, safe-direction).
    assert_eq!(
        parse_source_bind("1.2.3.4:99999").unwrap_err(),
        "failed to parse port '99999'"
    );
    // Empty-IP `:port` form: the one oracle-meaningful input we refuse (the oracle wildcard-binds the
    // port on a nil IP). `IpAddr::from_str("")` fails → reject, safe-direction.
    assert_eq!(
        parse_source_bind(":8080").unwrap_err(),
        "invalid source_addr IP ''"
    );
    // Unparseable IP → reject (the oracle's `net.ParseIP` nil → wildcard bind; we reject).
    assert_eq!(
        parse_source_bind("garbage").unwrap_err(),
        "invalid source_addr IP 'garbage'"
    );
}
// ----- appData parse -----
#[test]
fn empty_or_absent_app_data_yields_required_error_for_forward_ip() {
    let cfg = fwd_ip_cfg();
    // forward_address with no appData → dst_ip required but not provided.
    let err = resolve_target(&cfg, None).unwrap_err();
    assert_eq!(err, "dst_ip required but not provided");
    let err2 = resolve_target(&cfg, Some(&[])).unwrap_err();
    assert_eq!(err2, "dst_ip required but not provided");
}
#[test]
fn malformed_app_data_is_rejected() {
    let cfg = fwd_ip_cfg();
    let err = resolve_target(&cfg, Some(b"{not json")).unwrap_err();
    assert!(err.starts_with("invalid appData:"), "got: {err}");
}
#[test]
fn non_object_app_data_is_rejected() {
    let cfg = fwd_ip_cfg();
    let err = resolve_target(&cfg, Some(b"[1,2,3]")).unwrap_err();
    assert_eq!(err, "invalid appData: not a JSON object");
}
