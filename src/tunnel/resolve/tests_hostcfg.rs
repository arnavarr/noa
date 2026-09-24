use crate::edge::dial::build_app_data;

use super::target::resolve_target;
use super::testsupport::{fwd_ip_cfg, fwd_proto_cfg};

// ----- T4b-2b: forwardProtocol (`dst_protocol` validated against `allowedProtocols`) -----
/// forwardProtocol HAPPY: `dst_protocol="tcp"` in `allowedProtocols=["tcp"]` resolves to "tcp"
/// (oracle `GetProtocol`: `getValue(dst_protocol)` then `stringz.Contains(AllowedProtocols, p)`,
/// `service.go:271-280`). The resolved protocol drives the dial.
#[test]
fn forward_protocol_resolves_dst_protocol_when_in_allow_list() {
    let cfg = fwd_proto_cfg(&["tcp"]);
    let app = build_app_data("tcp", "127.0.0.1", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("forwardProtocol tcp resolves");
    assert_eq!(target.protocol, "tcp");
    assert_eq!(target.address, "127.0.0.1");
    assert_eq!(target.port, 19009);
}
/// forwardProtocol REJECT (byte-exact, dialer-observable): a `dst_protocol` NOT in `allowedProtocols`
/// is rejected with the oracle's `"protocol '%s' is not in allowed protocols"` (`service.go:280`).
/// Mutation-killer: pins the byte-exact reason (not merely `is_err`).
#[test]
fn forward_protocol_not_in_allow_list_is_rejected_byte_exact() {
    let cfg = fwd_proto_cfg(&["tcp"]);
    let app = build_app_data("udp", "127.0.0.1", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "protocol 'udp' is not in allowed protocols");
}
/// forwardProtocol with an ABSENT `dst_protocol` rejects byte-exact via `getValue`'s
/// `"%v required but not provided"` (`service.go:257`) — `GetProtocol` calls `getValue` FIRST.
/// (`build_app_data` always emits `dst_protocol`, so hand-build a map without it.)
#[test]
fn forward_protocol_missing_dst_protocol_is_rejected_byte_exact() {
    let cfg = fwd_proto_cfg(&["tcp"]);
    let app = serde_json::to_vec(&serde_json::json!({
        "dst_ip": "127.0.0.1", "dst_port": "19009",
    }))
    .unwrap();
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "dst_protocol required but not provided");
}
/// FIDELITY: the `allowedProtocols` membership is CASE-SENSITIVE — unlike the address matchers, the
/// oracle uses `stringz.Contains` (exact `==`, no `strings.ToLower`, `service.go:277`), so
/// `dst_protocol="TCP"` does NOT match `allowedProtocols=["tcp"]`. Mutation-killer: kills a
/// `to_lowercase`/case-fold mutant on the protocol comparison.
#[test]
fn forward_protocol_allow_list_is_case_sensitive() {
    let cfg = fwd_proto_cfg(&["tcp"]);
    let app = build_app_data("TCP", "127.0.0.1", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(err, "protocol 'TCP' is not in allowed protocols");
}
/// SCOPING PIN: the resolver is protocol-AGNOSTIC — `dst_protocol="udp"` in `allowedProtocols=["udp"]`
/// RESOLVES to "udp" (faithful to the oracle's `GetProtocol`, which would then `dialAddress` udp,
/// `hosting.go:206`). The TCP-only limitation is enforced at the HOST level (`run_tcp_host_forwarding`
/// rejects a non-tcp resolved protocol), NOT here — see `host/tests_forward.rs`'s
/// `handle_host_forward_conn_forward_protocol_udp_is_rejected`. This split keeps `GetProtocol` faithful.
#[test]
fn forward_protocol_resolves_udp_when_in_allow_list() {
    let cfg = fwd_proto_cfg(&["udp"]);
    let app = build_app_data("udp", "127.0.0.1", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("resolver allows udp; host rejects it");
    assert_eq!(target.protocol, "udp");
    assert_eq!(target.address, "127.0.0.1");
}
/// PRECEDENCE (mutation-killer for a check-reorder): `GetProtocol` runs FIRST (oracle `Dial`,
/// `hosting.go:397-411`), so a protocol error WINS over an address error. Here the `dst_protocol` is
/// not allowed AND the `dst_ip` is outside the allow-list; the protocol reason must surface.
#[test]
fn forward_protocol_error_wins_over_address_error() {
    let cfg = fwd_proto_cfg(&["tcp"]);
    // dst_protocol=udp (not allowed) AND dst_ip=10.0.0.5 (outside 127.0.0.1/32).
    let app = build_app_data("udp", "10.0.0.5", "19009", None, None);
    let err = resolve_target(&cfg, Some(&app)).unwrap_err();
    assert_eq!(
        err, "protocol 'udp' is not in allowed protocols",
        "GetProtocol runs before GetAddress, so the protocol error wins"
    );
}
/// forwardProtocol=false keeps the FIXED `protocol` and ignores any `dst_protocol` in the appData
/// (oracle `GetProtocol` returns `self.Protocol` when `!ForwardProtocol`, `service.go:282`).
#[test]
fn fixed_protocol_ignores_dst_protocol() {
    let mut cfg = fwd_ip_cfg();
    cfg.protocol = "tcp".to_string(); // forward_protocol stays false
    // appData carries dst_protocol=udp, but the fixed config wins → "tcp".
    let app = build_app_data("udp", "127.0.0.1", "19009", None, None);
    let target = resolve_target(&cfg, Some(&app)).expect("fixed protocol resolves");
    assert_eq!(target.protocol, "tcp");
}
