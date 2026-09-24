use std::time::Duration;

use super::testsupport::{fwd_ip_cfg, listen_opts};
use super::timeout::{get_dial_timeout, parse_go_duration};

// ----- T4b-2c: connectTimeout resolution (`GetDialTimeout` + the Go-duration parse) -----
/// DEFAULT: no `listenOptions` → the host's no-config default (oracle: `GetDialTimeout` returns the
/// passed `5 * time.Second` default when `ListenOptions == nil`, `service.go:223,231`).
#[test]
fn get_dial_timeout_uses_default_without_listen_options() {
    let cfg = fwd_ip_cfg(); // listen_options: None
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)),
        Ok(Duration::from_secs(5))
    );
}
/// DEFAULT: `listenOptions` present but neither timeout set → still the default (oracle: both inner
/// `!= nil` checks fail, `service.go:224-229`, falling to `return defaultTimeout`).
#[test]
fn get_dial_timeout_uses_default_with_empty_listen_options() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(None, None));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)),
        Ok(Duration::from_secs(5))
    );
}
/// `connectTimeoutSeconds` path (oracle `service.go:227-228`: `time.Second * Duration(seconds)`).
#[test]
fn get_dial_timeout_reads_connect_timeout_seconds() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(None, Some(12)));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)),
        Ok(Duration::from_secs(12))
    );
}
/// `connectTimeout` (Go-duration string) path resolves to the parsed duration (oracle
/// `service.go:224-225`). `"1m30s"` → 90s.
#[test]
fn get_dial_timeout_reads_connect_timeout_string() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(Some("1m30s"), None));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)),
        Ok(Duration::from_secs(90))
    );
}
/// PRECEDENCE (mutation-killer): `connectTimeout` WINS over `connectTimeoutSeconds` when both are set
/// (oracle checks `ConnectTimeout != nil` FIRST, `service.go:224`). Here the string says 3s and the
/// seconds say 99; the resolved timeout must be 3s.
#[test]
fn get_dial_timeout_connect_timeout_string_wins_over_seconds() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(Some("3s"), Some(99)));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)),
        Ok(Duration::from_secs(3))
    );
}
/// PRECEDENCE on FAILURE (mutation-killer): a present-but-MALFORMED `connectTimeout` is a hard `Err`
/// — it does NOT fall through to `connectTimeoutSeconds` (here 7) nor the default. The oracle never
/// reaches `connectTimeoutSeconds` once `ConnectTimeout != nil`, and a malformed string fails the whole
/// `mapstructure` decode (`service.go:391,397`). The reason is a clear operator-facing message (NOT
/// byte-matched to Go's `"time: invalid duration ..."`).
#[test]
fn get_dial_timeout_malformed_connect_timeout_errs_without_falling_back() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(Some("notaduration"), Some(7)));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)).unwrap_err(),
        "invalid host.v1 connectTimeout 'notaduration'"
    );
}
/// NON-POSITIVE (mutation-killer, conscious safe-direction deviation): a resolved `"0s"` is rejected
/// loudly. Go would treat `Dialer.Timeout <= 0` as no-timeout, but `tokio::time::timeout(ZERO, ...)`
/// fires immediately and an unbounded host dial breaks our hang-protection invariant — so we fail loud.
#[test]
fn get_dial_timeout_zero_connect_timeout_is_rejected() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(Some("0s"), None));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)).unwrap_err(),
        "host.v1 connectTimeout '0s' must be a positive duration"
    );
}
/// NON-POSITIVE: a NEGATIVE `connectTimeout` (`"-5s"`, which Go PARSES to a negative duration) is
/// rejected loudly (not silently treated as no-timeout). Pins that the parser accepts the sign but the
/// policy rejects the non-positive result.
#[test]
fn get_dial_timeout_negative_connect_timeout_is_rejected() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(Some("-5s"), None));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)).unwrap_err(),
        "host.v1 connectTimeout '-5s' must be a positive duration"
    );
}
/// NON-POSITIVE: `connectTimeoutSeconds: 0` is rejected loudly (same deviation as `"0s"`, via the
/// seconds path).
#[test]
fn get_dial_timeout_zero_connect_timeout_seconds_is_rejected() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(None, Some(0)));
    assert_eq!(
        get_dial_timeout(&cfg, Duration::from_secs(5)).unwrap_err(),
        "host.v1 connectTimeoutSeconds must be a positive number of seconds"
    );
}
/// DIFFERENTIAL BATTERY: `parse_go_duration` matched to `go time.ParseDuration` over the realistic
/// input surface (the expected nanos/None were produced by running Go's `time.ParseDuration` over this
/// battery — see the T4b-2c spec/handoff). The load-bearing surface is the grammar ACCEPT/REJECT set +
/// common values. The SOLE known divergence — the `2^64`-wrap overflow family (deviation #3 on
/// `get_dial_timeout`), which Go ACCEPTS but we fail-closed REJECT — is pinned separately in
/// `parse_go_duration_overflow_wrap_is_fail_closed`; every case in THIS battery genuinely matches Go.
#[test]
fn parse_go_duration_matches_go_reference() {
    // (input, Some(nanos) | None) — None == Go returns an error.
    let cases: &[(&str, Option<i64>)] = &[
        ("0", Some(0)),
        ("0s", Some(0)),
        ("5s", Some(5_000_000_000)),
        ("5", None), // missing unit
        ("", None),  // empty
        ("1.5h", Some(5_400_000_000_000)),
        ("100ms", Some(100_000_000)),
        (".5s", Some(500_000_000)),
        ("5.s", Some(5_000_000_000)),
        ("5x", None), // unknown unit
        ("+3h", Some(10_800_000_000_000)),
        ("-5s", Some(-5_000_000_000)),
        ("1m30s", Some(90_000_000_000)),
        ("5s5s", Some(10_000_000_000)), // repeated groups sum
        ("µs", None),                   // bare unit, no number
        ("μs", None),
        ("us", None),
        ("10000000h", None), // overflow
        (".s", None),        // no digits
        ("1.5", None),       // missing unit
        ("0.5s", Some(500_000_000)),
        ("2h45m", Some(9_900_000_000_000)),
        ("1us", Some(1_000)),
        ("1µs", Some(1_000)), // U+00B5 micro sign
        ("1μs", Some(1_000)), // U+03BC Greek mu
        ("1ns", Some(1)),
        ("9223372036854775807ns", Some(9_223_372_036_854_775_807)), // max int64
        ("9223372036854775808ns", None),                            // overflow (1<<63)
        ("01s", Some(1_000_000_000)), // leading zeros in a NUMBER are fine (not an IP boundary)
        ("1.0s", Some(1_000_000_000)),
        ("1.s", Some(1_000_000_000)),
        (".5h", Some(1_800_000_000_000)),
        ("0m", Some(0)),
        ("-0s", Some(0)),
        ("+0", Some(0)),
        ("100us", Some(100_000)),
        ("1m0.5s", Some(60_500_000_000)),
        ("  5s", None), // no whitespace trimming
        ("5s ", None),
        ("300ms-", None), // trailing sign is not a valid next group
        ("-", None),
        ("+", None),
    ];
    for (input, expected) in cases {
        assert_eq!(
            parse_go_duration(input),
            *expected,
            "parse_go_duration({input:?}) must match go time.ParseDuration"
        );
    }
}
/// DEVIATION #3 (`2^64`-wrap overflow): the ONLY inputs where `parse_go_duration` deliberately diverges
/// from `go time.ParseDuration`. Go accumulates with a WRAPPING `uint64 d += v`, so two exactly-`2^63`-ns
/// terms wrap the accumulator to 0 and Go ACCEPTS (`"…808ns…808ns"` → 0; `"…808ns…808ns5s"` → 5s); our
/// `checked_add` REJECTS the `2^64` wrap → fail-closed (the host refuses to serve, never an over-permit).
/// We keep this stricter behavior on purpose (see `get_dial_timeout` deviation #3); a future change to
/// `wrapping_add` (which would match Go) makes this test go RED.
#[test]
fn parse_go_duration_overflow_wrap_is_fail_closed() {
    assert_eq!(
        parse_go_duration("9223372036854775808ns9223372036854775808ns"),
        None
    );
    assert_eq!(
        parse_go_duration("9223372036854775808ns9223372036854775808ns5s"),
        None
    );
}
