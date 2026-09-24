// F6 tramo 2b troceo: tests movidos verbatim del monolito de `intercept/resolve` (mod tests).

use std::time::Duration;

use crate::edge::conn::DEFAULT_CONNECT_TIMEOUT;
use crate::edge::model::PortRange;

use super::config::dial_timeout_for;
use super::testsupport::*;
use super::{DialOptions, InterceptV1Config, intercept_v1_config};

// ───────────────────────── intercept.v1 parse ─────────────────────────

#[test]
fn intercept_v1_parses_full_shape() {
    let s = svc(
        "svc",
        r#"{"intercept.v1":{"protocols":["tcp","udp"],"addresses":["10.0.0.0/24","app.example.com"],
                "portRanges":[{"low":80,"high":90}],"dialOptions":{"connectTimeoutSeconds":7,"identity":"$dst_ip"},
                "sourceIp":"1.2.3.4","allowedSourceAddresses":["192.168.0.0/16"]}}"#,
    );
    let cfg = intercept_v1_config(&s)
        .unwrap()
        .expect("intercept.v1 present");
    assert_eq!(cfg.protocols, vec!["tcp", "udp"]);
    assert_eq!(cfg.addresses, vec!["10.0.0.0/24", "app.example.com"]);
    assert_eq!(cfg.port_ranges, vec![PortRange { low: 80, high: 90 }]);
    assert_eq!(
        cfg.dial_options.as_ref().unwrap().connect_timeout_seconds,
        Some(7)
    );
    assert_eq!(
        cfg.dial_options.as_ref().unwrap().identity.as_deref(),
        Some("$dst_ip")
    );
    assert_eq!(cfg.source_ip.as_deref(), Some("1.2.3.4"));
    assert_eq!(cfg.allowed_source_addresses, vec!["192.168.0.0/16"]);
}

#[test]
fn intercept_v1_absent_is_none() {
    let s = svc(
        "svc",
        r#"{"host.v1":{"address":"x","port":1,"protocol":"tcp"}}"#,
    );
    assert!(intercept_v1_config(&s).unwrap().is_none());
}

#[test]
fn intercept_v1_malformed_is_err() {
    // protocols debe ser un array; un número rompe el deserialize.
    let s = svc("svc", r#"{"intercept.v1":{"protocols":3}}"#);
    assert!(intercept_v1_config(&s).is_err());
}

// ───────────────────────── dial timeout (svcpoll + <1→15s) ─────────────────────────

#[test]
fn dial_timeout_default_5s_without_dial_options() {
    let cfg = InterceptV1Config::default();
    assert_eq!(dial_timeout_for(&cfg), Duration::from_secs(5));
}

#[test]
fn dial_timeout_default_5s_with_dial_options_but_no_secs() {
    let cfg = InterceptV1Config {
        dial_options: Some(DialOptions {
            connect_timeout_seconds: None,
            identity: Some("x".into()),
        }),
        ..Default::default()
    };
    // svcpoll solo sobreescribe cuando connectTimeoutSeconds != nil → queda en 5s.
    assert_eq!(dial_timeout_for(&cfg), Duration::from_secs(5));
}

#[test]
fn dial_timeout_explicit_seconds() {
    let cfg = InterceptV1Config {
        dial_options: Some(DialOptions {
            connect_timeout_seconds: Some(30),
            identity: None,
        }),
        ..Default::default()
    };
    assert_eq!(dial_timeout_for(&cfg), Duration::from_secs(30));
}

#[test]
fn dial_timeout_zero_maps_to_sdk_15s_not_5s() {
    // connectTimeoutSeconds=0 → svc.DialTimeout=0 → SDK <1→15s (ziti.go:1449), NO el default de 5s.
    let cfg = InterceptV1Config {
        dial_options: Some(DialOptions {
            connect_timeout_seconds: Some(0),
            identity: None,
        }),
        ..Default::default()
    };
    assert_eq!(dial_timeout_for(&cfg), DEFAULT_CONNECT_TIMEOUT);
    assert_eq!(dial_timeout_for(&cfg), Duration::from_secs(15));
}
