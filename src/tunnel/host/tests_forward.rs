//! Tests for the FORWARDING host mode (T4b-1): dynamic target resolved from appData.
//!
//! (F6 tramo 9: movido verbatim del monolito de `tunnel/host`.)

use super::HOST_DIAL_TIMEOUT;
use super::forward::handle_host_forward_conn;
use super::testsupport::{
    TEST_CONN_ID, fake_pending_with_app_data, fin_frame, flags_of, fwd_cfg, tcp_echo_once,
};
use crate::channel::connect::read_message;
use crate::edge::bind::{CT_DIAL_FAILED, CT_DIAL_SUCCESS};
use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, build_app_data, build_data};
use crate::tunnel::resolve::{build_address_translations, check_deferred_config};
use std::time::Duration;
use tokio::net::TcpListener;

// ----- T4b-1 forwarding host: dynamic target resolved from appData -----

/// Forwarding happy path: the inbound dial's appData (`dst_ip`/`dst_port`) resolves against the
/// service's `host.v1` to the local echo's address, the host dials it, completes the accept
/// (DialSuccess), and the payload round-trips. The dynamic target replaces T2's fixed argument.
#[tokio::test]
async fn handle_host_forward_conn_round_trips_via_resolved_app_data() {
    // The echo (the resolved target). The dialer's appData must point HERE.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(tcp_echo_once(echo_listener));

    // appData resolving to the echo's ip:port via the forwardAddress/forwardPort cfg.
    let app = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        None,
        None,
    );
    let (pending, state, data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut echoed = Vec::new();
        let mut saw_dial_success = false;
        let mut saw_state_closed = false;
        loop {
            let Ok(msg) = read_message(&mut router).await else {
                break;
            };
            match msg.content_type {
                CT_DIAL_SUCCESS => saw_dial_success = true,
                CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => {}
                CT_DATA => echoed.extend_from_slice(&msg.body),
                CT_STATE_CLOSED => {
                    saw_state_closed = true;
                    break;
                }
                _ => {}
            }
        }
        (saw_dial_success, echoed, saw_state_closed)
    });

    data_tx
        .send(build_data(TEST_CONN_ID, b"hello-forward", false))
        .await
        .unwrap();
    data_tx.send(fin_frame()).await.unwrap();
    drop(data_tx);

    handle_host_forward_conn(pending, &fwd_cfg(), &[], HOST_DIAL_TIMEOUT).await;

    let (saw_dial_success, echoed, saw_state_closed) = router_task.await.unwrap();
    echo.await.unwrap();
    assert!(saw_dial_success, "resolved target reachable → DialSuccess");
    assert_eq!(
        echoed, b"hello-forward",
        "round-trip via the resolved target"
    );
    assert!(saw_state_closed, "splice tore down after both directions");
    assert_eq!(state.conn_count(), 0, "child deregistered exactly once");
}

/// Forwarding LOUD reject: appData whose `dst_ip` is OUTSIDE `allowedAddresses` → the host sends
/// DialFailed (never dials a target), with the byte-exact oracle reason in the body, and the child
/// is deregistered. The dialer's `connect()` thus fails — never a silent wrong-dial.
#[tokio::test]
async fn handle_host_forward_conn_rejects_disallowed_address_with_dial_failed() {
    // allowedAddresses only loopback /32; appData points at 10.0.0.5 → not allowed.
    let app = build_app_data("tcp", "10.0.0.5", "8080", None, None);
    let (pending, state, _data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut frames: Vec<i32> = Vec::new();
        let mut reason: Option<String> = None;
        while frames.len() < 2 {
            let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut router)).await
            else {
                break;
            };
            if msg.content_type == CT_DIAL_FAILED {
                reason = Some(String::from_utf8_lossy(&msg.body).into_owned());
            }
            frames.push(msg.content_type);
        }
        (frames, reason)
    });

    handle_host_forward_conn(pending, &fwd_cfg(), &[], HOST_DIAL_TIMEOUT).await;

    let (frames, reason) = router_task.await.unwrap();
    assert_eq!(
        frames,
        vec![CT_DIAL_FAILED, CT_STATE_CLOSED],
        "disallowed address → DialFailed THEN StateClosed (no DialSuccess, no target dial)"
    );
    assert!(!frames.contains(&CT_DIAL_SUCCESS));
    assert_eq!(
        reason.as_deref(),
        Some("address '10.0.0.5' is not in allowed addresses"),
        "the DialFailed body is the byte-exact oracle GetAddress reason (dialer-observable)"
    );
    assert_eq!(state.conn_count(), 0, "child deregistered after the reject");
}

/// T4b-2a: a `dst_hostname` whose string does not match the (CIDR-only) allow-list is rejected with
/// the byte-exact not-in-allowed reason — the oracle tries the hostname FIRST and a `cidrAddress`
/// never matches a string, so it never falls back to the present `dst_ip` (precedence). The DialFailed
/// body is dialer-observable.
#[tokio::test]
async fn handle_host_forward_conn_dst_hostname_not_in_cidr_allow_list_is_rejected() {
    // Both dst_hostname AND a valid dst_ip present; fwd_cfg's allow-list is CIDR-only (127.0.0.1/32).
    let app = build_app_data("tcp", "127.0.0.1", "8080", Some("example.com"), None);
    let (pending, _state, _data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut reason: Option<String> = None;
        for _ in 0..2 {
            let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut router)).await
            else {
                break;
            };
            if msg.content_type == CT_DIAL_FAILED {
                reason = Some(String::from_utf8_lossy(&msg.body).into_owned());
            }
        }
        reason
    });

    handle_host_forward_conn(pending, &fwd_cfg(), &[], HOST_DIAL_TIMEOUT).await;

    assert_eq!(
        router_task.await.unwrap().as_deref(),
        Some("address 'example.com' is not in allowed addresses"),
        "a dst_hostname unmatched by a CIDR-only allow-list rejects (no dst_ip fallback), byte-exact"
    );
}

/// T4b-2a: the host forwards a `dst_hostname`-resolved target. A `*` domain allow-list string-matches
/// the `dst_hostname` (here an IP literal, so the resolved target is dialable in-process and the test
/// stays DNS-free), the host dials it, completes the accept, and the payload round-trips — proving the
/// host wires the resolved hostname-path address through `handle_host_conn` exactly like a `dst_ip`.
#[tokio::test]
async fn handle_host_forward_conn_round_trips_via_resolved_hostname() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(tcp_echo_once(echo_listener));

    // `*` domain matches any dst_hostname string; use the echo's IP literal so the resolved target
    // ("127.0.0.1:<port>") is dialable without DNS. dst_ip is present but the hostname path wins.
    let mut cfg = fwd_cfg();
    cfg.allowed_addresses = vec!["*".to_string()];
    let app = build_app_data(
        "tcp",
        &echo_addr.ip().to_string(),
        &echo_addr.port().to_string(),
        Some(&echo_addr.ip().to_string()),
        None,
    );
    let (pending, state, data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut echoed = Vec::new();
        let mut saw_dial_success = false;
        let mut saw_state_closed = false;
        loop {
            let Ok(msg) = read_message(&mut router).await else {
                break;
            };
            match msg.content_type {
                CT_DIAL_SUCCESS => saw_dial_success = true,
                CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => {}
                CT_DATA => echoed.extend_from_slice(&msg.body),
                CT_STATE_CLOSED => {
                    saw_state_closed = true;
                    break;
                }
                _ => {}
            }
        }
        (saw_dial_success, echoed, saw_state_closed)
    });

    data_tx
        .send(build_data(TEST_CONN_ID, b"hello-hostname", false))
        .await
        .unwrap();
    data_tx.send(fin_frame()).await.unwrap();
    drop(data_tx);

    handle_host_forward_conn(pending, &cfg, &[], HOST_DIAL_TIMEOUT).await;

    let (saw_dial_success, echoed, saw_state_closed) = router_task.await.unwrap();
    echo.await.unwrap();
    assert!(
        saw_dial_success,
        "resolved hostname target reachable → DialSuccess"
    );
    assert_eq!(
        echoed, b"hello-hostname",
        "round-trip via the resolved hostname target"
    );
    assert!(saw_state_closed, "splice tore down after both directions");
    assert_eq!(state.conn_count(), 0, "child deregistered exactly once");
}

/// Forwarding LOUD reject: a resolved non-`tcp` protocol (a udp service) is rejected — this host
/// dials TCP, so it never silently TCP-dials a udp target.
#[tokio::test]
async fn handle_host_forward_conn_rejects_non_tcp_protocol() {
    let mut cfg = fwd_cfg();
    cfg.protocol = "udp".to_string();
    let app = build_app_data("udp", "127.0.0.1", "8080", None, None);
    let (pending, _state, _data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut reason: Option<String> = None;
        for _ in 0..2 {
            let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut router)).await
            else {
                break;
            };
            if msg.content_type == CT_DIAL_FAILED {
                reason = Some(String::from_utf8_lossy(&msg.body).into_owned());
            }
        }
        reason
    });

    handle_host_forward_conn(pending, &cfg, &[], HOST_DIAL_TIMEOUT).await;

    assert!(
        router_task
            .await
            .unwrap()
            .is_some_and(|r| r.contains("dials TCP only")),
        "non-tcp resolved protocol is rejected loudly with a TCP-only reason"
    );
}

/// T4b-2b SCOPING PIN: a `forwardProtocol` service whose `allowedProtocols` permits `udp` resolves a
/// `dst_protocol=udp` (the resolver is protocol-agnostic, faithful to the oracle's `GetProtocol`), but
/// this TCP-only forwarding host then REJECTS it loudly via DialFailed — the same non-tcp guard,
/// now reachable through the `forwardProtocol` path. Pins the conscious deviation (the oracle would
/// udp-dial it). Pairs with the resolver test `forward_protocol_resolves_udp_when_in_allow_list`.
#[tokio::test]
async fn handle_host_forward_conn_forward_protocol_udp_is_rejected() {
    let mut cfg = fwd_cfg();
    cfg.forward_protocol = true;
    cfg.allowed_protocols = vec!["udp".to_string()];
    // The dialer's appData carries dst_protocol=udp; the resolver returns "udp"; the host rejects.
    let app = build_app_data("udp", "127.0.0.1", "8080", None, None);
    let (pending, _state, _data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut reason: Option<String> = None;
        for _ in 0..2 {
            let Ok(Ok(msg)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut router)).await
            else {
                break;
            };
            if msg.content_type == CT_DIAL_FAILED {
                reason = Some(String::from_utf8_lossy(&msg.body).into_owned());
            }
        }
        reason
    });

    handle_host_forward_conn(pending, &cfg, &[], HOST_DIAL_TIMEOUT).await;

    assert!(
        router_task
            .await
            .unwrap()
            .is_some_and(|r| r.contains("dials TCP only") && r.contains("'udp'")),
        "a forwardProtocol-resolved udp is rejected loudly by the TCP-only host"
    );
}

/// The startup config guard (still-deferred config capabilities) is enforced by
/// `run_tcp_host_forwarding` via `check_deferred_config`; assert it rejects an `allowedSourceAddresses`
/// config (T4b-2d-2, still deferred) and passes a plain forward-ip config. (T4b-2d-1:
/// `forwardAddressTranslations` is NO LONGER rejected here — it now BUILDS via
/// `build_address_translations`, asserted below.)
#[test]
fn forwarding_startup_guard_rejects_deferred_config() {
    let mut cfg = fwd_cfg();
    cfg.allowed_source_addresses = vec!["10.0.0.0/8".to_string()];
    assert!(check_deferred_config(&cfg).is_err());
    assert!(check_deferred_config(&fwd_cfg()).is_ok());
    // A translations config is no longer a deferred reject — it builds at startup.
    let mut tcfg = fwd_cfg();
    tcfg.forward_address_translations = vec![crate::edge::model::AddressTranslation {
        from: "1.2.3.0".to_string(),
        to: "4.5.6.0".to_string(),
        prefix_length: 24,
    }];
    assert!(check_deferred_config(&tcfg).is_ok());
    assert_eq!(build_address_translations(&tcfg).unwrap().len(), 1);
}

/// T4b-2d-1 END-TO-END through the host: the inbound dial's `dst_ip` resolves to an address INSIDE
/// the allow-list, but `forwardAddressTranslations` renumbers it onto a DIFFERENT network (the
/// in-process echo's loopback) before the host dials. Proves the host applies the translation to the
/// real dial target (not just the resolver in isolation): the allow-list is checked PRE-translation,
/// and the dialed target is the POST-translation address. A regression that dialed the resolved
/// (pre-translation) address would hit nothing on `10.x` → no DialSuccess/echo → RED.
#[tokio::test]
async fn handle_host_forward_conn_dials_the_translated_target() {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo = tokio::spawn(tcp_echo_once(echo_listener));

    // The dialer asks for `10.0.0.<echo_low_byte>` (allowed by a /8 allow-list); the translation
    // renumbers `10.0.0.0/24 → 127.0.0.<host bits>`, so the host dials `127.0.0.<echo_low_byte>`.
    // Keep the echo's low byte as the host part: bind the echo, take its port, and use dst_ip
    // `10.0.0.7` translating to `127.0.0.7` — but the echo is on an ephemeral port at 127.0.0.1, and
    // its IP is 127.0.0.1, so translate `10.0.0.1/24 → 127.0.0.0/24` makes host-bit `.1` → 127.0.0.1.
    let mut cfg = fwd_cfg();
    cfg.allowed_addresses = vec!["10.0.0.0/8".to_string()];
    cfg.forward_address_translations = vec![crate::edge::model::AddressTranslation {
        from: "10.0.0.0".to_string(),
        to: "127.0.0.0".to_string(),
        prefix_length: 24,
    }];
    let translations = build_address_translations(&cfg).expect("translations build");
    // dst_ip = 10.0.0.1 (in 10.0.0.0/8, passes the allow-list) → translates to 127.0.0.1.
    let app = build_app_data("tcp", "10.0.0.1", &echo_addr.port().to_string(), None, None);
    let (pending, state, data_tx, mut router) = fake_pending_with_app_data(app);

    let router_task = tokio::spawn(async move {
        let mut echoed = Vec::new();
        let mut saw_dial_success = false;
        let mut saw_state_closed = false;
        loop {
            let Ok(msg) = read_message(&mut router).await else {
                break;
            };
            match msg.content_type {
                CT_DIAL_SUCCESS => saw_dial_success = true,
                CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => {}
                CT_DATA => echoed.extend_from_slice(&msg.body),
                CT_STATE_CLOSED => {
                    saw_state_closed = true;
                    break;
                }
                _ => {}
            }
        }
        (saw_dial_success, echoed, saw_state_closed)
    });

    data_tx
        .send(build_data(TEST_CONN_ID, b"hello-translated", false))
        .await
        .unwrap();
    data_tx.send(fin_frame()).await.unwrap();
    drop(data_tx);

    handle_host_forward_conn(pending, &cfg, &translations, HOST_DIAL_TIMEOUT).await;

    let (saw_dial_success, echoed, saw_state_closed) = router_task.await.unwrap();
    echo.await.unwrap();
    assert!(
        saw_dial_success,
        "the TRANSLATED target (127.0.0.1) was reachable → DialSuccess (the pre-translation 10.0.0.1 would not be)"
    );
    assert_eq!(
        echoed, b"hello-translated",
        "round-trip via the POST-translation target"
    );
    assert!(saw_state_closed, "splice tore down after both directions");
    assert_eq!(state.conn_count(), 0, "child deregistered exactly once");
}
