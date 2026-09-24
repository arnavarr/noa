//! Unit tests for `wire.rs`: the four message constructors, the `ListenerId` generator and the
//! bind-reply classifier — i.e. the router-observable bytes.

use super::{
    CT_BIND, CT_DIAL_FAILED, CT_DIAL_SUCCESS, CT_UNBIND, HDR_LISTENER_ID,
    HDR_ROUTER_PROVIDED_CONN_ID, HDR_SUPPORTS_BIND_SUCCESS, HDR_SUPPORTS_INSPECT, build_bind,
    build_dial_failed, build_dial_success, build_unbind, classify_bind_reply, new_listener_id,
};
use crate::edge::dial::{CT_STATE_CLOSED, CT_STATE_CONNECTED, HDR_CONN_ID, HDR_USE_XGRESS_TO_SDK};

#[test]
fn build_bind_assembles_minimal_plaintext_bind() {
    let msg = build_bind(3, "bind-jwt", "lid-1234", None);
    assert_eq!(msg.content_type, CT_BIND); // 60790
    assert_eq!(msg.body, b"bind-jwt"); // body = bind-session token
    assert_eq!(
        msg.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
        &3u32.to_le_bytes()
    );
    // The four always-on bool flags (1 byte each):
    assert_eq!(
        msg.headers.get(&HDR_SUPPORTS_INSPECT).unwrap().as_slice(),
        &[1u8]
    );
    assert_eq!(
        msg.headers
            .get(&HDR_SUPPORTS_BIND_SUCCESS)
            .unwrap()
            .as_slice(),
        &[1u8]
    );
    assert_eq!(
        msg.headers.get(&HDR_USE_XGRESS_TO_SDK).unwrap().as_slice(),
        &[0u8]
    );
    assert_eq!(
        msg.headers
            .get(&HDR_ROUTER_PROVIDED_CONN_ID)
            .unwrap()
            .as_slice(),
        &[1u8]
    );
    // ListenerId present (string).
    assert_eq!(
        msg.headers.get(&HDR_LISTENER_ID).unwrap().as_slice(),
        b"lid-1234"
    );
    // Plaintext: no crypto headers.
    assert!(!msg.headers.contains_key(&crate::edge::dial::HDR_PUBLIC_KEY));
    assert!(
        !msg.headers
            .contains_key(&crate::edge::dial::HDR_CRYPTO_METHOD)
    );
    // Deferred options absent.
    assert!(!msg.headers.contains_key(&1004)); // Cost
    assert!(!msg.headers.contains_key(&1005)); // Precedence
    assert!(!msg.headers.contains_key(&1006)); // TerminatorIdentity
}

#[test]
fn build_bind_with_pubkey_sets_crypto_headers() {
    // 7b will pass Some(pubkey); confirm the branch builds the crypto headers.
    let pk = [9u8; 32];
    let msg = build_bind(1, "jwt", "lid", Some(&pk));
    assert_eq!(
        msg.headers
            .get(&crate::edge::dial::HDR_PUBLIC_KEY)
            .unwrap()
            .as_slice(),
        &pk[..]
    );
    assert_eq!(
        msg.headers
            .get(&crate::edge::dial::HDR_CRYPTO_METHOD)
            .unwrap()
            .as_slice(),
        &[crate::edge::dial::CRYPTO_METHOD_LIBSODIUM]
    );
}

#[test]
fn build_unbind_is_token_body_with_conn_id_no_extra_headers() {
    let msg = build_unbind(5, "bind-jwt");
    assert_eq!(msg.content_type, CT_UNBIND); // 60791
    assert_eq!(msg.body, b"bind-jwt");
    assert_eq!(
        msg.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
        &5u32.to_le_bytes()
    );
    assert_eq!(msg.headers.len(), 1, "Unbind has only the ConnId header");
}

#[test]
fn new_listener_id_is_uuid_v4() {
    let id = new_listener_id();
    assert_eq!(id.len(), 36, "uuid string length: {id}");
    let parts: Vec<&str> = id.split('-').collect();
    assert_eq!(
        parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "uuid 8-4-4-4-12: {id}"
    );
    assert!(parts[2].starts_with('4'), "version 4 nibble: {id}");
    assert!(
        matches!(parts[3].chars().next().unwrap(), '8' | '9' | 'a' | 'b'),
        "variant nibble: {id}"
    );
    assert!(
        id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
        "hex + dashes: {id}"
    );
    assert_ne!(new_listener_id(), new_listener_id(), "random");
}

#[test]
fn classify_bind_reply_maps_each_content_type() {
    assert!(
        classify_bind_reply(crate::channel::message::Message::new(
            CT_STATE_CONNECTED,
            vec![]
        ))
        .is_ok()
    );
    assert!(matches!(
        classify_bind_reply(crate::channel::message::Message::new(CT_STATE_CLOSED, b"no bind".to_vec())),
        Err(crate::edge::error::EdgeError::BindRejected(m)) if m == "no bind"
    ));
    assert!(matches!(
        classify_bind_reply(crate::channel::message::Message::new(7, vec![])),
        Err(crate::edge::error::EdgeError::Channel(
            crate::channel::error::ChannelError::UnexpectedContentType(7)
        ))
    ));
}

#[test]
fn build_dial_success_carries_bind_id_and_child_body() {
    let msg = build_dial_success(3, 42);
    assert_eq!(msg.content_type, CT_DIAL_SUCCESS); // 60788
    assert_eq!(
        msg.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
        &3u32.to_le_bytes(),
        "ConnId header = the BIND conn-id"
    );
    assert_eq!(
        msg.body,
        42u32.to_le_bytes(),
        "body = the CHILD conn-id (u32 LE)"
    );
}

#[test]
fn build_dial_failed_carries_bind_id_and_reason_body() {
    let msg = build_dial_failed(5, "invalid token");
    assert_eq!(msg.content_type, CT_DIAL_FAILED); // 60789
    assert_eq!(
        msg.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
        &5u32.to_le_bytes()
    );
    assert_eq!(msg.body, b"invalid token");
}
