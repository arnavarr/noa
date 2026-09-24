//! Edge dial: the Connect message (Connect -> StateConnected). Oracle:
//! sdk-golang `ziti/edge/network/conn.go` (`edgeConn.Connect`) + `ziti/edge/conn.go`
//! (`MsgChannel.WriteTraced`/`NewDataMsg` via `edge/messages.go`). Plaintext only
//! (encryptionRequired=false); crypto headers are slice 5.

use base64::Engine;

use crate::channel::error::ChannelError;
use crate::channel::message::Message;
use crate::edge::error::EdgeError;

/// Edge dial content types (proto `ContentType_*`). Confirmed in source + live.
pub const CT_CONNECT: i32 = 60783;
pub const CT_STATE_CONNECTED: i32 = 60784;
pub const CT_STATE_CLOSED: i32 = 60785;

/// Edge dial header IDs (proto `HeaderId_*`).
pub const HDR_CONN_ID: i32 = 1000;
pub const HDR_CONNECTION_MARKER: i32 = 1025;
pub const HDR_CIRCUIT_ID: i32 = 1026;
pub const HDR_USE_XGRESS_TO_SDK: i32 = 1028;

/// Crypto headers (proto `HeaderId_PublicKey` / `HeaderId_CryptoMethod`). Slice 5.
pub const HDR_PUBLIC_KEY: i32 = 1003;
pub const HDR_CRYPTO_METHOD: i32 = 1009;
/// `CryptoMethod` value for libsodium (crypto_kx + secretstream). The only method we support.
pub const CRYPTO_METHOD_LIBSODIUM: u8 = 0;

/// `CallerId` header (proto `HeaderId_CallerId` = 1008). Carries the dialer's identity NAME
/// so the host can see who connected. Oracle: `ziti/edge/messages.go:91` + `NewConnectMsg`
/// (`messages.go:301`, only set when non-empty).
pub const HDR_CALLER_ID: i32 = 1008;

/// `AppData` header (proto `HeaderId_AppData` = 1011). Carries opaque application data the dialer
/// attaches to the Connect; the router relays it verbatim and the HOST reads it on accept to drive a
/// dynamic dial target (the tunneler's `forwardAddress`/`forwardPort`). The SDK ports it as a
/// JSON `string`→`string` map of `dst_*` keys (see [`build_app_data`]). Oracle:
/// `ziti/edge/messages.go:94` (`AppDataHeader = HeaderId_AppData`) + `NewConnectMsg`
/// (`messages.go:304-306`, set when non-nil) + the host read in `hosting_conn.go:309`.
pub const HDR_APPDATA: i32 = 1011;

/// AppData JSON keys (tunneler `dst_*`). Byte-for-byte the oracle's `tunnel/const.go` constants, so a
/// noa dialer and a Go host (or vice-versa) interoperate. Oracle: `ziti/tunnel/const.go:4-8`.
pub const APPDATA_KEY_PROTOCOL: &str = "dst_protocol";
pub const APPDATA_KEY_HOSTNAME: &str = "dst_hostname";
pub const APPDATA_KEY_IP: &str = "dst_ip";
pub const APPDATA_KEY_PORT: &str = "dst_port";
pub const APPDATA_KEY_SOURCE_ADDR: &str = "source_addr";

/// Edge data content type + headers/flags (proto). Confirmed in source + live.
pub const CT_DATA: i32 = 60786;
pub const HDR_SEQ: i32 = 1001;
pub const HDR_FLAGS: i32 = 1010;
pub const FLAG_FIN: u32 = 1;
pub const FLAG_MULTIPART: u32 = 4;
pub const FLAG_MULTIPART_MSG: u32 = 16;

/// Build the edge Connect message: body = the per-service session JWT, header `ConnId`
/// (uint32 LE), `ConnectionMarker` (string), `UseXgressToSdk` = false. When `pubkey` is
/// `Some`, add `PublicKey` (32 raw bytes) + `CryptoMethod` (1 byte, libsodium) for e2e
/// encryption. When `caller_id` is `Some(non-empty)`, add the `CallerId` header (1008)
/// with the dialer's identity name. When `app_data` is `Some`, add the `AppData` header (1011)
/// with the opaque bytes (the host reads it to drive a dynamic dial target). The caller sets the
/// `sequence` at send time. Oracle: `NewConnectMsg` (edge/messages.go:291).
#[must_use]
pub fn build_connect(
    conn_id: u32,
    token: &str,
    marker: &str,
    pubkey: Option<&[u8; 32]>,
    caller_id: Option<&str>,
    app_data: Option<&[u8]>,
) -> Message {
    let mut msg = Message::new(CT_CONNECT, token.as_bytes().to_vec());
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    msg.headers
        .insert(HDR_CONNECTION_MARKER, marker.as_bytes().to_vec());
    msg.headers.insert(HDR_USE_XGRESS_TO_SDK, vec![0u8]);
    if let Some(pk) = pubkey {
        msg.headers.insert(HDR_PUBLIC_KEY, pk.to_vec());
        msg.headers
            .insert(HDR_CRYPTO_METHOD, vec![CRYPTO_METHOD_LIBSODIUM]);
    }
    // CallerId only if non-empty (mirrors `if options.CallerId != ""`, messages.go:301).
    if let Some(name) = caller_id.filter(|n| !n.is_empty()) {
        msg.headers.insert(HDR_CALLER_ID, name.as_bytes().to_vec());
    }
    // AppData only when supplied (mirrors `if options.AppData != nil`, messages.go:304).
    if let Some(bytes) = app_data {
        msg.headers.insert(HDR_APPDATA, bytes.to_vec());
    }
    msg
}

/// Marshal the tunneler's destination appData as a JSON `string`→`string` map, equivalent to the
/// oracle's `GetAppInfo` (`tunnel/tunnel.go:72-84`) FOR THE IP/ASCII PATH: `dst_protocol`/`dst_ip`/
/// `dst_port` are always present, `dst_hostname`/`source_addr` are omitted when empty. Values are
/// STRINGS (the host's `getValue` asserts `.(string)`; e.g. `dst_port` is the decimal port string
/// `"19009"`, NOT a number). NOTE: this is not byte-identical to Go's `encoding/json` for ALL inputs —
/// serde does not HTML-escape `<`/`>`/`&`/U+2028/U+2029 the way Go does — but it is semantically
/// transparent under the host's `json.Unmarshal`, and the IP/ASCII `dst_*` values T4b-1 emits contain
/// none of those bytes, so the wire is identical for this slice.
///
/// T4b-1 emits the IP path: a caller passes `dst_ip` + `dst_port` (+ the fixed protocol), exercising
/// the host's `GetAddress` `dst_ip` fallback branch. `dst_hostname` (the deferred string-matched path)
/// and `source_addr` are accepted here but the T4b-1 host resolver rejects a `dst_hostname` dial loudly.
///
/// Returns the JSON bytes to put in the Connect's [`HDR_APPDATA`] header. A `BTreeMap` gives a
/// deterministic key order (the oracle's `map[string]string` order is irrelevant — the host parses by
/// key — but determinism keeps the wire test stable).
#[must_use]
pub fn build_app_data(
    protocol: &str,
    dst_ip: &str,
    dst_port: &str,
    dst_hostname: Option<&str>,
    source_addr: Option<&str>,
) -> Vec<u8> {
    let mut map: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    map.insert(APPDATA_KEY_PROTOCOL, protocol);
    if let Some(h) = dst_hostname.filter(|h| !h.is_empty()) {
        map.insert(APPDATA_KEY_HOSTNAME, h);
    }
    map.insert(APPDATA_KEY_IP, dst_ip);
    map.insert(APPDATA_KEY_PORT, dst_port);
    if let Some(s) = source_addr.filter(|s| !s.is_empty()) {
        map.insert(APPDATA_KEY_SOURCE_ADDR, s);
    }
    serde_json::to_vec(&map).expect("a string->string BTreeMap always serializes")
}

/// Build a Data frame: content-type 60786, header `ConnId` (u32 LE), body=data.
/// The FIRST frame of a connection advertises `Flags = MULTIPART(4)` (it indicates
/// the client can accept multipart messages). No `Seq` header. Oracle:
/// `MsgChannel.WriteTraced` (ziti/edge/conn.go:186) + `NewDataMsg` (messages.go:237).
/// The caller sets `sequence` at send time.
#[must_use]
pub fn build_data(conn_id: u32, data: &[u8], first: bool) -> Message {
    let mut msg = Message::new(CT_DATA, data.to_vec());
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    if first {
        msg.headers
            .insert(HDR_FLAGS, FLAG_MULTIPART.to_le_bytes().to_vec());
    }
    msg
}

/// Build a StateClosed frame (content-type 60785, `ConnId`, empty body) to tell the
/// router we are closing the connection. Oracle: `NewStateClosedMsg` (messages.go:317).
#[must_use]
pub fn build_state_closed(conn_id: u32) -> Message {
    let mut msg = Message::new(CT_STATE_CLOSED, Vec::new());
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    msg
}

/// Classify the dial reply: `StateConnected` → Ok(reply); `StateClosed` →
/// `DialRejected(body)`; anything else → `UnexpectedContentType`. Oracle:
/// `edgeConn.Connect` (`ziti/edge/network/conn.go:583-590`).
///
/// # Errors
/// `EdgeError::DialRejected` on StateClosed; `EdgeError::Channel` on any other type.
pub fn classify_dial_reply(reply: Message) -> Result<Message, EdgeError> {
    match reply.content_type {
        CT_STATE_CONNECTED => Ok(reply),
        CT_STATE_CLOSED => Err(EdgeError::DialRejected(
            String::from_utf8_lossy(&reply.body).into_owned(),
        )),
        other => Err(EdgeError::Channel(ChannelError::UnexpectedContentType(
            other,
        ))),
    }
}

/// An 8-char base64url connection marker (base64url of 6 random bytes), mirroring
/// the Go SDK's `newMarker`. Informational (tracing); the router does not validate it.
#[must_use]
pub fn new_marker() -> String {
    let mut buf = [0u8; 6];
    getrandom::fill(&mut buf).expect("OS RNG available");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::message::{CT_HELLO, Message};

    #[test]
    fn build_connect_assembles_connect_message() {
        let msg = build_connect(1, "dummy-jwt", "probe123", None, None, None);
        let mut expected = Message::new(CT_CONNECT, b"dummy-jwt".to_vec());
        expected
            .headers
            .insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
        expected
            .headers
            .insert(HDR_CONNECTION_MARKER, b"probe123".to_vec());
        expected.headers.insert(HDR_USE_XGRESS_TO_SDK, vec![0u8]);
        assert_eq!(msg, expected);
        // ConnId is uint32 LE; body is the session token; no crypto headers.
        assert_eq!(msg.content_type, CT_CONNECT);
        assert_ne!(msg.content_type, CT_HELLO);
        assert!(!msg.headers.contains_key(&1003)); // PublicKey absent (plaintext)
        assert!(!msg.headers.contains_key(&HDR_CALLER_ID)); // CallerId absent when None
        assert!(!msg.headers.contains_key(&HDR_APPDATA)); // AppData absent when None
    }

    #[test]
    fn build_connect_with_pubkey_sets_crypto_headers() {
        let pk = [7u8; 32];
        let msg = build_connect(1, "jwt", "marker12", Some(&pk), None, None);
        assert_eq!(
            msg.headers.get(&HDR_PUBLIC_KEY).unwrap().as_slice(),
            &pk[..]
        );
        assert_eq!(
            msg.headers.get(&HDR_CRYPTO_METHOD).unwrap().as_slice(),
            &[CRYPTO_METHOD_LIBSODIUM]
        );
        // Plaintext base headers still present.
        assert_eq!(msg.content_type, CT_CONNECT);
        assert_eq!(msg.body, b"jwt");
    }

    #[test]
    fn new_marker_is_eight_base64url_chars() {
        let m = new_marker();
        assert_eq!(m.len(), 8, "base64url of 6 bytes is 8 chars: {m}");
        assert!(
            m.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "base64url charset: {m}"
        );
        assert_ne!(new_marker(), new_marker(), "markers are random");
    }

    #[test]
    fn parses_real_state_connected_fixture() {
        let bytes = include_bytes!("../../tests/fixtures/channel_stateconnected_recv.bin");
        let msg = crate::channel::message::parse_frame(bytes).expect("real StateConnected parses");
        assert_eq!(msg.content_type, CT_STATE_CONNECTED);
        assert_eq!(
            msg.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
            &[1, 0, 0, 0]
        );
        assert_eq!(msg.headers.get(&1).unwrap().as_slice(), &[1, 0, 0, 0]); // ReplyFor == 1
        assert!(
            msg.headers.contains_key(&HDR_CIRCUIT_ID),
            "circuit id present"
        );
        assert!(msg.body.is_empty());
    }

    #[test]
    fn build_data_first_frame_sets_multipart_no_seq() {
        let first = build_data(7, b"abc", true);
        assert_eq!(first.content_type, CT_DATA);
        assert_eq!(
            first.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
            &[7, 0, 0, 0]
        );
        assert_eq!(
            first.headers.get(&HDR_FLAGS).unwrap().as_slice(),
            &[4, 0, 0, 0]
        ); // MULTIPART
        assert!(!first.headers.contains_key(&HDR_SEQ)); // no Seq on Data writes
        assert_eq!(first.body, b"abc");
        let next = build_data(7, b"de", false);
        assert!(!next.headers.contains_key(&HDR_FLAGS)); // only the first frame flags
        assert_eq!(next.body, b"de");
    }

    #[test]
    fn build_state_closed_is_empty_with_conn_id() {
        let m = build_state_closed(9);
        assert_eq!(m.content_type, CT_STATE_CLOSED);
        assert_eq!(
            m.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
            &[9, 0, 0, 0]
        );
        assert!(m.body.is_empty());
    }

    #[test]
    fn classify_dial_reply_maps_each_content_type() {
        let mut ok = Message::new(CT_STATE_CONNECTED, vec![]);
        ok.headers.insert(HDR_CIRCUIT_ID, b"circ".to_vec());
        assert_eq!(
            classify_dial_reply(ok).unwrap().content_type,
            CT_STATE_CONNECTED
        );

        let closed = Message::new(CT_STATE_CLOSED, b"no terminators".to_vec());
        assert!(matches!(
            classify_dial_reply(closed),
            Err(crate::edge::error::EdgeError::DialRejected(m)) if m == "no terminators"
        ));

        let weird = Message::new(7, vec![]);
        assert!(matches!(
            classify_dial_reply(weird),
            Err(crate::edge::error::EdgeError::Channel(
                crate::channel::error::ChannelError::UnexpectedContentType(7)
            ))
        ));
    }

    #[test]
    fn build_connect_sets_caller_id_when_present() {
        let msg = build_connect(1, "jwt", "marker12", None, Some("alice"), None);
        assert_eq!(
            msg.headers.get(&HDR_CALLER_ID).unwrap().as_slice(),
            b"alice",
            "CallerId is the raw identity-name bytes"
        );
    }

    #[test]
    fn build_connect_omits_caller_id_when_none_or_empty() {
        let none = build_connect(1, "jwt", "marker12", None, None, None);
        assert!(!none.headers.contains_key(&HDR_CALLER_ID));
        // Empty name sends NO header (mirrors Go's `if options.CallerId != ""`).
        let empty = build_connect(1, "jwt", "marker12", None, Some(""), None);
        assert!(!empty.headers.contains_key(&HDR_CALLER_ID));
    }

    #[test]
    fn build_connect_sets_app_data_header_when_present() {
        let app = build_app_data("tcp", "127.0.0.1", "19009", None, None);
        let msg = build_connect(1, "jwt", "marker12", None, None, Some(&app));
        assert_eq!(
            msg.headers.get(&HDR_APPDATA).unwrap().as_slice(),
            app.as_slice(),
            "AppData header carries the opaque appData bytes verbatim"
        );
        // AppData is additive: base headers untouched, no CallerId/crypto.
        assert!(!msg.headers.contains_key(&HDR_CALLER_ID));
        assert!(!msg.headers.contains_key(&HDR_PUBLIC_KEY));
    }

    #[test]
    fn build_app_data_ip_path_is_oracle_get_app_info_shape() {
        // The IP path T4b-1 emits: dst_protocol/dst_ip/dst_port present, dst_hostname/source_addr
        // omitted (mirrors GetAppInfo's omit-when-empty, tunnel.go:72-84). Values are STRINGS
        // (dst_port = "19009", not a number — the host's getValue asserts .(string)).
        let bytes = build_app_data("tcp", "127.0.0.1", "19009", None, None);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 3, "only the 3 always-present keys");
        assert_eq!(obj[APPDATA_KEY_PROTOCOL], serde_json::json!("tcp"));
        assert_eq!(obj[APPDATA_KEY_IP], serde_json::json!("127.0.0.1"));
        assert_eq!(
            obj[APPDATA_KEY_PORT],
            serde_json::json!("19009"),
            "dst_port is a JSON string, not a number"
        );
        assert!(!obj.contains_key(APPDATA_KEY_HOSTNAME));
        assert!(!obj.contains_key(APPDATA_KEY_SOURCE_ADDR));
    }

    #[test]
    fn build_app_data_includes_hostname_and_source_when_non_empty() {
        let bytes = build_app_data(
            "tcp",
            "1.2.3.4",
            "80",
            Some("example.com"),
            Some("10.0.0.1"),
        );
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj[APPDATA_KEY_HOSTNAME], serde_json::json!("example.com"));
        assert_eq!(obj[APPDATA_KEY_SOURCE_ADDR], serde_json::json!("10.0.0.1"));
        // Empty strings are omitted (GetAppInfo's `if dstHostname != ""`).
        let bytes2 = build_app_data("tcp", "1.2.3.4", "80", Some(""), Some(""));
        let v2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();
        assert!(!v2.as_object().unwrap().contains_key(APPDATA_KEY_HOSTNAME));
        assert!(
            !v2.as_object()
                .unwrap()
                .contains_key(APPDATA_KEY_SOURCE_ADDR)
        );
    }

    #[test]
    fn parses_real_data_echo_fixture() {
        let bytes = include_bytes!("../../tests/fixtures/channel_data_recv_1.bin");
        let msg = crate::channel::message::parse_frame(bytes).expect("real Data echo parses");
        assert_eq!(msg.content_type, CT_DATA);
        assert_eq!(
            msg.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
            &[1, 0, 0, 0]
        );
        assert!(!msg.headers.contains_key(&HDR_FLAGS)); // router echoes plain Data, no flags
        assert_eq!(msg.body, b"hello-slice4b\n");
    }
}
