//! Bind wire vocabulary: the router-observable bytes of the bind path — the Bind/Unbind/Dial
//! content-types and header ids, the four message constructors (`build_bind`/`build_unbind`/
//! `build_dial_success`/`build_dial_failed`), the `ListenerId` generator and the bind-reply
//! classifier. Oracle: sdk-golang `ziti/edge/messages.go` (`NewBindMsg`/`NewUnbindMsg`/
//! `NewDialSuccessMsg`/`NewDialFailedMsg`), `ziti/edge/network/hosting_conn.go:482-491` (the
//! classifier's order) and `pb/edge_client_pb/edge_client.pb.go` (the literal values).

use crate::channel::error::ChannelError;
use crate::channel::message::Message;
use crate::edge::dial::{
    CRYPTO_METHOD_LIBSODIUM, CT_STATE_CLOSED, CT_STATE_CONNECTED, HDR_CONN_ID, HDR_CRYPTO_METHOD,
    HDR_PUBLIC_KEY, HDR_USE_XGRESS_TO_SDK,
};
use crate::edge::error::EdgeError;

/// Bind/Unbind content types (proto `ContentType_*`). Verified in source.
pub const CT_BIND: i32 = 60790;
pub const CT_UNBIND: i32 = 60791;
/// Async "terminator established" signal (proto `ContentType_BindSuccess`). The router
/// sends it after `StateConnected` because we advertise `SupportsBindSuccess`. 7a does NOT
/// register the bind conn-id in the mux, so the rx-loop discards it; full handling is 7b.
pub const CT_BIND_SUCCESS: i32 = 60800;

/// Serve-side dial content types (proto `ContentType_*`, `edge_client.pb.go:40-42`). The router
/// sends `Dial` to our bind conn-id when a client dials the hosted service; we reply
/// `DialSuccess` (accept) or `DialFailed` (reject). Slice 7b-1 (plaintext serve).
pub const CT_DIAL: i32 = 60787;
pub const CT_DIAL_SUCCESS: i32 = 60788;
pub const CT_DIAL_FAILED: i32 = 60789;

/// Bind header IDs (proto `HeaderId_*`).
pub const HDR_SUPPORTS_INSPECT: i32 = 1023;
pub const HDR_SUPPORTS_BIND_SUCCESS: i32 = 1024;
pub const HDR_ROUTER_PROVIDED_CONN_ID: i32 = 1012;
pub const HDR_LISTENER_ID: i32 = 1021;

/// A random UUID v4 string (`8-4-4-4-12` hex), mirroring the Go SDK's `uuid.NewString()`
/// (ziti.go:2219, set unconditionally as the ListenerId). The router does not interpret
/// its value; it identifies this listener across reconnects (multi-listener dedup/HA).
#[must_use]
pub fn new_listener_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS RNG available");
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Build the edge Bind message: body = the Bind-session token, header `ConnId` (uint32 LE),
/// the four always-on bool flags (`SupportsInspect`=1, `SupportsBindSuccess`=1,
/// `UseXgressToSdk`=0, `RouterProvidedConnId`=1), and `ListenerId` (string). When `pubkey` is
/// `Some` (slice 7b), add `PublicKey` + `CryptoMethod`. The caller sets `sequence` at send
/// time. Oracle: `NewBindMsg` (edge/messages.go:327).
#[must_use]
pub fn build_bind(
    conn_id: u32,
    token: &str,
    listener_id: &str,
    pubkey: Option<&[u8; 32]>,
) -> Message {
    let mut msg = Message::new(CT_BIND, token.as_bytes().to_vec());
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    msg.headers.insert(HDR_SUPPORTS_INSPECT, vec![1u8]);
    msg.headers.insert(HDR_SUPPORTS_BIND_SUCCESS, vec![1u8]);
    msg.headers.insert(HDR_USE_XGRESS_TO_SDK, vec![0u8]);
    msg.headers.insert(HDR_ROUTER_PROVIDED_CONN_ID, vec![1u8]);
    msg.headers
        .insert(HDR_LISTENER_ID, listener_id.as_bytes().to_vec());
    if let Some(pk) = pubkey {
        msg.headers.insert(HDR_PUBLIC_KEY, pk.to_vec());
        msg.headers
            .insert(HDR_CRYPTO_METHOD, vec![CRYPTO_METHOD_LIBSODIUM]);
    }
    msg
}

/// Build the edge Unbind message: content-type 60791, body = the Bind-session token,
/// header `ConnId` (uint32 LE), no other headers. Oracle: `NewUnbindMsg` (messages.go:363).
#[must_use]
pub fn build_unbind(conn_id: u32, token: &str) -> Message {
    let mut msg = Message::new(CT_UNBIND, token.as_bytes().to_vec());
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    msg
}

/// Build the `DialSuccess` reply (accept an incoming dial): content-type 60788, header
/// `ConnId` = the BIND conn-id, body = the CHILD conn-id (uint32 LE). The caller sets
/// `sequence` and the `ReplyFor` header (= the Dial's sequence). Oracle: `NewDialSuccessMsg`
/// (messages.go:384) + `dialSucceeded` (`ziti/edge/network/conn.go:989`).
#[must_use]
pub fn build_dial_success(bind_conn_id: u32, child_conn_id: u32) -> Message {
    let mut msg = Message::new(CT_DIAL_SUCCESS, child_conn_id.to_le_bytes().to_vec());
    msg.headers
        .insert(HDR_CONN_ID, bind_conn_id.to_le_bytes().to_vec());
    msg
}

/// Build the `DialFailed` reply: content-type 60789, header `ConnId` = `conn_id`, body = the reason
/// string. The caller sets `sequence` and the `ReplyFor` header (= the Dial's sequence). Oracle:
/// `NewDialFailedMsg` (messages.go:391).
///
/// ⚠ **`conn_id` is NOT always the bind's, and the oracle's two producers disagree ON PURPOSE:**
/// - the pre-target REJECTS (`accept_pending`) and `complete_failed` carry the **BIND** conn-id
///   (`dialFailed`, `self.conn.Id()` with `self.conn` = the `edgeHostConn`,
///   `ziti/edge/network/conn.go:971`);
/// - the start-handshake failure of `complete_success` carries the **CHILD** conn-id
///   (`CompleteAcceptSuccess`, `conn.Id()` with `conn` = the child `edgeConn` the accept-complete
///   handler hangs off, `conn.go:902` + `hosting_conn.go:385`).
///
/// This builder therefore takes whatever `u32` the caller decides; naming it `bind_conn_id` would be
/// a lie at one of the two sites.
#[must_use]
pub fn build_dial_failed(conn_id: u32, reason: &str) -> Message {
    let mut msg = Message::new(CT_DIAL_FAILED, reason.as_bytes().to_vec());
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    msg
}

/// Classify the bind reply (correlated by sequence): `StateConnected` → Ok; `StateClosed`
/// → `BindRejected(body)`; anything else → `UnexpectedContentType`. Oracle:
/// `edgeHostConn.listen` (network/hosting_conn.go:482-491).
///
/// # Errors
/// `EdgeError::BindRejected` on StateClosed; `EdgeError::Channel` on any other type.
#[allow(clippy::needless_pass_by_value)]
pub fn classify_bind_reply(reply: Message) -> Result<(), EdgeError> {
    match reply.content_type {
        CT_STATE_CONNECTED => Ok(()),
        CT_STATE_CLOSED => Err(EdgeError::BindRejected(
            String::from_utf8_lossy(&reply.body).into_owned(),
        )),
        other => Err(EdgeError::Channel(ChannelError::UnexpectedContentType(
            other,
        ))),
    }
}
