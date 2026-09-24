//! Tests de `token` (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`).

use super::testsupport::make_jwt;
use super::token::*;

/// `parse_token_response` extracts access/refresh/expires_in and the identity name from the
/// id_token, validating the nonce. The shape mirrors the live `/oidc/oauth/token` 200.
#[test]
fn parse_token_response_extracts_tokens_and_name() {
    let id_token = make_jwt(r#"{"name":"alice","nonce":"NON5"}"#);
    let body = format!(
        r#"{{"access_token":"ey.acc","refresh_token":"ey.ref","expires_in":1800,"id_token":"{id_token}","token_type":"Bearer"}}"#
    );
    let t = parse_token_response(&body, "NON5").unwrap();
    assert_eq!(t.access, "ey.acc");
    assert_eq!(t.refresh.as_deref(), Some("ey.ref"));
    assert_eq!(t.expires_in, 1800);
    assert_eq!(t.identity_name.as_deref(), Some("alice"));
}

/// A nonce mismatch in the id_token is rejected (binds the request to the token, oracle `:477`).
#[test]
fn parse_token_response_rejects_nonce_mismatch() {
    let id_token = make_jwt(r#"{"name":"alice","nonce":"WRONG"}"#);
    let body = format!(r#"{{"access_token":"a","expires_in":1,"id_token":"{id_token}"}}"#);
    assert!(
        parse_token_response(&body, "NON5").is_err(),
        "nonce mismatch must be rejected"
    );
}

/// An empty refresh token is normalised to None (faithful to `omitempty` style). The id_token is
/// PRESENT with a matching nonce (the nonce check is unconditional). Absent `name` claim → None.
#[test]
fn parse_token_response_handles_empty_refresh() {
    let id_token = make_jwt(r#"{"nonce":"NON5"}"#);
    let body = format!(
        r#"{{"access_token":"a","refresh_token":"","expires_in":5,"id_token":"{id_token}"}}"#
    );
    let t = parse_token_response(&body, "NON5").unwrap();
    assert_eq!(t.access, "a");
    assert!(t.refresh.is_none(), "empty refresh → None");
    assert!(t.identity_name.is_none(), "no name claim → no name");
}

/// An ABSENT id_token is rejected: the oracle's nil `IDTokenClaims` has `Nonce == ""`, which never
/// matches the non-empty flow nonce → it errors. We mirror that (the unconditional nonce check —
/// no id_token, no anti-replay binding, reject). The OIDC-1 review fix.
#[test]
fn parse_token_response_rejects_missing_id_token() {
    let body = r#"{"access_token":"a","refresh_token":"","expires_in":5}"#;
    assert!(
        parse_token_response(body, "NON5").is_err(),
        "a missing id_token must be rejected (unconditional nonce check)"
    );
}
