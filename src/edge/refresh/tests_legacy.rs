//! Tests del brazo legacy (`do_reauthenticate`: el ext-jwt falla LOUDLY sin HTTP).
//! (F6 tramo 7: movidos verbatim del monolito de `edge/refresh`.)

use super::*;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::edge::auth_token::AuthToken;
use crate::edge::error::EdgeError;
use crate::edge::reauth::ReauthMethod;

/// `do_reauthenticate` with `ReauthMethod::ExtJwt` fails LOUDLY with [`EdgeError::ExtJwtReauthUnsupported`]
/// (an ext-jwt credential cannot perform a legacy re-auth). The token re-check passes
/// (`token == token_used`), so the match arm is reached — and it MUST error before any HTTP, NOT
/// fabricate a session. Mutation: replace the arm with a fake `do_authenticate` → this goes RED.
#[tokio::test]
async fn do_reauthenticate_ext_jwt_fails_loudly() {
    crate::enroll::trust::ensure_crypto_provider();
    let token = Arc::new(RwLock::new(Some(AuthToken::Legacy("TOK".into()))));
    let expires = Arc::new(RwLock::new(None));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let dial = Arc::new(Mutex::new(HashMap::new()));
    let err = do_reauthenticate(
        &token,
        &expires,
        &lock,
        &dial,
        None,
        // No server is running on this URL — the ExtJwt arm errors BEFORE any request, so the
        // unreachable client is never used. (If the arm ever did an HTTP call this would hang/fail
        // differently, not return ExtJwtReauthUnsupported.)
        &reqwest::Client::new(),
        "https://127.0.0.1:1/edge/client/v1",
        &ReauthMethod::ExtJwt,
        None,
        "TOK",
    )
    .await
    .expect_err("ext-jwt cannot legacy-reauthenticate");
    assert!(
        matches!(err, EdgeError::ExtJwtReauthUnsupported),
        "got {err:?}"
    );
    // The token was NOT rotated (no fabricated session was stored).
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("TOK"),
        "a failed ext-jwt reauth leaves the token untouched"
    );
}
