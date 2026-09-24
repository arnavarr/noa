//! Tests de las primitivas de token-state (`store_token_and_expiry`, `guarded_store_refresh`).
//! (F6 tramo 7: movidos verbatim del monolito de `edge/refresh`.)

use super::*;

use std::sync::{Arc, RwLock};

use crate::edge::auth_token::AuthToken;

/// The §4.3-class fix: `store_token_and_expiry` writes BOTH the token and the parsed expiry to the
/// shared `Arc`s; an unparseable expiry stores `None` (the timer then uses its DEFAULT).
#[test]
fn store_token_and_expiry_writes_both_arcs() {
    let token = Arc::new(RwLock::new(None));
    let expires = Arc::new(RwLock::new(None));

    store_token_and_expiry(
        &token,
        &expires,
        AuthToken::Legacy("TOK".into()),
        Some("2026-06-17T12:00:00Z"),
    );
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("TOK")
    );
    assert!(
        expires.read().unwrap().is_some(),
        "a valid expiry is parsed and stored"
    );

    store_token_and_expiry(
        &token,
        &expires,
        AuthToken::Legacy("TOK2".into()),
        Some("garbage"),
    );
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("TOK2")
    );
    assert!(
        expires.read().unwrap().is_none(),
        "an unparseable expiry stores None"
    );

    store_token_and_expiry(&token, &expires, AuthToken::Legacy("TOK3".into()), None);
    assert!(
        expires.read().unwrap().is_none(),
        "an absent expiry stores None"
    );
}

/// §3.6 MANDATED guard — SKIP when the token already rotated: a concurrent reactive re-auth
/// rotated `stale → fresh`; a timer GET-write issued with `token_used = stale` must be SKIPPED
/// (the `reauth_lock` + token re-check), so the re-auth's fresh token WINS and the GET value does
/// NOT clobber it. This is the production guard (`guarded_store_refresh`, used by `run_refreshes`).
/// Mutation: drop the re-check → the GET value clobbers `fresh` → this goes RED.
#[tokio::test]
async fn guarded_get_write_skips_stale() {
    // a re-auth already rotated it to "fresh"
    let token = Arc::new(RwLock::new(Some(AuthToken::Legacy("fresh".to_string()))));
    let expires = Arc::new(RwLock::new(None));
    let lock = Arc::new(tokio::sync::Mutex::new(()));

    let stored = guarded_store_refresh(
        &token,
        &expires,
        &lock,
        "stale",
        AuthToken::Legacy("stale-get-value".into()),
        None,
    )
    .await;

    assert!(!stored, "the stale GET write was skipped");
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("fresh"),
        "the re-auth's fresh token wins; the stale GET value did NOT clobber it"
    );
}

/// §3.6 guard — STORE when the token still matches: no concurrent re-auth, so the live token still
/// equals `token_used` → the GET-refresh's token+expiry are persisted.
#[tokio::test]
async fn guarded_get_write_stores_when_token_matches() {
    let token = Arc::new(RwLock::new(Some(AuthToken::Legacy("live".to_string()))));
    let expires = Arc::new(RwLock::new(None));
    let lock = Arc::new(tokio::sync::Mutex::new(()));

    let stored = guarded_store_refresh(
        &token,
        &expires,
        &lock,
        "live",
        AuthToken::Legacy("refreshed".into()),
        Some("2099-01-01T00:00:00Z"),
    )
    .await;

    assert!(stored, "the matching GET write was stored");
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("refreshed")
    );
    assert!(
        expires.read().unwrap().is_some(),
        "the new expiry was persisted"
    );
}
