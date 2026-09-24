//! Tests del exchange OIDC dedupeado (`do_oidc_session_refresh`: rotación write-back, dedup
//! stale-skip y el merge `.or(prior_refresh)`).
//! (F6 tramo 7: movidos verbatim del monolito de `edge/refresh`.)

use super::*;

use std::sync::{Arc, RwLock};

use crate::edge::auth_token::AuthToken;

/// The shared helper [`do_oidc_session_refresh`] write-back THROUGH ROTATION (the green-but-broken
/// guard): a wiremock token endpoint that ROTATES and REJECTS the stale refresh. Exchange #1 with
/// `refresh1` → 200 `{access2, refresh2}`; a SECOND exchange presenting `refresh1` → 400; presenting
/// `refresh2` → 200 `{access3, refresh3}`. Driving the helper A→B→C asserts the SDK stored BOTH the
/// rotated access AND the rotated refresh AND the new expiry each round. A missing refresh
/// write-back → the 2nd call re-sends `refresh1` → 400 → RED.
#[tokio::test]
async fn oidc_session_refresh_writes_back_rotated_refresh() {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // refresh1 → {access2, refresh2}. A stale refresh1 presented again (after rotation) → 400.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .and(body_string_contains("subject_token=refresh1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"access2","refresh_token":"refresh2","expires_in":1799}"#,
        ))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    // refresh2 → {access3, refresh3}.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .and(body_string_contains("subject_token=refresh2"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"access3","refresh_token":"refresh3","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    // Any OTHER subject (a re-sent stale refresh1 after its single use, or a non-rotated SDK) → 400.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(400).set_body_string("invalid_grant"))
        .mount(&server)
        .await;

    let token = Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: "access1".into(),
        refresh: Some("refresh1".into()),
    })));
    let expires = Arc::new(RwLock::new(None));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let http = reqwest::Client::new();
    let oidc_base = server.uri();

    // A → B: refresh1 → access2/refresh2, new expiry stored.
    do_oidc_session_refresh(&token, &expires, &lock, &http, &oidc_base, "access1")
        .await
        .expect("exchange #1 (refresh1) succeeds");
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("access2"),
        "access rotated to access2"
    );
    assert_eq!(
        read_token(&token).and_then(|t| t.refresh_token().map(str::to_string)),
        Some("refresh2".to_string()),
        "refresh ROTATED to refresh2 (written back)"
    );
    assert!(
        expires.read().unwrap().is_some(),
        "the new expiry was stored on exchange #1"
    );

    // B → C: the re-check key is now access2; refresh2 → access3/refresh3. If the write-back of
    // refresh2 were missing, this would re-send refresh1 → 400 → the expect below fails.
    do_oidc_session_refresh(&token, &expires, &lock, &http, &oidc_base, "access2")
        .await
        .expect("exchange #2 (refresh2) succeeds — proves refresh2 was written back");
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("access3"),
        "access rotated to access3"
    );
    assert_eq!(
        read_token(&token).and_then(|t| t.refresh_token().map(str::to_string)),
        Some("refresh3".to_string()),
        "refresh rotated to refresh3"
    );
}

/// DEDUP — the helper's re-check skips a STALE write across an OIDC access rotation. One real
/// rotation (A→B: access1→access2) followed by a STALE call still carrying `token_used = access1`,
/// which must SKIP (the endpoint is not hit a second time, the token stays access2). The
/// re-check compares the failed op's access against the CURRENT access, so a stale value is caught.
/// (The genuine two-rotation write-back property A→B→C lives in
/// `oidc_session_refresh_writes_back_rotated_refresh`; this test is one-rotation-plus-stale-skip.)
/// Mutation: dropping the re-check → the stale call reads refresh2 and rotates to access3 → the
/// token-stays-access2 assertion + the `expect(0)` on the refresh2 exchange go RED.
#[tokio::test]
async fn oidc_session_refresh_dedup_skips_stale() {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // refresh1 → {access2, refresh2}. The ONLY legitimate exchange in this test.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .and(body_string_contains("subject_token=refresh1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"access2","refresh_token":"refresh2","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;
    // If the re-check were dropped, the stale call would read refresh2 and exchange it → catch it.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .and(body_string_contains("subject_token=refresh2"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"access3","refresh_token":"refresh3","expires_in":1799}"#,
        ))
        .expect(0)
        .mount(&server)
        .await;

    let token = Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: "access1".into(),
        refresh: Some("refresh1".into()),
    })));
    let expires = Arc::new(RwLock::new(None));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let http = reqwest::Client::new();
    let oidc_base = server.uri();

    // A→B: the real refresh rotates access1 → access2.
    do_oidc_session_refresh(&token, &expires, &lock, &http, &oidc_base, "access1")
        .await
        .expect("the live refresh rotates the token");
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("access2")
    );

    // A stale caller still carrying access1 (B→C window): the re-check finds access2 ≠ access1 →
    // SKIP (no exchange). The token stays access2.
    do_oidc_session_refresh(&token, &expires, &lock, &http, &oidc_base, "access1")
        .await
        .expect("a stale-token refresh is a no-op (Ok skip)");
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("access2"),
        "the stale refresh did NOT rotate the token (the re-check skipped it)"
    );
    // `expect(1)` on refresh1 + `expect(0)` on refresh2 verified on drop.
}

/// MERGE FALLBACK (spec §5 step 5): a token-exchange 200 that OMITS `refresh_token` (never seen
/// live, but a one-off omission must not strand the session) keeps the PRIOR refresh — the access
/// still rotates. Asserts the stored token is the new access AND the refresh stayed the prior one.
/// Mutation: dropping the `.or(prior_refresh)` merge (`let new_refresh = refreshed.refresh;`) →
/// the refresh becomes `None` → RED. (The rotation tests above always return a refresh, so ONLY
/// this test guards the fallback.)
#[tokio::test]
async fn oidc_session_refresh_keeps_prior_refresh_when_response_omits_it() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // A 200 with NO refresh_token (the controller omitted it).
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"access_token":"access2","expires_in":1799}"#),
        )
        .mount(&server)
        .await;

    let token = Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: "access1".into(),
        refresh: Some("refresh1".into()),
    })));
    let expires = Arc::new(RwLock::new(None));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let http = reqwest::Client::new();

    do_oidc_session_refresh(&token, &expires, &lock, &http, &server.uri(), "access1")
        .await
        .expect("refresh with an omitted refresh_token still succeeds");

    // The access ROTATED, but the prior refresh was KEPT (the .or fallback).
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("access2"),
        "the access rotated even though the response omitted the refresh"
    );
    assert_eq!(
        read_token(&token).and_then(|t| t.refresh_token().map(str::to_string)),
        Some("refresh1".to_string()),
        "a missing refresh in the response KEEPS the prior refresh (.or fallback)"
    );
}

// The NO-CLEAR fidelity assertion lives at the client level (`oidc_reactive_refresh_keeps_dial_cache`
// in `edge::client` tests): the helper signature here structurally CANNOT clear the Dial cache (it
// takes no `dial_sessions`), so the load-bearing mutation target — routing the OIDC reactive 401
// through `reauthenticate` (which clears) instead of `oidc_session_refresh` — is exercised there.
