//! Tests del loop del timer (`run_refreshes`: exchange OIDC, push del rotado, reschedule, park).
//! (F6 tramo 7: movidos verbatim del monolito de `edge/refresh`.)

use super::*;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use crate::edge::auth_token::{ApiSessionType, AuthToken};
use crate::edge::data::CT_UPDATE_TOKEN_SUCCESS;
use crate::edge::reauth::ReauthMethod;

use super::testsupport::push_target;

/// PROACTIVE OIDC refresh (OIDC-3, was a defer): the timer with an OIDC token refreshes via the
/// RFC 8693 token-exchange grant (`POST /oidc/oauth/token`), NOT the legacy GET
/// `/current-api-session`. The starting expiry is in the PAST → `next_sleep` = ZERO → the timer
/// fires ONE exchange immediately; the response carries a real `expires_in` (~30min) so the next
/// `next_sleep` reschedules far beyond the 50ms window (no hot-loop, exactly one exchange).
/// Discriminators preserved: the legacy GET fires ZERO times (`expect(0)`); the token ROTATES to
/// the new access. Mutation: routing OIDC through the legacy GET path → `/current-api-session` hit
/// → `expect(0)` RED; dropping the refresh (parking) → token not rotated + endpoint not hit → RED.
#[tokio::test]
async fn oidc_session_proactive_refresh_does_token_exchange() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // The legacy GET-refresh must NEVER fire for an OIDC session.
    Mock::given(method("GET"))
        .and(path("/current-api-session"))
        .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-HAPPEN"))
        .expect(0)
        .mount(&server)
        .await;
    // The OIDC token-exchange fires EXACTLY once (the ~30min `expires_in` reschedules past the
    // window) and rotates the tokens.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"ey.access2","refresh_token":"ey.refresh2","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let token = Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: "ey.access".into(),
        refresh: Some("ey.refresh1".into()),
    })));
    let expires = Arc::new(RwLock::new(Some(
        // An expiry in the PAST → fire the (OIDC token-exchange) refresh immediately.
        SystemTime::now() - Duration::from_secs(60),
    )));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let dial = Arc::new(Mutex::new(HashMap::new()));
    let tiny = RefreshIntervals {
        lead: Duration::from_millis(1),
        default: Duration::from_millis(2),
        retry: Duration::from_millis(2),
    };
    let handle = tokio::spawn(run_refreshes(
        token.clone(),
        expires,
        lock,
        dial,
        None,
        reqwest::Client::new(),
        // base_url ends in the ztAPI edge path; `oidc_base` strips it to the controller root, so
        // the token-exchange POST lands on `{server.uri()}/oidc/oauth/token`.
        format!("{}/edge/client/v1", server.uri()),
        Arc::new(ReauthMethod::Cert),
        None,
        Arc::new(Mutex::new(Vec::new())),
        tiny,
    ));
    // One exchange fires immediately (ZERO sleep); the ~30min reschedule keeps it at exactly one.
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    // The token ROTATED to the new access (the proactive token-exchange ran), and stayed OIDC.
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("ey.access2"),
        "the OIDC token rotated via the proactive token-exchange refresh"
    );
    assert_eq!(
        read_token(&token).map(|t| t.session_type()),
        Some(ApiSessionType::Oidc),
        "the session stayed OIDC"
    );
    // `expect(0)` on GET /current-api-session + `expect(1)` on /oidc/oauth/token verified on drop.
}

/// SEAM (proactive timer): after the OIDC token-exchange, `run_refreshes` PUSHES the rotated Bearer
/// to the live edge-router channels (the OIDC-2 wiring). A live channel is registered in the
/// `live_channels` the timer is spawned with; after the exchange rotates the access to `ey.rotated`,
/// that channel's router must receive an `UpdateToken` (60803) carrying `ey.rotated`. MUTATION:
/// delete the `push_token_to_live_channels` call from the `Ok(())` arm of `run_refreshes` → the
/// router never sees the 60803 → RED.
#[tokio::test]
async fn oidc_proactive_refresh_pushes_rotated_token_to_live_channels() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"access_token":"ey.rotated","refresh_token":"ey.refresh2","expires_in":1799}"#,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let token = Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: "ey.access".into(),
        refresh: Some("ey.refresh1".into()),
    })));
    let expires = Arc::new(RwLock::new(Some(
        SystemTime::now() - Duration::from_secs(60),
    )));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let dial = Arc::new(Mutex::new(HashMap::new()));
    // A live channel registered with the timer → the proactive push must reach it with the ROTATED
    // bearer (NOT the pre-refresh `ey.access`).
    let (ch, rx) = push_target(CT_UPDATE_TOKEN_SUCCESS);
    let live: LiveChannels = Arc::new(Mutex::new(vec![ch.state_weak()]));
    let tiny = RefreshIntervals {
        lead: Duration::from_millis(1),
        default: Duration::from_millis(2),
        retry: Duration::from_millis(2),
    };
    let handle = tokio::spawn(run_refreshes(
        token.clone(),
        expires,
        lock,
        dial,
        None,
        reqwest::Client::new(),
        format!("{}/edge/client/v1", server.uri()),
        Arc::new(ReauthMethod::Cert),
        None,
        live,
        tiny,
    ));

    let pushed = tokio::time::timeout(Duration::from_secs(2), rx)
        .await
        .expect("the proactive timer pushed to the live channel within the window")
        .unwrap();
    handle.abort();

    assert_eq!(
        pushed,
        Some(b"ey.rotated".to_vec()),
        "the proactive timer pushed the ROTATED Bearer to the registered live channel"
    );
    drop(ch);
}

/// FIX 2 (TR) — PROACTIVE timer on a token-endpoint FAILURE: a non-200 `/oidc/oauth/token`
/// reschedules on `retry` and does NOT hot-loop or panic. The token endpoint 400s; the timer fires
/// the exchange (past expiry → ZERO sleep), gets the error, logs+reschedules `retry`, and on the
/// next wake fires again — so over a bounded window the endpoint is hit ≥1 time (a bounded number,
/// not thousands), the token is NOT rotated, and the task is still alive (no panic propagated). A
/// `retry` of 5ms keeps the count small over the 50ms window. MUTATION CHECK: a panic-on-error
/// (e.g. `.expect()` instead of the `Err` arm) would abort the task → the post-abort assertions
/// (token unchanged) still hold, but a hot-loop (dropping the `retry` sleep) would push the hit
/// count into the hundreds — the bounded `assert!(hits <= …)` pins it.
#[tokio::test]
async fn oidc_session_proactive_refresh_reschedules_on_failure() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    struct CountingFail(Arc<AtomicUsize>);
    impl Respond for CountingFail {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            self.0.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400).set_body_string("invalid_grant")
        }
    }

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    let hits = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(CountingFail(hits.clone()))
        .mount(&server)
        .await;

    let token = Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: "ey.access".into(),
        refresh: Some("ey.refresh1".into()),
    })));
    let expires = Arc::new(RwLock::new(Some(
        // Past expiry → fire immediately on each iteration.
        SystemTime::now() - Duration::from_secs(60),
    )));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let dial = Arc::new(Mutex::new(HashMap::new()));
    let tiny = RefreshIntervals {
        lead: Duration::from_millis(1),
        // A 5ms retry keeps the hit count small but non-zero over the 50ms window.
        default: Duration::from_millis(5),
        retry: Duration::from_millis(5),
    };
    let handle = tokio::spawn(run_refreshes(
        token.clone(),
        expires,
        lock,
        dial,
        None,
        reqwest::Client::new(),
        format!("{}/edge/client/v1", server.uri()),
        Arc::new(ReauthMethod::Cert),
        None,
        Arc::new(Mutex::new(Vec::new())),
        tiny,
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    let n = hits.load(Ordering::SeqCst);
    // The timer kept trying (≥1) but did NOT hot-loop: bounded by the 5ms retry over 50ms.
    assert!(n >= 1, "the timer fired the failing exchange at least once");
    assert!(
        n < 50,
        "the timer reschedules on `retry` (not a hot-loop): {n} hits in 50ms"
    );
    // The token was NOT rotated by a failing exchange.
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("ey.access"),
        "a failing exchange left the OIDC token untouched"
    );
}

/// An OIDC session with NO refresh token cannot token-exchange: the timer PARKS on `default` and
/// neither the legacy GET nor the token-exchange fires (both `expect(0)`). Pins the no-refresh
/// branch (a race / a controller that omitted the refresh). Mutation: dropping the no-refresh park
/// → the timer would call `do_oidc_session_refresh` with no subject → still `Ok` (skip), so the
/// endpoint stays at 0; the park is the cheaper, explicit path.
#[tokio::test]
async fn oidc_session_without_refresh_token_parks() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/current-api-session"))
        .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-HAPPEN"))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-HAPPEN"))
        .expect(0)
        .mount(&server)
        .await;

    let token = Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: "ey.access".into(),
        refresh: None,
    })));
    let expires = Arc::new(RwLock::new(Some(
        SystemTime::now() - Duration::from_secs(60),
    )));
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    let dial = Arc::new(Mutex::new(HashMap::new()));
    let tiny = RefreshIntervals {
        lead: Duration::from_millis(1),
        default: Duration::from_millis(2),
        retry: Duration::from_millis(2),
    };
    let handle = tokio::spawn(run_refreshes(
        token.clone(),
        expires,
        lock,
        dial,
        None,
        reqwest::Client::new(),
        format!("{}/edge/client/v1", server.uri()),
        Arc::new(ReauthMethod::Cert),
        None,
        Arc::new(Mutex::new(Vec::new())),
        tiny,
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();

    // Unchanged: no exchange, no GET — the OIDC token without a refresh just parks.
    assert_eq!(
        channel_token_value(read_token(&token).as_ref()).as_deref(),
        Some("ey.access"),
        "the OIDC token without a refresh was not touched"
    );
}
