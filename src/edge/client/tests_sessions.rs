use super::testsupport::*;
use super::*;

#[tokio::test]
async fn create_session_without_auth_is_not_authenticated() {
    // Build via test helper (no network, no PEMs needed).
    let client = EdgeClient::from_identity_for_test();
    let err = client
        .create_session("svc-1", SessionType::Dial)
        .await
        .unwrap_err();
    assert!(matches!(err, EdgeError::NotAuthenticated));
}

#[test]
fn dial_session_cache_store_get_evict_roundtrip() {
    let client = EdgeClient::from_identity_for_test();
    assert!(client.cached_dial_session("svc-1").is_none());
    client.cache_dial_session("svc-1", dial_detail("svc-1", "tok"));
    assert_eq!(client.cached_dial_session("svc-1").unwrap().token, "tok");
    client.evict_dial_session("svc-1");
    assert!(client.cached_dial_session("svc-1").is_none());
}

#[tokio::test]
async fn get_or_create_dial_session_creates_once_then_reuses_cache() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess-1","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1) // created exactly once: the 2nd call must hit the cache
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let first = client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .unwrap();
    let second = client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .unwrap();
    assert_eq!(first.token, "jwt-1");
    assert_eq!(second.token, "jwt-1");
    // MockServer verifies `.expect(1)` on drop → fails if /sessions was POSTed more than once.
}

#[tokio::test]
async fn evict_forces_recreate_on_next_get_or_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess-1","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(2) // create #1, cache hit, evict, create #2
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .unwrap(); // create #1
    client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .unwrap(); // cache hit (no POST)
    client.evict_dial_session("svc-1");
    client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .unwrap(); // create #2
}

/// T-OBS1: a cache MISS followed by a cache HIT are both observable. Mirror of
/// `get_or_create_dial_session_creates_once_then_reuses_cache`, with a
/// `TOKSECRET`-sentinel token so this test ALSO pins the token is never logged. RED without P1
/// or P2 (§6.3 M1/M2).
#[traced_test]
#[tokio::test]
async fn get_or_create_logs_cache_hit_and_miss() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess-1","token":"TOKSECRET-jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1) // created exactly once: the 2nd call must hit the cache
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .unwrap(); // miss + create
    client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .unwrap(); // hit

    assert!(
        logs_contain("dial session cache miss"),
        "P2: the miss is logged"
    );
    assert!(
        logs_contain("dial session cache hit"),
        "P1: the hit is logged"
    );
    assert!(logs_contain("service=svc-1"), "the service id is a field");
    assert!(
        logs_contain("session_id=sess-1"),
        "the session id is a field"
    );
    assert!(
        !logs_contain("TOKSECRET"),
        "the session token is NEVER logged"
    );
}

/// T-OBS2: `create_session_with_backoff` logs `establishing session` (port of `ziti.go:2068`)
/// and, on success, `successfully created session` with the resulting `session_id` and
/// `elapsed_ms` (port of `ziti.go:2099`). RED without P3 or P4 (§6.3 M3).
#[traced_test]
#[tokio::test]
async fn create_session_logs_establishing_and_created_with_session_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess-1","token":"TOKSECRET-jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    client
        .create_session_with_backoff("svc-1", SessionType::Dial, TEST_TOTAL)
        .await
        .unwrap();

    assert!(
        logs_contain("establishing session"),
        "P3: port of ziti.go:2068"
    );
    assert!(
        logs_contain("successfully created session"),
        "P4: port of ziti.go:2099"
    );
    assert!(logs_contain("session_id=sess-1"), "P4 carries session_id");
    assert!(logs_contain("elapsed_ms"), "P4 carries elapsed_ms");
    assert!(
        !logs_contain("TOKSECRET"),
        "the session token is NEVER logged"
    );
}

/// T-OBS3: `evict_dial_session` logs the eviction. Mirror of
/// `dial_session_cache_store_get_evict_roundtrip`. RED without P7 (§6.3 M4).
#[traced_test]
#[test]
fn evict_dial_session_logs_eviction() {
    let client = EdgeClient::from_identity_for_test();
    client.cache_dial_session("svc-1", dial_detail("svc-1", "opaque-TOKSECRET-1"));
    client.evict_dial_session("svc-1");

    assert!(
        logs_contain("evicted cached dial session"),
        "P7: the eviction is logged"
    );
    assert!(logs_contain("service=svc-1"), "the service id is a field");
    assert!(
        client.cached_dial_session("svc-1").is_none(),
        "the entry is gone"
    );
    assert!(
        !logs_contain("TOKSECRET"),
        "the session token is NEVER logged"
    );
}

/// T-OBS5: `cache_dial_session`'s raw store emits a `trace!` event — proving `#[traced_test]`'s
/// default filter (`noa_sdk=trace`) captures it — and never the token. RED without P5 (§6.3
/// M6).
#[traced_test]
#[test]
fn cache_store_trace_logs_but_never_the_token() {
    let client = EdgeClient::from_identity_for_test();
    client.cache_dial_session("svc-1", dial_detail("svc-1", "opaque-TOKSECRET-9"));

    assert!(
        logs_contain("cached dial session"),
        "P5: the raw store is logged at trace"
    );
    assert!(logs_contain("session_id="), "the session id is a field");
    assert!(
        !logs_contain("TOKSECRET"),
        "the session token is NEVER logged"
    );
}

#[test]
fn transient_create_errors_are_retriable() {
    // Transport failure (request never got a verdict), any 5xx, and the canonical backoff
    // triggers 429 (rate-limited) + 408 (request timeout) are transient — the oracle backs off
    // on these and a later attempt can succeed with no other state change.
    assert!(is_retriable_create_error(&EdgeError::SessionResponse(
        "connection reset".into()
    )));
    assert!(is_retriable_create_error(&session_http(500)));
    assert!(is_retriable_create_error(&session_http(503)));
    assert!(is_retriable_create_error(&session_http(429)));
    assert!(is_retriable_create_error(&session_http(408)));
}

#[test]
fn client_side_and_other_create_errors_are_permanent() {
    // 404 NOT_FOUND (service gone), 400/403 (won't change on retry), and 401 (re-auth is a
    // follow-up) must NOT be retried, else backoff would hammer with no state change.
    assert!(!is_retriable_create_error(&session_http(404)));
    assert!(!is_retriable_create_error(&session_http(401)));
    assert!(!is_retriable_create_error(&session_http(403)));
    assert!(!is_retriable_create_error(&session_http(400)));
    assert!(!is_retriable_create_error(&EdgeError::NotAuthenticated));
}

/// Transient failure then success: `POST /sessions` returns 500, 500, then 201 → the create
/// SUCCEEDS after retrying. `.expect(2)` on the 500 mock + `.expect(1)` on the 201 = 3 attempts
/// (two retries before the success). Oracle: `createSessionWithBackoff` retries `createSession`
/// until it succeeds within the budget (`ziti.go:2009-2046`).
///
/// O4 (observability): each FAILED attempt warns once (oracle `createSession` `ziti.go:2071`,
/// which logs on every failure of the retried unit), so the two 500s emit TWO
/// `"failure creating session"` warns; the 201 success emits none. `inspect_err` (not
/// `backon`'s `.notify`, which fires only before a retry sleep) makes the count faithful.
#[traced_test]
#[tokio::test]
async fn create_session_retries_transient_then_succeeds() {
    let server = MockServer::start().await;
    // wiremock matches mocks in REGISTRATION order, so register the two transient 500s FIRST
    // (and cap them with `up_to_n_times(2)` so they're exhausted after 2 calls)...
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(r#"{"error":{"code":"UNHANDLED","message":"boom"}}"#),
        )
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    // ...then the eventual 201, which only matches once the 500 mock is exhausted (3rd call).
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess-1","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let session = client
        .create_session_with_policy("svc-1", SessionType::Dial, fast_backoff())
        .await
        .expect("create succeeds after retrying the transient 500s");
    assert_eq!(session.token, "jwt-1");
    // Two 500s + one 201 = the create was attempted exactly 3 times (verified on drop).
    // O4: exactly TWO `"failure creating session"` warns (one per failed 500); the 201
    // success emits none (NEGATIVE: the count is 2, not 3 — a per-attempt log on the
    // SUCCESS would be a false positive).
    logs_assert(|lines: &[&str]| {
        let warns = lines
            .iter()
            .filter(|l| l.contains("failure creating session"))
            .count();
        if warns == 2 {
            Ok(())
        } else {
            Err(format!(
                "expected 2 'failure creating session' warns, got {warns}"
            ))
        }
    });
    // The warn carries the service id + session type as structured fields (id-vs-name
    // deviation: the oracle has the resolved `*service.Name`; we log the id we hold).
    assert!(
        logs_contain("service=svc-1"),
        "the warn carries the service id field"
    );
    assert!(
        logs_contain("session_type=Dial"),
        "the warn carries the session type field"
    );
}

/// Permanent failure: `POST /sessions` returns 404 NOT_FOUND → the create FAILS WITHOUT
/// retrying. `.expect(1)` witnesses a single attempt. Oracle: the service is gone, so backoff
/// must not retry (our `do_resolve_service` enforces the oracle's structural permanent-on-gone
/// one layer up; a controller 404 here is treated as permanent — see `is_retriable_create_error`).
///
/// O4 (observability): the permanent failure IS logged — exactly ONE
/// `"failure creating session"` warn. This is precisely why we use `inspect_err` (logs every
/// attempt's failure, retriable AND the final permanent one) over `backon`'s `.notify` (which
/// fires only BEFORE a retry sleep → would MISS this non-retriable final failure).
#[traced_test]
#[tokio::test]
async fn create_session_does_not_retry_on_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"service not found"}}"#),
        )
        .expect(1) // exactly one attempt: a 404 is permanent, no retry
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let err = client
        .create_session_with_policy("svc-1", SessionType::Dial, fast_backoff())
        .await
        .expect_err("a 404 NOT_FOUND must fail fast");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 404, .. }),
        "the create error propagates unwrapped: {err:?}"
    );
    // O4: the permanent 404 IS logged — exactly ONE warn (the point of `inspect_err` over
    // `.notify`: the final non-retriable failure still emits).
    logs_assert(|lines: &[&str]| {
        let warns = lines
            .iter()
            .filter(|l| l.contains("failure creating session"))
            .count();
        if warns == 1 {
            Ok(())
        } else {
            Err(format!(
                "expected 1 'failure creating session' warn, got {warns}"
            ))
        }
    });
}

/// O4 NEGATIVE: a create that succeeds on the FIRST attempt (201) emits NO
/// `"failure creating session"` warn — the per-attempt failure log fires only on failures, so
/// the happy path is silent (oracle `createSession` `ziti.go:2071` is on the error branch).
#[traced_test]
#[tokio::test]
async fn create_session_first_attempt_success_does_not_warn() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess-1","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let session = client
        .create_session_with_policy("svc-1", SessionType::Dial, fast_backoff())
        .await
        .expect("a first-attempt 201 succeeds with no retry");
    assert_eq!(session.token, "jwt-1");
    assert!(
        !logs_contain("failure creating session"),
        "a first-attempt success must NOT warn"
    );
}

/// Witnesses the BACKOFF WIRING into `get_or_create_dial_session` (the slice's whole point):
/// a transient 500 then a 201 → the cached-create path retries and succeeds. Drives the real
/// `get_or_create_dial_session` (production backoff: one ~50ms retry), NOT the injectable seam,
/// so it is the one test that proves the cache-miss path goes through `create_session_with_backoff`
/// and not plain `create_session` — reverting the wiring would let the 500 propagate after a
/// single attempt (the 201 mock never fires) and fail this test two ways.
#[tokio::test]
async fn get_or_create_dial_session_retries_transient_through_backoff() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(r#"{"error":{"code":"UNHANDLED","message":"boom"}}"#),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
            .and(path("/edge/client/v1/sessions"))
            .respond_with(ResponseTemplate::new(201).set_body_string(
                r#"{"data":{"id":"sess-1","token":"jwt-1","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let session = client
        .get_or_create_dial_session("svc-1", TEST_TOTAL)
        .await
        .expect("get_or_create retries the transient 500 through backoff and succeeds");
    assert_eq!(session.token, "jwt-1");
    // 1×500 + 1×201 = the cache-miss create was attempted twice (verified on drop).
}

/// Binds the connect-timeout → backoff `total` threading (slice 10b): a ZERO budget allows
/// exactly ONE attempt (the first retry would need to sleep `min_delay`=50ms > 0 budget → no
/// retry fires), so a transient 500 fails fast. If `session_backoff` ignored `total` and
/// hardcoded 15s, the 500 would retry (a 2nd POST) and fail this `expect(1)` — so this is the
/// discriminating test that `total` actually flows into the production backoff policy.
#[tokio::test]
async fn create_session_with_backoff_zero_budget_does_not_retry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(r#"{"error":{"code":"UNHANDLED","message":"boom"}}"#),
        )
        .expect(1) // zero budget → no retry → exactly one attempt
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let err = client
        .create_session_with_backoff("svc-1", SessionType::Dial, Duration::ZERO)
        .await
        .expect_err("a zero budget must not retry the transient 500");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 500, .. }),
        "got {err:?}"
    );
}
