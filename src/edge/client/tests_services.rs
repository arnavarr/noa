use super::testsupport::*;
use super::*;

/// `poll_services` end-to-end over a (stateful) wiremock `/services`: poll 1 reports both services
/// Added and fires the listener; a pre-seeded dial session for the soon-removed service is present;
/// poll 2 reports the dropped service Removed, fires the listener, and EVICTS its cached dial
/// session (oracle `deleteServiceSessions`). Pins the full wiring: fetch → diff against the
/// persistent cache → events → listener fan-out → dial-session eviction.
#[tokio::test]
async fn poll_services_reports_added_then_removed_and_evicts_dial_session() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{Request, Respond};

    // Call 1 → [alpha(id s1), beta(id s2)]; call 2+ → [alpha(id s1)] (beta dropped).
    struct ServiceList(Arc<AtomicUsize>);
    impl Respond for ServiceList {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            let body = if n == 0 {
                r#"{"data":[
                        {"id":"s1","name":"alpha","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]},
                        {"id":"s2","name":"beta","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}
                    ],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":2}}}"#
            } else {
                r#"{"data":[
                        {"id":"s1","name":"alpha","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}
                    ],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#
            };
            ResponseTemplate::new(200).set_body_string(body)
        }
    }

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ServiceList(Arc::new(AtomicUsize::new(0))))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    // A listener records each event; pin that the fan-out fires.
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_cb = seen.clone();
    client.add_service_listener(Arc::new(move |ev: &ServiceEvent| {
        let label = match ev {
            ServiceEvent::Added(s) => format!("+{}", s.name),
            ServiceEvent::Changed(s) => format!("~{}", s.name),
            ServiceEvent::Removed(s) => format!("-{}", s.name),
        };
        seen_cb.lock().unwrap().push(label);
    }));

    // Pre-seed a cached dial session for beta (id s2): the eviction must remove it on removal.
    client
        .dial_sessions
        .lock()
        .unwrap()
        .insert("s2".to_string(), dial_detail("s2", "tok"));

    // Poll 1 → both Added.
    let e1 = client.poll_services(&[]).await.expect("poll 1");
    assert_eq!(e1.len(), 2, "first poll = all Added: {e1:?}");
    assert!(e1.iter().all(|e| matches!(e, ServiceEvent::Added(_))));
    assert!(client.dial_sessions.lock().unwrap().contains_key("s2"));

    // Poll 2 → beta Removed; its dial session evicted; alpha unchanged (no event).
    let e2 = client.poll_services(&[]).await.expect("poll 2");
    assert_eq!(e2.len(), 1, "second poll = one Removed: {e2:?}");
    assert!(matches!(&e2[0], ServiceEvent::Removed(s) if s.name == "beta" && s.id == "s2"));
    assert!(
        !client.dial_sessions.lock().unwrap().contains_key("s2"),
        "removed service's cached dial session must be evicted"
    );

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            "+alpha".to_string(),
            "+beta".to_string(),
            "-beta".to_string()
        ],
        "listener saw Added×2 then Removed"
    );
}

/// The `lastChangeAt` comparison is INSTANT-based, NOT string-based: the oracle's gate is
/// `strfmt.DateTime.Equal` → `time.Time.Equal` (the UTC instant). Two RFC3339 timestamps in
/// DIFFERENT offsets that denote the SAME moment parse to the SAME `i128` (so they would NOT
/// trigger a refresh); a different moment parses to a different `i128`. A naive string compare
/// would mis-fire on the offset rewrite. Garbage → `None` (the GET surfaces a response error).
#[test]
fn parse_last_change_at_is_instant_based() {
    let z = parse_last_change_at("2026-06-26T12:00:00Z").unwrap();
    let plus2 = parse_last_change_at("2026-06-26T14:00:00+02:00").unwrap();
    assert_eq!(z, plus2, "same instant in different offsets must be equal");
    let later = parse_last_change_at("2026-06-26T12:00:00.001Z").unwrap();
    assert_ne!(z, later, "a 1ms-later instant must differ");
    assert_eq!(parse_last_change_at("not-a-date"), None);
    assert_eq!(parse_last_change_at(""), None);
}

/// Update-check gate: when the controller's `lastChangeAt` matches the last-seen instant, the
/// second `poll_services_if_changed` returns NO events WITHOUT re-fetching `/services`. The first
/// call (no stored instant) fetches and stores; the second (stored == controller's, instant-equal)
/// short-circuits. Pins both the no-fetch optimization AND the instant comparison against a real
/// (mocked) controller timestamp. Oracle: `refreshServices(false)` gating `GetServices` on
/// `IsServiceListUpdateAvailable` (`ziti.go:885`/`:907`).
#[tokio::test]
async fn service_updates_unchanged_skips_the_fetch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let server = MockServer::start().await;
    let fetches = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"lastChangeAt":"2026-06-26T12:00:00.000Z"},"meta":{}}"#,
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(CountingServices(fetches.clone()))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let e1 = client.poll_services_if_changed(&[]).await.expect("poll 1");
    assert_eq!(
        e1.len(),
        1,
        "first check (no stored instant) fetches: {e1:?}"
    );
    assert_eq!(fetches.load(Ordering::SeqCst), 1, "first poll fetched once");

    let e2 = client.poll_services_if_changed(&[]).await.expect("poll 2");
    assert!(e2.is_empty(), "unchanged → no events: {e2:?}");
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "unchanged lastChangeAt must NOT re-fetch /services"
    );
}

/// [`EdgeClient::prime_service_cache`] seeds the [`ServiceWatcher`] so the FIRST
/// `poll_services_if_changed` diffs against the primed set (only REAL deltas fire) instead of
/// re-emitting every service as `Added` against an empty cache. Primes with `alpha`; the controller
/// then serves `[alpha]` (unchanged) → the first poll yields NO events (contrast:
/// [`service_updates_unchanged_skips_the_fetch`] shows the UN-primed first poll returns 1 `Added`).
/// Pins the intercept subcommand's startup seed (`main.rs`) that keeps its live svc-poll arm from
/// re-adding everything on the first tick.
#[tokio::test]
async fn prime_service_cache_makes_first_poll_emit_only_real_deltas() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"lastChangeAt":"2026-06-26T12:00:00.000Z"},"meta":{}}"#,
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/services"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":[{"id":"s1","name":"alpha","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    // Seed with the SAME `alpha` the controller will serve.
    let alpha = Service {
        id: "s1".into(),
        name: "alpha".into(),
        encryption_required: false,
        permissions: vec!["Dial".into()],
        config: serde_json::Map::new(),
        configs: vec![],
    };
    client.prime_service_cache(std::slice::from_ref(&alpha));

    let events = client.poll_services_if_changed(&[]).await.expect("poll");
    assert!(
        events.is_empty(),
        "primed cache → the first poll emits no spurious Added: {events:?}"
    );
}

/// Update-check gate, the other arm: when the controller's `lastChangeAt` DIFFERS from the
/// last-seen instant, `poll_services_if_changed` re-fetches. First poll stores T0; the controller
/// then reports T1 ≠ T0 → the second poll fetches again.
#[tokio::test]
async fn service_updates_changed_triggers_the_fetch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct ChangingUpdates(Arc<AtomicUsize>);
    impl wiremock::Respond for ChangingUpdates {
        fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            let ts = if n == 0 {
                "2026-06-26T12:00:00.000Z"
            } else {
                "2026-06-26T12:05:00.000Z"
            };
            ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"data":{{"lastChangeAt":"{ts}"}},"meta":{{}}}}"#
            ))
        }
    }
    let server = MockServer::start().await;
    let fetches = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(ChangingUpdates(Arc::new(AtomicUsize::new(0))))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(CountingServices(fetches.clone()))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    client.poll_services_if_changed(&[]).await.expect("poll 1");
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    client.poll_services_if_changed(&[]).await.expect("poll 2");
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        2,
        "a changed lastChangeAt must re-fetch"
    );
}

/// The force-path-resets-to-nil quirk (oracle `refreshServices` leaves the function-local
/// `lastServiceUpdate` unassigned in the force branch → `CtrlClt.lastServiceUpdate = nil`,
/// `ziti.go:930`). Sequence: a checked poll stores the instant → a repeat checked poll is a no-op
/// (unchanged) → a FORCED `poll_services` resets the stored instant to `None` → the next checked
/// poll fetches AGAIN even though the controller's `lastChangeAt` is unchanged. A mutant that kept
/// the instant across the force path would make the final poll a no-op and go RED.
#[tokio::test]
async fn forced_poll_resets_last_update_so_next_check_refetches() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let server = MockServer::start().await;
    let checked_fetches = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"lastChangeAt":"2026-06-26T12:00:00.000Z"},"meta":{}}"#,
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(CountingServices(checked_fetches.clone()))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    client.poll_services_if_changed(&[]).await.expect("check 1");
    assert_eq!(checked_fetches.load(Ordering::SeqCst), 1, "check 1 fetched");
    client.poll_services_if_changed(&[]).await.expect("check 2");
    assert_eq!(
        checked_fetches.load(Ordering::SeqCst),
        1,
        "check 2 unchanged → no fetch (instant stored)"
    );

    // A FORCED poll resets the stored instant to None.
    client.poll_services(&[]).await.expect("force");
    assert_eq!(
        checked_fetches.load(Ordering::SeqCst),
        2,
        "the forced poll always fetches"
    );

    // The next checked poll must fetch AGAIN (stored instant was reset to None), even though the
    // controller's lastChangeAt has NOT changed.
    client.poll_services_if_changed(&[]).await.expect("check 3");
    assert_eq!(
        checked_fetches.load(Ordering::SeqCst),
        3,
        "force reset lastServiceUpdate → next check must re-fetch despite unchanged lastChangeAt"
    );
}

/// A 503 update-check (`ListServiceUpdatesServiceUnavailable`) maps to
/// [`EdgeError::ControllerUnavailable`] and does NOT fetch `/services` — the oracle returns
/// `ErrControllerUnavailable` before `GetServices` (`ziti.go:891`). `/services` is mounted with
/// `expect(0)` so a spurious fetch fails the test.
#[tokio::test]
async fn service_updates_503_is_controller_unavailable_and_skips_fetch() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(ResponseTemplate::new(503).set_body_string(
            r#"{"error":{"code":"SERVICE_UNAVAILABLE","message":"controller unavailable"}}"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let err = client
        .poll_services_if_changed(&[])
        .await
        .expect_err("503 update-check must error");
    assert!(
        matches!(err, EdgeError::ControllerUnavailable),
        "503 → ControllerUnavailable, got {err:?}"
    );
}

/// Any NON-503 check error (here a 500, and equivalently a 401 expired session) falls through to
/// "fetch anyway": the oracle re-auths + re-checks on 401 then sets `checkService = true`, and on
/// other errors logs + `checkService = true` (`ziti.go:891-901`). We collapse this to a fetch
/// (which itself reauth-retries). The fetch occurs (counter = 1) and produces events.
#[tokio::test]
async fn service_updates_other_error_fetches_anyway() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let server = MockServer::start().await;
    let fetches = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(r#"{"error":{"code":"UNHANDLED","message":"boom"}}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(CountingServices(fetches.clone()))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let events = client
        .poll_services_if_changed(&[])
        .await
        .expect("a non-503 check error still fetches");
    assert_eq!(
        fetches.load(Ordering::SeqCst),
        1,
        "fetched despite check error"
    );
    assert_eq!(
        events.len(),
        1,
        "fetch produced the Added event: {events:?}"
    );
}

/// The public [`is_service_list_update_available`](EdgeClient::is_service_list_update_available) is
/// a PURE check: it returns `true` (no prior instant) but does NOT store anything, so a second call
/// with the SAME controller timestamp ALSO returns `true` (a mutation would store the instant and
/// the second call would return `false`). Faithful to the oracle's read-only
/// `IsServiceListUpdateAvailable` (the write lives in `refreshServices`).
#[tokio::test]
async fn is_service_list_update_available_is_a_pure_check() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"lastChangeAt":"2026-06-26T12:00:00.000Z"},"meta":{}}"#,
            ),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    assert!(
        client.is_service_list_update_available().await.unwrap(),
        "no stored instant → available"
    );
    assert!(
        client.is_service_list_update_available().await.unwrap(),
        "the pure check must NOT have stored the instant → still available"
    );
}

/// A 200 `/service-updates` body missing `lastChangeAt` is a response error (the field is
/// `validate.Required` in the oracle's model). `poll_services_if_changed` falls into the
/// "fetch anyway" arm (the parse error is NON-503), so this asserts the lower-level wire surfaces
/// the parse failure rather than silently treating an empty body as "no change".
#[tokio::test]
async fn service_updates_missing_last_change_at_is_response_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data":{},"meta":{}}"#))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "T0");

    let err = client
        .is_service_list_update_available()
        .await
        .expect_err("missing lastChangeAt must error");
    assert!(
        matches!(err, EdgeError::ServiceUpdatesResponse(_)),
        "missing lastChangeAt → ServiceUpdatesResponse, got {err:?}"
    );
}
