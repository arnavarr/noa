use super::testsupport::*;
use super::*;

/// GWT-1 / T1: an OPAQUE session token (not `ey`-prefixed) probes via `GET /sessions/{id}`
/// (DetailSession), NOT `GET /services/{id}/edge-routers`. RED without D1's else branch: the old
/// code always hits edge-routers, so `/sessions/{id}` `.expect(1)` fails on drop.
#[tokio::test]
async fn refresh_opaque_token_hits_session_detail_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/sessions/sess"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"sess","token":"opaque-abc","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    // The JWT-branch endpoint must NOT be touched for an opaque token.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-1/edge-routers"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    client
        .refresh_session(&dial_detail("svc-1", "opaque-abc"))
        .await
        .expect("an opaque token probes /sessions/{id} and the controller reports alive");
}

/// GWT-2 / T2: a JWT session token (`ey`-prefixed) probes via `GET /services/{id}/edge-routers`
/// (the pre-existing behaviour, preserved). RED under an inverted branch (everything to
/// `/sessions/{id}`): the edge-routers `.expect(1)` fails on drop.
#[tokio::test]
async fn refresh_jwt_token_hits_service_edge_routers_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-1/edge-routers"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"data":{"edgeRouters":[]},"meta":{}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    // The DetailSession endpoint must NOT be touched for a JWT token.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/sess"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    client
        .refresh_session(&dial_detail("svc-1", "eyJhbGci.dial.jwt"))
        .await
        .expect("a JWT token probes /services/{id}/edge-routers (preserved behaviour)");
}

/// GWT-3 / T3 (the recovery pin): an OPAQUE token whose DetailSession returns 404 probes `Err` —
/// this is what makes `dial_with_refresh_retry` evict + recreate. RED if the DetailSession helper
/// treated a non-2xx as `Ok` (then the fast-path would never fire).
#[tokio::test]
async fn refresh_opaque_dead_session_probes_err() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/sess"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let err = client
        .refresh_session(&dial_detail("svc-1", "opaque-dead"))
        .await
        .expect_err("a 404 DetailSession must probe Err so the retry fires");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 404, .. }),
        "got {err:?}"
    );
}

/// T4 (the alive twin of T3): an OPAQUE token whose DetailSession returns 200 probes `Ok`.
#[tokio::test]
async fn refresh_opaque_alive_session_probes_ok() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/sessions/sess"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"sess","token":"opaque-live","serviceId":"svc-1","type":"Dial","edgeRouters":[]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    client
        .refresh_session(&dial_detail("svc-1", "opaque-live"))
        .await
        .expect("a 200 DetailSession probes Ok (alive)");
}

/// TA1: an OPAQUE refresh RE-CACHES the `SessionDetail` the controller returned. Seed S opaque with
/// `[er_old]`; `GET /sessions/{id}` → 200 with `[er_new]`; `refresh_session` returns `Ok(S')` AND
/// the cache for `S.service_id` now carries `[er_new]` (sanitized). RED without the re-cache (M1) —
/// the cache would still hold `[er_old]`.
#[tokio::test]
async fn refresh_opaque_recaches_returned_session() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/sessions/sess"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"sess","token":"opaque-x","serviceId":"svc-1","type":"Dial","edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls://router:443"}}]},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc-1", dial_detail_ers("svc-1", "opaque-x", "er_old"));

    let refreshed = client
        .refresh_session(&dial_detail_ers("svc-1", "opaque-x", "er_old"))
        .await
        .expect("opaque refresh returns the refreshed SessionDetail");
    assert_eq!(
        er_names(&refreshed),
        vec!["er_new".to_string()],
        "returns S'"
    );
    assert_eq!(
        er_names(
            &client
                .cached_dial_session("svc-1")
                .expect("session re-cached")
        ),
        vec!["er_new".to_string()],
        "the cache was re-populated with the refreshed edge-routers"
    );
}

/// TA2: a JWT refresh RECONSTRUCTS (DV-A2: reuse session + fresh edge-routers) and RE-CACHES. Seed S
/// JWT with `[er_old]`; `GET /services/{id}/edge-routers` → `{data:{edgeRouters:[er_new]}}`;
/// `refresh_session` returns `Ok(S with edge_routers=[er_new])` AND the cache reflects `[er_new]`.
/// RED if the JWT branch discards the ERs (M2) or does not re-cache (M1).
#[tokio::test]
async fn refresh_jwt_recaches_with_refreshed_edge_routers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/services/svc-1/edge-routers"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls://router:443"}}]},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc-1", dial_detail_ers("svc-1", "eyJ.dial.jwt", "er_old"));

    let refreshed = client
        .refresh_session(&dial_detail_ers("svc-1", "eyJ.dial.jwt", "er_old"))
        .await
        .expect("jwt refresh returns the reconstructed SessionDetail");
    assert_eq!(
        er_names(&refreshed),
        vec!["er_new".to_string()],
        "reconstructed with fresh ERs"
    );
    assert_eq!(
        refreshed.token, "eyJ.dial.jwt",
        "DV-A2: every field except edge_routers is reused from the cached session"
    );
    assert_eq!(
        er_names(
            &client
                .cached_dial_session("svc-1")
                .expect("session re-cached")
        ),
        vec!["er_new".to_string()],
        "the cache was re-populated with the refreshed edge-routers"
    );
}

/// TA3: a DEAD refresh does NOT re-cache (pin of the `if err != nil { return nil, err }` order,
/// ziti.go:2112-2114 before :2116). Seed S opaque with `[er_old]`; `GET /sessions/{id}` → 404;
/// `refresh_session` returns `Err(SessionHttp{404})` AND the cache is UNTOUCHED (still `[er_old]`).
/// RED if the re-cache runs before the error check (M3).
#[tokio::test]
async fn refresh_dead_session_does_not_recache() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/sess"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    // Seed a DISTINCT marker (`er_seed`) from the probed session (`er_probe`) so ANY write to the
    // cache on the error path is detectable — a faithful dead refresh writes NOTHING (the `?`
    // propagates before the insert), so the cache must still read `er_seed` after the 404.
    client.cache_dial_session("svc-1", dial_detail_ers("svc-1", "opaque-dead", "er_seed"));

    let err = client
        .refresh_session(&dial_detail_ers("svc-1", "opaque-dead", "er_probe"))
        .await
        .expect_err("a dead session probes Err");
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 404, .. }),
        "got {err:?}"
    );
    assert_eq!(
        er_names(
            &client
                .cached_dial_session("svc-1")
                .expect("cache untouched")
        ),
        vec!["er_seed".to_string()],
        "a dead refresh does NOT re-cache: the cache is untouched (not overwritten with the probe)"
    );
}

/// T7: the gate itself, as a PURE function (no async, no network) — the four states of the key.
/// (a) ABSENT → no write, no key created (CN-1). (b) same `id` → writes in place (the normal path).
/// (c) DIFFERENT `id` → no write, the newer entry untouched (CN-2). (d) same `id` but the refreshed
/// session carries a DIFFERENT `service_id` → the write lands under the SNAPSHOT's key (CN-3).
/// RED for (a) under a blind insert and for (c) under an existence-only guard.
///
/// ⚠ **What (d) actually pins, stated precisely.** The mutation it catches is keying the GATE by
/// `refreshed.service_id` (`guard.get_mut(&refreshed.service_id)`, as the oracle keys,
/// `ziti.go:2121`): that variant looks up `svc-OTHER`, finds it ABSENT and **skips** ⇒ `wrote ==
/// false` ⇒ the **`assert!(wrote)`** below goes RED. It is **NOT** the "no phantom key" assert that
/// catches it — a write GATE can never create a key **however it is keyed** (`get_mut` does not
/// insert), so `!contains_key("svc-OTHER")` stays GREEN under that mutation. That assert is kept as
/// a standing pin of the *gate can add no key* property (the one that makes over-permit impossible),
/// not as the discriminant of the keying decision.
#[test]
fn recache_refreshed_dial_session_is_a_pure_write_gate() {
    // (a) key ABSENT → skip, and NO key is created (the gate can never ADD a key).
    let map: Mutex<HashMap<String, SessionDetail>> = Mutex::new(HashMap::new());
    let wrote = recache_refreshed_dial_session(
        &map,
        "svc-1",
        "sess",
        dial_detail_ers("svc-1", "tok", "er_new"),
    );
    assert!(!wrote, "(a) CN-1: an absent key is NOT resurrected");
    assert!(
        map.lock().unwrap().is_empty(),
        "(a) the gate created no entry"
    );

    // (b) same `id` → write in place, key untouched.
    let map = Mutex::new(HashMap::from([(
        "svc-1".to_string(),
        dial_detail_ers("svc-1", "tok", "er_old"),
    )]));
    let wrote = recache_refreshed_dial_session(
        &map,
        "svc-1",
        "sess",
        dial_detail_ers("svc-1", "tok", "er_new"),
    );
    assert!(
        wrote,
        "(b) the same session under the same key IS refreshed"
    );
    let guard = map.lock().unwrap();
    assert_eq!(guard.len(), 1);
    assert_eq!(
        er_names(guard.get("svc-1").expect("the key is intact")),
        vec!["er_new".to_string()],
        "(b) the entry gained the refreshed edge-routers"
    );
    drop(guard);

    // (c) DIFFERENT `id` under the key → skip; the newer entry is untouched.
    let map = Mutex::new(HashMap::from([(
        "svc-1".to_string(),
        dial_detail_id_ers("svc-1", "sess-2", "tok-2", "er_s2"),
    )]));
    let wrote = recache_refreshed_dial_session(
        &map,
        "svc-1",
        "sess",
        dial_detail_ers("svc-1", "tok", "er_new"),
    );
    assert!(!wrote, "(c) CN-2: a different session.id is NOT clobbered");
    let guard = map.lock().unwrap();
    let kept = guard.get("svc-1").expect("the newer entry survives");
    assert_eq!(kept.id, "sess-2", "(c) the newer session is still there");
    assert_eq!(
        er_names(kept),
        vec!["er_s2".to_string()],
        "(c) untouched, not merged"
    );
    drop(guard);

    // (d) CN-3: the write is keyed by the SNAPSHOT's key, never by `refreshed.service_id`.
    let map = Mutex::new(HashMap::from([(
        "svc-1".to_string(),
        dial_detail_ers("svc-1", "tok", "er_old"),
    )]));
    let wrote = recache_refreshed_dial_session(
        &map,
        "svc-1",
        "sess",
        dial_detail_ers("svc-OTHER", "tok", "er_new"),
    );
    // ↓ THE discriminant of CN-3: a gate keyed by `refreshed.service_id` would look up `svc-OTHER`,
    // find it absent and SKIP ⇒ `wrote == false` ⇒ RED here (and RED on the `er_new` assert below).
    assert!(
        wrote,
        "(d) CN-3: the gate looks up the SNAPSHOT's key — keying it by refreshed.service_id \
             (svc-OTHER) would find that key absent and skip, writing nothing"
    );
    let guard = map.lock().unwrap();
    assert_eq!(guard.len(), 1, "(d) exactly one entry");
    // ↓ NOT the CN-3 discriminant: this holds under ANY keying, because a write gate never inserts
    // (`get_mut`). It pins the *gate can add no key* property — the one that makes over-permit
    // impossible — and is deliberately kept as a standing regression pin of it.
    assert!(
        !guard.contains_key("svc-OTHER"),
        "(d) a write GATE can add NO key, however it is keyed (`get_mut` does not insert)"
    );
    assert_eq!(
        er_names(guard.get("svc-1").expect("written under the snapshot key")),
        vec!["er_new".to_string()],
        "(d) the refreshed value landed under the SNAPSHOT's key"
    );
}
