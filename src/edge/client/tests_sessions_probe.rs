use super::testsupport::*;
use super::*;

/// **T8 (4a)**: the PURGE gate as a pure function — the three states of the key. (i) the key still
/// holds the SAME `session.id` the snapshot photographed → evicted, `true`; (ii) the key holds a
/// DIFFERENT (newer, live) session → **not** evicted, `false` (DV-4a-4); (iii) the key is absent →
/// `false`, no-op. RED under dropping the `id` comparison: case (ii) would evict a live session.
///
/// The key handed to the gate is ALWAYS the snapshot's `service_id`, never `session.id` — the
/// upstream key bug (`ziti.go:841` marks bare ids, `:854` removes them from a `serviceId:type` map).
#[test]
fn evict_dead_dial_session_removes_only_the_same_session_id() {
    // (i) same id under the key → evict.
    let map = Mutex::new(HashMap::from([(
        "svc-1".to_string(),
        dial_detail_id_ers("svc-1", "sess-1", "tok", "er"),
    )]));
    assert!(
        evict_dead_dial_session(&map, "svc-1", "sess-1"),
        "(i) the proven-dead session under its own key IS purged"
    );
    assert!(
        map.lock().unwrap().is_empty(),
        "(i) the entry is gone (evicted by the SNAPSHOT's key)"
    );

    // (ii) a DIFFERENT session now occupies the key (DV-C3's retry cached a fresh one) → no-op.
    let map = Mutex::new(HashMap::from([(
        "svc-1".to_string(),
        dial_detail_id_ers("svc-1", "sess-2", "tok", "er"),
    )]));
    assert!(
        !evict_dead_dial_session(&map, "svc-1", "sess-1"),
        "(ii) DV-4a-4: a NEWER session under the key is NOT evicted"
    );
    let guard = map.lock().unwrap();
    assert_eq!(
        guard.get("svc-1").expect("the newer entry survives").id,
        "sess-2",
        "(ii) the live session is intact"
    );
    drop(guard);

    // (iii) the key is already gone (svc-poll `Removed`, reauth `clear()`, DV-C3) → no-op.
    let map: Mutex<HashMap<String, SessionDetail>> = Mutex::new(HashMap::new());
    assert!(
        !evict_dead_dial_session(&map, "svc-1", "sess-1"),
        "(iii) an absent key is a no-op"
    );
    assert!(
        map.lock().unwrap().is_empty(),
        "(iii) the gate created nothing"
    );
}

/// **T9 (4a, DV-O1)**: the purge gate NEVER logs the session token (a credential) — only the service
/// key and the `session_id`. RED if the eviction logs the `SessionDetail` (`{:?}`) or the token.
#[traced_test]
#[test]
fn evict_dead_dial_session_never_logs_the_token() {
    let map = Mutex::new(HashMap::from([(
        "svc-1".to_string(),
        dial_detail_id_ers("svc-1", "sess-1", "TOKSECRET", "er"),
    )]));

    assert!(evict_dead_dial_session(&map, "svc-1", "sess-1"));

    assert!(
        logs_contain("purged dead dial session"),
        "the purge IS logged (else the token assert below would be vacuous)"
    );
    assert!(
        !logs_contain("TOKSECRET"),
        "DV-O1: the session token is NEVER logged"
    );
}

/// **T10 (4a, the DISCRIMINANT OF DEATH — the whole table)**: `is_proven_dead` over
/// {legacy, oidc} × {404, 401, 5xx, transport}. **Exactly ONE quadrant is `true`: (legacy, 404).**
///
/// The two quadrants that are *not* obviously false and that this test PINS:
/// - **(legacy, 401) ⇒ false.** A 401 on `GET /sessions/{id}` is the API-SESSION's business (the reauth
///   owns it; it `clear()`s the cache anyway), not a verdict on the session.
/// - **(oidc, 401) ⇒ false.** The stateless route is registered with `permissions.IsAuthenticated()`
///   (`ziti@9bf62f3 controller/internal/routes/service_router.go:77-80`), so `AppEnv.IsAllowed` answers
///   401 when the API-SESSION is invalid, BEFORE the handler runs (`controller/env/appenv.go:991-1002`),
///   and the handler's `ValidateServiceAccessToken` failure (`service_router.go:428-435`) is the SAME
///   bare `errorz.NewUnauthorized()`. The 401 is therefore NOT attributable to the session — and there is
///   no persisted OIDC session to purge anyway (`session_router.go:220-226`).
///
/// Mutations that turn this RED (both were live code at some point in 4a's history):
/// - `Legacy => matches!(err, SessionHttp { status: 404 | 401, .. })` → the (legacy, 401) case fails.
/// - `Oidc => matches!(err, SessionHttp { status: 401, .. })` → the (oidc, 401) case fails.
#[test]
fn is_proven_dead_only_for_legacy_404() {
    let legacy = AuthToken::Legacy("API-TOK".into());
    let oidc = AuthToken::Oidc {
        access: "API-TOK".into(),
        refresh: None,
    };
    let http = |status: u16| EdgeError::SessionHttp {
        status,
        code: String::new(),
        message: String::new(),
    };
    let transport = || EdgeError::SessionResponse("connection reset".into());

    // ── LEGACY (durable probe, `GET /sessions/{id}`): the 404 is the ONLY proof.
    assert!(
        is_proven_dead(&legacy, &http(404)),
        "(legacy, 404): the session STORE said NotFound — the one and only proof of death"
    );
    assert!(
        !is_proven_dead(&legacy, &http(401)),
        "(legacy, 401): an api-session 401 is the REAUTH's business, not proof the session is dead"
    );
    assert!(
        !is_proven_dead(&legacy, &http(503)),
        "(legacy, 5xx): a blip is not a proof (DV-4a-5)"
    );
    assert!(
        !is_proven_dead(&legacy, &transport()),
        "(legacy, transport): a blip is not a proof (DV-4a-5)"
    );

    // ── OIDC (stateless probe): NOTHING proves the session dead — not even the 401.
    assert!(
        !is_proven_dead(&oidc, &http(401)),
        "(oidc, 401): conflates «the API-SESSION expired» with «the session token was rejected» — \
             purging on it would wipe the cache of LIVE sessions on an ordinary access-token expiry"
    );
    assert!(
        !is_proven_dead(&oidc, &http(404)),
        "(oidc, 404): that 404 is the SERVICE's (svc-poll's `Removed` arm owns it), not the session's"
    );
    assert!(
        !is_proven_dead(&oidc, &http(503)),
        "(oidc, 5xx): a blip is not a proof"
    );
    assert!(
        !is_proven_dead(&oidc, &transport()),
        "(oidc, transport): a blip is not a proof"
    );
}

/// T5 (CN-1 on the DIAL path, W2): `refresh_session`'s re-cache must NOT resurrect an entry that
/// DV-C3 evicted while the probe was in flight. The probe answers alive after 300 ms; at 100 ms the
/// intruder calls `evict_dial_session("svc-1")` (the very closure the dial retry runs,
/// `edge/conn/retry.rs`). Three asserts: (1) the LIVENESS VERDICT is unchanged — `refresh_session` still
/// returns `Ok` (C2: the gate rules the WRITE, not the returned value), (2) the eviction STANDS, and
/// (3) **the gate actually FIRED** with `reason=absent`.
/// RED under the blind re-cache (`cache_dial_session(&refreshed.service_id, …)`) on (2); RED on (1)
/// if the gate were (wrongly) allowed to change the verdict.
///
/// ⚠ (2) alone could pass by VACUITY: if the intruder ran AFTER the write landed, the `remove` would
/// simply delete what a BLIND insert had just re-created and the map would end up empty anyway. The
/// `.expect(1)` (the probe really happened, so we are not green on a 404 with nothing to write) plus
/// (3) (`#[traced_test]` + `logs_contain`, since a bare `#[tokio::test]` installs NO subscriber and
/// stdout carries ANSI) turn that vacuous green into a real one: the SKIP is observed, not inferred.
#[traced_test]
#[tokio::test]
async fn refresh_session_does_not_resurrect_evicted_session() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/sess"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(alive_detail_body())
                .set_delay(Duration::from_millis(300)),
        )
        .expect(1) // the probe MUST have run: a broken route (404) would make the skip vacuous
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc-1", dial_detail_ers("svc-1", "opaque-x", "er_old"));

    let probed = dial_detail_ers("svc-1", "opaque-x", "er_old");
    // The wiremock delay (300 ms) > the intruder's sleep (100 ms) makes the interleaving
    // deterministic without depending on the poll order (`join!` rotates it).
    let (outcome, ()) = tokio::join!(client.refresh_session(&probed), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.evict_dial_session("svc-1");
    });

    outcome.expect("C2: the liveness verdict is unchanged — the controller said ALIVE");
    assert!(
        client.cached_dial_session("svc-1").is_none(),
        "CN-1: the DV-C3 eviction STANDS — the refresh write found the key absent and skipped"
    );
    assert!(
        logs_contain("refresh re-cache skipped"),
        "the GATE fired (not a vacuous green: the write was reached and skipped)"
    );
    assert!(
        logs_contain(r#"reason="absent""#),
        "CN-1's discriminant: the key was ABSENT at write time"
    );
}

/// T6 (CN-2 on the DIAL path, W2): `refresh_session`'s re-cache must NOT clobber a NEWER session.
/// Same fixture as T5, but the intruder REPLACES the entry with a fresh `sess-2` (evict +
/// `get_or_create`, `edge/conn/retry.rs`). RED under the blind re-cache **and** RED under a WEAK guard
/// (write-if-key-exists): the key is occupied, so the weak guard would clobber `sess-2` with the
/// stale-and-evicted `sess`.
///
/// ⚠ Same anti-vacuity armour as T5 (a late intruder would overwrite a blind write anyway):
/// `.expect(1)` on the probe + `logs_contain` proving the gate SKIPPED with `reason=id-mismatch`.
#[traced_test]
#[tokio::test]
async fn refresh_session_does_not_clobber_newer_session() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/sessions/sess"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(alive_detail_body())
                .set_delay(Duration::from_millis(300)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc-1", dial_detail_ers("svc-1", "opaque-x", "er_old"));

    let probed = dial_detail_ers("svc-1", "opaque-x", "er_old");
    let (outcome, ()) = tokio::join!(client.refresh_session(&probed), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        client.cache_dial_session(
            "svc-1",
            dial_detail_id_ers("svc-1", "sess-2", "opaque-2", "er_s2"),
        );
    });

    outcome.expect("C2: the liveness verdict is unchanged");
    let cached = client
        .cached_dial_session("svc-1")
        .expect("the newer session is still cached");
    assert_eq!(
        cached.id, "sess-2",
        "CN-2: the NEWER session survives — the refresh write saw a different session.id and skipped"
    );
    assert_eq!(
        er_names(&cached),
        vec!["er_s2".to_string()],
        "CN-2: the newer session's edge-routers are intact"
    );
    assert!(
        logs_contain(r#"reason="id-mismatch""#),
        "the GATE fired on the IDENTITY comparison (not a vacuous green, and not mere existence)"
    );
}

/// T8 (CN-3 pinned at the D2 CALL SITE, W2 — the gap T7(d) does NOT cover). T7(d) pins the gate's
/// own keying; nothing pinned `refresh_session`'s **call site** (`&session.service_id`), because
/// every other fixture returns a `serviceId` EQUAL to the key ⇒ swapping it for
/// `&refreshed.service_id` left the whole suite GREEN. Here the controller's 200 body lies: it
/// answers `serviceId: "svcEVIL"` for a session cached under `svc-1`.
///
/// Asserts what the code REALLY does (not what we might wish): the entry is refreshed **under
/// `svc-1`** — the key we photographed — and `svcEVIL` is never created. Under the mutation
/// (`recache_refreshed_dial_session(&self.dial_sessions, &refreshed.service_id, …)`) the lookup
/// misses ⇒ skip ⇒ `svc-1` keeps `er_old` ⇒ **RED**. (`svcEVIL` stays absent under BOTH — a write
/// gate never inserts; see T7(d).)
///
/// This corner is **UNREACHABLE today**: the JWT branch rebuilds with `..session.clone()` (DV-A2), so
/// it copies the snapshot's `service_id` bit for bit, and the opaque branch would need a controller
/// that echoes back a service you did not ask for (DV-R5). And if it ever happened, the worst case is
/// a **misroute to a service the controller already authorised for this identity** — the wire
/// `Connect` carries only the token and the controller derives the service from the session
/// (`create_circuit.go:88-91` → `common.go:418`) — **never an over-permit**.
#[tokio::test]
async fn refresh_session_recaches_under_the_snapshot_key_not_the_bodys_service_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/sessions/sess"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"sess","token":"opaque-x","serviceId":"svcEVIL","type":"Dial","edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls://router:443"}}]},"meta":{}}"#,
            ))
            .expect(1)
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session("svc-1", dial_detail_ers("svc-1", "opaque-x", "er_old"));

    let refreshed = client
        .refresh_session(&dial_detail_ers("svc-1", "opaque-x", "er_old"))
        .await
        .expect("C2: the liveness verdict is unchanged");
    assert_eq!(
        refreshed.service_id, "svcEVIL",
        "the RETURNED value is the controller's body verbatim (C2: the gate rules the write only)"
    );
    // THE discriminant: the refresh landed on the entry we photographed.
    assert_eq!(
        er_names(
            &client
                .cached_dial_session("svc-1")
                .expect("CN-3: the snapshot's key is the one that gets updated")
        ),
        vec!["er_new".to_string()],
        "CN-3: keying the call site by refreshed.service_id would miss and skip, leaving er_old"
    );
    assert!(
        client.cached_dial_session("svcEVIL").is_none(),
        "no phantom key — holds under ANY keying, because a write gate never inserts"
    );
}

/// T-OBS4: the D2 re-cache is observable, and the token is NEVER logged — not even by the D1
/// probe-log that fires in the same call (`refresh_session_probe`). Fixture of
/// `refresh_opaque_recaches_returned_session` with a `TOKSECRET` sentinel token. RED without P6
/// (§6.3 M5); RED if the token leaks from ANY event, including D1's probe log (§6.3 M8).
/// Since 2026-07-11 both P5 and P6 are emitted by [`recache_refreshed_dial_session`] (the write
/// gate), not inline in `refresh_session` — this test is ALSO the positive control of the gate's
/// WRITE arm: the seeded `(svc-1, id=sess)` is the one probed, so the gate passes and logs.
#[traced_test]
#[tokio::test]
async fn refresh_recache_logs_and_never_logs_token() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/sessions/sess"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"id":"sess","token":"opaque-TOKSECRET-x","serviceId":"svc-1","type":"Dial","edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls://router:443"}}]},"meta":{}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");
    client.cache_dial_session(
        "svc-1",
        dial_detail_ers("svc-1", "opaque-TOKSECRET-x", "er_old"),
    );

    let refreshed = client
        .refresh_session(&dial_detail_ers("svc-1", "opaque-TOKSECRET-x", "er_old"))
        .await
        .expect("opaque refresh returns the refreshed SessionDetail");
    assert_eq!(er_names(&refreshed), vec!["er_new".to_string()]);
    assert_eq!(
        er_names(
            &client
                .cached_dial_session("svc-1")
                .expect("session re-cached")
        ),
        vec!["er_new".to_string()],
        "D2 contract intact: the cache reflects the refreshed edge-routers"
    );
    assert!(
        logs_contain("re-cached refreshed dial session"),
        "P6: the re-cache is logged"
    );
    assert!(
        !logs_contain("TOKSECRET"),
        "the session token is NEVER logged, including by the D1 probe log"
    );
}

/// Live validation of the refresh probe's WIRE FORMAT against the real controller — the one
/// new wire reconstruction in slice 9 that the happy-path live tests never exercise (they
/// dial OK on the first try, so the refresh branch is never entered). A `#[cfg(test)]` unit
/// test (not an integration test) because `refresh_session` is `pub(crate)`. Asserts BOTH
/// directions: a valid session probes `Ok` (controller accepts our request + reports alive),
/// and an invalid session token probes `Err` (so the retry actually fires — guards against an
/// endpoint that authorizes via the api-session and ignores `session-token`). Run with
/// `ZITI_EDGE_JWT` set.
#[tokio::test]
#[ignore = "requires a live controller + testsvc-noenc (validates the refresh probe wire format)"]
async fn refresh_probe_alive_and_invalid_session_live() {
    let jwt_path = std::env::var("ZITI_EDGE_JWT").expect("set ZITI_EDGE_JWT to a JWT path");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read JWT");
    let cfg = crate::enroll::ott::enroll(jwt.trim(), crate::enroll::ott::EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // A real, valid Dial session for a visible service.
    let services = client.list_services().await.expect("list services");
    let svc = services
        .iter()
        .find(|s| s.name == "testsvc-noenc")
        .expect("testsvc-noenc visible to this identity");
    let session = client
        .create_session(&svc.id, SessionType::Dial)
        .await
        .expect("create Dial session");

    // D1 (dial-sessions-race): the branch is chosen by the token prefix — JWT → the stateless
    // `GET /services/{id}/edge-routers`, OPAQUE → the stateful `GET /sessions/{id}`. The token
    // value is a credential and is NEVER printed; only the branch NAME is (the discriminant of
    // DV-3). This tells the driver which world the rig is in.
    let probe_branch = if session.token.starts_with(JWT_TOKEN_PREFIX) {
        "jwt"
    } else {
        "opaque"
    };

    // Alive: the controller accepts our probe and reports the valid session as live → Ok.
    client
        .refresh_session(&session)
        .await
        .expect("a valid session must probe Ok (controller accepts the request)");

    // Invalid session → must be rejected on WHICHEVER branch the rig's token type selects; if this
    // returned Ok, the probe ignores real liveness and the retry would NEVER fire — the feature
    // would be dead. Corrupt WITHIN the branch (keep the discriminant so the branch is unchanged):
    // for JWT keep the `ey` prefix but garble the token body (rejected via the `session-token`
    // header); for OPAQUE corrupt the session id so `GET /sessions/{id}` 404s.
    let mut bogus = session.clone();
    if session.token.starts_with(JWT_TOKEN_PREFIX) {
        bogus.token = "eyJhbGciOiJSUzI1NiJ9.this-is-not-a-valid-jwt.sig".to_string();
    } else {
        bogus.id = "this-session-id-does-not-exist".to_string();
        bogus.token = "this-is-not-a-valid-session-token".to_string();
    }
    let err = client
        .refresh_session(&bogus)
        .await
        .expect_err("an invalid session must probe Err (else the retry never fires)");
    // `err` is a SessionHttp{status,code,message} from the controller — carries no token.
    println!(
        "dial-sessions-race refresh probe OK live: branch={probe_branch}, valid→alive, invalid→{err}"
    );
}

/// **4a — LIVE ACCEPTANCE (G1/G2)**: the session-refresh tick PURGES a dial-session the controller
/// DELETED, and does NOT purge (nor poison) a live one. Observable in the rig precisely because the
/// rig authenticates LEGACY (`authenticate()` → `AuthToken::Legacy`), and a legacy api-session is the
/// only one whose sessions the controller PERSISTS (`ziti@9bf62f3
/// controller/internal/routes/session_router.go:220-226`) ⇒ they can be deleted and `GET /sessions/{id}`
/// 404s afterwards. The client deletes its OWN session through the CLIENT api (`DeleteClient`,
/// `session_router.go:76-78`) — no admin credentials, no `ziti` CLI.
///
/// Order matters: tick #1 is the NEGATIVE control (a live session must survive, with its JWT intact —
/// DV-4a-2's mine would show up here as a poisoned token), tick #2 is the ACCEPTANCE.
/// RED under: the inert eviction arm (step 5) · the old token-prefix discriminant (the stateless probe
/// answers 200 for a deleted session ⇒ step 5 fails) · re-caching the detail body wholesale (step 3's
/// token assert fails: the body's `token` is the stored **cuid**, `session_api_model.go:58-59`).
#[tokio::test]
#[ignore = "requires a live controller + testsvc-noenc (4a: the tick purges a DELETED session)"]
async fn session_refresh_tick_purges_deleted_session_live() {
    use crate::edge::session_refresh::session_refresh_tick;

    let jwt_path = std::env::var("ZITI_EDGE_JWT").expect("set ZITI_EDGE_JWT to a JWT path");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read JWT");
    let cfg = crate::enroll::ott::enroll(jwt.trim(), crate::enroll::ott::EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");
    assert!(
        matches!(
            client.auth_token().expect("authenticated").session_type(),
            ApiSessionType::Legacy
        ),
        "the rig authenticates LEGACY — the régime in which sessions are durable (and this test meaningful)"
    );

    let services = client.list_services().await.expect("list services");
    let svc = services
        .iter()
        .find(|s| s.name == "testsvc-noenc")
        .expect("testsvc-noenc visible to this identity");
    let session = client
        .get_or_create_dial_session(&svc.id, TEST_TOTAL)
        .await
        .expect("create + cache a Dial session");
    let id0 = session.id.clone();
    let token0 = session.token.clone();

    // ── Tick #1: the NEGATIVE control (G2). A LIVE session must survive the tick untouched.
    session_refresh_tick(
        &client.http,
        &client.base_url,
        &client.token,
        &client.dial_sessions,
    )
    .await;
    let after = client
        .cached_dial_session(&svc.id)
        .expect("G2: the tick must NOT purge a LIVE session (false purge = under-permit churn)");
    assert_eq!(after.id, id0, "G2: still the same session");
    assert_eq!(
        after.token, token0,
        "DV-4a-2: the cached session token (the JWT) is PRESERVED — the detail body's `token` is the \
             stored cuid and adopting it would break every subsequent dial"
    );
    assert!(
        !after.edge_routers.is_empty(),
        "the durable probe really refreshed the edge-routers (the 200 body was read)"
    );

    // ── Delete OUR OWN session through the CLIENT api (`DELETE /sessions/{id}` → DeleteForIdentity).
    let api_token = client.auth_token().expect("authenticated");
    let url = format!("{}/sessions/{}", client.base_url, id0);
    let resp = apply_access_header(client.http.delete(&url), &api_token)
        .send()
        .await
        .expect("DELETE /sessions/{id} (client api)");
    assert!(
        resp.status().is_success(),
        "the client api deletes its own session: got {}",
        resp.status()
    );

    // ── Tick #2: the ACCEPTANCE (G1). The corpse is PURGED — no dial needed to discover it.
    session_refresh_tick(
        &client.http,
        &client.base_url,
        &client.token,
        &client.dial_sessions,
    )
    .await;
    assert!(
        client.cached_dial_session(&svc.id).is_none(),
        "G1 (4a acceptance): the tick PURGED the deleted session from the dial-session cache"
    );

    // ── Reinforcement: the next dial mints a FRESH session (the controller re-authorises, C5).
    let fresh = client
        .get_or_create_dial_session(&svc.id, TEST_TOTAL)
        .await
        .expect("a new POST /sessions after the purge");
    assert_ne!(
        fresh.id, id0,
        "the purge produced a cache MISS ⇒ a brand-new session id"
    );
    println!("4a live OK: live session survived tick #1, deleted session purged by tick #2");
}

/// D3-CHURN live harness (spec `docs/superpowers/specs/2026-07-11-d3-churn-robustness-design.md`,
/// §6.2 escenario A / §6.3 escenario B). Drives `connect()` repeatedly while the DRIVER deletes
/// dial-sessions (or flaps the service-policy) underneath it, so the `invalid session` retry path
/// is exercised for real and DV-C3's corpse-eviction becomes observable in the trace.
///
/// **This test does NOT grade the gate.** The acceptance criteria of §6.2 are graded by the driver
/// from `RUST_LOG=noa_sdk=debug` (the churn must bite: `trigger=invalid-session` ≥1; the next
/// `connect()` after a double-`invalid session` must log `dial session cache miss`, never
/// `cache hit` → `trigger=invalid-session`) plus the summary line printed below. Deliberately it
/// does **not** assert `ok >= 1`: the mandatory NEGATIVE CONTROL CN-1 (§6.4) runs this very test
/// with the echo backend down and must read `ok=0` from the summary — an assert would turn that
/// control into a panic instead of a measurement.
///
/// It asserts TWO things by itself, in-process (so no `grep` can misread them):
/// 1. **C3 (the acceptance of DV-C3), as an ASSERTION, not a log.** After ANY iteration whose
///    `connect()` returns an `invalid session` `Err` — i.e. BOTH dials were rejected, so the fresh
///    session is proven dead — the dial-session cache MUST be empty for that service. **RED if
///    DV-C3 is reverted.** (Without this the whole live test stayed green with the fix removed.)
/// 2. **§6.2 criterion 5 — never count a failure as a success** (a live harness needs a negative control:
///    `nc` exits rc=0 with the dial down, so success is measured by PAYLOAD, never by a return
///    code). A short read, an EOF, a write error or a foreign payload counts as `err`.
///
/// ⚠ Post-`connect()` failures are **counted, never panicked**: with the echo backend down (CN-1)
/// the router can still answer `StateConnected` and then EOF, and a panic there would kill the run
/// before the summary line printed, making CN-1 unreadable. Counting them keeps the invariant that
/// matters (a failure is NEVER an `ok`) *and* keeps CN-1 a measurement.
///
/// Run (rig up, echo on 127.0.0.1:19009, churn loop in the background — see §6.2):
/// `RUST_LOG=noa_sdk=debug ZITI_EDGE_JWT=<path> cargo test -- --ignored d3_churn_sustained_session_deletion_live --nocapture 2> /tmp/churnA.log`
#[tokio::test]
#[ignore = "requires a live controller + router + testsvc-noenc AND a session-churn generator (D3-CHURN gate, spec §6.2/§6.3); the driver runs it"]
async fn d3_churn_sustained_session_deletion_live() {
    const SVC: &str = "testsvc-noenc";

    // A `#[tokio::test]` installs NO tracing subscriber (only the `noa` binary does), so
    // `RUST_LOG` alone emits nothing: install one here or the P1..P8 dial-cache trace
    // (`617b3fa`) is invisible to the gate. Grading, though, does NOT depend on it — the C3
    // assertion below is in-process precisely so no log grep can misread it.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    // DV-C3 fires only when BOTH dials are rejected `invalid session`, i.e. the churn must kill the
    // FRESHLY created session inside the retry's ~10ms window — rare per connect. 30 iterations
    // almost never hit it (measured: c3_checks=0). The count is therefore tunable so the gate can
    // buy the observation statistically instead of pretending 0 hits is a pass.
    let iterations: usize = std::env::var("D3_CHURN_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    let jwt_path = std::env::var("ZITI_EDGE_JWT").expect("set ZITI_EDGE_JWT to a JWT path");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read JWT");
    let cfg = crate::enroll::ott::enroll(jwt.trim(), crate::enroll::ott::EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // The dial-session cache is keyed by service ID, so resolve it once up front: this is what makes
    // C3 assertable in-process.
    let svc_id = client
        .list_services()
        .await
        .expect("list services")
        .into_iter()
        .find(|s| s.name == SVC)
        .unwrap_or_else(|| panic!("the rig must expose the service `{SVC}`"))
        .id;

    let (mut ok, mut err, mut c3_checks) = (0usize, 0usize, 0usize);
    for i in 0..iterations {
        // C2 (no hangs): `connect()` carries the 15s connect-timeout internally, so churn can make
        // it FAIL but never make it hang. An Err here is a legitimate outcome of the gate (the
        // oracle surrenders too, `ziti.go:1507`) — count it, do not panic.
        let expected = format!("PING-{i}\n");
        match client.connect(SVC).await {
            Err(e) => {
                err += 1;
                println!("d3-churn iter={i}: connect Err ({e})");
                // C3 — THE ACCEPTANCE OF THIS SLICE. An `invalid session` Err means BOTH dials were
                // rejected (D3 already retried once), so the freshly created session is PROVEN DEAD
                // and DV-C3 must have evicted it. If it is still cached, the next connect() would
                // cache-HIT the corpse and burn one of its two dials on it. RED if DV-C3 is reverted.
                if e.is_dial_invalid_session() {
                    c3_checks += 1;
                    assert!(
                        client.cached_dial_session(&svc_id).is_none(),
                        "iter={i}: DV-C3 — after a double-`invalid session` the proven-dead session \
                             must NOT be left in the dial-session cache (svc_id={svc_id})"
                    );
                }
            }
            Ok(mut conn) => {
                // Criterion 5: PAYLOAD equality or bust — but as a COUNTED failure, never a panic
                // (see the doc above: a panic here makes CN-1 unreadable).
                let echoed = match conn.write(expected.as_bytes()).await {
                    Err(e) => Err(format!("write failed: {e}")),
                    Ok(()) => match conn.read().await {
                        Err(e) => Err(format!("read failed: {e}")),
                        Ok(None) => Err("EOF: the echo closed without replying".to_string()),
                        Ok(Some(bytes)) if bytes == expected.as_bytes() => Ok(()),
                        Ok(Some(bytes)) => Err(format!(
                            "payload mismatch (short/foreign read): got {bytes:?}, want {:?}",
                            expected.as_bytes()
                        )),
                    },
                };
                match echoed {
                    Ok(()) => ok += 1,
                    Err(why) => {
                        err += 1;
                        println!("d3-churn iter={i}: dial OK but NOT a round-trip ({why})");
                    }
                }
                let _ = conn.close().await;
            }
        }
    }
    // The line the driver greps. `ok=0` is a VALID reading (CN-1); the grading is the driver's.
    // `c3_checks` says how many times the C3 assertion actually FIRED: if it is 0 the churn never
    // bit, and §6.2 criterion 1 fails the gate at the driver's level (this test cannot know that).
    println!("D3-CHURN summary: ok={ok} err={err} total={iterations} c3_checks={c3_checks}");
}

/// Slice 10a happy-path live check: `create_session_with_backoff` returns a real Dial session
/// against the live controller (the create succeeds on the first attempt, so backoff just wraps a
/// single call — no regression). The retry/permanent classification is deterministically covered
/// by the wiremock tests above (transient failures can't be provoked reliably live). A
/// `#[cfg(test)]` unit test because the helper is `pub(crate)`. Run with `ZITI_EDGE_JWT` set,
/// Oracle: `createSessionWithBackoff` (`ziti.go:2009`).
#[tokio::test]
#[ignore = "requires a live controller + testsvc-noenc (slice 10a backoff happy path)"]
async fn create_session_with_backoff_happy_path_live() {
    let jwt_path = std::env::var("ZITI_EDGE_JWT").expect("set ZITI_EDGE_JWT to a JWT path");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read JWT");
    let cfg = crate::enroll::ott::enroll(jwt.trim(), crate::enroll::ott::EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    let services = client.list_services().await.expect("list services");
    let svc = services
        .iter()
        .find(|s| s.name == "testsvc-noenc")
        .expect("testsvc-noenc visible to this identity");
    let session = client
        .create_session_with_backoff(&svc.id, SessionType::Dial, TEST_TOTAL)
        .await
        .expect("create_session_with_backoff returns a real Dial session");
    assert!(!session.token.is_empty(), "session has a token");
    assert_eq!(
        session.service_id, svc.id,
        "session is for the right service"
    );
    println!(
        "slice 10a backoff happy path OK live: session token len {}",
        session.token.len()
    );
}
