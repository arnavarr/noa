use super::testsupport::*;
use super::*;

/// DEFENSE-IN-DEPTH Send pin at the PUBLIC spawn surface: the future of the public
/// [`EdgeClient::from_updb_oidc_with_totp`] constructor — built (NOT run) with a CONCRETE
/// `Some(&provider)` so the `Option<&TotpCodeProvider>` is actually carried across the OIDC
/// awaits — must be `Send` (so callers can `tokio::spawn` it). The internal
/// `oidc_authenticate_future_is_send_with_a_provider` canary pins the same property on the helper;
/// this pins the exact public surface. MUTATION: drop `+ Sync` from the
/// [`TotpCodeProvider`](crate::edge::oidc::TotpCodeProvider) alias → `&dyn Fn` is not `Send` → the
/// future is not `Send` → this fails to COMPILE (RED). Non-vacuous: a borrowed provider IS held
/// across the awaits.
#[test]
fn from_updb_oidc_with_totp_future_is_send() {
    fn assert_send<T: Send>(_t: T) {}
    let cfg = updb_cfg("http://127.0.0.1:1");
    let provider = || Ok("123456".to_string());
    let fut = EdgeClient::from_updb_oidc_with_totp(&cfg, Some(&provider));
    assert_send(fut);
}

/// Send pin for the enroll-at-login PUBLIC surface: the future of
/// [`EdgeClient::from_updb_oidc_with_mfa`] built with a CONCRETE `Some(&enroll_handler)` must be
/// `Send` (so callers can `tokio::spawn` it). MUTATION: drop `+ Sync` from the
/// [`TotpEnrollmentHandler`](crate::edge::oidc::TotpEnrollmentHandler) alias → `&dyn Fn` is not
/// `Send` → the future is not `Send` → fails to COMPILE (RED). Non-vacuous: a borrowed handler IS
/// held across the OIDC awaits. `ensure_crypto_provider()` first (it builds a reqwest client; the
/// process-wide rustls crypto provider must be installed first in every isolated test), AFTER the inner `fn` item to
/// avoid `clippy::items-after-statements`.
#[test]
fn from_updb_oidc_with_mfa_future_is_send() {
    fn assert_send<T: Send>(_t: T) {}
    crate::enroll::trust::ensure_crypto_provider();
    let cfg = updb_cfg("http://127.0.0.1:1");
    let provider = || Ok("123456".to_string());
    let handler = |_url: &str| Ok("654321".to_string());
    let fut = EdgeClient::from_updb_oidc_with_mfa(&cfg, Some(&provider), Some(&handler));
    assert_send(fut);
}

#[tokio::test]
async fn from_updb_password_auth_then_cert_yields_ready_client_with_synthetic_config() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    let leaf = ephemeral_leaf();
    // A distinct second block so "leaf-only" (not chain) is observable in id.cert.
    let inter =
        "-----BEGIN CERTIFICATE-----\nSGVsbG9JbnRlcm1lZGlhdGU=\n-----END CERTIFICATE-----\n";
    mount_updb_flow(&server, &leaf, inter, 200, 1).await;
    let base = format!("{}/edge/client/v1", server.uri());

    let cfg = updb_cfg(&base);
    let client = EdgeClient::from_updb(&cfg).await.expect("from_updb ready");

    // The client is READY: token + identity name set (from the password api-session).
    assert_eq!(client.token().as_deref(), Some("updb-tok"));
    assert_eq!(client.identity_name(), Some("updbuser"));
    assert!(
        client.cached_dial_session("any").is_none(),
        "dial-session cache starts empty"
    );

    // Synthetic Config: each id value carries EXACTLY ONE `pem:` prefix (the channel's
    // `pem_value` errors without it; a double prefix would corrupt the PEM).
    let id = &client.config().id;
    for (field, value) in [("cert", &id.cert), ("key", &id.key), ("ca", &id.ca)] {
        let rest = value
            .strip_prefix("pem:")
            .unwrap_or_else(|| panic!("id.{field} must start with `pem:`: {value}"));
        assert!(
            !rest.contains("pem:"),
            "id.{field} double-prefixed: {value}"
        );
    }
    // id.cert is the LEAF only (one BEGIN CERTIFICATE block), not the full chain.
    let cert_rest = id.cert.strip_prefix("pem:").unwrap();
    assert_eq!(
        cert_rest.matches("-----BEGIN CERTIFICATE-----").count(),
        1,
        "id.cert is leaf-only (faithful: oracle keeps certs[0]); got the chain"
    );
    assert_eq!(cert_rest, leaf, "id.cert is exactly the minted leaf");
    // id.key is the ephemeral private key S1 generated for the CSR (a private-key PEM, NOT a
    // cert). It is generated INSIDE `acquire_api_session_cert`, so it is unpredictable here — we
    // assert only its shape (and that it is not accidentally the cert).
    let key_rest = id.key.strip_prefix("pem:").unwrap();
    assert!(
        key_rest.contains("PRIVATE KEY"),
        "id.key is the ephemeral private key: {key_rest}"
    );
    assert!(
        !key_rest.contains("BEGIN CERTIFICATE"),
        "id.key must be a key, not a cert"
    );
    // id.ca came from cfg.ca (here empty → `pem:` only). zt_api threaded through.
    assert_eq!(client.base_url(), base);
    assert_eq!(client.config().zt_api, base);
}

#[tokio::test]
async fn from_updb_auth_failure_does_not_request_cert() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    let leaf = ephemeral_leaf();
    // auth 401, and the cert mock `.expect(0)` → the cert request must NEVER be made.
    mount_updb_flow(&server, &leaf, "", 401, 0).await;
    let base = format!("{}/edge/client/v1", server.uri());

    // `EdgeClient` is not `Debug`, so unwrap the error via `let-else` (not `expect_err`).
    let Err(err) = EdgeClient::from_updb(&updb_cfg(&base)).await else {
        panic!("password-auth 401 must fail before any cert request");
    };
    assert!(
        matches!(err, EdgeError::AuthHttp { status: 401, .. }),
        "got {err:?}"
    );
    // `.expect(0)` on the cert mock is verified on `server` drop: proves auth failed FIRST.
}

#[tokio::test]
async fn from_updb_cert_mint_400_maps_to_session_cert_http() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    // Password auth succeeds...
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "password"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "id": "s", "token": "updb-tok", "authQueries": [],
                      "identity": { "name": "updbuser" } },
            "meta": {}
        })))
        .mount(&server)
        .await;
    // ...but the cert mint returns 400 COULD_NOT_PROCESS_CSR.
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/current-api-session/certificates"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": { "code": "COULD_NOT_PROCESS_CSR", "message": "bad csr" }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());

    // `EdgeClient` is not `Debug`, so unwrap the error via `let-else` (not `expect_err`).
    let Err(err) = EdgeClient::from_updb(&updb_cfg(&base)).await else {
        panic!("cert-mint 400 must surface as SessionCertHttp");
    };
    assert!(
        matches!(err, EdgeError::SessionCertHttp { status: 400, .. }),
        "got {err:?}"
    );
}

/// The cert-identity path of `channel_client_config` (`session_cert`=None): builds a config from
/// `self.config` + returns the leaf CN, WITHOUT touching the network (no controller/mint). This is
/// the byte-identity-by-construction guarantee — it calls the same `client_config(&self.config)`
/// and `leaf_common_name_for` as before this slice, so it cannot regress the validated cert path.
#[tokio::test]
async fn channel_client_config_cert_identity_builds_without_network() {
    let cfg = cert_identity_config();
    // `from_identity` builds an mTLS reqwest client but makes NO request; no server is running, so
    // if the seam tried to hit the network it would fail. It does not (session_cert=None).
    let client = EdgeClient::from_identity(&cfg).expect("cert-identity client builds");
    assert!(
        client.session_cert.is_none(),
        "a cert-identity must have no renewable session-cert"
    );
    let (_cc, cn) = client
        .channel_client_config()
        .await
        .expect("cert-identity config builds offline");
    assert_eq!(cn, "client-cn", "CN comes from the config leaf");
}

/// `from_updb` wires the RENEWABLE session-cert holder (`session_cert`=Some) — the SOLE
/// channel-TLS source for updb, so the re-mint actually takes effect. The holder's initial leaf is
/// the minted leaf. (The S2 synthetic `config` still exists for introspection but is NOT the live
/// TLS leaf on the Some path.)
#[tokio::test]
async fn from_updb_wires_renewable_session_cert_holder() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    let leaf = ephemeral_leaf();
    mount_updb_flow(&server, &leaf, "", 200, 1).await;
    let base = format!("{}/edge/client/v1", server.uri());

    let client = EdgeClient::from_updb(&updb_cfg(&base))
        .await
        .expect("from_updb ready");

    let holder = client
        .session_cert
        .as_ref()
        .expect("updb client must carry a renewable session-cert holder");
    let guard = holder.lock().await;
    // The holder's leaf is exactly the minted leaf (the live TLS source for updb).
    assert_eq!(
        guard.leaf_pem(),
        leaf,
        "the holder starts from the minted leaf"
    );
}

/// THE discriminating test for the slice's reason-to-exist: `channel_client_config`'s `Some`
/// (updb) branch must build the channel TLS from the HOLDER's (re-minted) leaf, NOT from the
/// stale synthetic `config` leaf. A mutant that read `self.config.id.cert` would survive the live
/// forced-remint proof (the original session-cert stays ~12h-valid, so the round-trip passes and
/// the holder-leaf still changes) — only a CN distinction catches it, and live can't (the
/// controller overwrites the Subject with the identity id, so L0 and L1 share a CN there).
///
/// We own ONE P-256 key (the holder's reused ephemeral key) and build the original + re-minted
/// leaves over it with DISTINCT CNs. The seam re-mints (wiremock) and must return the RE-MINTED
/// CN; a config-leaf read would return the ORIGINAL CN (asserted to differ). The shared key is why
/// the re-minted leaf + the holder's reused key pass `with_client_auth_cert`.
#[tokio::test]
async fn channel_client_config_updb_uses_reminted_holder_leaf_not_config() {
    crate::enroll::trust::ensure_crypto_provider();
    // One CA + one leaf key (the holder's REUSED ephemeral key). Both leaves share the leaf key.
    let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).unwrap();
    let ca_der = ca.der().to_vec();

    let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let original = p256_leaf_cn_signed("original-cn", &leaf_kp, &ca_params, &ca_kp);
    let reminted = p256_leaf_cn_signed("reminted-cn", &leaf_kp, &ca_params, &ca_kp);

    let server = MockServer::start().await;
    // The seam's ensure-fresh re-mint returns the re-minted leaf (CN distinct, same pubkey).
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/current-api-session/certificates"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": { "id": "cert-1", "certificate": reminted }, "meta": {}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());

    // Build the updb client DIRECTLY (not via from_updb, whose internal key we couldn't match):
    // config leaf = the ORIGINAL leaf (CN original-cn), holder seeded from the SAME leaf + key.
    let mut client = EdgeClient::for_test_with(&base, "updb-tok");
    client.config.id.cert = format!("pem:{original}");
    client.config.id.key = format!("pem:{}", leaf_kp.serialize_pem());
    let holder = crate::edge::session_cert_renew::SessionCertState::new(
        &crate::edge::session_cert::SessionCert {
            leaf_pem: original.clone(),
            chain_pem: original.clone(),
            key_pem: leaf_kp.serialize_pem(),
            id: "cert-0".into(),
        },
        vec![ca_der],
    )
    .expect("holder builds");
    client.session_cert = Some(std::sync::Arc::new(tokio::sync::Mutex::new(holder)));

    // Force the holder stale so the NEXT channel_client_config re-mints.
    client
        .session_cert
        .as_ref()
        .unwrap()
        .lock()
        .await
        .force_renew_from_now();

    // The seam re-mints (cert POST → reminted leaf) and builds TLS + CN from the HOLDER's new leaf.
    let (_cc, cn) = client
        .channel_client_config()
        .await
        .expect("seam re-mints + builds from the holder leaf");
    assert_eq!(
        cn, "reminted-cn",
        "the seam built TLS from the RE-MINTED holder leaf, not the stale config leaf"
    );
    // The config leaf still carries the ORIGINAL CN — a config-leaf read would return THIS, which
    // is what makes the assertion above discriminating.
    let config_cn = crate::edge::channel::leaf_common_name_for(
        client.config().id.cert.strip_prefix("pem:").unwrap(),
    )
    .unwrap();
    assert_eq!(
        config_cn, "original-cn",
        "the (stale) config leaf carries the ORIGINAL CN — a config-leaf read would return this"
    );
}

/// `refresh(&mut self)` (now delegating to `do_refresh_get`) extends the session: it GETs
/// `/current-api-session` and persists BOTH the refreshed token AND the new expiry (the §4.3 fix —
/// the old `refresh` discarded `expiresAt`). Brings the previously-dead `refresh()` method to life.
#[tokio::test]
async fn refresh_persists_token_and_expiry() {
    let server = MockServer::start().await;
    mount_refresh_get(&server, "T-REFRESHED", FAR_EXPIRY, 1).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    assert!(client.expires_at().is_none(), "precondition: no expiry yet");

    client.refresh().await.expect("refresh succeeds");

    assert_eq!(
        client.token().as_deref(),
        Some("T-REFRESHED"),
        "the refreshed token is persisted"
    );
    assert!(
        client.expires_at().is_some(),
        "the new expiry is persisted (the §4.3 fix; the old refresh discarded it)"
    );
}

/// TIMER GET success: a spawned timer with a ZERO `default` interval fires immediately, GETs
/// `/current-api-session`, and rotates the token + persists the new expiry. Injected tiny intervals
/// (no real-time wait); the far-future expiry parks the loop after the first tick.
#[tokio::test]
async fn timer_refreshes_token_and_expiry() {
    let server = MockServer::start().await;
    // First tick fires immediately (default=0) and GETs; after that the far expiry parks it.
    mount_refresh_get(&server, "T-TIMER", FAR_EXPIRY, 1).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    // Tiny intervals: default=0 → the first tick fires now; lead big enough that the far expiry
    // parks the loop well into the future after the GET.
    client.spawn_refresh_timer_with(crate::edge::refresh::RefreshIntervals {
        lead: Duration::from_secs(1),
        default: Duration::ZERO,
        retry: Duration::from_millis(10),
    });

    // Wait for the timer to fire its single GET (poll the token rotation, bounded).
    for _ in 0..200 {
        if client.token().as_deref() == Some("T-TIMER") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        client.token().as_deref(),
        Some("T-TIMER"),
        "the timer rotated the token via the GET"
    );
    assert!(
        client.expires_at().is_some(),
        "the timer persisted the new expiry"
    );
    // `mount_refresh_get(..., 1)` verified on drop: exactly one GET (the loop parked afterwards).
}

/// TIMER 401 → full re-auth fallback: the timer's GET 401s (the api-session is gone), so the timer
/// falls back to a deduped `do_reauthenticate` (POST `/authenticate`) — keeping an idle session
/// alive across a hard expiry. The token rotates to the re-auth's fresh value.
#[tokio::test]
async fn timer_401_falls_back_to_reauth() {
    let server = MockServer::start().await;
    // GET 401 (session gone). `up_to_n_times(1)` so it is consumed once, then the loop re-auths.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // The fallback re-auth mints T-REAUTH (cert method, the test ctor's reauth_method).
    mount_cert_reauth(&server, "T-REAUTH", 1).await;
    // After the re-auth the loop reschedules (retry) and GETs again with the fresh token — return
    // a far-expiry 200 so it parks (any positive count; we only assert the token rotated).
    mount_refresh_get(&server, "T-REAUTH", FAR_EXPIRY, 0).await; // T-REAUTH GET (>=0; may not run)
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    client.spawn_refresh_timer_with(crate::edge::refresh::RefreshIntervals {
        lead: Duration::from_secs(1),
        default: Duration::ZERO,
        retry: Duration::from_millis(5),
    });

    for _ in 0..400 {
        if client.token().as_deref() == Some("T-REAUTH") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        client.token().as_deref(),
        Some("T-REAUTH"),
        "the timer's 401 fell back to a full re-auth"
    );
}

/// SPAWN-ONCE: two `authenticate()`s spawn the timer exactly once (the second does not replace the
/// handle). Mirrors the oracle's `firstAuthOnce.Do`. Asserts the JoinHandle identity is stable
/// across the second auth.
#[tokio::test]
async fn authenticate_spawns_refresh_timer_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "cert"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "id": "a", "token": "TOK", "expiresAt": FAR_EXPIRY,
                      "authQueries": [], "identity": { "name": "tester" } },
            "meta": {}
        })))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    assert!(
        client.refresh_task.is_none(),
        "no timer before authenticate"
    );

    client.authenticate().await.expect("auth 1");
    assert!(client.refresh_task.is_some(), "timer spawned on first auth");
    // §4.3 (AUTH path): `authenticate` persists token AND expiry (mutate it to drop
    // `session.expires_at` → this goes RED). The timer reads this fresh deadline.
    assert_eq!(client.token().as_deref(), Some("TOK"), "auth set the token");
    assert!(
        client.expires_at().is_some(),
        "auth persisted the api-session expiry (§4.3)"
    );
    let id1 = client.refresh_task.as_ref().unwrap().id();

    client.authenticate().await.expect("auth 2");
    let id2 = client.refresh_task.as_ref().unwrap().id();
    assert_eq!(id1, id2, "the second auth did NOT re-spawn (spawn-once)");
}

/// DROP aborts the timer: a spawned timer's JoinHandle is captured, the client is dropped, and the
/// task ends (abort). Mirrors `EdgeChannel::Drop`. We capture the handle's abort-handle BEFORE the
/// drop and assert the task is finished afterwards.
#[tokio::test]
async fn drop_aborts_refresh_timer() {
    let server = MockServer::start().await;
    // A GET that never matches a positive expiry → the timer would loop forever if not aborted.
    // (We don't even need to mount it; the timer parks on a long default before its first tick.)
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    // A LONG default so the task is parked in `sleep` (not racing to exit on its own).
    client.spawn_refresh_timer_with(crate::edge::refresh::RefreshIntervals {
        lead: Duration::from_secs(1),
        default: Duration::from_secs(3600),
        retry: Duration::from_secs(5),
    });
    let abort = client.refresh_task.as_ref().unwrap().abort_handle();
    assert!(!abort.is_finished(), "the timer is parked, not finished");

    drop(client);

    // After Drop aborts the handle, the task winds down. Poll the abort-handle (bounded).
    for _ in 0..200 {
        if abort.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        abort.is_finished(),
        "Drop aborted the background timer task"
    );
}

/// DROP aborts the (opt-in) SERVICE-refresh timer too (T5-2b). Start the poller with a long
/// interval so the task parks in `sleep`, capture its abort-handle, drop the client, assert it
/// winds down. Mutation: dropping the `service_refresh_task.take().abort()` from `Drop` → the task
/// outlives the client → RED here.
#[tokio::test]
async fn drop_aborts_service_refresh_timer() {
    let server = MockServer::start().await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    // A LONG interval so the task parks before its first tick (no HTTP needed).
    client.start_service_polling_with(
        vec![],
        crate::edge::service_refresh::ServiceRefreshIntervals {
            interval: Duration::from_secs(3600),
            jitter: 0.0,
        },
    );
    let abort = client.service_refresh_task.as_ref().unwrap().abort_handle();
    assert!(
        !abort.is_finished(),
        "the svc timer is parked, not finished"
    );

    drop(client);

    for _ in 0..200 {
        if abort.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        abort.is_finished(),
        "Drop aborted the svc-refresh timer task"
    );
}

/// `start_service_polling` is START-ONCE: a second call does NOT re-spawn (mirrors the proactive
/// timer's spawn-once). Pins the idempotency guard. Mutation: dropping the `is_some()` early-return
/// → a second task id ≠ the first → RED.
#[tokio::test]
async fn start_service_polling_is_start_once() {
    let server = MockServer::start().await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    let long = crate::edge::service_refresh::ServiceRefreshIntervals {
        interval: Duration::from_secs(3600),
        jitter: 0.0,
    };
    client.start_service_polling_with(vec![], long);
    let id1 = client.service_refresh_task.as_ref().unwrap().id();
    client.start_service_polling_with(vec!["host.v1".into()], long);
    let id2 = client.service_refresh_task.as_ref().unwrap().id();
    assert_eq!(id1, id2, "the second start did NOT re-spawn (start-once)");
}

/// TW1 (D2): the session-refresh timer is ALWAYS-ON after the first auth and START-ONCE. Two
/// `authenticate()`s spawn it exactly once (the second does not replace the handle) — mirror of
/// `authenticate_spawns_refresh_timer_once`. Faithful to the oracle spawning `runRefreshes` (all
/// three arms) unconditionally in `firstAuthOnce.Do`. RED without the always-on spawn (`None`) or
/// without the start-once guard (a re-spawn changes the id).
#[tokio::test]
async fn session_refresh_timer_always_on_and_start_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "cert"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "id": "a", "token": "TOK", "expiresAt": FAR_EXPIRY,
                      "authQueries": [], "identity": { "name": "tester" } },
            "meta": {}
        })))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    assert!(
        client.session_refresh_task.is_none(),
        "no session timer before authenticate"
    );

    client.authenticate().await.expect("auth 1");
    assert!(
        client.session_refresh_task.is_some(),
        "the session-refresh timer went always-on with the first auth"
    );
    let id1 = client.session_refresh_task.as_ref().unwrap().id();

    client.authenticate().await.expect("auth 2");
    let id2 = client.session_refresh_task.as_ref().unwrap().id();
    assert_eq!(
        id1, id2,
        "the second auth did NOT re-spawn the session timer (start-once)"
    );
}

/// TW2 (D2): `Drop` aborts the session-refresh timer. Start it with a long interval so the task
/// parks in `sleep`, capture its abort-handle, drop the client, assert it winds down — mirror of
/// `drop_aborts_service_refresh_timer`. Mutation: dropping the 3rd `session_refresh_task.take().abort()`
/// arm from `Drop` → the task outlives the client → RED here.
#[tokio::test]
async fn session_refresh_task_aborted_on_drop() {
    let server = MockServer::start().await;
    let base = format!("{}/edge/client/v1", server.uri());
    let mut client = EdgeClient::for_test_with(&base, "T0");
    // A LONG interval so the task parks before its first tick (no HTTP needed).
    client.spawn_session_refresh_timer_with(SessionRefreshIntervals {
        interval: Duration::from_secs(3600),
        jitter: 0.0,
    });
    let abort = client.session_refresh_task.as_ref().unwrap().abort_handle();
    assert!(
        !abort.is_finished(),
        "the session timer is parked, not finished"
    );

    drop(client);

    for _ in 0..200 {
        if abort.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        abort.is_finished(),
        "Drop aborted the always-on session-refresh timer task"
    );
}

/// NON-VACUOUS live validation of the T5-2b background svc-refresh TIMER end-to-end: spawn the real
/// `run_service_refreshes` with a TINY interval (injected via the `pub(crate)`
/// `start_service_polling_with`, hence a `#[cfg(test)]` unit test, not an integration test) against
/// the real controller, and assert the timer's first tick actually DROVE a gated service refresh —
/// `GET /current-api-session/service-updates` then `GET /services` then the diff fan-out — by
/// observing the registered listener fire with the identity's visible services as `Added`. The
/// scheduling/jitter/backoff is client logic (wiremock/unit-covered per `noa-live-validation-rule`);
/// the WIRE the tick exercises is already live (T5-2a), but this proves the NEW timer path stitches
/// them together against a live controller (a broken spawn / Send issue / wrong free-core wiring
/// would fire 0 events). Drop then aborts the task. Run with `ZITI_EDGE_JWT` set, default +
///
#[tokio::test]
#[ignore = "requires a live controller + a visible Dial service; tunneler T5-2b timer"]
async fn start_service_polling_drives_a_live_gated_refresh() {
    use crate::edge::service_refresh::ServiceRefreshIntervals;
    use crate::edge::services::ServiceEvent;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let jwt_path = std::env::var("ZITI_EDGE_JWT").expect("set ZITI_EDGE_JWT to a JWT path");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read JWT");
    let cfg = crate::enroll::ott::enroll(jwt.trim(), crate::enroll::ott::EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client.authenticate().await.expect("authenticate succeeds");

    // A listener counts the Added events the timer's first tick fans out.
    let added = Arc::new(AtomicUsize::new(0));
    let added_cb = added.clone();
    let _id = client.add_service_listener(Arc::new(move |ev: &ServiceEvent| {
        if matches!(ev, ServiceEvent::Added(_)) {
            added_cb.fetch_add(1, Ordering::SeqCst);
        }
    }));

    // Start the REAL background timer with a 250ms period so it ticks within the test window. The
    // first tick: cache empty + no stored instant → check reports "available" → fetch /services →
    // every visible service is Added → the listener fires.
    client.start_service_polling_with(
        vec![],
        ServiceRefreshIntervals {
            interval: Duration::from_millis(250),
            jitter: 0.0,
        },
    );

    // Poll the counter (bounded): the first tick is ~250ms out, then it re-arms every ~250ms but the
    // set is unchanged afterwards (no further Added), so we just need ONE Added wave.
    let mut fired = 0;
    for _ in 0..40 {
        fired = added.load(Ordering::SeqCst);
        if fired >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        fired >= 1,
        "the background svc-refresh timer drove a live gated refresh and fanned out >=1 Added event"
    );

    // Drop aborts the timer (no hang).
    drop(client);
    println!(
        "tunneler T5-2b OK live: background timer drove a gated refresh, {fired} Added event(s)"
    );
}
