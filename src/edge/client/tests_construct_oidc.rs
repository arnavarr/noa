use super::testsupport::*;
use super::*;

/// `from_ext_jwt` fails fast (`OidcNotSupported`) against a controller without `OIDC_AUTH`, BEFORE
/// any OIDC endpoint is hit (the `/version` gate; mirrors `from_updb_oidc`). The OIDC mocks below
/// are `.expect(0)` — proving the early return precedes the PKCE flow.
#[tokio::test]
async fn from_ext_jwt_fails_fast_without_oidc_capability() {
    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"version":"v1.0.0","capabilities":["HA_CONTROLLER"]},"meta":{}}"#,
        ))
        .mount(&server)
        .await;
    // No OIDC endpoint must be touched.
    Mock::given(method("GET"))
        .and(path("/oidc/authorize"))
        .respond_with(ResponseTemplate::new(302))
        .expect(0)
        .mount(&server)
        .await;

    let cfg = ExtJwtConfig {
        zt_api: format!("{}/edge/client/v1", server.uri()),
        ca: String::new(),
    };
    // `EdgeClient` is intentionally not `Debug` (no secret leak), so match instead of `expect_err`.
    let Err(err) = EdgeClient::from_ext_jwt("ey.ext.jwt", &cfg).await else {
        panic!("from_ext_jwt must fail fast when OIDC_AUTH is not advertised");
    };
    assert!(matches!(err, EdgeError::OidcNotSupported), "got {err:?}");
}

/// `from_ext_jwt` END-TO-END offline (the not-a-half-feature proof at unit level): capability gate
/// → OIDC ext-jwt PKCE flow → token-exchange 200 → Bearer-authed session-cert mint → a READY OIDC
/// client. Pins: (1) the login POST is `/oidc/login/ext-jwt` carrying `Authorization: Bearer
/// <jwt>`; (2) the session-cert mint authenticates with the `Bearer` (NOT zt-session); (3) the
/// built client is an OIDC session whose channel token is the access JWT; (4) `reauth_method` is
/// `ExtJwt` (the fail-loud guard, NOT a fabricated Updb/Cert); (5) the synthetic config is
/// leaf-only. The mint mock matches the Bearer header, so a missing/wrong Bearer → 404 → RED.
#[tokio::test]
#[allow(clippy::too_many_lines)] // the full PKCE-ext-jwt + mint flow needs all five responders inline
async fn from_ext_jwt_full_flow_yields_ready_oidc_client() {
    use base64::Engine as _;
    use std::sync::Arc as StdArc;
    use std::sync::Mutex as StdMutex;
    use wiremock::matchers::header;
    use wiremock::{Request, Respond};

    // The authorize responder captures the client's state + nonce so the callback can echo the
    // state and the token id_token can echo the nonce (the unconditional nonce check).
    struct AuthorizeResponder {
        state: StdArc<StdMutex<String>>,
        nonce: StdArc<StdMutex<String>>,
    }
    impl Respond for AuthorizeResponder {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let pick = |key: &str| {
                req.url
                    .query_pairs()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            *self.state.lock().unwrap() = pick("state");
            *self.nonce.lock().unwrap() = pick("nonce");
            ResponseTemplate::new(302)
                .insert_header("Location", "/oidc/login/ext-jwt?authRequestID=AR1")
        }
    }
    struct CallbackResponder(StdArc<StdMutex<String>>);
    impl Respond for CallbackResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let state = self.0.lock().unwrap().clone();
            ResponseTemplate::new(302).insert_header(
                "Location",
                format!("http://localhost:8080/auth/callback?code=CODE1&state={state}").as_str(),
            )
        }
    }
    struct TokenResponder(StdArc<StdMutex<String>>);
    impl Respond for TokenResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let nonce = self.0.lock().unwrap().clone();
            let h = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"RS256\"}");
            let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(format!(r#"{{"name":"ext-user","nonce":"{nonce}"}}"#).as_bytes());
            let id_token = format!("{h}.{p}.sig");
            ResponseTemplate::new(200).set_body_string(format!(
                    r#"{{"access_token":"ey.EXTACCESS","refresh_token":"ey.EXTREFRESH","expires_in":1800,"id_token":"{id_token}","token_type":"Bearer"}}"#
                ))
        }
    }

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    let captured_state: StdArc<StdMutex<String>> = StdArc::new(StdMutex::new(String::new()));
    let captured_nonce: StdArc<StdMutex<String>> = StdArc::new(StdMutex::new(String::new()));

    // (0) capability gate.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"version":"v1.0.0","capabilities":["OIDC_AUTH"]},"meta":{}}"#,
        ))
        .mount(&server)
        .await;
    // (1) authorize → 302 to /oidc/login/ext-jwt, capturing state + nonce.
    Mock::given(method("GET"))
        .and(path("/oidc/authorize"))
        .respond_with(AuthorizeResponder {
            state: captured_state.clone(),
            nonce: captured_nonce.clone(),
        })
        .mount(&server)
        .await;
    // (2) login → 302 to the callback. The mock ONLY matches if the Authorization Bearer is the
    // external JWT (so a missing/wrong Bearer → no match → 404 → the flow errors → RED).
    Mock::given(method("POST"))
        .and(path("/oidc/login/ext-jwt"))
        .and(header("authorization", "Bearer ey.THE-EXTERNAL-JWT"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "/oidc/authorize/callback?id=AR1"),
        )
        .mount(&server)
        .await;
    // (3) callback → 302 to redirect_uri with code + echoed state.
    Mock::given(method("GET"))
        .and(path("/oidc/authorize/callback"))
        .respond_with(CallbackResponder(captured_state.clone()))
        .mount(&server)
        .await;
    // (4) token exchange → 200 Bearer + id_token echoing the nonce.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(TokenResponder(captured_nonce.clone()))
        .mount(&server)
        .await;
    // (5) session-cert mint, authenticated with the BEARER (NOT zt-session) → 201 leaf.
    let leaf = ephemeral_leaf();
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/current-api-session/certificates"))
        .and(header("authorization", "Bearer ey.EXTACCESS"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": { "id": "cert-1", "certificate": leaf, "cas": "\n<ca>" },
            "meta": {}
        })))
        .mount(&server)
        .await;

    let cfg = ExtJwtConfig {
        zt_api: format!("{}/edge/client/v1", server.uri()),
        ca: String::new(),
    };
    let client = EdgeClient::from_ext_jwt("ey.THE-EXTERNAL-JWT", &cfg)
        .await
        .expect("from_ext_jwt: OIDC ext-jwt flow + Bearer mint → ready client");

    // READY: the channel token is the OIDC access JWT; the session is OIDC; identity from id_token.
    assert_eq!(
        client.token().as_deref(),
        Some("ey.EXTACCESS"),
        "the channel token is the OIDC access Bearer"
    );
    assert_eq!(
        client.auth_token().map(|t| t.session_type()),
        Some(ApiSessionType::Oidc),
        "an ext-jwt session is an OIDC session"
    );
    assert_eq!(client.identity_name(), Some("ext-user"));
    // The fail-loud guard is wired (NOT a fabricated Updb/Cert).
    assert!(
        matches!(client.reauth_method(), ReauthMethod::ExtJwt),
        "from_ext_jwt wires ReauthMethod::ExtJwt"
    );
    // Leaf-only synthetic config (faithful certs[0]).
    let cert_rest = client.config().id.cert.strip_prefix("pem:").unwrap();
    assert_eq!(
        cert_rest.matches("-----BEGIN CERTIFICATE-----").count(),
        1,
        "id.cert is leaf-only"
    );
    assert_eq!(cert_rest, leaf, "id.cert is exactly the minted leaf");
}

/// CERT-OIDC forced refresh (the mTLS sibling): the token-exchange runs over the mTLS `self.http`
/// (from_identity). Asserts the access Bearer VALUE rotates across two `refresh()` calls and a
/// `connect` works under the rotated Bearer. Run with `ZITI_EDGE_JWT_OIDC` set.
#[tokio::test]
#[ignore = "requires a live OIDC-capable controller + router + testsvc-noenc; OIDC-3 cert forced-refresh"]
async fn oidc_cert_forced_refresh_rotates_live() {
    let jwt_path =
        std::env::var("ZITI_EDGE_JWT_OIDC").expect("set ZITI_EDGE_JWT_OIDC to a JWT path");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read JWT");
    let cfg = crate::enroll::ott::enroll(jwt.trim(), crate::enroll::ott::EnrollOptions::default())
        .await
        .expect("enrolment succeeds");
    let mut client = EdgeClient::from_identity(&cfg).expect("mTLS client builds");
    client
        .authenticate_oidc()
        .await
        .expect("OIDC cert authenticate succeeds");

    let t0 = client.token().expect("OIDC access present after auth");
    // Refresh #1: the RFC 8693 token-exchange over the mTLS http.
    client
        .refresh()
        .await
        .expect("OIDC refresh #1 succeeds live");
    let t1 = client
        .token()
        .expect("OIDC access present after refresh #1");
    assert_ne!(t0, t1, "the access Bearer ROTATED on refresh #1");

    // Refresh #2: proves the rotated refresh token was written back (else this would re-send the
    // consumed refresh — works on this controller, but the VALUE must still rotate again).
    client
        .refresh()
        .await
        .expect("OIDC refresh #2 succeeds live");
    let t2 = client
        .token()
        .expect("OIDC access present after refresh #2");
    assert_ne!(t1, t2, "the access Bearer ROTATED again on refresh #2");

    // The session survives past the original window: a control-plane + data-plane call works under
    // the NEW Bearer.
    let conn = client
        .connect("testsvc-noenc")
        .await
        .expect("connect under the rotated OIDC Bearer succeeds");
    conn.close().await.ok();
    println!("OIDC-3 cert forced-refresh OK live: access rotated twice + connect under new Bearer");
}

/// UPDB-OIDC forced refresh (the genuinely-UNPROVEN non-mTLS sibling): the token-exchange runs over
/// the NON-mTLS, token-only `self.http` (RootCAs-only) — the probe only exercised the mTLS client,
/// so this is the new wire the spec §7 flags. Asserts the same rotation + connect. Run with
/// `ZITI_EDGE_JWT_UPDB_OIDC` + `ZITI_EDGE_UPDB_OIDC_PASS`.
#[tokio::test]
#[ignore = "requires a live OIDC-capable controller + router + testsvc-noenc + updb identity; OIDC-3 updb forced-refresh"]
async fn oidc_updb_forced_refresh_rotates_live() {
    let jwt_path = std::env::var("ZITI_EDGE_JWT_UPDB_OIDC")
        .expect("set ZITI_EDGE_JWT_UPDB_OIDC to a JWT path");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read JWT");
    let username = std::env::var("ZITI_EDGE_UPDB_OIDC_USER").unwrap_or_default();
    let password =
        std::env::var("ZITI_EDGE_UPDB_OIDC_PASS").unwrap_or_else(|_| "oidcpassword123".into());

    let updb_cfg = crate::enroll::updb::enroll_updb(
        jwt.trim(),
        &username,
        &password,
        crate::enroll::ott::EnrollOptions::default(),
    )
    .await
    .expect("updb enrolment sets the password");
    let mut client = EdgeClient::from_updb_oidc(&updb_cfg)
        .await
        .expect("from_updb_oidc: OIDC password-auth + Bearer session-cert mint + ready client");

    let t0 = client.token().expect("OIDC access present after auth");
    // Refresh #1 + #2 over the NON-mTLS http (the unproven wire).
    client
        .refresh()
        .await
        .expect("updb-OIDC refresh #1 succeeds live (non-mTLS http)");
    let t1 = client
        .token()
        .expect("OIDC access present after refresh #1");
    assert_ne!(t0, t1, "the access Bearer ROTATED on refresh #1 (non-mTLS)");
    client
        .refresh()
        .await
        .expect("updb-OIDC refresh #2 succeeds live (non-mTLS http)");
    let t2 = client
        .token()
        .expect("OIDC access present after refresh #2");
    assert_ne!(
        t1, t2,
        "the access Bearer ROTATED again on refresh #2 (non-mTLS)"
    );

    let conn = client
        .connect("testsvc-noenc")
        .await
        .expect("connect under the rotated updb-OIDC Bearer succeeds");
    conn.close().await.ok();
    println!(
        "OIDC-3 updb forced-refresh OK live: access rotated twice over non-mTLS http + connect"
    );
}
