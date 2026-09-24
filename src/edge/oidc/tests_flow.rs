//! Tests de `flow` (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`).

use super::testsupport::make_jwt;
use super::*;

/// The LOAD-BEARING wire fragment of the ext-jwt slice: the login POST presents the external JWT
/// as `Authorization: Bearer <jwt>` for ExtJwt ONLY, and adds NO Authorization header for
/// password/cert (those use the form body / the mTLS transport). The negative assertions are the
/// mutation-killers: if the injection were unconditional (or wrong for ext-jwt), one of these goes
/// RED.
///
/// It ALSO pins that the ext-jwt login form carries an EMPTY `username`/`password` — the JWT rides
/// the Bearer header, NOT the form body (oracle `JwtCredentials.AuthenticateRequest`,
/// `credentials.go:340`, only ADDS the header). Mutation: writing the JWT into the form `username`
/// (or `password`) makes the empty-form assertion RED.
///
/// Oracle `JwtCredentials.AuthenticateRequest` (`credentials.go:340`).
#[tokio::test]
async fn login_post_injects_bearer_only_for_ext_jwt() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The recorded login POST: its `Authorization` header (if any) and its form body.
    struct LoginCapture {
        auth_header: Option<String>,
        body: String,
    }

    // Drive authorize→login (callback intentionally unmocked → the flow errors AFTER the login
    // POST is recorded), then read the recorded login POST's Authorization header + form body.
    async fn capture_login(grant: &OidcGrant) -> LoginCapture {
        crate::enroll::trust::ensure_crypto_provider();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oidc/authorize"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "/oidc/login/seg?authRequestID=AR1"),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/oidc/login/{}", grant.login_segment())))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "/oidc/authorize/callback?id=AR1"),
            )
            .mount(&server)
            .await;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        // The flow errors at the unmocked callback — irrelevant; the login POST is already sent.
        let _ = oidc_authenticate(&http, &server.uri(), grant, None, None).await;
        let reqs = server.received_requests().await.expect("recording enabled");
        let login = reqs
            .iter()
            .find(|r| r.url.path().starts_with("/oidc/login/"))
            .expect("the login POST was recorded");
        LoginCapture {
            auth_header: login
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_string()),
            body: String::from_utf8(login.body.clone()).expect("the login body is UTF-8"),
        }
    }

    /// Read the value of a single `application/x-www-form-urlencoded` field.
    fn form_field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
        body.split('&')
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
    }

    // ext-jwt → exactly `Bearer <jwt>` (the literal space, the verbatim JWT) AND an empty form
    // username/password (the JWT rides the header, NOT the body).
    let ext = capture_login(&OidcGrant::ExtJwt {
        jwt: "THEJWT".into(),
    })
    .await;
    assert_eq!(
        ext.auth_header.as_deref(),
        Some("Bearer THEJWT"),
        "ext-jwt presents the external JWT as `Authorization: Bearer <jwt>`"
    );
    assert_eq!(
        form_field(&ext.body, "username"),
        Some(""),
        "ext-jwt login form `username` MUST be empty (the JWT rides the Bearer header, not the body): {}",
        ext.body
    );
    assert_eq!(
        form_field(&ext.body, "password"),
        Some(""),
        "ext-jwt login form `password` MUST be empty (the JWT rides the Bearer header, not the body): {}",
        ext.body
    );
    // password → NO Authorization header (the injection is ext-jwt-only).
    assert!(
        capture_login(&OidcGrant::Password {
            username: "u".into(),
            password: "p".into()
        })
        .await
        .auth_header
        .is_none(),
        "password must NOT add an Authorization header"
    );
    // cert → NO Authorization header (the client cert rides the mTLS transport).
    assert!(
        capture_login(&OidcGrant::Cert).await.auth_header.is_none(),
        "cert must NOT add an Authorization header"
    );
}

/// Orchestration wire-sequence (happy path): authorize 302 → login form 302 → callback 302 →
/// token 200. Asserts the flow reaches the token endpoint and parses the Bearer. The login POST is
/// `application/x-www-form-urlencoded` (the §1 cert-401 fix). The callback must echo the client's
/// `state`, and (after the unconditional-nonce review fix) the token endpoint must return an
/// id_token carrying the client's `nonce` — so the authorize responder captures BOTH `state` and
/// `nonce` from the inbound query, the callback echoes the state, and the token responder bakes the
/// captured nonce into the id_token (the same capture→echo pattern). Driven with a no-redirect
/// client.
#[tokio::test]
async fn oidc_authenticate_drives_the_full_wire_sequence() {
    use std::sync::Arc as StdArc;
    use std::sync::Mutex as StdMutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    // Responders defined up-front (items before statements). The authorize responder captures the
    // client's `state` + `nonce`; the callback echoes the state; the token responder echoes the
    // nonce inside the id_token (the unconditional nonce check requires the round-trip).
    struct AuthorizeResponder {
        state: StdArc<StdMutex<String>>,
        nonce: StdArc<StdMutex<String>>,
    }
    impl Respond for AuthorizeResponder {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let url = req.url.clone();
            let pick = |key: &str| {
                url.query_pairs()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default()
            };
            *self.state.lock().unwrap() = pick("state");
            *self.nonce.lock().unwrap() = pick("nonce");
            ResponseTemplate::new(302)
                .insert_header("Location", "/oidc/login/password?authRequestID=AR1")
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
    // The token responder bakes an id_token carrying `name` + the captured `nonce` so the
    // unconditional nonce check passes (mirrors the live controller, which echoes our nonce).
    struct TokenResponder(StdArc<StdMutex<String>>);
    impl Respond for TokenResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let nonce = self.0.lock().unwrap().clone();
            let id_token = make_jwt(&format!(r#"{{"name":"alice","nonce":"{nonce}"}}"#));
            ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"access_token":"ey.ACCESS","refresh_token":"ey.REFRESH","expires_in":1800,"id_token":"{id_token}","token_type":"Bearer"}}"#
            ))
        }
    }

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    let captured_state: StdArc<StdMutex<String>> = StdArc::new(StdMutex::new(String::new()));
    let captured_nonce: StdArc<StdMutex<String>> = StdArc::new(StdMutex::new(String::new()));

    // (1) authorize → 302 to /oidc/login/password, capturing the client's state + nonce.
    Mock::given(method("GET"))
        .and(path("/oidc/authorize"))
        .respond_with(AuthorizeResponder {
            state: captured_state.clone(),
            nonce: captured_nonce.clone(),
        })
        .mount(&server)
        .await;

    // (2) login → 302 to the callback.
    Mock::given(method("POST"))
        .and(path("/oidc/login/password"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "/oidc/authorize/callback?id=AR1"),
        )
        .mount(&server)
        .await;

    // (3) callback → 302 to the redirect_uri with a fixed code + the echoed state.
    Mock::given(method("GET"))
        .and(path("/oidc/authorize/callback"))
        .respond_with(CallbackResponder(captured_state.clone()))
        .mount(&server)
        .await;

    // The token step: 200 with a Bearer + an id_token echoing the captured nonce.
    Mock::given(method("POST"))
        .and(path("/oidc/oauth/token"))
        .respond_with(TokenResponder(captured_nonce.clone()))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let tokens = oidc_authenticate(
        &http,
        &server.uri(),
        &OidcGrant::Password {
            username: "alice".into(),
            password: "pw".into(),
        },
        None,
        None,
    )
    .await
    .expect("the full wire sequence completes");

    assert_eq!(tokens.access, "ey.ACCESS");
    assert_eq!(tokens.refresh.as_deref(), Some("ey.REFRESH"));
    assert_eq!(tokens.expires_in, 1800);
    assert_eq!(
        tokens.identity_name.as_deref(),
        Some("alice"),
        "the id_token name is parsed (nonce round-trip validated)"
    );
}

/// An unexpected status at the authorize step maps to [`EdgeError::OidcHttp`] naming the step.
#[tokio::test]
async fn oidc_authenticate_maps_authorize_error() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oidc/authorize"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, None)
        .await
        .expect_err("a 500 at authorize is an error");
    assert!(
        matches!(err, EdgeError::OidcHttp { status: 500, ref step, .. } if step == "authorize"),
        "got {err:?}"
    );
}

/// THE signature ext-jwt failure: a 401 at the login leg (a bad/expired/wrong-binding external
/// JWT — `sub`/`aud` mismatch) maps to [`EdgeError::OidcHttp`] naming the `login` step. The live
/// test is happy-path only, so this pins the failure branch the completeness lens cares about.
/// authorize 302s (to reach the login POST); the login returns 401.
#[tokio::test]
async fn oidc_authenticate_maps_ext_jwt_login_401() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oidc/authorize"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "/oidc/login/ext-jwt?authRequestID=AR1"),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/ext-jwt"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid ext-jwt"))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let err = oidc_authenticate(
        &http,
        &server.uri(),
        &OidcGrant::ExtJwt {
            jwt: "ey.bad-jwt".into(),
        },
        None,
        None,
    )
    .await
    .expect_err("a 401 at the ext-jwt login leg is an error");
    assert!(
        matches!(err, EdgeError::OidcHttp { status: 401, ref step, .. } if step == "login"),
        "got {err:?}"
    );
}
