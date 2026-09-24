//! HTTP-level tests for the edge client REST steps (no TLS; wiremock over plain HTTP).

use noa_sdk::edge::auth_token::AuthToken;
use noa_sdk::edge::client::{
    do_authenticate, do_create_session, do_get_service_edge_routers, do_list_services,
};
use noa_sdk::edge::conn::do_resolve_dial_session;
use noa_sdk::edge::error::EdgeError;
use noa_sdk::edge::model::SessionType;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// reqwest's `rustls-tls-no-provider` requires the process crypto provider installed.
fn http_client() -> reqwest::Client {
    noa_sdk::enroll::trust::ensure_crypto_provider();
    reqwest::Client::new()
}

#[tokio::test]
async fn authenticate_captures_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"data":{"token":"TOK-123","authQueries":[]},"meta":{}}"#),
        )
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let session = do_authenticate(&http_client(), &base, "{}", None)
        .await
        .unwrap();
    assert_eq!(session.token, "TOK-123");
}

#[tokio::test]
async fn authenticate_with_auth_queries_is_mfa_required() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"token":"T","authQueries":[{"typeId":"MFA"}]},"meta":{}}"#,
        ))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_authenticate(&http_client(), &base, "{}", None)
        .await
        .unwrap_err();
    assert!(matches!(err, EdgeError::MfaRequired));
}

#[tokio::test]
async fn authenticate_surfaces_error_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string(r#"{"error":{"code":"INVALID_AUTH","message":"bad cert"}}"#),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_authenticate(&http_client(), &base, "{}", None)
        .await
        .unwrap_err();
    let s = err.to_string();
    assert!(s.contains("401") && s.contains("INVALID_AUTH"), "got: {s}");
}

#[tokio::test]
async fn list_services_sends_session_header_and_paginates() {
    let server = MockServer::start().await;
    // Page 1 (offset 0): totalCount 600 forces a second request.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(query_param("offset", "0"))
        .and(header("zt-session", "TOK-123"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"a","name":"svcA","permissions":["Dial"]}],
                "meta":{"pagination":{"limit":500,"offset":0,"totalCount":600}}}"#,
        ))
        .mount(&server)
        .await;
    // Page 2 (offset 500).
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(query_param("offset", "500"))
        .and(header("zt-session", "TOK-123"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"b","name":"svcB","permissions":["Dial"]}],
                "meta":{"pagination":{"limit":500,"offset":500,"totalCount":600}}}"#,
        ))
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let services = do_list_services(
        &http_client(),
        &base,
        &AuthToken::Legacy("TOK-123".into()),
        &[],
    )
    .await
    .unwrap();
    let names: Vec<_> = services.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["svcA", "svcB"]);
}

// T4b-0: configTypes on the service list. When requested, each type is a repeated `configTypes`
// query param (oracle `ziti/client.go:394`); when empty, NO `configTypes` param (wire-identical).

#[tokio::test]
async fn list_services_with_config_types_sends_repeated_query_params() {
    let server = MockServer::start().await;
    // This mock ONLY answers a request carrying BOTH requested config types. If the call omitted
    // either configTypes param (e.g. a drop-the-loop mutant), no mock matches → the call errors.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(query_param("configTypes", "host.v1"))
        .and(query_param("configTypes", "intercept.v1"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"a","name":"svcA","permissions":["Dial"],
                "config":{"host.v1":{"address":"localhost","port":19009,"protocol":"tcp"}}}],
                "meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let services = do_list_services(
        &http_client(),
        &base,
        &AuthToken::Legacy("TOK-123".into()),
        &["host.v1".to_string(), "intercept.v1".to_string()],
    )
    .await
    .expect("list with config types matches the mock requiring both configTypes params");
    // The host.v1 config came back populated (the whole point of requesting config types).
    let cfg = services[0]
        .host_v1_config()
        .unwrap()
        .expect("host.v1 present");
    assert_eq!(cfg.port, 19009);
}

#[tokio::test]
async fn list_services_empty_config_types_sends_no_config_types_param() {
    use wiremock::matchers::query_param_is_missing;
    let server = MockServer::start().await;
    // This mock ONLY answers a request with NO `configTypes` param. A mutant that always appended a
    // configTypes (even for an empty slice) would not match → the call errors. Pins the wire-identical
    // contract for the connect/bind/list-services path.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .and(query_param_is_missing("configTypes"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"a","name":"svcA","permissions":["Dial"]}],
                "meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let services = do_list_services(
        &http_client(),
        &base,
        &AuthToken::Legacy("TOK-123".into()),
        &[],
    )
    .await
    .expect("empty config_types sends no configTypes param (wire-identical)");
    assert_eq!(services.len(), 1);
}

#[tokio::test]
async fn create_session_sends_header_body_and_parses_routers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("zt-session", "TOK-123"))
        .and(body_string_contains("\"serviceId\":\"svc-1\""))
        .and(body_string_contains("\"type\":\"Dial\""))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"data":{"id":"sess1","token":"JWT","serviceId":"svc-1","type":"Dial",
                "apiSessionId":"as1","identityId":"id1",
                "edgeRouters":[{"name":"er1","hostname":"localhost",
                  "supportedProtocols":{"tls":"tls://localhost:3022"}}]},"meta":{}}"#,
        ))
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let detail = do_create_session(
        &http_client(),
        &base,
        &AuthToken::Legacy("TOK-123".into()),
        "svc-1",
        SessionType::Dial,
    )
    .await
    .unwrap();
    assert_eq!(detail.token, "JWT");
    assert_eq!(detail.session_type, SessionType::Dial);
    assert_eq!(detail.edge_routers.len(), 1);
    // sanitized: `://` -> `:`
    assert_eq!(
        detail.edge_routers[0]
            .supported_protocols
            .get("tls")
            .unwrap(),
        "tls:localhost:3022"
    );
}

#[tokio::test]
async fn create_session_surfaces_not_found_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(404).set_body_string(
            r#"{"error":{"code":"NOT_FOUND","message":"service with id x not found"}}"#,
        ))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_create_session(
        &http_client(),
        &base,
        &AuthToken::Legacy("T".into()),
        "x",
        SessionType::Dial,
    )
    .await
    .unwrap_err();
    let s = err.to_string();
    assert!(s.contains("404") && s.contains("NOT_FOUND"), "got: {s}");
}

#[tokio::test]
async fn create_session_rejects_2xx_without_data() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(201).set_body_string(r#"{"meta":{}}"#))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_create_session(
        &http_client(),
        &base,
        &AuthToken::Legacy("T".into()),
        "x",
        SessionType::Dial,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EdgeError::SessionResponse(_)), "got: {err}");
}

#[tokio::test]
async fn authenticate_captures_identity_name() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "cert"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":{"id":"a","token":"TOK","authQueries":[],
               "identity":{"id":"id1","name":"alice"}},"meta":{}}"#,
        ))
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let session = do_authenticate(&http_client(), &base, "{}", None)
        .await
        .unwrap();
    assert_eq!(session.identity.name, "alice");
}

/// `do_resolve_dial_session` lists services, matches by exact name, and creates a Dial
/// session — returning the service's `encryption_required` flag read from the Service.
#[tokio::test]
async fn resolve_dial_session_reads_encryption_flag_from_service() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[
                 {"id":"id-enc","name":"testsvc","encryptionRequired":true,"permissions":["Dial"]},
                 {"id":"id-pln","name":"testsvc-noenc","encryptionRequired":false,"permissions":["Dial"]}],
               "meta":{"pagination":{"limit":500,"offset":0,"totalCount":2}}}"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .and(header("zt-session", "TOK"))
        .and(body_string_contains("\"serviceId\":\"id-enc\""))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"data":{"id":"s1","token":"JWT","serviceId":"id-enc","type":"Dial",
                "edgeRouters":[{"name":"er1","supportedProtocols":{"tls":"tls://localhost:3022"}}]},
               "meta":{}}"#,
        ))
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let (detail, enc) = do_resolve_dial_session(
        &http_client(),
        &base,
        &AuthToken::Legacy("TOK".into()),
        "testsvc",
    )
    .await
    .unwrap();
    assert_eq!(detail.service_id, "id-enc");
    assert!(enc, "encryption flag read from the Service");
}

/// An unknown service name short-circuits with `ServiceNotFound` and NEVER calls
/// `create_session` (the sessions mock is mounted with `expect(0)`).
#[tokio::test]
async fn resolve_dial_session_unknown_name_is_service_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"a","name":"alpha","permissions":["Dial"]}],
               "meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(201))
        .expect(0) // create_session must NOT be called
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_resolve_dial_session(
        &http_client(),
        &base,
        &AuthToken::Legacy("TOK".into()),
        "missing",
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EdgeError::ServiceNotFound(n) if n == "missing"));
    // server drop verifies the expect(0) on the sessions mock.
}

/// A not-dialable service surfaces the controller's create_session error unchanged
/// (no local Permissions pre-check; faithful to the oracle).
#[tokio::test]
async fn resolve_dial_session_not_dialable_surfaces_session_http() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"b","name":"bindonly","encryptionRequired":false,"permissions":["Bind"]}],
               "meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(
            ResponseTemplate::new(401).set_body_string(
                r#"{"error":{"code":"UNAUTHORIZED","message":"dial not allowed"}}"#,
            ),
        )
        .mount(&server)
        .await;

    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_resolve_dial_session(
        &http_client(),
        &base,
        &AuthToken::Legacy("TOK".into()),
        "bindonly",
    )
    .await
    .unwrap_err();
    let s = err.to_string();
    assert!(s.contains("401") && s.contains("UNAUTHORIZED"), "got: {s}");
}

/// The session-liveness probe (oracle `refreshSession` → `GetSessionFromJwt`): a 2xx means the
/// session is still valid. Asserts the exact path + both auth headers (`zt-session` = api-session,
/// `session-token` = the session JWT).
#[tokio::test]
async fn get_service_edge_routers_ok_when_session_alive() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-9/edge-routers"))
        .and(header("zt-session", "API-TOK"))
        .and(header("session-token", "SESS-JWT"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"{"data":{"edgeRouters":[]},"meta":{}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    do_get_service_edge_routers(
        &http_client(),
        &base,
        &AuthToken::Legacy("API-TOK".into()),
        "svc-9",
        "SESS-JWT",
    )
    .await
    .expect("alive session probe returns Ok");
}

/// A 404 from the probe means the session expired/was revoked → surfaced as `SessionHttp{404}`
/// (this is what drives `connect()`'s evict + recreate + retry).
#[tokio::test]
async fn get_service_edge_routers_404_is_session_http_expired() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services/svc-9/edge-routers"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string(r#"{"error":{"code":"NOT_FOUND","message":"session not found"}}"#),
        )
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let err = do_get_service_edge_routers(
        &http_client(),
        &base,
        &AuthToken::Legacy("API-TOK".into()),
        "svc-9",
        "SESS-JWT",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, EdgeError::SessionHttp { status: 404, .. }),
        "expired session → SessionHttp 404: {err:?}"
    );
}
