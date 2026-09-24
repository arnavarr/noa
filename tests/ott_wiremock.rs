//! HTTP-level tests for the OTT enrolment steps (no TLS; wiremock over plain HTTP).

use noa_sdk::enroll::ott::{fetch_cacerts, request_cert};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A reqwest client for the HTTP-level tests. Since the crate uses reqwest's
/// `rustls-tls-no-provider` feature (single crypto backend = aws-lc-rs), the
/// process-wide CryptoProvider must be installed before building any client.
fn http_client() -> reqwest::Client {
    noa_sdk::enroll::trust::ensure_crypto_provider();
    reqwest::Client::new()
}

#[tokio::test]
async fn request_cert_extracts_cert_from_json_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/enroll"))
        .and(query_param("method", "ott"))
        .and(query_param("token", "TOK"))
        .and(header("content-type", "application/x-pem-file"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"data":{"cert":"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"}}"#),
        )
        .mount(&server)
        .await;

    let client = http_client();
    let url = format!(
        "{}/edge/client/v1/enroll?method=ott&token=TOK",
        server.uri()
    );
    let cert = request_cert(&client, &url, "CSRPEM").await.unwrap();
    assert!(cert.contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn request_cert_surfaces_error_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/enroll"))
        .respond_with(ResponseTemplate::new(404).set_body_string(
            r#"{"error":{"code":"INVALID_ENROLLMENT_TOKEN","message":"bad token"}}"#,
        ))
        .mount(&server)
        .await;

    let client = http_client();
    let url = format!(
        "{}/edge/client/v1/enroll?method=ott&token=TOK",
        server.uri()
    );
    let err = request_cert(&client, &url, "CSRPEM").await.unwrap_err();
    let s = err.to_string();
    assert!(
        s.contains("404") && s.contains("INVALID_ENROLLMENT_TOKEN"),
        "got: {s}"
    );
}

#[tokio::test]
async fn fetch_cacerts_returns_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/.well-known/est/cacerts"))
        .and(header("accept", "application/pkcs7-mime"))
        .respond_with(ResponseTemplate::new(200).set_body_string("BASE64BLOB"))
        .mount(&server)
        .await;

    let client = http_client();
    let url = format!("{}/edge/client/v1/.well-known/est/cacerts", server.uri());
    let body = fetch_cacerts(&client, &url).await.unwrap();
    assert_eq!(body, b"BASE64BLOB");
}
