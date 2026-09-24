//! Tests del enroll-at-login de `totp` (primer enrolamiento TOTP durante el login).
//! (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`.)
//!
//! ───────────────── enroll-at-login: first-time TOTP enrollment DURING login ─────────────────

use super::testsupport::mount_oidc_brackets;
use super::totp::*;
use super::*;

/// `auth_request_id_payload` serialises the enroll-start body EXACTLY: JSON `{"id": <authRequestId>}`
/// (oracle `authRequestIdPayload{AuthRequestId json:"id"}`, `clients_shared.go:265-267`).
#[test]
fn auth_request_id_payload_is_oracle_json() {
    let body = auth_request_id_payload("AR1");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["id"], "AR1");
    assert_eq!(v.as_object().unwrap().len(), 1, "ONLY the id field");
}

/// `parse_provisioning_url` reads `provisioningUrl` from the `DetailMfa` body; missing/unparseable →
/// empty (the caller treats empty as "no provisioning URL"). The exact live body shape (probed:
/// `provisioningUrl: otpauth://totp/...?secret=BASE32`).
#[test]
fn parse_provisioning_url_reads_the_field() {
    let body = r#"{"isVerified":false,"provisioningUrl":"otpauth://totp/openziti.io:bob?issuer=openziti.io&secret=GCCLMDQJR5UGOP5L","recoveryCodes":["AAAA"]}"#;
    assert_eq!(
        parse_provisioning_url(body),
        "otpauth://totp/openziti.io:bob?issuer=openziti.io&secret=GCCLMDQJR5UGOP5L"
    );
    assert_eq!(parse_provisioning_url("{}"), "", "missing field → empty");
    assert_eq!(
        parse_provisioning_url("not json"),
        "",
        "unparseable → empty"
    );
    assert_eq!(
        parse_provisioning_url(r#"{"provisioningUrl":""}"#),
        "",
        "empty field → empty"
    );
}

/// THE happy path: a `totp-required` login with `isTotpEnrolled:false` + an enroll handler drives
/// the WHOLE enrollment flow to tokens: enroll-start (201, provisioningUrl) → handler(url)→code →
/// enroll-verify (302) → callback → token-exchange. Pins the enroll-start body `{"id":"AR1"}`, the
/// handler receiving the EXACT provisioning URL, AND the verify body `{"code":..,"id":"AR1"}`. The
/// handler's code is the discriminator: a wrong verify body → the verify mock 404s → RED.
#[tokio::test]
async fn enroll_at_login_happy_path_completes_the_flow() {
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use wiremock::matchers::{body_json_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;

    // Login → 200 + totp-required + NOT-enrolled authQueries. FAITHFUL WIRE REPLICA: the live
    // controller OMITS `isTotpEnrolled` entirely for a fresh not-enrolled identity (spike-captured)
    // → it defaults to `false` → enrollment. (MFA-1's enrolled tests carry the explicit `true`.)
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("totp-required", "true")
                .set_body_string(
                    r#"{"authQueries":[{"format":"numeric","httpMethod":"POST","httpUrl":"./oidc/login/totp","maxLength":8,"minLength":6,"provider":"ziti","typeId":"TOTP"}]}"#,
                ),
        )
        .mount(&server)
        .await;
    // Enroll-start: body MUST be `{"id":"AR1"}`, application/json → 201 + a DetailMfa with the URL.
    let prov_url = "otpauth://totp/openziti.io:bob?issuer=openziti.io&secret=GCCLMDQJR5UGOP5L";
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll"))
        .and(header("content-type", "application/json"))
        .and(body_json_string(r#"{"id":"AR1"}"#))
        .respond_with(ResponseTemplate::new(201).set_body_string(format!(
            r#"{{"isVerified":false,"provisioningUrl":"{prov_url}","recoveryCodes":["AAAA","BBBB"]}}"#
        )))
        .mount(&server)
        .await;
    // Enroll-verify: body MUST be `{"code":"555111","id":"AR1"}` → 302 success.
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll/verify"))
        .and(header("content-type", "application/json"))
        .and(body_json_string(r#"{"code":"555111","id":"AR1"}"#))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "/oidc/authorize/callback?id=AR1"),
        )
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // The handler captures the URL it received and returns the verification code.
    let seen: StdArc<StdMutex<String>> = StdArc::new(StdMutex::new(String::new()));
    let seen_c = seen.clone();
    let handler = move |url: &str| {
        *seen_c.lock().unwrap() = url.to_string();
        Ok("555111".to_string())
    };
    let tokens = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, Some(&handler))
        .await
        .expect("not-enrolled + handler → enroll → verify 302 → tokens");
    assert_eq!(tokens.access, "ey.MFAACCESS");
    assert_eq!(tokens.identity_name.as_deref(), Some("mfauser"));
    assert_eq!(
        *seen.lock().unwrap(),
        prov_url,
        "the handler received the EXACT provisioning URL from the enroll-start body"
    );
}

/// Enroll-start returns a non-201 status → [`EdgeError::OidcHttp`] (oracle `:625-627`), NOT a
/// success. MUTATION: relaxing the strict-201 check (e.g. treating 200 as OK) would parse a missing
/// provisioningUrl → a different error. Here a 200 is the wrong status.
#[tokio::test]
async fn enroll_start_non_201_maps_to_oidc_http() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("totp-required", "true")
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":false}]}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let handler = |_url: &str| Ok("555111".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, Some(&handler))
        .await
        .expect_err("enroll-start non-201 is an error");
    assert!(
        matches!(err, EdgeError::OidcHttp { status: 200, ref step, .. } if step == "totp enroll start"),
        "got {err:?}"
    );
}

/// Enroll-start returns 201 but an EMPTY provisioningUrl → [`EdgeError::OidcResponse`] (oracle
/// `:634-636`), and NO verify is posted (the missing verify mock would 404 if it were).
#[tokio::test]
async fn enroll_start_empty_provisioning_url_is_oidc_response() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("totp-required", "true")
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":false}]}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll"))
        .respond_with(ResponseTemplate::new(201).set_body_string(r#"{"isVerified":false}"#))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let handler = |_url: &str| Ok("555111".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, Some(&handler))
        .await
        .expect_err("empty provisioningUrl is an error");
    assert!(
        matches!(err, EdgeError::OidcResponse(ref m) if m.contains("provisioning URL")),
        "got {err:?}"
    );
}

/// Enroll-verify returns 400 → [`EdgeError::TotpEnrollmentCodeRejected`] (the DISTINCT enrollment
/// rejection, byte-exact message), NOT the already-enrolled [`EdgeError::TotpCodeRejected`] and NOT
/// folded into `OidcHttp`. MUTATION: reusing `TotpCodeRejected` would change the variant → RED.
#[tokio::test]
async fn enroll_verify_400_maps_to_enrollment_code_rejected() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("totp-required", "true")
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":false}]}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll"))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"isVerified":false,"provisioningUrl":"otpauth://totp/x?secret=AAAA"}"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll/verify"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            r#"{"code":"INVALID TOTP CODE","message":"an invalid TOTP code was supplied"}"#,
        ))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let handler = |_url: &str| Ok("000000".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, Some(&handler))
        .await
        .expect_err("a 400 on enroll-verify is a rejected enrollment code");
    assert!(
        matches!(err, EdgeError::TotpEnrollmentCodeRejected),
        "400 → TotpEnrollmentCodeRejected (distinct from TotpCodeRejected), got {err:?}"
    );
}

/// Enroll-verify returns 200 (verified, but a FURTHER unsupported step) → an `OidcResponse`
/// (oracle `:671-672`), NOT a success.
#[tokio::test]
async fn enroll_verify_200_maps_to_unsupported() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("totp-required", "true")
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":false}]}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll"))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"isVerified":false,"provisioningUrl":"otpauth://totp/x?secret=AAAA"}"#,
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let handler = |_url: &str| Ok("555111".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, Some(&handler))
        .await
        .expect_err("a 200 on enroll-verify is an unsupported further step");
    assert!(
        matches!(err, EdgeError::OidcResponse(ref m)
            if m == "totp enrollment verified, but additional authentication is required that is not supported or not configured, cannot authenticate"),
        "got {err:?}"
    );
}

/// The enroll handler returning an error aborts WITHOUT posting to verify (no verify mock mounted →
/// if verify were called the error would differ). Oracle `:644-646` (`"totp enrollment cancelled: %w"`).
#[tokio::test]
async fn enroll_handler_error_aborts_without_verify() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("totp-required", "true")
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":false}]}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp/enroll"))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"isVerified":false,"provisioningUrl":"otpauth://totp/x?secret=AAAA"}"#,
        ))
        .mount(&server)
        .await;
    // NOTE: no enroll/verify mock — proving a handler error NEVER posts to verify.

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let handler = |_url: &str| Err(EdgeError::OidcResponse("enrollment cancelled".into()));
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, Some(&handler))
        .await
        .expect_err("a handler error aborts the enrollment flow");
    assert!(
        matches!(err, EdgeError::TotpProvider(ref m) if m.contains("enrollment cancelled")),
        "got {err:?}"
    );
}
