//! Tests de la pata TOTP de `totp` (secondary auth de una identidad ya enrolada).
//! (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`.)
//!
//! ───────────────────────────── MFA-1: TOTP secondary auth (OIDC) ─────────────────────────────

use super::testsupport::mount_oidc_brackets;
use super::totp::*;
use super::*;

/// The provider's `+ Sync` bound keeps `oidc_authenticate`'s future `Send` (so the `from_*`
/// constructors that delegate with a typed `Option<&TotpCodeProvider>` stay spawnable). MUTATION:
/// drop `+ Sync` from the [`TotpCodeProvider`] alias → `&dyn Fn` is not `Send` → this assertion
/// fails to compile (RED). Asserts the auto-trait at compile time via a `fn(T) where T: Send`.
#[test]
fn oidc_authenticate_future_is_send_with_a_provider() {
    fn assert_send<T: Send>(_t: T) {}
    crate::enroll::trust::ensure_crypto_provider();
    // Build (do not run) the future with a concrete provider — the borrow is the load-bearing bit.
    let http = reqwest::Client::new();
    let provider = || Ok("123456".to_string());
    let fut = oidc_authenticate(&http, "https://x", &OidcGrant::Cert, Some(&provider), None);
    assert_send(fut);
}

/// `is_totp_enrolled` reads the TOTP `authQueries` entry's `isTotpEnrolled`; an explicit `false`
/// → not enrolled. The exact live body shape (probed: `typeId:"TOTP"`, `isTotpEnrolled:true`).
///
/// LOAD-BEARING: the PRODUCTION enroll-at-login trigger is the field being ABSENT — the live spike
/// captured `{"authQueries":[{...,"typeId":"TOTP"}]}` with NO `isTotpEnrolled` for a fresh
/// not-enrolled identity → the `#[serde(default)]` on a `bool` makes it `false` → enrollment. This
/// is the case the real controller emits; without the absent-field assertion a serde-default change
/// or an `is_none_or` flip would keep every deterministic test green while breaking the real path.
#[test]
fn is_totp_enrolled_reads_the_flag() {
    let enrolled = r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":true,"httpUrl":"./oidc/login/totp","minLength":6,"maxLength":8,"provider":"ziti"}]}"#;
    assert!(is_totp_enrolled(enrolled), "isTotpEnrolled:true → enrolled");

    let not_enrolled = r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":false}]}"#;
    assert!(
        !is_totp_enrolled(not_enrolled),
        "isTotpEnrolled:false → NOT enrolled"
    );

    // The PRODUCTION wire shape: a TOTP entry with NO `isTotpEnrolled` field (live-captured for a
    // fresh not-enrolled identity) → the field defaults to `false` → NOT enrolled → enrollment.
    let field_absent = r#"{"authQueries":[{"format":"numeric","httpMethod":"POST","httpUrl":"./oidc/login/totp","maxLength":8,"minLength":6,"provider":"ziti","typeId":"TOTP"}]}"#;
    assert!(
        !is_totp_enrolled(field_absent),
        "absent isTotpEnrolled (the live not-enrolled wire) → NOT enrolled (defaults false)"
    );
}

/// `is_totp_enrolled` defaults to TRUE when the body is unparseable or carries no TOTP entry —
/// faithful to the oracle (`clients_shared.go:546-554`, the default-enrolled `if err == nil`
/// guard). MUTATION: flipping the default to `false` would route an enrolled identity into the
/// (deferred) enrollment path → this goes RED.
#[test]
fn is_totp_enrolled_defaults_true_on_unparseable_or_missing() {
    assert!(
        is_totp_enrolled("not json at all"),
        "unparseable → default true"
    );
    assert!(is_totp_enrolled("{}"), "no authQueries → default true");
    assert!(
        is_totp_enrolled(r#"{"authQueries":[{"typeId":"OTHER","isTotpEnrolled":false}]}"#),
        "no TOTP entry → default true (the `false` belongs to a non-TOTP query)"
    );
}

/// `totp_code_payload` serialises EXACTLY the oracle wire: JSON `{"code":..,"id":..}`
/// (`totpCodePayload{MfaCode.Code→"code", AuthRequestId→"id"}`, `clients_shared.go:260-263`).
#[test]
fn totp_code_payload_is_oracle_json() {
    let body = totp_code_payload("123456", "AR1");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["code"], "123456", "code field");
    assert_eq!(v["id"], "AR1", "id = authRequestId");
    assert_eq!(
        v.as_object().unwrap().len(),
        2,
        "exactly the two oracle fields, no extras: {body}"
    );
}

/// A login leg that returns 200 + `totp-required` (TOTP enrolled) → submit → 302 success drives
/// the WHOLE flow to tokens. Pins the TOTP submit's JSON body `{"code","id"}` AND its
/// `application/json` content-type (the submit is JSON, NOT the form the login legs use). The
/// provider's code is the discriminator: a wrong body → the totp mock 404s → RED.
#[tokio::test]
async fn totp_required_then_submit_302_completes_the_flow() {
    use wiremock::matchers::{body_json_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;

    // Login → 200 + totp-required header + an enrolled authQueries body.
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("totp-required", "true")
                .set_body_string(
                    r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":true,"httpUrl":"./oidc/login/totp","minLength":6,"maxLength":8,"provider":"ziti"}]}"#,
                ),
        )
        .mount(&server)
        .await;
    // TOTP submit must be JSON `{"code":"424242","id":"AR1"}` with application/json → 302.
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp"))
        .and(header("content-type", "application/json"))
        .and(body_json_string(r#"{"code":"424242","id":"AR1"}"#))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", "/oidc/authorize/callback?id=AR1"),
        )
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let provider = |code: &str| {
        let code = code.to_string();
        move || Ok(code.clone())
    };
    let p = provider("424242");
    let tokens = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, Some(&p), None)
        .await
        .expect("totp-required → submit 424242 → 302 → tokens");
    assert_eq!(tokens.access, "ey.MFAACCESS");
    assert_eq!(tokens.identity_name.as_deref(), Some("mfauser"));
}

/// The TOTP submit returns 400 → [`EdgeError::TotpCodeRejected`] (byte-exact message), NOT folded
/// into `OidcHttp`. MUTATION: mapping 400 → `OidcHttp` would change the variant → RED.
#[tokio::test]
async fn totp_submit_400_maps_to_totp_code_rejected() {
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
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":true}]}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp"))
        .respond_with(ResponseTemplate::new(400).set_body_string(
            r#"{"code":"INVALID TOTP CODE","message":"an invalid TOTP code was supplied"}"#,
        ))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let p = || Ok("000000".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, Some(&p), None)
        .await
        .expect_err("a 400 on the totp submit is a rejected code");
    assert!(
        matches!(err, EdgeError::TotpCodeRejected),
        "400 → TotpCodeRejected, got {err:?}"
    );
}

/// The TOTP submit returns 200 (verified, but a FURTHER unsupported step) → an `OidcResponse`
/// error naming the unsupported step (oracle `:591-592`), NOT success.
#[tokio::test]
async fn totp_submit_200_maps_to_unsupported() {
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
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":true}]}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/totp"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let p = || Ok("424242".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, Some(&p), None)
        .await
        .expect_err("a 200 on the totp submit is an unsupported further step");
    assert!(
        matches!(err, EdgeError::OidcResponse(ref m) if m.contains("not supported")),
        "got {err:?}"
    );
}

/// ADDITIVE GUARANTEE: a `totp-required` (enrolled) login with NO provider →
/// [`EdgeError::TotpProviderRequired`] (the OIDC producer of the no-provider error; distinct from
/// the generic legacy `MfaRequired`). This is the exact path the unchanged
/// `authenticate_oidc`/`from_*_oidc` (which delegate with `None`) take when they meet an MFA
/// identity. MUTATION: submitting a code with no provider would panic/misroute → this stays RED;
/// emitting `MfaRequired` here instead → also RED (the variant is now producer-specific).
#[tokio::test]
async fn totp_required_without_provider_is_totp_provider_required() {
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
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":true}]}"#),
        )
        .mount(&server)
        .await;
    // NOTE: no /oidc/login/totp mock — proving the no-provider path NEVER submits a code.

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, None, None)
        .await
        .expect_err("totp-required + no provider → TotpProviderRequired");
    assert!(
        matches!(err, EdgeError::TotpProviderRequired),
        "got {err:?}"
    );
}

/// A `totp-required` login whose authQueries say `isTotpEnrolled:false` with NO enroll handler →
/// [`EdgeError::TotpEnrollmentRequired`] (the no-handler short-circuit, BEFORE any enroll POST),
/// checked BEFORE the code-provider — even WITH a code provider, an un-enrolled identity cannot
/// submit a code. ADDITIVE GUARANTEE: the existing `*_with_totp` constructors delegate
/// `enroll_handler=None`, so an enroll challenge on them stays this error, byte-unchanged.
/// MUTATION: dropping the enrollment check (or ordering it after the provider) would submit a code →
/// the missing totp mock 404s, changing the error.
#[tokio::test]
async fn totp_not_enrolled_without_handler_is_enrollment_required() {
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
    // NOTE: no /oidc/login/totp/enroll mock — proving the no-handler path NEVER posts to enroll.

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // WITH a code provider but NO enroll handler — to prove the enrollment branch fires first AND
    // short-circuits without a handler.
    let p = || Ok("424242".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, Some(&p), None)
        .await
        .expect_err("not enrolled + no handler → TotpEnrollmentRequired");
    assert!(
        matches!(err, EdgeError::TotpEnrollmentRequired),
        "got {err:?}"
    );
}

/// A 200 login WITHOUT the `totp-required` header → [`EdgeError::OidcResponse`] ("unknown
/// additional authentication ... unsupported", oracle `:539`), NOT a TOTP error. This is the
/// header-gate the advisor flagged: detection is the HEADER, not the bare 200. MUTATION: keying
/// off the 200 alone (the pre-MFA-1 code) would return the no-provider error → RED.
#[tokio::test]
async fn login_200_without_totp_header_is_unsupported_not_mfa() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    crate::enroll::trust::ensure_crypto_provider();
    let server = MockServer::start().await;
    mount_oidc_brackets(&server).await;
    Mock::given(method("POST"))
        .and(path("/oidc/login/cert"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}")) // NO totp-required header
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let p = || Ok("424242".to_string());
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, Some(&p), None)
        .await
        .expect_err("200 without totp-required → unknown unsupported step");
    assert!(
        matches!(err, EdgeError::OidcResponse(ref m) if m.contains("unsupported")),
        "200-without-header → OidcResponse(unsupported), NOT a TOTP error: {err:?}"
    );
}

/// The provider returning an error aborts the flow with [`EdgeError::TotpProvider`] WITHOUT
/// submitting a code (no totp mock mounted → if a code were submitted the error would differ).
/// Oracle `:569-571` (`"error getting totp code: %w"`).
#[tokio::test]
async fn totp_provider_error_aborts_without_submit() {
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
                .set_body_string(r#"{"authQueries":[{"typeId":"TOTP","isTotpEnrolled":true}]}"#),
        )
        .mount(&server)
        .await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let p = || Err(EdgeError::OidcResponse("user cancelled".into()));
    let err = oidc_authenticate(&http, &server.uri(), &OidcGrant::Cert, Some(&p), None)
        .await
        .expect_err("a provider error aborts the flow");
    assert!(
        matches!(err, EdgeError::TotpProvider(ref m) if m.contains("user cancelled")),
        "got {err:?}"
    );
}
