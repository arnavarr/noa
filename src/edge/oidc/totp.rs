//! MFA-1: la pata TOTP del login OIDC (secondary auth de una identidad ya enrolada) y el
//! enroll-at-login (primer enrolamiento durante el propio login), más sus payloads JSON.
//! (F6 tramo 4: movido verbatim del monolito de `edge/oidc`.)

use serde::Deserialize;

use crate::edge::error::EdgeError;

use super::wire::{absolutize, location_of, oidc_http_err};
use super::{TotpCodeProvider, TotpEnrollmentHandler};

/// The TOTP-required HTTP header the login leg sets when secondary auth is needed. Oracle
/// `TotpRequiredHeader = "totp-required"` (`edge-apis/client_base.go:18`). Matched
/// case-insensitively by reqwest; the live controller answers `Totp-Required: true`.
const TOTP_REQUIRED_HEADER: &str = "totp-required";

/// Handle the TOTP secondary-auth step of an OIDC login (the login POST returned 200). Returns the
/// callback `Location` to continue the standard callback→token tail, or an error.
///
/// Faithful port of the TOTP branch of `handlePrimaryAndSecondaryAuth`
/// (`edge-apis/clients_shared.go:537-600`):
/// - The `totp-required` header MUST be present-and-non-empty (oracle `:537-540`); absent → an
///   unknown unsupported secondary step ([`EdgeError::OidcResponse`], oracle `:539`).
/// - `authQueries` is parsed to read `isTotpEnrolled` (default `true` on an unparseable body, oracle
///   `:546-554`). NOT enrolled → first-time enrollment via [`handle_totp_enrollment`] (oracle `:556-558`
///   `handleTotpEnrollment`). This check comes BEFORE the provider check (an un-enrolled identity cannot
///   submit a code).
/// - Enrolled but no `totp_provider` → [`EdgeError::TotpProviderRequired`] (oracle `:560-562`).
/// - Otherwise call the provider, `POST /oidc/login/totp` with JSON `{code, id}` (oracle `:577-582`),
///   and switch on the status: 302 → success (return the callback `Location`, oracle `:593-595`);
///   400 → [`EdgeError::TotpCodeRejected`] (oracle `:596-597`); 200 → an unsupported further step
///   (oracle `:591-592`); anything else → [`EdgeError::OidcHttp`] (oracle `:598-599`).
pub(super) async fn handle_totp_secondary_auth(
    http: &reqwest::Client,
    base: &str,
    resp: reqwest::Response,
    auth_request_id: &str,
    totp_provider: Option<&TotpCodeProvider<'_>>,
    enroll_handler: Option<&TotpEnrollmentHandler<'_>>,
) -> Result<String, EdgeError> {
    // (a) The header gate: present-and-non-empty → TOTP; absent → unknown unsupported step.
    let totp_required = resp
        .headers()
        .get(TOTP_REQUIRED_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.is_empty());
    if !totp_required {
        return Err(EdgeError::OidcResponse(
            "login returned 200 without the totp-required header: an unknown additional \
             authentication step is required but unsupported"
                .into(),
        ));
    }

    // (b) `isTotpEnrolled`: parse the authQueries body (default true on an unparseable body). NOT
    // enrolled → drive first-time enrollment inline (oracle `:556-558` `handleTotpEnrollment`).
    let body = resp.text().await.unwrap_or_default();
    if !is_totp_enrolled(&body) {
        return handle_totp_enrollment(http, base, auth_request_id, enroll_handler).await;
    }

    // (c) Enrolled: a provider is required to obtain the code.
    let Some(provider) = totp_provider else {
        return Err(EdgeError::TotpProviderRequired);
    };
    let code = provider().map_err(|e| EdgeError::TotpProvider(e.to_string()))?;

    // (d) Submit the code as JSON `{code, id}` to `/oidc/login/totp`.
    let totp_url = format!("{base}/oidc/login/totp");
    let payload = totp_code_payload(&code, auth_request_id);
    let resp = http
        .post(&totp_url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("totp submit: {e}")))?;

    // (e) Switch on the TOTP-submit status (oracle `:590-600`).
    match resp.status() {
        reqwest::StatusCode::FOUND => Ok(absolutize(base, &location_of(&resp, "totp")?)),
        reqwest::StatusCode::BAD_REQUEST => Err(EdgeError::TotpCodeRejected),
        reqwest::StatusCode::OK => Err(EdgeError::OidcResponse(
            "totp code verified, but additional authentication is required that is not supported"
                .into(),
        )),
        // CONSCIOUS DEVIATION: the oracle's default branch is status-code-only (`clients_shared.go:599`);
        // we read the response body via `oidc_http_err` for richer diagnostics, consistent with every
        // other `oidc_http_err` call site. NO leak: the TOTP code lives in the REQUEST body, not the
        // RESPONSE body that `oidc_http_err` reads.
        _ => Err(oidc_http_err("totp", resp).await),
    }
}

/// Drive first-time TOTP enrollment during an OIDC login (the login leg returned 200 + `totp-required`
/// with `isTotpEnrolled: false`). Returns the callback `Location` to continue the standard
/// callback→token tail, or an error.
///
/// Faithful port of `handleTotpEnrollment` (`edge-apis/clients_shared.go:603-676`):
/// - No `enroll_handler` → [`EdgeError::TotpEnrollmentRequired`] (oracle's `TotpEnrollmentProvider == nil`,
///   `:608-610`), short-circuit BEFORE any POST.
/// - `POST /oidc/login/totp/enroll` body `{"id": authRequestId}` (`authRequestIdPayload`,
///   `:615-617`) → strict **201 Created** (oracle `:625-627`; non-201 → [`EdgeError::OidcHttp`]).
/// - Parse the `DetailMfa` body for `provisioningUrl` (`:629-636`); empty/missing →
///   [`EdgeError::OidcResponse`].
/// - Invoke `enroll_handler(provisioningUrl)` (oracle `:639` `GetTotpEnrollmentCode`); a handler error
///   aborts WITHOUT verifying ([`EdgeError::TotpProvider`], oracle `:644-646`).
/// - `POST /oidc/login/totp/enroll/verify` body `{"code": code, "id": authRequestId}` (the same
///   `totpCodePayload` shape as the already-enrolled submit, `:660-665`) and switch on the status:
///   302 → success (callback `Location`, oracle `:668-670`); 400 → [`EdgeError::TotpEnrollmentCodeRejected`]
///   (oracle `:673-674`); 200 → an unsupported further step (oracle `:671-672`); else →
///   [`EdgeError::OidcHttp`] (oracle `:675-676`).
async fn handle_totp_enrollment(
    http: &reqwest::Client,
    base: &str,
    auth_request_id: &str,
    enroll_handler: Option<&TotpEnrollmentHandler<'_>>,
) -> Result<String, EdgeError> {
    // (a) No handler → the no-provider short-circuit (oracle `:608-610`). NEVER posts anything.
    let Some(handler) = enroll_handler else {
        return Err(EdgeError::TotpEnrollmentRequired);
    };

    // (b) Start enrollment: POST {id} → strict 201 + a DetailMfa body.
    let enroll_url = format!("{base}/oidc/login/totp/enroll");
    let start_body = auth_request_id_payload(auth_request_id);
    let resp = http
        .post(&enroll_url)
        .header("Content-Type", "application/json")
        .body(start_body)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("totp enroll start: {e}")))?;
    if resp.status() != reqwest::StatusCode::CREATED {
        return Err(oidc_http_err("totp enroll start", resp).await);
    }
    let detail = resp
        .text()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("totp enroll start body: {e}")))?;

    // (c) Extract the provisioning URL; empty/missing → an unusable enrollment (oracle `:634-636`).
    let provisioning_url = parse_provisioning_url(&detail);
    if provisioning_url.is_empty() {
        return Err(EdgeError::OidcResponse(
            "totp enrollment response did not contain a provisioning URL".into(),
        ));
    }

    // (d) Hand the provisioning URL to the caller to enrol; they return the FIRST verification code.
    // A handler error cancels WITHOUT verifying (oracle `:642-646`).
    let code = handler(&provisioning_url).map_err(|e| EdgeError::TotpProvider(e.to_string()))?;

    // (e) Verify: POST {code, id} (same shape as the already-enrolled submit) → switch on status.
    let verify_url = format!("{base}/oidc/login/totp/enroll/verify");
    let verify_body = totp_code_payload(&code, auth_request_id);
    let resp = http
        .post(&verify_url)
        .header("Content-Type", "application/json")
        .body(verify_body)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("totp enroll verify: {e}")))?;
    match resp.status() {
        reqwest::StatusCode::FOUND => Ok(absolutize(base, &location_of(&resp, "totp enroll verify")?)),
        reqwest::StatusCode::BAD_REQUEST => Err(EdgeError::TotpEnrollmentCodeRejected),
        reqwest::StatusCode::OK => Err(EdgeError::OidcResponse(
            "totp enrollment verified, but additional authentication is required that is not supported or not configured, cannot authenticate"
                .into(),
        )),
        // Same conscious deviation as the already-enrolled submit's default branch: read the RESPONSE
        // body for diagnostics (the enrollment code lives in the REQUEST body, never logged).
        _ => Err(oidc_http_err("totp enroll verify", resp).await),
    }
}

/// Serialise the enroll-start body: JSON `{"id": <authRequestId>}`. Oracle `authRequestIdPayload`
/// (`clients_shared.go:265-267`, `AuthRequestId` JSON tag `id`).
pub(super) fn auth_request_id_payload(auth_request_id: &str) -> String {
    serde_json::json!({ "id": auth_request_id }).to_string()
}

/// Read `provisioningUrl` from the enroll-start `DetailMfa` body. Empty string on an unparseable body
/// or a missing/empty field (the caller treats empty as "no provisioning URL", oracle `:634-636`).
/// Oracle `rest_model.DetailMfa.ProvisioningURL` (JSON `provisioningUrl`, `detail_mfa.go`).
///
/// CONSCIOUS DEVIATION: the oracle splits the 201-body failure into two messages —
/// `"failed to parse totp enrollment response"` (unparseable, `:631`) vs
/// `"...did not contain a provisioning URL"` (parsed, empty, `:635`). We collapse both into the latter
/// (the empty-string default routes both to the caller's single "did not contain" branch). Same error
/// class (`OidcResponse`); the distinction has no observable effect on the flow.
pub(super) fn parse_provisioning_url(body: &str) -> String {
    #[derive(Deserialize)]
    struct DetailMfa {
        #[serde(rename = "provisioningUrl", default)]
        provisioning_url: String,
    }
    serde_json::from_str::<DetailMfa>(body)
        .map(|d| d.provisioning_url)
        .unwrap_or_default()
}

/// Whether TOTP is already enrolled, per the login leg's `authQueries` body. Reads the TOTP entry's
/// `isTotpEnrolled` flag; an unparseable body (or no TOTP entry) defaults to `true` — faithful to the
/// oracle, which defaults enrolled and only flips to enrollment on an explicit `false`
/// (`clients_shared.go:546-554`).
pub(super) fn is_totp_enrolled(body: &str) -> bool {
    #[derive(Deserialize)]
    struct AuthQuery {
        #[serde(rename = "typeId", default)]
        type_id: String,
        #[serde(rename = "isTotpEnrolled", default)]
        is_totp_enrolled: bool,
    }
    #[derive(Deserialize)]
    struct AuthQueries {
        #[serde(rename = "authQueries", default)]
        auth_queries: Vec<AuthQuery>,
    }
    match serde_json::from_str::<AuthQueries>(body) {
        Ok(parsed) => parsed
            .auth_queries
            .iter()
            .find(|q| q.type_id == "TOTP")
            .is_none_or(|q| q.is_totp_enrolled),
        // Unparseable body → default enrolled (oracle: the `if err == nil` guard leaves the default).
        Err(_) => true,
    }
}

/// Serialise the TOTP submit body: JSON `{"code": <code>, "id": <authRequestId>}`. Oracle
/// `totpCodePayload{MfaCode{Code}, AuthRequestId}` (`clients_shared.go:260-263`,
/// `rest_model.MfaCode.Code` JSON tag `code`, `AuthRequestId` JSON tag `id`).
pub(super) fn totp_code_payload(code: &str, auth_request_id: &str) -> String {
    serde_json::json!({ "code": code, "id": auth_request_id }).to_string()
}
