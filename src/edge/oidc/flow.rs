//! La secuencia del grant PKCE: authorize → login → callback → token, conducida a mano desde el
//! `Location` de cada 302. (F6 tramo 4: movido verbatim del monolito de `edge/oidc`.)

use crate::edge::error::EdgeError;

use super::pkce::{new_nonce, new_pkce, new_state};
use super::token::parse_token_response;
use super::totp::handle_totp_secondary_auth;
use super::wire::{
    absolutize, authorize_url, extract_auth_request_id, extract_code, location_of, oidc_http_err,
    url_encoded,
};
use super::{DEFAULT_REDIRECT_URI, OidcGrant, OidcTokens, TotpCodeProvider, TotpEnrollmentHandler};

/// Run the OIDC PKCE direct-grant flow and return the tokens. `http` MUST be configured with
/// `redirect(Policy::none())` (we drive redirects by hand) and carry the client cert at the
/// transport for [`OidcGrant::Cert`] (the caller's mTLS client). `base` is `https://{host}` (the
/// controller host, no path). `totp_provider` supplies a TOTP code if the login leg signals
/// `totp-required` (see [`TotpCodeProvider`]); pass `None` for the non-MFA flow (then a
/// `totp-required` login → [`EdgeError::TotpProviderRequired`]). Oracle `handlePrimaryAndSecondaryAuth`
/// (`clients_shared.go:495-601`).
///
/// # Errors
/// [`EdgeError::OidcHttp`] on an unexpected status at any step; [`EdgeError::OidcResponse`] on a
/// missing Location / bad body / state-or-nonce mismatch / a 200 login WITHOUT the `totp-required`
/// header (an unknown unsupported secondary step, oracle `:539`); [`EdgeError::TotpProviderRequired`]
/// if the login signals `totp-required` (enrolled) but no `totp_provider` was supplied;
/// [`EdgeError::TotpEnrollmentRequired`] if TOTP is not yet enrolled but no `enroll_handler` was
/// supplied; [`EdgeError::TotpProvider`] if a provider/handler returns an error;
/// [`EdgeError::TotpCodeRejected`]/[`EdgeError::TotpEnrollmentCodeRejected`] if the controller rejects
/// the submitted code (400) on the already-enrolled / enrollment-verify leg respectively.
pub(crate) async fn oidc_authenticate(
    http: &reqwest::Client,
    base: &str,
    grant: &OidcGrant,
    totp_provider: Option<&TotpCodeProvider<'_>>,
    enroll_handler: Option<&TotpEnrollmentHandler<'_>>,
) -> Result<OidcTokens, EdgeError> {
    let pkce = new_pkce();
    let state = new_state();
    let nonce = new_nonce();

    // (1) authorize → 302 to /oidc/login/{method}?authRequestID=...
    let auth_url = authorize_url(base, &pkce, &state, &nonce);
    let resp = http
        .get(&auth_url)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("authorize: {e}")))?;
    if resp.status() != reqwest::StatusCode::FOUND {
        return Err(oidc_http_err("authorize", resp).await);
    }
    let login_loc = location_of(&resp, "authorize")?;
    let auth_request_id = extract_auth_request_id(&login_loc)
        .ok_or_else(|| EdgeError::OidcResponse("no authRequestID in authorize redirect".into()))?;

    // (2) POST /oidc/login/{segment} form → 302 to the callback (or 200 w/ TOTP header).
    let login_url = format!("{base}/oidc/login/{}", grant.login_segment());
    let (username, password) = match grant {
        // Cert rides the mTLS transport; ext-jwt rides the `Authorization: Bearer` header below.
        // Both send an EMPTY form username/password (oracle: `JwtCredentials.AuthenticateRequest`
        // only ADDS the header, `credentials.go:340`; `CertCredentials` rides the transport).
        OidcGrant::Cert | OidcGrant::ExtJwt { .. } => ("", ""),
        OidcGrant::Password { username, password } => (username.as_str(), password.as_str()),
    };
    let form = url_encoded(&[
        ("id", auth_request_id.as_str()),
        ("username", username),
        ("password", password),
    ]);
    let mut login_req = http
        .post(&login_url)
        .header("Content-Type", "application/x-www-form-urlencoded");
    // ext-jwt ONLY: present the external IdP JWT as a Bearer header (additive — cert/password add
    // NOTHING here). Oracle `JwtCredentials.AuthenticateRequest` (`credentials.go:340`):
    // `Add("Authorization", "Bearer "+c.JWT)` (the literal space after `Bearer`).
    if let OidcGrant::ExtJwt { jwt } = grant {
        login_req = login_req.header("Authorization", format!("Bearer {jwt}"));
    }
    let resp = login_req
        .body(form)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("login: {e}")))?;
    let status = resp.status();
    // The login leg resolves to a callback `Location` either directly (302, no secondary auth) or
    // after the TOTP secondary-auth step (200 + `totp-required` → submit a code → 302). Both paths
    // converge to the SAME callback→token tail below.
    let callback_loc = if status == reqwest::StatusCode::FOUND {
        // (2a) No secondary auth: 302 straight to the callback.
        absolutize(base, &location_of(&resp, "login")?)
    } else if status == reqwest::StatusCode::OK {
        // (2b) A bare 200 means a secondary auth step is required. Oracle `:537` keys off the
        // `totp-required` HEADER (not the 200 alone): present → the TOTP secondary-auth path; absent →
        // an unknown, unsupported secondary step (oracle `:539`). The TOTP path returns the callback
        // `Location` from its own 302.
        handle_totp_secondary_auth(
            http,
            base,
            resp,
            &auth_request_id,
            totp_provider,
            enroll_handler,
        )
        .await?
    } else {
        return Err(oidc_http_err("login", resp).await);
    };

    // (3) GET the callback → 302 to redirect_uri?code=...&state=...
    let resp = http
        .get(&callback_loc)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("callback: {e}")))?;
    if resp.status() != reqwest::StatusCode::FOUND {
        return Err(oidc_http_err("callback", resp).await);
    }
    let redirect_loc = location_of(&resp, "callback")?;
    let code = extract_code(&redirect_loc, &state)?;

    // (4) POST /oidc/oauth/token → 200 JSON tokens.
    let token_url = format!("{base}/oidc/oauth/token");
    let token_form = url_encoded(&[
        ("grant_type", "authorization_code"),
        ("client_id", "native"),
        ("code_verifier", &pkce.verifier),
        ("code", &code),
        ("redirect_uri", DEFAULT_REDIRECT_URI),
    ]);
    let resp = http
        .post(&token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(token_form)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("token exchange: {e}")))?;
    if resp.status() != reqwest::StatusCode::OK {
        return Err(oidc_http_err("token exchange", resp).await);
    }
    let body = resp
        .text()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("token exchange body: {e}")))?;
    parse_token_response(&body, &nonce)
}
