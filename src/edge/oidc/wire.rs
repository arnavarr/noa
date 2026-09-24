//! Formas HTTP del flujo OIDC: la URL de `/oidc/authorize`, el form-urlencode, la lectura del
//! `Location` (relativo o absoluto) y el mapeo de una respuesta inesperada a `OidcHttp`.
//! (F6 tramo 4: movido verbatim del monolito de `edge/oidc`.)

use crate::edge::error::EdgeError;

use super::DEFAULT_REDIRECT_URI;
use super::pkce::Pkce;

/// Build the `GET /oidc/authorize` URL with the PKCE + flow params. Oracle `initOAuthFlow`
/// (`clients_shared.go:685-694`): `client_id=native`, `response_type=code`,
/// `scope=openid offline_access`, `code_challenge_method=S256`, the fixed `redirect_uri`, plus
/// `state`/`nonce`/`code_challenge`. PURE/testable. `base` is `https://{host}` (no trailing slash).
pub(super) fn authorize_url(base: &str, pkce: &Pkce, state: &str, nonce: &str) -> String {
    let q = url_encoded(&[
        ("client_id", "native"),
        ("response_type", "code"),
        ("scope", "openid offline_access"),
        ("state", state),
        ("code_challenge", &pkce.challenge),
        ("code_challenge_method", "S256"),
        ("redirect_uri", DEFAULT_REDIRECT_URI),
        ("nonce", nonce),
    ]);
    format!("{base}/oidc/authorize?{q}")
}

/// Form-urlencode key/value pairs (application/x-www-form-urlencoded, also used for query strings).
/// Uses `url`'s `form_urlencoded` (in-tree). DRY for both the authorize query and the form bodies.
pub(super) fn url_encoded(pairs: &[(&str, &str)]) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        ser.append_pair(k, v);
    }
    ser.finish()
}

/// The `authRequestID` query param value from a `Location` like
/// `/oidc/login/cert?authRequestID=<uuid>` (or an absolute URL). Oracle: the redirect from
/// `/oidc/authorize` carries `authRequestID` (`clients_shared.go:711` reads it from a header in the
/// resty flow; the live controller puts it in the `Location` query — confirmed by the cert-probe).
pub(super) fn extract_auth_request_id(location: &str) -> Option<String> {
    location
        .split_once("authRequestID=")
        .map(|(_, rest)| rest.split(['&', '#']).next().unwrap_or(rest).to_string())
        .filter(|v| !v.is_empty())
}

/// The `code` (and check `state`) from the final callback `Location`
/// (`http://localhost:8080/auth/callback?code=...&state=...`). Validates `state` matches ours (oracle
/// `:463`). Oracle `finishOAuthFlow` (`:457-469`).
pub(super) fn extract_code(location: &str, expected_state: &str) -> Result<String, EdgeError> {
    let parsed = url::Url::parse(location)
        .map_err(|e| EdgeError::OidcResponse(format!("callback location not a url: {e}")))?;
    let mut code = None;
    let mut state = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }
    if state.as_deref() != Some(expected_state) {
        return Err(EdgeError::OidcResponse("state mismatch in callback".into()));
    }
    code.filter(|c| !c.is_empty())
        .ok_or_else(|| EdgeError::OidcResponse("no code in callback".into()))
}

/// Resolve a `Location` header that may be relative (`/oidc/...`) to an absolute URL under `base`.
pub(super) fn absolutize(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else {
        format!("{base}{location}")
    }
}

/// Read the `Location` header of a response, erroring if absent.
pub(super) fn location_of(resp: &reqwest::Response, step: &str) -> Result<String, EdgeError> {
    resp.headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| EdgeError::OidcResponse(format!("{step}: no Location header")))
}

/// Build an [`EdgeError::OidcHttp`] from a non-expected-status response (reads the body for the
/// message, best-effort).
pub(super) async fn oidc_http_err(step: &str, resp: reqwest::Response) -> EdgeError {
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    EdgeError::OidcHttp {
        status,
        step: step.to_string(),
        message: body.chars().take(200).collect(),
    }
}
