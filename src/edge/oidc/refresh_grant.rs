//! OIDC-3: el grant de refresh por token-exchange (RFC 8693).
//! (F6 tramo 4: movido verbatim del monolito de `edge/oidc`.)
//!
//! ───────────────────────────── OIDC-3: refresh-token-exchange grant ─────────────────────────────
//!
//! The RFC 8693 token-exchange grant the oracle uses to refresh an OIDC api-session (NOT the plain
//! `grant_type=refresh_token`). Faithful to `exchangeTokens` (`edge-apis/clients_shared.go:135`) via
//! zitadel's `tokenexchange.ExchangeToken` (form schema `pkg/oidc/token_request.go:228-236`):
//! `subject_token` = the current refresh token, `subject_token_type` = `...refresh_token`,
//! `requested_token_type` = `...refresh_token` (which — the zitadel quirk, probed live — returns BOTH
//! a fresh access_token AND a rotated refresh_token in one call). The oracle's SECOND id_token
//! exchange is SKIPPED: the identity `name` is invariant across a refresh (same precedent as
//! `reauthenticate`, which does not update `identity_name`). The access-token signature is the
//! controller's job (`ParseUnverified`); we do not verify it.

use crate::edge::error::EdgeError;

use super::RefreshedOidc;
use super::token::TokenResponse;
use super::wire::{oidc_http_err, url_encoded};

const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TOKEN_TYPE_REFRESH: &str = "urn:ietf:params:oauth:token-type:refresh_token";

/// Parse the token-exchange 200 body into [`RefreshedOidc`]. Reuses the [`TokenResponse`] shape
/// (`access_token`/`refresh_token`/`expires_in`). NO id_token/nonce validation: a refresh-grant
/// response carries no id_token, and the flow nonce belongs to the original authorize leg, not a
/// refresh. An empty `refresh_token` normalises to `None` (the caller keeps the prior refresh).
pub(super) fn parse_refresh_response(body: &str) -> Result<RefreshedOidc, EdgeError> {
    let tr: TokenResponse = serde_json::from_str(body)
        .map_err(|e| EdgeError::OidcResponse(format!("refresh response json: {e}")))?;
    Ok(RefreshedOidc {
        access: tr.access_token,
        refresh: tr.refresh_token.filter(|r| !r.is_empty()),
        expires_in: tr.expires_in,
    })
}

/// Refresh an OIDC api-session via the RFC 8693 token-exchange grant. `base` is the controller root
/// (`https://{host}`, the OIDC base — NOT the ztAPI edge path). POSTs the token-exchange form to
/// `{base}/oidc/oauth/token` and returns the rotated access+refresh+expiry. A free, Send helper
/// shared by the proactive timer and the reactive recovery (DRY, mirroring `do_refresh_get` for the
/// legacy path). Oracle: `exchangeTokens` (`clients_shared.go:135`, the `RefreshTokenType` branch).
///
/// `request_timeout` bounds THIS POST only (per-request, not client-wide): if the controller hangs,
/// the timeout fires during `.send()`/body-read and maps to [`EdgeError::OidcResponse`] (the existing
/// transport-error path) — bounded, never a hang (this POST is awaited under `reauth_lock`). Callers
/// pass [`OIDC_REFRESH_REQUEST_TIMEOUT`](super::OIDC_REFRESH_REQUEST_TIMEOUT).
///
/// # Errors
/// [`EdgeError::OidcResponse`] on transport / timeout / unparseable body; [`EdgeError::OidcHttp`] on a
/// non-200 (a 4xx means the refresh token is gone/rejected → the session needs a full re-login,
/// deferred).
pub(crate) async fn do_oidc_refresh(
    http: &reqwest::Client,
    base: &str,
    refresh_token: &str,
    request_timeout: std::time::Duration,
) -> Result<RefreshedOidc, EdgeError> {
    let form = url_encoded(&[
        ("grant_type", GRANT_TYPE_TOKEN_EXCHANGE),
        // CONSCIOUS DEVIATION: the oracle sends `client_id` as HTTP Basic auth, NOT a form field —
        // zitadel's `NewTokenExchangerClientCredentials(ctx, issuer, "native", "", …)` returns
        // `httphelper.AuthorizeBasic("native", "")` (`tokenexchange.go:33`), so the `TokenExchangeRequest`
        // body carries no `client_id`. We send it in the body instead. This body-form shape is
        // LIVE-PROVEN (the spec §2/§3 probe got 200×2 with rotation); switching to Basic auth would be
        // unvalidated new wire, so we keep the proven form (CLAUDE.md "start from the oracle" yields to
        // an empirically validated equivalent here).
        ("client_id", "native"),
        ("subject_token", refresh_token),
        ("subject_token_type", TOKEN_TYPE_REFRESH),
        ("requested_token_type", TOKEN_TYPE_REFRESH),
    ]);
    let resp = http
        .post(format!("{base}/oidc/oauth/token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .timeout(request_timeout)
        .body(form)
        .send()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("oidc refresh: {e}")))?;
    if resp.status() != reqwest::StatusCode::OK {
        return Err(oidc_http_err("oidc refresh", resp).await);
    }
    let body = resp
        .text()
        .await
        .map_err(|e| EdgeError::OidcResponse(format!("oidc refresh body: {e}")))?;
    parse_refresh_response(&body)
}
