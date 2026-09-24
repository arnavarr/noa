//! El brazo LEGACY compartido por el timer y la reactiva: el GET `/current-api-session`
//! (`do_refresh_get`) y la re-auth dedupeada con clear-on-reauth (`do_reauthenticate`).
//! (F6 tramo 7: movido verbatim del monolito de `edge/refresh`.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use crate::edge::auth_token::AuthToken;
use crate::edge::client::{
    MfaCodeProvider, do_authenticate, do_authenticate_password, parse_error_envelope,
};
use crate::edge::error::EdgeError;
use crate::edge::model::{ApiSession, Envelope, SessionDetail};
use crate::edge::reauth::ReauthMethod;
use crate::edge::session_cert_renew::SessionCertHolder;

use super::{channel_token_value, read_token, store_token_and_expiry};

/// The raw `GET /current-api-session` (extends the sliding window). A free, Send helper shared by the
/// timer and `EdgeClient::refresh` (DRY). Sends the `zt-session` header; the 200 body carries a
/// (possibly) refreshed token + a new `expiresAt`. Oracle: `CtrlClient.Refresh` (`ziti/client.go:129`).
///
/// # Errors
/// [`EdgeError::AuthResponse`] on transport / unparseable body; [`EdgeError::AuthHttp`] on a non-2xx
/// (a 401 here means the api-session is gone → the timer falls back to a full re-auth).
pub(crate) async fn do_refresh_get(
    http: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
) -> Result<ApiSession, EdgeError> {
    let url = format!("{base_url}/current-api-session");
    let (hname, hval) = token.access_header();
    let resp = http
        .get(&url)
        .header(hname, hval)
        .send()
        .await
        .map_err(|e| EdgeError::AuthResponse(e.to_string()))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| EdgeError::AuthResponse(e.to_string()))?;
    if !status.is_success() {
        let (code, message) = parse_error_envelope(&text);
        return Err(EdgeError::AuthHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }
    let env: Envelope<ApiSession> =
        serde_json::from_str(&text).map_err(|e| EdgeError::AuthResponse(format!("json: {e}")))?;
    Ok(env.data)
}

/// Re-authenticate the api-session, DEDUPED. The SINGLE implementation of the dedup + clear-on-reauth
/// logic, shared by the reactive path (`EdgeClient::reauthenticate`, a thin wrapper) and the proactive
/// timer (which cannot borrow `&self`). Both operate on the SAME `Arc`s, so they contend on the SAME
/// `reauth_lock` — a proactive re-auth never races a concurrent reactive one.
///
/// Takes `reauth_lock` + re-checks the token: if the current token already differs from `token_used`
/// (another op re-authed), skip. On a real re-auth: POST `/authenticate`, store the fresh token+expiry,
/// then mirror the oracle's `setUnauthenticated` (`ziti.go:1153`+`:1156`) — clear the Dial-session
/// cache (`sessions.Clear()`) and invalidate the updb session-cert (`ApiSessionCertificate = nil`),
/// both minted under the now-stale api-session.
///
/// Eight params (no `AuthState` struct / no token-site re-thread, per the driver mandate).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn do_reauthenticate(
    token: &Arc<RwLock<Option<AuthToken>>>,
    expires_at: &Arc<RwLock<Option<SystemTime>>>,
    reauth_lock: &tokio::sync::Mutex<()>,
    dial_sessions: &Mutex<HashMap<String, SessionDetail>>,
    session_cert: Option<&SessionCertHolder>,
    http: &reqwest::Client,
    base_url: &str,
    method: &ReauthMethod,
    mfa_provider: Option<&MfaCodeProvider>,
    token_used: &str,
) -> Result<(), EdgeError> {
    let _guard = reauth_lock.lock().await;
    // Someone already rotated the token (a concurrent re-auth won the race) → skip. Compare on the
    // channel-token VALUE (the uuid for legacy), the same identity the failed op carried.
    if channel_token_value(read_token(token).as_ref()).as_deref() != Some(token_used) {
        return Ok(());
    }
    // This helper is the LEGACY re-auth path (`POST /authenticate`); an OIDC session refreshes via the
    // token-exchange grant (`do_oidc_session_refresh`), NOT here. The OIDC branch in
    // `with_reauth_retry`/`run_refreshes` routes OIDC tokens to that helper, so this is only ever
    // reached with a legacy token, and the stored result is always Legacy. The `mfa_provider` (if the
    // identity is MFA-enrolled) re-satisfies a legacy MFA challenge on the re-auth — the genuine
    // MID-SESSION MFA path (oracle `authenticateMfa`, `ziti.go:1365`).
    let session = match method {
        ReauthMethod::Cert => do_authenticate(http, base_url, "{}", mfa_provider).await?,
        ReauthMethod::Updb { username, password } => {
            do_authenticate_password(http, base_url, username, password, mfa_provider).await?
        }
        // An ext-jwt session is always OIDC → the OIDC dispatch routes it to
        // `do_oidc_session_refresh`, never here. Unreachable in practice; fail LOUDLY (defense in
        // depth) rather than fabricate a legacy re-auth the credential cannot perform.
        ReauthMethod::ExtJwt => return Err(EdgeError::ExtJwtReauthUnsupported),
    };
    store_token_and_expiry(
        token,
        expires_at,
        AuthToken::Legacy(session.token),
        session.expires_at.as_deref(),
    );
    // Mirror `sessions.Clear()` (`ziti.go:1156`): the chained guard temporary drops at the `;` — it
    // never crosses the `invalidate().await` below (a `std::sync::Mutex` guard must not span an await).
    dial_sessions
        .lock()
        .expect("dial-session cache mutex poisoned")
        .clear();
    if let Some(holder) = session_cert {
        holder.lock().await.invalidate();
    }
    Ok(())
}
