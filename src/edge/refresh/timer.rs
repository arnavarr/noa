//! El loop del timer proactivo: `run_refreshes` (la rama OIDC en el TOP del loop, el GET
//! legacy con guarda, el fallback a re-auth dedupeada en el 401 y los reschedules).
//! (F6 tramo 7: movido verbatim del monolito de `edge/refresh`.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use crate::edge::auth_token::{ApiSessionType, AuthToken};
use crate::edge::client::{MfaCodeProvider, oidc_base};
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;
use crate::edge::reauth::ReauthMethod;
use crate::edge::session_cert_renew::SessionCertHolder;

use super::{
    LiveChannels, RefreshIntervals, do_oidc_session_refresh, do_reauthenticate, do_refresh_get,
    guarded_store_refresh, next_sleep, push_token_to_live_channels, read_token,
};

/// The proactive refresh timer task. Loops: sleep until ~`lead` before `expiresAt` (read FRESH each
/// iteration from the shared `Arc`), then GET `/current-api-session`. On success: under the MANDATED
/// `reauth_lock` guard, re-check the token and store the new token+expiry (skipping if a concurrent
/// re-auth already replaced the session). On a 401: fall back to a full deduped re-auth (keeps an idle
/// session alive across a hard expiry). On any other error: reschedule after `retry`. Cancelled by
/// `EdgeClient::Drop` aborting the JoinHandle.
///
/// Nine params (no `AuthState` struct / no token-site re-thread, per the driver mandate).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_refreshes(
    token: Arc<RwLock<Option<AuthToken>>>,
    expires_at: Arc<RwLock<Option<SystemTime>>>,
    reauth_lock: Arc<tokio::sync::Mutex<()>>,
    dial_sessions: Arc<Mutex<HashMap<String, SessionDetail>>>,
    session_cert: Option<SessionCertHolder>,
    http: reqwest::Client,
    base_url: String,
    method: Arc<ReauthMethod>,
    mfa_provider: Option<MfaCodeProvider>,
    live_channels: LiveChannels,
    intervals: RefreshIntervals,
) {
    // The OIDC base (controller root `/oidc/...`) is fixed for the client's life — derive it once. The
    // OIDC refresh branch (token-exchange) uses it; the legacy branch ignores it.
    let oidc_base = oidc_base(&base_url);
    loop {
        // OIDC-REFRESH BRANCH (checked at the TOP, BEFORE the legacy `next_sleep`): an OIDC
        // api-session refreshes via the RFC 8693 token-exchange grant, NOT the legacy GET
        // `/current-api-session`. OIDC-3 wires it in (it was deferred in OIDC-1). It schedules on the
        // SAME `next_sleep(exp, …)` as legacy (the OIDC access expiry is parsed+stored by
        // `expires_in_to_rfc3339`), so there is NO hot-poll. A legacy (or absent) token never enters
        // this branch → the legacy path below is byte-identical.
        if matches!(
            read_token(&token).map(|t| t.session_type()),
            Some(ApiSessionType::Oidc)
        ) {
            // No refresh token → cannot refresh: park on `default` (the OIDC session will hit its
            // access cliff and the reactive 401 recovery — itself a no-op without a refresh — takes
            // over; a full PKCE re-login is the deferred §6 case).
            if read_token(&token)
                .and_then(|t| t.refresh_token().map(str::to_string))
                .is_none()
            {
                tracing::debug!("oidc session has no refresh token; parking on default");
                tokio::time::sleep(intervals.default).await;
                continue;
            }
            let exp = *expires_at.read().expect("expires_at rwlock poisoned");
            let sleep_for = next_sleep(exp, SystemTime::now(), &intervals);
            tokio::time::sleep(sleep_for).await;
            // Re-read AFTER the sleep (a concurrent reactive refresh may have rotated the token) and
            // pass its access value as the dedup re-check key, mirroring the legacy GET path.
            let Some(token_used) = read_token(&token) else {
                tracing::warn!(
                    "could not refresh oidc api session, current token is nil; retrying"
                );
                tokio::time::sleep(intervals.retry).await;
                continue;
            };
            let token_value = token_used.channel_token().to_string();
            match do_oidc_session_refresh(
                &token,
                &expires_at,
                &reauth_lock,
                &http,
                &oidc_base,
                &token_value,
            )
            .await
            {
                Ok(()) => {
                    // OIDC-2: the access token just rotated — push it to every live edge-router
                    // channel so a long-lived idle binding does not orphan its router token. Oracle:
                    // `updateTokenOnAllErs` after the proactive refresh (`ziti.go:1060`).
                    push_token_to_live_channels(&live_channels, &token).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, "could not refresh oidc api session");
                    tokio::time::sleep(intervals.retry).await;
                }
            }
            continue;
        }

        let exp = *expires_at.read().expect("expires_at rwlock poisoned");
        let sleep_for = next_sleep(exp, SystemTime::now(), &intervals);
        tokio::time::sleep(sleep_for).await;

        let Some(token_used) = read_token(&token) else {
            // No token (unreachable post-spawn — the timer only starts after a successful auth — but it
            // mirrors the oracle's nil arm defensively). With no token there is nothing to refresh and
            // nothing to dedup a re-auth against, so we only retry soon and let the reactive path
            // recover; we do NOT re-authenticate here (a deliberate divergence from the oracle's nil
            // arm, which calls `Authenticate()`).
            tracing::warn!("could not refresh api session, current token is nil; retrying");
            tokio::time::sleep(intervals.retry).await;
            continue;
        };
        let token_value = token_used.channel_token().to_string();

        match do_refresh_get(&http, &base_url, &token_used).await {
            Ok(session) => {
                guarded_store_refresh(
                    &token,
                    &expires_at,
                    &reauth_lock,
                    &token_value,
                    AuthToken::Legacy(session.token),
                    session.expires_at.as_deref(),
                )
                .await;
            }
            Err(EdgeError::AuthHttp { status: 401, .. }) => {
                // The api-session is gone (hard expiry). A full re-auth keeps an idle client alive;
                // deduped against any concurrent reactive re-auth via the shared lock.
                tracing::warn!("api session expired, re-authenticating");
                if let Err(re) = do_reauthenticate(
                    &token,
                    &expires_at,
                    &reauth_lock,
                    &dial_sessions,
                    session_cert.as_ref(),
                    &http,
                    &base_url,
                    &method,
                    mfa_provider.as_ref(),
                    &token_value,
                )
                .await
                {
                    tracing::error!(error = %re, "failed to re-authenticate api session");
                }
                // After a re-auth attempt the expiry may have changed; recompute next iteration. The
                // oracle reschedules +5s here.
                tokio::time::sleep(intervals.retry).await;
            }
            Err(e) => {
                // Oracle: `Errorf("could not refresh apiSession: %v")` → reschedule +5s.
                tracing::error!(error = %e, "could not refresh api session");
                tokio::time::sleep(intervals.retry).await;
            }
        }
    }
}
