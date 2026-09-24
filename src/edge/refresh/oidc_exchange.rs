//! El brazo OIDC del refresh: `do_oidc_session_refresh`, el token-exchange RFC 8693 dedupeado
//! bajo `reauth_lock` (NO-CLEAR; escribe con el store BARE — ver la doc del helper).
//! (F6 tramo 7: movido verbatim del monolito de `edge/refresh`.)

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::edge::auth_token::AuthToken;
use crate::edge::client::expires_in_to_rfc3339;
use crate::edge::error::EdgeError;

use super::{channel_token_value, read_token, store_token_and_expiry};

/// Refresh an OIDC api-session via the RFC 8693 token-exchange grant, DEDUPED — the OIDC counterpart
/// of [`do_reauthenticate`](super::do_reauthenticate), shared by BOTH the proactive timer ([`run_refreshes`](super::run_refreshes)) and the reactive
/// recovery (`EdgeClient::oidc_session_refresh`, a thin wrapper). Both operate on the SAME `Arc`s →
/// contend on the SAME `reauth_lock`, so concurrent OIDC refreshes collapse to one exchange.
///
/// Body (ALL under `reauth_lock`, held across the HTTP exchange — that span IS the dedup, mirroring
/// `do_reauthenticate` holding the lock across `do_authenticate`):
/// 1. take `reauth_lock`;
/// 2. re-check the token on the OIDC `access` (channel-token) value — if another refresh already
///    rotated it, skip (`Ok`; the caller retries with the rotated token);
/// 3. read the CURRENT refresh token (the exchange subject) under the SAME guard, paired with the
///    re-checked access — `None` → nothing to refresh (`Ok`; the timer pre-parks on this, so here it
///    is only a race). CONSCIOUS DEVIATION: the oracle (`exchangeTokens`, clients_shared.go:139-158)
///    falls back to exchanging a non-expired ACCESS token (and ERRORS if none) when there is no
///    refresh; we return `Ok` (skip). Delta nil — `scope=openid offline_access` always yields a
///    refresh token, so this branch is unreachable live, and the fallback's access-token precondition
///    cannot hold during a refresh anyway (see spec §6);
/// 4. `do_oidc_refresh` (the single token-exchange POST);
/// 5. merge `response.refresh.or(prior_refresh)` (a `None` response keeps the prior refresh — never
///    live, but a one-off omission must not strand the session), INSIDE the guard;
/// 6. write back with the BARE [`store_token_and_expiry`].
///
/// **CRITICAL — NO-CLEAR semantics + the deadlock trap.** Unlike `do_reauthenticate` this clears
/// NOTHING: an OIDC refresh EXTENDS the SAME api-session (the oracle's OIDC arm just swaps tokens,
/// `&ApiSessionOidc{OidcTokens, …}`, `client_edge_client.go:227-237` — no `setUnauthenticated`, no
/// `sessions.Clear()`; the probe confirmed `z_asid` is CONSTANT across rotations). The write-back MUST
/// use the bare [`store_token_and_expiry`] and NEVER [`guarded_store_refresh`](super::guarded_store_refresh): the guard is already
/// held for the whole helper, and re-acquiring the non-reentrant `tokio::sync::Mutex` would deadlock.
/// Oracle: `exchangeTokens` (`edge-apis/clients_shared.go:135`); reactive arm `RefreshApiSession`
/// (`client_edge_client.go:211`, OIDC branch).
///
/// # Errors
/// Propagates [`crate::edge::oidc::do_oidc_refresh`]'s [`EdgeError::OidcHttp`] (a 4xx = the refresh token is gone/rejected
/// → a full re-login is needed, deferred) / [`EdgeError::OidcResponse`]. The timer reschedules `retry`
/// on `Err`; the reactive path propagates the original 401; `refresh()` propagates the error.
pub(crate) async fn do_oidc_session_refresh(
    token: &Arc<RwLock<Option<AuthToken>>>,
    expires_at: &Arc<RwLock<Option<SystemTime>>>,
    reauth_lock: &tokio::sync::Mutex<()>,
    http: &reqwest::Client,
    oidc_base: &str,
    token_used: &str,
) -> Result<(), EdgeError> {
    let _guard = reauth_lock.lock().await;
    // (2) Dedup re-check on the OIDC access value: a concurrent refresh already rotated it → skip.
    let current = read_token(token);
    if channel_token_value(current.as_ref()).as_deref() != Some(token_used) {
        return Ok(());
    }
    // (3) Read the CURRENT refresh token (the exchange subject) under the SAME guard, paired with the
    // re-checked access. None → nothing to refresh (the timer pre-parks; here it is only a race).
    let prior_refresh = current
        .as_ref()
        .and_then(|t| t.refresh_token().map(str::to_string));
    let Some(subject) = prior_refresh.clone() else {
        return Ok(());
    };
    // (4) The single token-exchange POST, bounded by the per-request timeout (it runs UNDER the
    // `reauth_lock` we hold, so an unbounded POST would freeze the timer + wedge concurrent ops).
    let refreshed = crate::edge::oidc::do_oidc_refresh(
        http,
        oidc_base,
        &subject,
        crate::edge::oidc::OIDC_REFRESH_REQUEST_TIMEOUT,
    )
    .await?;
    // (5) Merge INSIDE the guard: a None response keeps the prior refresh (never live; a one-off
    // omission must not strand the session). Writing back the ROTATED refresh slides the 24h refresh
    // horizon forward so an active client lives indefinitely.
    let new_refresh = refreshed.refresh.or(prior_refresh);
    // (6) BARE store (NOT guarded_store_refresh — the guard is already held). NOTHING is cleared.
    store_token_and_expiry(
        token,
        expires_at,
        AuthToken::Oidc {
            access: refreshed.access,
            refresh: new_refresh,
        },
        expires_in_to_rfc3339(refreshed.expires_in).as_deref(),
    );
    tracing::debug!("oidc api session refreshed");
    Ok(())
}
