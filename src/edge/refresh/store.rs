//! Primitivas de token-state sobre los `Arc`s compartidos: `read_token`, `channel_token_value`,
//! `store_token_and_expiry` y la guarda coordinada del GET (`guarded_store_refresh`).
//! (F6 tramo 7: movido verbatim del monolito de `edge/refresh`.)

use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use crate::edge::auth_token::AuthToken;

use super::parse_expires_at;

/// Read the shared token (clone out; the guard never crosses an await).
pub(crate) fn read_token(token: &Arc<RwLock<Option<AuthToken>>>) -> Option<AuthToken> {
    token.read().expect("token rwlock poisoned").clone()
}

/// The channel-token VALUE of an optional [`AuthToken`] (uuid for legacy, access-JWT for OIDC). Used
/// to compare the live token against the value a failed op carried (the dedup re-check).
pub(crate) fn channel_token_value(token: Option<&AuthToken>) -> Option<String> {
    token.map(|t| t.channel_token().to_string())
}

/// Store a fresh token + parsed expiry on the shared `Arc`s (the post-auth/refresh mutation). The
/// §4.3-class correctness fix: token AND expiry move together, so the timer never reprograms on a
/// stale deadline. Both guards are synchronous (never cross an await). `new_token` is already the
/// right [`AuthToken`] variant (Legacy for password/cert auth + GET-refresh; Oidc for the PKCE flow).
pub(crate) fn store_token_and_expiry(
    token: &Arc<RwLock<Option<AuthToken>>>,
    expires_at: &Arc<RwLock<Option<SystemTime>>>,
    new_token: AuthToken,
    new_expires_at: Option<&str>,
) {
    *token.write().expect("token rwlock poisoned") = Some(new_token);
    *expires_at.write().expect("expires_at rwlock poisoned") =
        new_expires_at.and_then(parse_expires_at);
}

/// Store a successful GET-refresh's token+expiry, but ONLY if the live token still equals the one the
/// GET was issued with (`token_used`). The MANDATED §3.6 coordination guard: take `reauth_lock` →
/// re-check the token → store. If a concurrent re-auth already rotated the token away from
/// `token_used`, the GET extended a session that no longer exists, so the write is SKIPPED (the fresh
/// re-auth token wins — no clobber). Sequential with `do_reauthenticate` (each takes `reauth_lock`
/// independently; never nested) → no deadlock. Extracted as a free fn so the guard is unit-testable
/// (a mutation that drops the re-check makes `guarded_get_write_skips_stale` go RED). Returns `true`
/// iff it stored (test introspection).
pub(crate) async fn guarded_store_refresh(
    token: &Arc<RwLock<Option<AuthToken>>>,
    expires_at: &Arc<RwLock<Option<SystemTime>>>,
    reauth_lock: &tokio::sync::Mutex<()>,
    token_used: &str,
    new_token: AuthToken,
    new_expires_at: Option<&str>,
) -> bool {
    let _guard = reauth_lock.lock().await;
    if channel_token_value(read_token(token).as_ref()).as_deref() == Some(token_used) {
        store_token_and_expiry(token, expires_at, new_token, new_expires_at);
        tracing::debug!("api session refreshed");
        true
    } else {
        // A concurrent re-auth rotated the token under us → skip the stale write.
        false
    }
}
