//! El push OIDC-2 del Bearer rotado a los edge routers vivos: `LiveChannels` y
//! `push_token_to_live_channels` (port de `updateTokenOnAllErs`).
//! (F6 tramo 7: movido verbatim del monolito de `edge/refresh`.)

use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::edge::auth_token::AuthToken;
use crate::edge::data::{ChannelState, UPDATE_TOKEN_TIMEOUT};

use super::read_token;

/// The registry of live edge-router channels (OIDC-2). A `Weak<ChannelState>` per channel that a live
/// `ServiceConn`/`ServiceBinding` keeps alive (the strong `Arc` lives in the connection); a dropped
/// connection's `Weak` fails to upgrade and is pruned. There is NO connection pool (slice 10c deferred
/// it), so this is one entry per kept channel, not the oracle's per-router-address pool — a conscious
/// architectural difference: each channel is a separate TLS connection independently holding a token,
/// so a per-channel push is correct (no dedup-by-router needed). Oracle's analogue: `routerConnections`
/// (`ziti.go:215`).
pub(crate) type LiveChannels = Arc<Mutex<Vec<Weak<ChannelState>>>>;

/// Push a rotated api-session token to EVERY live edge-router channel (OIDC-2). Port of
/// `updateTokenOnAllErs` (`ziti.go:974`): gated on `RequiresRouterTokenUpdate()` (true ONLY for OIDC —
/// a legacy refresh pushes nothing); iterates the live channels; sends `UpdateToken` (ct 60803) on each
/// and COLLECTS per-channel failures WITHOUT aborting (one router failing must not stop the others —
/// the oracle's `errors.Join`). We do not return the joined error (the refresh has already succeeded);
/// a per-channel failure is `warn!`-logged, matching the oracle's caller which only logs the join.
///
/// SEND-SAFE: the live-channel snapshot is taken (and dead `Weak`s pruned) under the `std::sync::Mutex`
/// in a block that DROPS the guard before the first `.await` — no std guard crosses an await, so this
/// is `Send` and safe to call from the proactive timer task. The upgraded `Arc`s keep the channels
/// alive across the push (a connection dropped mid-push merely pushes to a dying channel — harmless;
/// the 10s per-channel timeout bounds it).
///
/// CONSCIOUS DEVIATION (oracle has 3 `updateTokenOnAllErs` call sites, we wire 2): we push after the
/// proactive timer refresh (`ziti.go:1060`) and the reactive/`refresh()` funnel (`:1279`); the third,
/// `:1388`, is inside `authenticateMfa` (TOTP/MFA). The legacy MFA re-auth path now EXISTS (slice
/// `feat/edge-mfa-midsession`), but it mints a `Legacy` token whose `requires_router_token_update()` is
/// false → the 3rd site is a vacuous LEGACY no-op (nothing to push). The NON-VACUOUS case is an OIDC
/// session re-verifying MFA mid-session, which is DEFERRED (an OIDC session never enters the legacy MFA
/// path; and the oracle gates OIDC `authQueries` behind a nil stub `api_session.go:383` in v1.7.0). The
/// two wired sites therefore cover every OIDC token-rotation event that exists here.
pub(crate) async fn push_token_to_live_channels(
    live_channels: &LiveChannels,
    token: &Arc<RwLock<Option<AuthToken>>>,
) {
    // The OIDC-2 gate, mirroring `if apiSession.RequiresRouterTokenUpdate()`: only an OIDC session
    // rotates a Bearer the routers must learn; a legacy refresh pushes NOTHING.
    let Some(current) = read_token(token) else {
        return;
    };
    if !current.requires_router_token_update() {
        return;
    }
    let new_token = current.channel_token().to_string();

    // Snapshot the live channels OUT of the mutex (and prune dead Weaks) BEFORE awaiting — the guard
    // is dropped at the end of this block, so it never crosses the push `.await`s. SKIP channels that
    // have been torn down (`is_closed`): the router connection pool keeps a strong `Arc<EdgeChannel>`
    // for a pooled channel that has DIED, so its registry `Weak` still upgrades — but `update_token`
    // would write into the half-closed transport (a graceful router close leaves the write half
    // writable) and then block the full `UPDATE_TOKEN_TIMEOUT` awaiting a reply the gone rx-loop can
    // never deliver. Skipping mirrors the oracle, which only pushes to non-closed `routerConnections`;
    // the dead entry is reaped when the pool lazily evicts it (its `ChannelState` `Arc` drops → the
    // `Weak` no longer upgrades → pruned by the `retain` above on a later push).
    let channels: Vec<Arc<ChannelState>> = {
        let mut guard = live_channels.lock().expect("live-channels mutex poisoned");
        guard.retain(|w| w.strong_count() > 0);
        guard
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|ch| !ch.is_closed())
            .collect()
    };

    for ch in channels {
        if let Err(e) = ch.update_token(&new_token, UPDATE_TOKEN_TIMEOUT).await {
            // Collect-without-abort (oracle `errors.Join`): log and keep updating the other channels.
            tracing::warn!(error = %e, "error updating current api session token on edge routers");
        }
    }
}
