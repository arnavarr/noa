//! Proactive api-session refresh timer (PROACTIVE counterpart of the reactive `reauth-401`).
//!
//! The api-session is a sliding ~30-min window with no absolute cap: an IDLE client (no
//! `connect`/`bind`/`list_services`) never refreshes it, so it eventually expires. `reauth-401`
//! recovers a 401 at the next *use*, but an idle client has no next use. This module ports the
//! oracle's PROACTIVE background timer (`runRefreshes`, `sdk-golang` v1.7.0 `ziti/ziti.go:1002`):
//! a spawned task that GETs `/current-api-session` ~10 s before `expiresAt`, keeping an idle
//! session alive.
//!
//! # Why a background task, not a lazy ensure-fresh
//! "Proactive" means keeping an IDLE client's session alive. A lazy ensure-fresh fires only on use;
//! an idle client never uses → never fires → the goal is unmet. It MUST be a spawned task. Lifecycle
//! mirrors the rx-loop: `tokio::spawn` on the first successful auth (spawn-once, like the oracle's
//! `firstAuthOnce.Do`, `ziti.go:1333`), JoinHandle aborted in `EdgeClient`'s `Drop` (the oracle's
//! `closeNotify` arm, `ziti.go:1034`).
//!
//! # Ported scope
//! Only the api-session refresh arm of `runRefreshes` (the `refreshAt` arm). ⚠ *This used to add "the
//! service-refresh and session-refresh arms are out of scope: this SDK has no local services cache /
//! session-refresh loop". **Both now exist** and are ported as SIBLING tasks —
//! [`crate::edge::service_refresh::run_service_refreshes`] and
//! [`crate::edge::session_refresh::run_session_refreshes`] — so this module is one of three arms, not the
//! only one.* No `updateTokenOnAllErs` (router-token push): for the LEGACY
//! (`zt-session`) api-session this is a no-op — `RequiresRouterTokenUpdate()` returns `false` for
//! `ApiSessionLegacy` (`edge-apis/api_session.go:169`), so the oracle pushes nothing to routers (token
//! sync is controller↔router, not client→router). The reason is that legacy no-op, NOT "no long-lived
//! router connections" — a `ServiceBinding` DOES own a long-lived idle router channel. TODO(OIDC): when
//! bearer/OIDC api-sessions land, `RequiresRouterTokenUpdate()` becomes `true` and this arm must be
//! ported, or an idle long-lived `ServiceBinding` orphans its router token.
//!
//! # Send body (the trap the advisor flagged)
//! This is the FIRST `tokio::spawn` that could touch the auth primitives. The task body uses ONLY
//! free `async fn`s over primitives ([`do_refresh_get`], [`do_reauthenticate`]) — NEVER
//! `with_reauth_retry` (its `AsyncFn` closure is non-Send). No `std::sync` guard crosses an `.await`.
//! So the spawn compiles without `spawn_local`/`LocalSet` (a library must not impose a `LocalSet` on
//! its consumer).

mod legacy;
mod oidc_exchange;
mod push;
mod schedule;
mod store;
mod timer;

pub(crate) use legacy::{do_reauthenticate, do_refresh_get};
pub(crate) use oidc_exchange::do_oidc_session_refresh;
pub(crate) use push::{LiveChannels, push_token_to_live_channels};
pub(crate) use schedule::{PROD_INTERVALS, RefreshIntervals, next_sleep, parse_expires_at};
pub(crate) use store::{
    channel_token_value, guarded_store_refresh, read_token, store_token_and_expiry,
};
pub(crate) use timer::run_refreshes;

#[cfg(test)]
mod tests_legacy;
#[cfg(test)]
mod tests_oidc_exchange;
#[cfg(test)]
mod tests_push;
#[cfg(test)]
mod tests_schedule;
#[cfg(test)]
mod tests_store;
#[cfg(test)]
mod tests_timer;
#[cfg(test)]
mod testsupport;
