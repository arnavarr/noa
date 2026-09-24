//! Edge client REST calls + the stateful `EdgeClient`. Oracle: ziti/client.go.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use crate::edge::auth_token::AuthToken;
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;
use crate::edge::reauth::ReauthMethod;

const PAGE_LIMIT: i64 = 500;

/// Session-creation backoff schedule. Oracle: `createSessionWithBackoff` (`ziti/ziti.go:2009-2047`),
/// which builds `cenkalti/backoff/v4@v4.3.0`'s `NewExponentialBackOff()` and overrides ONLY
/// `InitialInterval=50ms`, `MaxInterval=10s`, `MaxElapsedTime=connectTimeout` — leaving the library
/// defaults `Multiplier=1.5` and `RandomizationFactor=0.5` (jitter ON) untouched
/// (`exponential.go:80-81`). Since slice 10b the `MaxElapsedTime` is the caller's connect-timeout
/// (threaded down from `connect`/`connect_with_timeout`), exactly as the oracle sets it to
/// `options.GetConnectTimeout()` (`ziti.go:2015`). The oracle bounds retries by elapsed time, not
/// by attempt count, so we drop backon's default `max_times` cap.
///
/// MECHANISM DEVIATION (conscious, see spec §5): cenkalti's `MaxElapsedTime` is true wall-clock
/// since the backoff started (`exponential.go:172-179`), so it *includes* time spent inside each
/// `createSession` call; backon's `with_total_delay` caps only the summed *sleep* between attempts
/// (`exponential.rs:240-247`), so a slow controller can push *this* total past the budget. Slice
/// 10b closes that gap at the `connect_inner` layer: an outer `tokio::time::timeout(connect_timeout,
/// …)` bounds true wall-clock for the whole flow (including time spent inside each create/dial), so
/// the backoff's softer summed-sleep bound is now backed by a hard wall-clock bound. The retry count
/// and min/max/factor match; only this inner budget's mechanism differs.
const SESSION_BACKOFF_INITIAL: Duration = Duration::from_millis(50);
const SESSION_BACKOFF_MAX_INTERVAL: Duration = Duration::from_secs(10);
/// Exact match for cenkalti's `DefaultMultiplier` (1.5) — NOT backon's default of 2.0.
const SESSION_BACKOFF_FACTOR: f32 = 1.5;

/// The first two characters of a Base64URL-encoded JWT header — the discriminant the oracle uses to
/// tell a JWT session token from an opaque/legacy one (`refreshSession`, `ziti/ziti.go:2106`:
/// `strings.HasPrefix(*session.Token, apis.JwtTokenPrefix)`). Oracle constant: `JwtTokenPrefix = "ey"`
/// (`edge-apis/oidc.go:10`).
pub(crate) const JWT_TOKEN_PREFIX: &str = "ey";

/// An owned TOTP-code provider stored on [`EdgeClient`] for the LEGACY MFA path. Unlike the borrowed
/// [`crate::edge::oidc::TotpCodeProvider`] (`&dyn Fn`, used transiently during an OIDC login), this is
/// an OWNED `Arc<dyn Fn … + Send + Sync>`: the provider must outlive the construction call so it can
/// satisfy a mid-session MFA challenge later (a session re-auth via slice reauth-401) — including from
/// the proactive-refresh background task, which is why the bound is `+ Send`. Mirrors `reauth_method`'s
/// `Arc` storage. Oracle: the `MfaCodeResponse` callback wired into `authenticateMfa` (`ziti.go:1416`).
pub type MfaCodeProvider = Arc<dyn Fn() -> Result<String, EdgeError> + Send + Sync>;

/// Stateful edge client: holds the mTLS client + the API-session token.
///
/// `dial_sessions` caches **Dial** sessions keyed by service id (the oracle's `getOrCreateSession`
/// cache, `ziti.go:1986`). Bind sessions are never cached — they use session tokens for routing
/// (oracle comment, `ziti.go:1991`). A `std::sync::Mutex` keeps `connect(&self)` (a shared,
/// concurrently-usable client); the guard is only ever held across synchronous map ops, never
/// across an `await`.
pub struct EdgeClient {
    base_url: String,
    http: reqwest::Client,
    /// The api-session token, INTERIOR-MUTABLE so a reactive re-auth (slice reauth-401) can swap it
    /// while `&self` control-plane ops (`connect()`/`bind()`) are in flight. An `Arc<RwLock<..>>`:
    /// the proactive refresh timer (slice proactive-refresh) captures a CLONE of the `Arc` so it can
    /// rotate the token from its own task; the guard is NEVER held across an `.await` (read → clone
    /// out → drop; write is synchronous), matching the crate-wide rule. Oracle: `ContextImpl` swaps
    /// the api-session on re-auth.
    token: Arc<RwLock<Option<AuthToken>>>,
    /// The current api-session expiry (parsed RFC3339 `expiresAt`), persisted ALONGSIDE the token on
    /// every session-minting path (auth/reauth/refresh) — the §4.3-class correctness fix so the
    /// proactive timer never reprograms on a stale deadline. `Arc<RwLock<..>>` for the same reason as
    /// `token`. `None` = expiry unknown (the timer falls back to its DEFAULT interval). Oracle:
    /// `ApiSession.GetExpiresAt()` (`ziti.go:1028`).
    expires_at: Arc<RwLock<Option<SystemTime>>>,
    /// How to re-authenticate on a 401 (`Cert` for `from_identity`, `Updb{..}` for `from_updb`).
    /// Holds the updb password (a SECRET); `ReauthMethod`'s `Debug` redacts it, and `EdgeClient` is
    /// not `Debug`. `Arc` so the refresh timer captures it without copying the secret. Oracle: the
    /// auth credentials `ContextImpl.Authenticate()` re-uses.
    reauth_method: Arc<ReauthMethod>,
    /// How to obtain a fresh TOTP code when a LEGACY auth/re-auth returns a partial api-session (MFA
    /// `authQueries`). `Some` only for an MFA identity built via `authenticate_with_totp`/
    /// `from_updb_with_totp`; `None` → a legacy MFA challenge is the generic [`EdgeError::MfaRequired`]
    /// (byte-identical to before this slice). Set once in the `&mut self` constructors and read-cloned
    /// later, so `connect`/`bind` stay `&self`. `Arc` so the proactive-refresh task captures it without
    /// copying the boxed closure. Oracle: the `MfaCodeResponse` callback wired into `authenticateMfa`
    /// (`ziti.go:1416`). NOTE: only the LEGACY path uses this; the OIDC TOTP path takes a transient
    /// borrowed [`crate::edge::oidc::TotpCodeProvider`] at login.
    mfa_provider: Option<MfaCodeProvider>,
    /// Serializes concurrent re-auths so a burst of 401s collapses to ONE `/authenticate` (the dedup
    /// is the lock + a token re-check in `reauthenticate`). Shared (`Arc`) with the proactive timer,
    /// so a proactive re-auth NEVER races a concurrent reactive one. A `tokio::sync::Mutex` (held
    /// across the re-auth `.await`). Oracle: `authAttemptLock` (`ziti.go:234,1198`).
    reauth_lock: Arc<tokio::sync::Mutex<()>>,
    identity_name: Option<String>,
    config: crate::enroll::identity::Config,
    dial_sessions: Arc<Mutex<HashMap<String, SessionDetail>>>,
    /// The renewable api-session certificate for a `updb` client. `None` for cert-identities (their
    /// channel mTLS reads `config` directly, byte-identical to before this slice). `Some` only for
    /// `updb` clients (`from_updb`), whose session-cert is RE-MINTED on expiry — a conscious
    /// improvement beyond the oracle (which never renews; see [`crate::edge::session_cert_renew`]).
    /// A `tokio::sync::Mutex` (NOT the crate's `std::sync::Mutex`): `ensure_fresh` holds the guard
    /// across the re-mint `.await`; the holder is the SOLE channel-TLS source for `updb` (the
    /// synthetic `config` leaf is never read on the `Some` path), so renewal actually takes effect.
    session_cert: Option<crate::edge::session_cert_renew::SessionCertHolder>,
    /// The proactive refresh timer's background task (slice proactive-refresh). Spawned ONCE after the
    /// first successful auth (`authenticate`/`from_updb`; `from_identity` does not authenticate, so it
    /// is `None` until `authenticate`). Spawn-once mirrors the oracle's `firstAuthOnce.Do`
    /// (`ziti.go:1066`); ABORTED in `Drop` (the oracle's `closeNotify` arm, `ziti.go:1034`). Always-on,
    /// faithful to the oracle which spawns `runRefreshes` unconditionally (an opt-out knob = YAGNI).
    refresh_task: Option<tokio::task::JoinHandle<()>>,
    /// The registry of live edge-router channels (OIDC-2). A `Weak` per channel kept alive by a live
    /// `ServiceConn`/`ServiceBinding`; registered the instant a `connect()`/`bind()` succeeds (so a
    /// 10c race loser is never registered), pruned on iterate. After an OIDC refresh rotates the
    /// Bearer, [`crate::edge::refresh::push_token_to_live_channels`] pushes it to every live channel so
    /// a long-lived idle binding does not orphan its router token. Shared (`Arc`) with the proactive
    /// timer task. Oracle's analogue: `routerConnections` (`ziti.go:215`), iterated by
    /// `updateTokenOnAllErs`.
    live_channels: crate::edge::refresh::LiveChannels,
    /// The router connection POOL (slice pool-first): the live edge-router channels keyed by router
    /// protocol-address (the `tls://host:port` url), so a later `connect()` REUSES an already-open
    /// channel instead of opening a fresh TLS connection. The faithful analogue of the oracle's
    /// `routerConnections cmap.ConcurrentMap[string, edge.RouterConn]` (`ziti.go:215`): one pooled
    /// channel is SHARED by many service dials (multiplexed by conn-id over the one rx-loop), which
    /// re-architects slice 4b's one-channel-per-`ServiceConn` ownership — the pool now OWNS the channel
    /// (a strong `Arc`) and a `ServiceConn` holds a shared `Arc` clone (so closing one conn no longer
    /// tears the channel down; see [`crate::edge::conn::ServiceConn::close`]). Eviction is LAZY at
    /// get-time: a dead channel is dropped and re-dialed, the faithful mirror of the oracle's
    /// `!IsClosed()` check at `ziti.go:1749`. "Dead" is decided by [`super::data::EdgeChannel::is_alive`], which
    /// reads `state.closed` (the exact `IsClosed()` analogue). This eviction is sound because the
    /// rx_loop latency-probe + close-notify mechanism (the `feat/edge-rxloop-close-notify` slice)
    /// GUARANTEES a channel's death is observed and `mark_closed`-flagged even when a sibling conn is
    /// HOL-stalled or the router black-holes — the pool review's previously-refuted "EOF-on-death"
    /// claim now holds (every conn EOFs via the map-clear, AND the channel reports dead via
    /// `state.closed`). The eager `OnClose` removal + latency SCORING (the probe already measures
    /// latency via the reflected `probeTime`) are deferred to the scoring slice. CONSCIOUS DEVIATION:
    /// only `connect()` pools; `bind()` keeps its own first-router channel (the oracle shares the pool
    /// across dial+bind via `listenerManager`). OBSERVABLE: a `connect()` and a `bind()` to the SAME
    /// router open TWO channels here (`tls_channel_opens` += 2), where the oracle would share one;
    /// benign (independent TLS conns, each with its own token), and bind-side pooling is the natural
    /// follow-up.
    /// The `std::sync::Mutex` is NEVER held across an `.await` (the dial happens outside the lock).
    channel_pool: Arc<Mutex<HashMap<String, Arc<crate::edge::data::EdgeChannel>>>>,
    /// Count of successful edge-router channel opens (TLS handshakes completed in `open_channel_to`).
    /// A diagnostic/observability counter that makes the pool's reuse NON-VACUOUSLY testable: two
    /// `connect()`s to the same router increment it ONCE (the second reuses the pooled channel), where
    /// without the pool it would be twice. Read via [`EdgeClient::tls_channel_opens`]. Negligible hot
    /// path cost (one relaxed atomic add per real handshake).
    tls_opens: Arc<AtomicUsize>,
    /// The local service cache + the service-event listener registry (T5 svc-poller). Holds the
    /// identity's last-seen service set keyed by name (the oracle's `context.services`) and the
    /// registered change listeners; [`EdgeClient::poll_services`] fetches, diffs against it, updates
    /// it, and fans the Added/Changed/Removed events out. An `Arc` so a future background svc-refresh
    /// timer (T5-2) can share it. Oracle: `context.services` + the `AddService*Listener` registry
    /// (`ziti.go:351-415`).
    services: Arc<crate::edge::services::ServiceWatcher>,
    /// The instant (UTC, in nanoseconds since the Unix epoch) of the controller's last service-set
    /// change as last seen by this client — the oracle's `CtrlClient.lastServiceUpdate`
    /// (`ziti/client.go:155`). `None` until the first `/service-updates` check stores one; a FORCED
    /// `poll_services` resets it to `None` (the oracle's function-local `lastServiceUpdate` is never
    /// assigned in the force branch, so `refreshServices` stores nil, `ziti.go:930`). Compared
    /// instant-wise to the controller's `lastChangeAt` (`strfmt.DateTime.Equal` → `time.Time.Equal`,
    /// the UTC instant) to decide whether a service refresh is needed. An `Arc<Mutex>` so the future
    /// background svc-refresh timer (T5-2b) shares it; the `std::sync::Mutex` is never held across an
    /// `.await`.
    last_service_update: Arc<Mutex<Option<i128>>>,
    /// The background SERVICE-refresh timer task (T5-2b). `None` until
    /// [`start_service_polling`](EdgeClient::start_service_polling) opts in (unlike `refresh_task`,
    /// which is always-on after auth). A SIBLING of `refresh_task` — the oracle's `runRefreshes` runs
    /// the api-session and service refresh arms in one goroutine; we split them into two tasks sharing
    /// the same `Arc`s. ABORTED in `Drop` (the oracle's `closeNotify` arm, `ziti.go:1034`). See
    /// [`crate::edge::service_refresh`].
    service_refresh_task: Option<tokio::task::JoinHandle<()>>,
    /// The background SESSION-refresh timer task (D2). Like `refresh_task` (and UNLIKE the opt-in
    /// `service_refresh_task`) it is ALWAYS-ON: spawned alongside the api-session timer in
    /// [`spawn_refresh_timer_with`](EdgeClient::spawn_refresh_timer_with) after the first auth, faithful
    /// to the oracle running all three refresh arms in one `runRefreshes` goroutine (`ziti.go:1080-1083`;
    /// the session arm needs nothing from the consumer, unlike the service arm's `configTypes`). ABORTED
    /// in `Drop` (the oracle's `closeNotify` arm, `ziti.go:1034`). See [`crate::edge::session_refresh`].
    session_refresh_task: Option<tokio::task::JoinHandle<()>>,
    /// The consumer-supplied edge-router URL filter (slice 4c). The faithful analogue of the oracle's
    /// `Options.EdgeRouterUrlFilter` (`options.go:47`), consulted through
    /// [`crate::edge::router_filter::is_edge_router_url_accepted`] (`options.go:50-51`) wherever a
    /// router's protocol URLs are enumerated. `None` (the oracle's `nil`, and the state of
    /// `DefaultOptions`) ⇒ **every URL is accepted** ⇒ byte-identical behavior to before the slice.
    /// Installed via [`EdgeClient::set_edge_router_url_filter`]. It can only ever REMOVE routers from
    /// the dial/bind candidate set (under-permit; never over-permit).
    edge_router_url_filter: Option<crate::edge::router_filter::EdgeRouterUrlFilter>,
}

impl Drop for EdgeClient {
    fn drop(&mut self) {
        // Mirror `EdgeChannel::Drop` (`edge/data/channel.rs`): abort the background tasks on drop, the equivalent
        // of the oracle's `closeNotify`-gated `return` from `runRefreshes` (`ziti.go:1034`). The
        // api-session timer, the always-on session-refresh timer, and the (opt-in) service-refresh
        // timer are all aborted.
        if let Some(t) = self.refresh_task.take() {
            t.abort();
        }
        if let Some(t) = self.service_refresh_task.take() {
            t.abort();
        }
        if let Some(t) = self.session_refresh_task.take() {
            t.abort();
        }
    }
}

/// The trust + endpoint material [`EdgeClient::from_ext_jwt`] needs to reach the controller. An
/// ext-jwt client has NO enrolment step — the identity PRE-EXISTS in the controller, bound by its
/// `externalId` to the external JWT's `sub` claim — so, unlike `from_updb`'s `UpdbConfig` (an
/// enrolment OUTPUT), the caller supplies these out-of-band. This mirrors the oracle, whose
/// `JwtCredentials` carries the controller `CaPool` from the loaded identity config
/// (`ziti/ziti.go:657-669` `LoginWithJWT`: `CaPool: context.CtrlClt.CaPool`). The external JWT itself
/// is passed SEPARATELY to [`EdgeClient::from_ext_jwt`] — it is short-lived/per-session, while this
/// config is stable.
///
/// Holds NO secrets (the ztAPI URL + the PUBLIC CA bundle), so a derived `Debug` is safe.
#[derive(Debug, Clone)]
pub struct ExtJwtConfig {
    /// Controller client API base URL (`<iss>/edge/client/v1`).
    pub zt_api: String,
    /// Controller CA bundle, PEM. Trust for the control-plane HTTPS AND the channel mTLS roots.
    pub ca: String,
}

mod auth;
mod construct;
mod oidc_glue;
mod pool;
mod services;
mod sessions;
mod sessions_probe;

pub use auth::{do_authenticate, do_authenticate_password};
pub use services::do_list_services;
pub use sessions::{do_create_session, do_get_service_edge_routers, do_get_session_detail};

pub(crate) use auth::apply_access_header;
pub(crate) use oidc_glue::{
    controller_supports_oidc, expires_in_to_rfc3339, oidc_base, parse_error_envelope,
};
pub(crate) use pool::{pool_get_alive_one, pool_store_or_reuse_into};
pub(crate) use services::{check_service_list_update_free, store_and_process_free};
pub(crate) use sessions_probe::{
    evict_dead_dial_session, is_proven_dead, recache_refreshed_dial_session, refresh_session_probe,
    refresh_session_probe_durable,
};

#[cfg(test)]
mod tests_auth;
#[cfg(test)]
mod tests_construct;
#[cfg(test)]
mod tests_construct_oidc;
#[cfg(test)]
mod tests_oidc_refresh;
#[cfg(test)]
mod tests_reauth;
#[cfg(test)]
mod tests_services;
#[cfg(test)]
mod tests_sessions;
#[cfg(test)]
mod tests_sessions_probe;
#[cfg(test)]
mod tests_sessions_refresh;
#[cfg(test)]
mod testsupport;
