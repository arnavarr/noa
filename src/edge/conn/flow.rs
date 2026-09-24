//! The `EdgeClient` connect flow: `connect` / `connect_with_timeout` / `connect_with_appdata` and
//! `connect_inner` (the injectable composition bounded by the connect-timeout). (F6 tramo 5:
//! movido verbatim del monolito de `edge/conn`.)

use std::sync::Arc;
use std::time::Duration;

use crate::edge::client::EdgeClient;
use crate::edge::data::EdgeChannel;
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;

use super::retry::dial_with_refresh_retry;
use super::{DEFAULT_CONNECT_TIMEOUT, ServiceConn, do_resolve_service};

impl EdgeClient {
    /// Connect to a service by name with the default [`DEFAULT_CONNECT_TIMEOUT`] (15s, the oracle's
    /// default). See [`EdgeClient::connect_with_timeout`] for the full flow and the timeout
    /// semantics. Oracle: `ziti.go` `DialContextWithOptions` (:1440, defaulting `ConnectTimeout` to
    /// 15s at :1449-1451).
    ///
    /// Behaviour change since slice 10b: a previously unbounded `connect()` now fails with
    /// [`EdgeError::ConnectTimedOut`] after 15s instead of hanging forever — faithful to the oracle.
    ///
    /// # Errors
    /// Same as [`EdgeClient::connect_with_timeout`].
    pub async fn connect(&self, service_name: &str) -> Result<ServiceConn, EdgeError> {
        self.connect_with_timeout(service_name, DEFAULT_CONNECT_TIMEOUT)
            .await
    }

    /// Connect to a service by name with an explicit connect-timeout budget, end-to-end: resolve the
    /// service, get-or-create its Dial session (cached, slice 9; the create's backoff `MaxElapsedTime`
    /// is this same `timeout`, slice 10a), open the channel, and dial — encrypting transparently when
    /// the service is `encryptionRequired=true` (the flag is read from the `Service`, not passed by the
    /// caller). If the dial fails because the cached session expired, the session is refreshed, evicted,
    /// recreated, and the dial retried once (faithful to `DialContextWithOptions`). A router
    /// `invalid session` rejection SKIPS the refresh and goes straight to evict + recreate + retry
    /// (beyond-oracle, D3): the controller's probe would report the session alive, yet it is dead at
    /// dial-authorization, so the router's verdict is authority — see [`dial_with_refresh_retry`].
    ///
    /// The whole flow is bounded by `timeout` (the oracle applies `ConnectTimeout` as a context
    /// deadline, `ziti.go:1453-1460`): on expiry the in-flight future is dropped — cancel-safe, as the
    /// drop tears down any partial channel via `EdgeChannel`'s `Drop` (which aborts its rx-loop) — and
    /// `connect` returns [`EdgeError::ConnectTimedOut`]. Mirrors how Go exposes
    /// `DialOptions.ConnectTimeout`. Requires a prior [`EdgeClient::authenticate`]. Returns a
    /// [`ServiceConn`] that owns the channel for the connection's lifetime.
    ///
    /// # Errors
    /// - `EdgeError::ConnectTimedOut` if the flow does not complete within `timeout`.
    /// - `EdgeError::NotAuthenticated` if `authenticate()` has not been called.
    /// - `EdgeError::ServiceNotFound` if no service matches `service_name`.
    /// - `EdgeError::ServicesHttp`/`SessionHttp` for REST failures (e.g. a not-dialable
    ///   service is rejected by the controller at session creation).
    /// - `EdgeError::NoTlsEdgeRouter`/`ChannelTls`/`Channel`/`DialRejected`/`ChannelClosed`/
    ///   `Crypto`/`UnsupportedCrypto` from channel open and dial.
    pub async fn connect_with_timeout(
        &self,
        service_name: &str,
        timeout: Duration,
    ) -> Result<ServiceConn, EdgeError> {
        self.connect_with_appdata(service_name, timeout, None).await
    }

    /// Connect to a service like [`EdgeClient::connect_with_timeout`], but additionally attach opaque
    /// `app_data` to the Connect (the `AppData` header, 1011). The router relays it verbatim and the
    /// HOST reads it on accept to drive a dynamic dial target (the tunneler's `forwardAddress`/
    /// `forwardPort` per the service's `host.v1` config). Build the bytes with
    /// [`crate::edge::dial::build_app_data`] (the tunneler `dst_*` JSON map). The production [`connect`]/
    /// [`connect_with_timeout`] pass `None` (no appData) — appData is purely opt-in via this seam, so the
    /// common dial path is byte-unchanged. Oracle: `DialOptions.AppData` (`ziti.go` `DialWithOptions` →
    /// `NewConnectMsg`, messages.go:304) threaded from the tunneler's `TunnelService` (`provider.go:103`).
    ///
    /// [`connect`]: EdgeClient::connect
    /// [`connect_with_timeout`]: EdgeClient::connect_with_timeout
    ///
    /// # Errors
    /// Same as [`EdgeClient::connect_with_timeout`].
    pub async fn connect_with_appdata(
        &self,
        service_name: &str,
        timeout: Duration,
        app_data: Option<&[u8]>,
    ) -> Result<ServiceConn, EdgeError> {
        // Pool slice: the connect path REUSES a pooled edge-router channel, or (on a miss) races all
        // `tls` routers (slice 10c failover) and pools the winner — unlike `bind`, which keeps its own
        // first-router `open_channel`. `connect_inner` is unchanged: it just gets the pool-aware opener
        // injected here, now returning a shared `Arc<EdgeChannel>`.
        //
        // OIDC-2 registration moved INTO `open_or_reuse_pooled_channel` (`pool_store_or_reuse_into`): a
        // channel is registered in the live-channel registry exactly when it is newly POOLED, never on
        // reuse — so a reused channel is not re-registered (no duplicate token pushes). With slice (B)'s
        // fan-out-and-pool-all, EVERY router that successfully dials is pooled (and thus registered once);
        // a router that fails or times out pools nothing and is not registered. Hence no
        // `register_live_channel` call here anymore.
        self.connect_inner(service_name, timeout, app_data, async |detail| {
            self.open_or_reuse_pooled_channel(detail).await
        })
        .await
    }

    /// `connect` with the channel-creation step injected, so tests can drive the full
    /// resolve → cache → dial → refresh → retry composition over fake routers (`open_channel`
    /// returning duplex-backed channels) without a live edge router. Production passes
    /// `self.open_channel`.
    ///
    /// `timeout` bounds the WHOLE flow (resolve → create[+backoff] → dial → refresh → retry) via an
    /// outer `tokio::time::timeout`, mirroring the oracle's context deadline applied at
    /// `ziti.go:1456` *before* `GetService`/`createSession`/`dialSession`. The same `timeout` is
    /// threaded into the session-creation backoff as its `MaxElapsedTime` (slice 10a; oracle :2015),
    /// so the two bounds share one value exactly as the oracle's ctx deadline (:1450) and
    /// `MaxElapsedTime` (:2015) do. The outer `timeout` is the hard wall-clock bound (it includes
    /// time spent inside each create/dial), which is what the backoff's `with_total_delay` — capping
    /// only summed sleep — could not bound on its own.
    // O5 (observability): a span scopes the whole connect flow so the O1/O3 client logs (crypto
    // downgrade warn, race-loser warns, crypto-established debug) inherit `service_name`. Renders
    // the oracle's `pfxlog.Logger().WithField(...)` scoped-logger pattern. `skip(self, open_channel)`
    // — neither is a useful/safe field; `service_name`/`timeout` are recorded. No secret in the args.
    // CONSCIOUS DEVIATION: the oracle's dial-path keys its logger on `sessionId` (ziti.go:1483,
    // :1665), not on the service name. We key on `service_name` because at span entry the session is
    // not yet minted (it's created inside the flow, and a refresh may mint a 2nd), so `service_name`
    // is the stable correlation key available here — and for an in-process SDK diagnostic it is the
    // more useful key than an opaque session id. (The oracle's `sessionId` is its cross-process join
    // key; recording it would mean threading `Span::current().record(...)` after resolution — a body
    // change to this purely-additive slice, deferred.) The session JWT is NEVER logged (vs oracle :1483).
    #[tracing::instrument(skip(self, open_channel), level = "debug")]
    pub(super) async fn connect_inner(
        &self,
        service_name: &str,
        timeout: Duration,
        app_data: Option<&[u8]>,
        open_channel: impl AsyncFn(&SessionDetail) -> Result<Arc<EdgeChannel>, EdgeError>,
    ) -> Result<ServiceConn, EdgeError> {
        let flow = async {
            // Resolve via the reauth-wrapped `list_services` (slice reauth-401): a 401 from listing
            // services (expired api-session) re-authenticates + retries once. `do_resolve_service`
            // takes the raw client+token, so wrap the resolve in `with_reauth_retry` here.
            let (service_id, encryption_required) = self
                .with_reauth_retry(async |token| {
                    do_resolve_service(self.http(), self.base_url(), &token, service_name).await
                })
                .await?;
            let (conn, channel) = dial_with_refresh_retry(
                async || self.get_or_create_dial_session(&service_id, timeout).await,
                async |session: SessionDetail| {
                    // = the oracle's `dialSession`: get a (pooled or freshly-raced) channel + Connect
                    // over it. With the pool the channel is a SHARED `Arc<EdgeChannel>` — on a dial
                    // failure our local `channel` clone drops, but the pool keeps its own `Arc`, so the
                    // router channel STAYS pooled for reuse (faithful: the oracle pools the router conn
                    // at channel-open, independent of a per-service Connect outcome). The retry path
                    // (refresh → dial #2) calls `open_channel` again → a pool HIT reuses this same
                    // channel.
                    let channel = open_channel(&session).await?;
                    let conn = channel
                        .dial(
                            &session,
                            encryption_required,
                            self.identity_name(),
                            app_data,
                        )
                        .await?;
                    Ok::<_, EdgeError>((conn, channel))
                },
                // D2: `refresh_session` RETURNS the refreshed `SessionDetail` and re-caches it as a side
                // effect; the dial path DISCARDS the value with `.map(|_| ())` — exactly as the oracle
                // discards it here (`ziti.go:1490`, `_, refreshErr = context.refreshSession(session)`).
                // The side effect happens only on the ALIVE branch; D3 short-circuits `invalid session`
                // BEFORE calling this, so that route never re-caches. Control flow of D1/D3 is UNCHANGED.
                //
                // ⚠ That side effect is NO LONGER the oracle's `cacheSession("refresh")` (2026-07-11):
                // the oracle's is a BLIND `Upsert` that inserts even into an absent key
                // (`ziti.go:2129-2132`); ours is a GUARDED update through
                // `recache_refreshed_dial_session` — it lands only if the key still holds the same
                // `session.id` the probe started from (DV-R1, CN-1/CN-2). That deliberate divergence is
                // precisely what stops this retry's own `evict()` below from being undone.
                async |session: SessionDetail| self.refresh_session(&session).await.map(|_| ()),
                || self.evict_dial_session(&service_id),
            )
            .await?;
            Ok::<_, EdgeError>(ServiceConn::from_parts(conn, channel))
        };
        // On expiry `flow` is dropped (cancel-safe: any partial `EdgeChannel` is torn down by its
        // `Drop`; no `std::sync::Mutex` guard ever crosses an await — only those can poison, and the
        // cache/waiter/conn maps are locked for synchronous ops only — so a mid-flight drop can't
        // poison the cache).
        match tokio::time::timeout(timeout, flow).await {
            Ok(result) => result,
            Err(_elapsed) => Err(EdgeError::ConnectTimedOut {
                service: service_name.to_string(),
                timeout,
            }),
        }
    }
}
