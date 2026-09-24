//! Flujo de apertura de `EdgeClient`: `tls_addrs` (el conjunto de candidatos del dial),
//! `open_channel`/`open_channel_to` (bind, primer-router), `open_or_reuse_pooled_channel`
//! (pool + fan-out 4c) y la recuperación 4b (`recover_empty_edge_routers`).
//! (F6 tramo 6: movido verbatim del monolito de `edge/channel`.)

use std::sync::Arc;

use crate::channel::address::parse_tls_address;
use crate::edge::client::{EdgeClient, JWT_TOKEN_PREFIX};
use crate::edge::data::EdgeChannel;
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;
use crate::edge::router_filter::{EdgeRouterUrlFilter, is_edge_router_url_accepted};

use super::dial::dial_handshake;
use super::fanout::ROUTER_DIAL_TIMEOUT;
use super::{RouterOpenerCtx, fan_out_first_ok, open_and_pool_router, spawn_router_openers};

/// All `tls` edge-router addresses of a session that the client's [`EdgeRouterUrlFilter`] ACCEPTS, in
/// order: the dial's CANDIDATE SET, used for BOTH the pool scoring and the fan-out (`open_channel`, the
/// bind path, keeps its own first-accepted-router pick). Oracle: the `session.EdgeRouters` ×
/// `SupportedProtocols` walk in `getEdgeRouterConn` (`ziti.go:1689`), gated by `isEdgeRouterUrlAccepted`
/// (`ziti.go:1710`), and restricted to the `tls` protocol (the only transport we open today — DV-4c-2,
/// preexisting).
///
/// **NOT a divergence (checked, was DV-4c-6): filtering the SCORING set too is behaviorally identical.**
/// The oracle consults the filter only on the unconnected fan-out (`:1710`) — its scoring loop
/// (`:1689-1701`) reads the pool unfiltered — but its pool **cannot contain a rejected URL in the first
/// place**: the `Upsert` that fills it (`ziti.go:1874`) is reachable ONLY through `connectEdgeRouter`
/// (`:1746`) ← `handleConnectEdgeRouter` (`:1736`), and its FOUR callers (`:858`, `:1241`, `:1711`,
/// `:2545`) are ALL gated by `isEdgeRouterUrlAccepted` (`:845`, `:1237`, `:1710`, `:2529`). Ours likewise:
/// the only paths that pool are the dial fan-outs, both fed by this filtered set. So we are **not more
/// restrictive: we are identical** — the sets coincide. The one construction that could tell them apart
/// (installing a filter AFTER channels are pooled) is unreachable upstream (`context.options` is fixed at
/// construction) and, on our setter, would leave us strictly under-permit — never over-permit.
pub(super) fn tls_addrs(
    detail: &SessionDetail,
    filter: Option<&EdgeRouterUrlFilter>,
) -> Vec<String> {
    detail
        .edge_routers
        .iter()
        .filter_map(|er| er.supported_protocols.get("tls"))
        .filter(|url| is_edge_router_url_accepted(filter, url))
        .cloned()
        .collect()
}

impl EdgeClient {
    /// Open the V2 binary channel to ONE specific edge router (`tls_url`): TCP + mTLS + Hello/Result.
    /// The per-router body shared by `open_channel` (first-router, bind path) and the connect race.
    /// Requires a prior `authenticate()` (the Hello carries the api-session token in header 1002).
    /// Oracle: sdk-golang `ziti.go` `connectEdgeRouter`.
    ///
    /// # Errors
    /// - `EdgeError::NotAuthenticated` if there is no api-session token.
    /// - `EdgeError::Channel` on address-parse failure or a rejected channel handshake.
    /// - `EdgeError::ChannelTls` on TLS failure (config / TCP connect / TLS handshake).
    pub(crate) async fn open_channel_to(&self, tls_url: &str) -> Result<EdgeChannel, EdgeError> {
        let token = self.token().ok_or(EdgeError::NotAuthenticated)?;
        let (host, port) = parse_tls_address(tls_url)?;
        // The channel's mTLS config + leaf CN come from the single `channel_client_config` seam:
        // cert-identities get today's `client_config(config)` (byte-identical); a `updb` client gets an
        // ENSURE-FRESH path that re-mints the session-cert on expiry (reusing the key) — a conscious
        // improvement beyond the oracle. The actual dial (TCP+mTLS+Hello, the connectTime seed, the
        // tls-open count) is the shared `dial_handshake`, which the connect fan-out also uses.
        let (cc, cn) = self.channel_client_config().await?;
        dial_handshake(
            &host,
            port,
            Arc::new(cc),
            &cn,
            &token,
            &self.tls_opens_handle(),
        )
        .await
    }

    /// Abre el canal binario V2 al primer edge router con protocolo `tls` **que el
    /// [`EdgeRouterUrlFilter`] acepte**. Requiere `authenticate()` previo (el Hello lleva el token de
    /// api-session en el header 1002). Lo usa `bind` (camino del host = `listenerManager`, no
    /// `getEdgeRouterConn`): mantiene la selección primer-router y NO pasa por el pool (desviación
    /// consciente: el oráculo comparte el pool entre dial y bind). El camino de connect usa
    /// `open_or_reuse_pooled_channel` (pool + race). Oráculo: `connectEdgeRouter` (`ziti.go:1746`), y el
    /// filtro es el `if !isEdgeRouterUrlAccepted(routerUrl) { continue }` con que `makeMoreListeners`
    /// SALTA una url no usable antes de conectar (`ziti.go:2528-2533`) — un router rechazado se salta,
    /// no aborta la búsqueda, de ahí el `filter` DENTRO del `find_map`.
    ///
    /// # Errors
    /// - `EdgeError::NotAuthenticated` si no hay token de api-session.
    /// - `EdgeError::NoTlsEdgeRouter` si el `SessionDetail` no trae router `tls` aceptado por el filtro.
    /// - `EdgeError::Channel` en fallo de parseo de address o rechazo del handshake del canal.
    /// - `EdgeError::ChannelTls` en fallo de TLS (config / TCP connect / TLS handshake).
    pub async fn open_channel(&self, detail: &SessionDetail) -> Result<EdgeChannel, EdgeError> {
        let filter = self.edge_router_url_filter();
        let tls_url = detail
            .edge_routers
            .iter()
            .filter_map(|er| er.supported_protocols.get("tls"))
            .find(|url| is_edge_router_url_accepted(filter, url))
            .ok_or(EdgeError::NoTlsEdgeRouter)?;
        self.open_channel_to(tls_url).await
    }

    /// The connect path's pool-aware channel opener — the full oracle `getEdgeRouterConn`
    /// (`ziti.go:1664-1733`). Returns a shared `Arc<EdgeChannel>` so the channel outlives the individual
    /// `ServiceConn` (many service dials multiplex over the one pooled channel). `bind` keeps
    /// `open_channel` (its own first-router channel, not pooled — conscious deviation).
    ///
    /// The two phases are NOT mutually exclusive — the oracle's fan-out over the UNCONNECTED routers runs
    /// **unconditionally and BEFORE** the cache-hit return (`ziti.go:1708-1714` ≺ `:1716`):
    ///
    /// - **Scoring (both paths):** among the session's routers that ALREADY have an alive pooled channel,
    ///   pick the LOWEST-mean-latency one (`pool_get_alive`, `ziti.go:1689-1701`). If there is one, it is
    ///   returned — but only AFTER the fan-out below has been kicked off.
    /// - **Fan-out over the UNCONNECTED routers (always, hit or miss):** every session router with NO alive
    ///   pooled channel is dialed, and EVERY success is pooled (not just a race winner) — the oracle's `go
    ///   handleConnectEdgeRouter` per unconnected router (`:1708-1714`), each running `connectEdgeRouter` +
    ///   `Upsert` (`:1746`, `:1874`) regardless of who won. The two paths differ ONLY in who waits:
    ///   - **on a MISS** there is nothing to reuse, so we WAIT for the first handshake to win the race and
    ///     return it ([`fan_out_first_ok`] — the oracle's `select` on `ch`, `:1722-1731`);
    ///   - **on a HIT** we return the scored channel IMMEDIATELY and the openers run FIRE-AND-FORGET
    ///     ([`spawn_router_openers`] — the oracle's nil `ch` + `if ret != nil` discard, `:1703-1706`,
    ///     `:1738`). Without this, a router could NEVER be pooled while any other router of the session
    ///     stays alive (a second session sharing one router; a channel that died and was evicted) ⇒ a
    ///     permanent degradation to a single router: no failover redundancy, no scoring candidates.
    ///
    ///   The per-client mTLS config + CN + token are computed ONCE (`channel_client_config`, the per-`updb`
    ///   ensure-fresh seam) and shared by the detached `'static` opener tasks ([`open_and_pool_router`]),
    ///   which run to completion (pooling themselves) after this returns.
    ///
    /// - **Empty edge-routers — refresh-and-continue (slice 4b):** a cached session that carries ZERO
    ///   edge-routers is REFRESHED before we give up, and the FRESH routers are dialed
    ///   (`ziti.go:1667-1683`). See [`Self::recover_empty_edge_routers`].
    ///
    /// # Errors
    /// - `EdgeError::NoTlsEdgeRouter` if the session has no `tls` edge router (and, for a router-less
    ///   session, the refresh yielded none either).
    /// - the refresh's own error (`SessionHttp`/`SessionResponse`) if the session had no edge-routers and
    ///   the refresh failed.
    /// - the last router error if every open fails (see [`fan_out_first_ok`]); `NotAuthenticated` if there
    ///   is no api-session token; `Channel`/`ChannelTls` from the dial.
    pub(crate) async fn open_or_reuse_pooled_channel(
        &self,
        detail: &SessionDetail,
    ) -> Result<Arc<EdgeChannel>, EdgeError> {
        // The oracle's empty-edge-routers guard (`ziti.go:1667-1683`), which runs BEFORE the scoring/
        // fan-out. It reassigns only its LOCAL `session` (`:1681`) — `dialSession` keeps dialing with the
        // ORIGINAL session pointer (`:1594`) — so the recovery is self-contained here: no signature
        // change, no refreshed session propagated to the caller's `Connect`.
        let refreshed = if detail.edge_routers.is_empty() {
            Some(self.recover_empty_edge_routers(detail).await?)
        } else {
            None
        };
        let detail = refreshed.as_ref().unwrap_or(detail);

        let addrs = tls_addrs(detail, self.edge_router_url_filter());
        if addrs.is_empty() {
            return Err(EdgeError::NoTlsEdgeRouter);
        }
        // Pool HIT: reuse the LOWEST-mean-latency alive pooled channel among the session's routers
        // (lazy-evicting any dead session-router entries on the way). Oracle Phase-1, ziti.go:1689-1701.
        if let Some(channel) = self.pool_get_alive(&addrs) {
            // ...but FIRST kick off the fan-out over the routers of this session that have NO alive pooled
            // channel — the oracle runs it UNCONDITIONALLY and BEFORE the hit-return (`:1708-1714` ≺
            // `:1716`), fire-and-forget (nil `ch`). Fire-and-forget here too: the hit returns immediately.
            self.spawn_unconnected_router_openers(&addrs).await;
            return Ok(channel);
        }
        // Pool MISS — Phase-2: compute the per-client config ONCE (the oracle's `GetIdentity` is the same
        // identity for every router), then fan out to ALL routers and pool every success. The opener tasks
        // are `'static` (they own `Arc` clones via `RouterOpenerCtx`), so the losers keep running and pool
        // themselves after the winner returns — the oracle's `go handleConnectEdgeRouter` + `Upsert`.
        // `cc`/`cn` computed ONCE: faithful — the oracle's `GetIdentity` (ziti.go:1781) returns the same
        // identity for every router. `token` is read ONCE too: a conscious BENIGN deviation (the oracle
        // reads the api-session token per-goroutine, ziti.go:1771) — the `Arc<RwLock>` token could be read
        // per-router, but a single connect's fan-out completes well within a token's lifetime.
        let token = self.token().ok_or(EdgeError::NotAuthenticated)?;
        let (cc, cn) = self.channel_client_config().await?;
        let ctx = RouterOpenerCtx {
            cc: Arc::new(cc),
            cn,
            token,
            channel_pool: self.channel_pool_handle(),
            live_channels: self.live_channels_handle(),
            tls_opens: self.tls_opens_handle(),
        };
        fan_out_first_ok(
            addrs,
            move |addr| {
                let ctx = ctx.clone();
                async move { open_and_pool_router(ctx, addr).await }
            },
            ROUTER_DIAL_TIMEOUT,
        )
        .await
    }

    /// The CACHE-HIT half of the oracle's fan-out (`ziti.go:1708-1714` with a **nil `ch`**): re-open, in the
    /// BACKGROUND, every router of this session that has no alive pooled channel, then return at once. The
    /// oracle spawns these goroutines on EVERY dial — hit included, and with no dedup of in-flight dials at
    /// this layer (its only such dedup, `mgr.connects`, is in `makeMoreListeners`, `:2535`) — so a repeat
    /// dial to a session with a down router keeps retrying it, exactly as here.
    ///
    /// Never fails the dial: this runs AFTER a channel has already been chosen, so anything that goes wrong
    /// while PREPARING the openers (no api-session token; a `channel_client_config` that cannot build — e.g.
    /// an `updb` re-mint whose controller is unreachable) only skips the background fan-out and logs. Upstream
    /// behaves the same: its `GetIdentity` failure lives INSIDE the goroutine (`:1781`), it can only fail
    /// that router's connect, never the hit.
    ///
    /// **Cost on the steady-state hit is ZERO:** when every session router is already pooled and alive (the
    /// common case, and always the case for a single-router service) `pool_unconnected` is empty and we
    /// return before touching the token or the TLS config. The dials themselves NEVER run in the foreground
    /// (the oracle builds its identity inside the goroutine too) — DV: we build the shared `(cc, cn)` in the
    /// foreground when there IS something to open, which the MISS path already did; it is bounded by the same
    /// outer connect-timeout, and it is the price of computing the config ONCE for all the openers.
    async fn spawn_unconnected_router_openers(&self, addrs: &[String]) {
        let unconnected = self.pool_unconnected(addrs);
        if unconnected.is_empty() {
            return; // every router of the session is pooled and alive — the oracle's empty `unconnected`
        }
        let Some(token) = self.token() else {
            tracing::debug!("no api-session token: skipping the background edge-router fan-out");
            return;
        };
        let (cc, cn) = match self.channel_client_config().await {
            Ok(parts) => parts,
            Err(e) => {
                tracing::warn!(error = %e, "skipping the background edge-router fan-out: no channel config");
                return;
            }
        };
        let ctx = RouterOpenerCtx {
            cc: Arc::new(cc),
            cn,
            token,
            channel_pool: self.channel_pool_handle(),
            live_channels: self.live_channels_handle(),
            tls_opens: self.tls_opens_handle(),
        };
        spawn_router_openers(
            unconnected,
            move |addr| {
                let ctx = ctx.clone();
                async move { open_and_pool_router(ctx, addr).await }
            },
            ROUTER_DIAL_TIMEOUT,
        );
    }

    /// The oracle's `getEdgeRouterConn` recovery for a session carrying **ZERO edge-routers**
    /// (`ziti.go:1667-1683`) — reachable whenever the controller minted the session while no edge router
    /// was online (a rebooting router), which a HIT then serves from cache forever. Before this slice we
    /// gave up on the spot with `NoTlsEdgeRouter`: an **UNDER-PERMIT** (a `connect()` the oracle completes).
    /// Returns the REFRESHED session whose routers the caller must dial. Three arms, all the oracle's:
    ///
    /// - **refresh 404 on the OPAQUE branch** (`:1668-1673`): the controller says the session is GONE ⇒
    ///   evict the cached Dial session (`sessions.Remove("{serviceId}:{type}")`, `:1671-1672` — our cache
    ///   is Dial-only and keyed by `service_id`, the same key `get_or_create_dial_session` writes) and give
    ///   up (`:1675`). We do NOT recreate/retry here: that is the outer caller's job in the oracle too
    ///   (`:1495-1502`), and ours does it in `dial_with_refresh_retry` (D3/DV-C3).
    /// - **refresh fails otherwise** (transport, 5xx, 401 — or ANY error on the JWT branch, see DV-4b-4
    ///   below): give up WITHOUT evicting. The oracle's eviction is narrow —
    ///   `errors.As(&rest_session.DetailSessionNotFound{})` (`:1669-1670`) — because a blip is no proof of
    ///   death.
    /// - **refresh OK** (`:1676-1682`): if it yielded routers, CONTINUE with them (`:1681`); if it yielded
    ///   none, give up (`:1677-1678`) and — again — do NOT evict: the session is ALIVE.
    ///
    /// **DV-4b-4 (the eviction is gated on the OPAQUE branch, not just on the status code).**
    /// `refresh_session` splits on the token prefix exactly like the oracle's `refreshSession`
    /// (`ziti.go:2106-2110`): an OPAQUE token probes `GET /sessions/{id}` (`GetSession` →
    /// `DetailSession`, `ziti/client.go:237-248`), whose 404 IS `*rest_session.DetailSessionNotFound` and
    /// therefore the ONLY error the oracle's `errors.As` can match (`rest_util.WrapErr` keeps the source
    /// reachable via `Unwrap()`, edge-api `rest_util/errors.go:27-49`). A JWT token instead probes
    /// `GET /services/{id}/edge-routers` (`GetSessionFromJwt` → `ListServiceEdgeRouters`,
    /// `ziti/client.go:250-268`), whose 404 is a `ListServiceEdgeRoutersNotFound` — "service not found /
    /// not visible", NEVER a `DetailSessionNotFound` — so **the oracle can never evict on the JWT
    /// branch**. We reproduce that by requiring the token to be opaque as well as the status to be 404.
    /// Recovery is not lost: `dial_with_refresh_retry` (D3/DV-C3) evicts on ANY probe error one layer out.
    ///
    /// **Authorization is untouched** (no over-permit): the refresh only asks the controller to re-state
    /// the routers of a session it ALREADY granted, an eviction can only cause a cache MISS (⇒ a fresh
    /// `POST /sessions`, where the controller decides), and the refresh writes through the
    /// `recache_refreshed_dial_session` write gate, which can never CREATE a key (so it can never turn a
    /// MISS into a HIT). DV-4b-1: we propagate the refresh's TYPED error instead of the oracle's wrapping
    /// string (`:1675`); the flow is identical.
    async fn recover_empty_edge_routers(
        &self,
        detail: &SessionDetail,
    ) -> Result<SessionDetail, EdgeError> {
        tracing::debug!(
            service = %detail.service_id, session_id = %detail.id,
            "cached dial session has no edge routers, refreshing"
        );
        let refreshed = match self.refresh_session(detail).await {
            Ok(refreshed) => refreshed,
            Err(e) => {
                // ONLY a 404 from the OPAQUE probe proves the session is dead (the oracle's
                // `DetailSessionNotFound`, unreachable from the JWT branch — DV-4b-4 above).
                let is_opaque = !detail.token.starts_with(JWT_TOKEN_PREFIX);
                if is_opaque && matches!(e, EdgeError::SessionHttp { status: 404, .. }) {
                    self.evict_dial_session(&detail.service_id);
                }
                return Err(e);
            }
        };
        if refreshed.edge_routers.is_empty() {
            // Alive, but still router-less: give up WITHOUT evicting (`:1677-1678`).
            return Err(EdgeError::NoTlsEdgeRouter);
        }
        Ok(refreshed)
    }
}
