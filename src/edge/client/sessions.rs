use super::{
    EdgeClient, JWT_TOKEN_PREFIX, SESSION_BACKOFF_FACTOR, SESSION_BACKOFF_INITIAL,
    SESSION_BACKOFF_MAX_INTERVAL, apply_access_header, parse_error_envelope,
    recache_refreshed_dial_session, refresh_session_probe,
};
use std::time::Duration;

use backon::{ExponentialBuilder, Retryable};

use crate::edge::auth_token::AuthToken;
use crate::edge::error::EdgeError;
use crate::edge::model::{
    Envelope, ServiceEdgeRouterList, SessionCreate, SessionDetail, SessionEdgeRouter, SessionType,
    sanitize_supported_protocols,
};

/// The production session-creation backoff policy (the oracle's `ExponentialBackOff` settings).
/// `total` is the backoff's `MaxElapsedTime` = the caller's connect-timeout (oracle `ziti.go:2015`).
///
/// Jitter: the oracle keeps `RandomizationFactor=0.5` (jitter ON). We enable backon's jitter to
/// preserve the *presence* of randomization (load-spreading across concurrent dials), but the
/// distribution model differs — a conscious deviation: cenkalti randomizes SYMMETRICALLY in
/// `[delay×0.5, delay×1.5]`, whereas backon's jitter is POSITIVE-only (`[delay, delay×2.0)`). The
/// retry *count* and the min/max/total bounds match; only the per-attempt random offset shape
/// differs. See spec §5.
pub(crate) fn session_backoff(total: Duration) -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(SESSION_BACKOFF_INITIAL)
        .with_max_delay(SESSION_BACKOFF_MAX_INTERVAL)
        .with_factor(SESSION_BACKOFF_FACTOR)
        .with_total_delay(Some(total))
        .with_jitter()
        .without_max_times()
}

/// Whether a `create_session` error is transient (retry with backoff) vs permanent (fail fast).
///
/// Oracle: `createSessionWithBackoff` only declares `backoff.Permanent` when the service is gone from
/// the local services cache (`latestSvc == nil`, `ziti.go:2021`); cenkalti otherwise retries every
/// non-`Permanent` error until `MaxElapsedTime`. We have no local services cache / `refreshServices`
/// loop and resolve the service one layer up (`do_resolve_service` returns `ServiceNotFound` *before*
/// this path), so we classify by "could a later attempt plausibly succeed with no other state change":
/// - **transient (retry):** a transport failure (no verdict), any 5xx, **429** (rate-limited — the
///   canonical backoff trigger) and **408** (request timeout). The oracle backs off on these.
/// - **permanent (fail fast):** every other 4xx — 400/403 (won't change on retry), 404 (service gone;
///   already caught earlier), 401 (needs re-auth, a follow-up — see spec §Deviations). Retrying these
///   would just hammer the controller with no state change.
///
/// CONSCIOUS DEVIATION (spec §5): for 400/403/404/401 we fail fast where the oracle would keep retrying
/// (it relies on `refreshServices`/re-auth between attempts, which we lack); 401 re-auth is a follow-up.
pub(crate) fn is_retriable_create_error(err: &EdgeError) -> bool {
    match err {
        // Transport-level send/read failure (reqwest) — the request never got a verdict → retry.
        EdgeError::SessionResponse(_) => true,
        // 5xx (server-side) + 429 (rate-limit) + 408 (timeout) are transient; other 4xx are permanent.
        EdgeError::SessionHttp { status, .. } => *status >= 500 || *status == 429 || *status == 408,
        _ => false,
    }
}

/// POST a session-create (dial/bind) and return the parsed `SessionDetail`.
/// Sends the api-session auth header (`zt-session` for legacy, `Authorization: Bearer` for OIDC) via
/// [`apply_access_header`]; success is HTTP 2xx (201). Edge-router
/// `supportedProtocols` are rewritten (`://` -> `:`) like the SDK.
/// Oracle: ziti/client.go CreateSession + sanitizeSessionUrls.
pub async fn do_create_session(
    client: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
    service_id: &str,
    session_type: SessionType,
) -> Result<SessionDetail, EdgeError> {
    let url = format!("{base_url}/sessions");
    let body = serde_json::to_string(&SessionCreate {
        service_id: service_id.to_string(),
        session_type,
    })
    .map_err(|e| EdgeError::SessionResponse(format!("serialize request: {e}")))?;
    let resp = apply_access_header(client.post(&url), token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| EdgeError::SessionResponse(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| EdgeError::SessionResponse(e.to_string()))?;
    if !status.is_success() {
        let (code, message) = parse_error_envelope(&text);
        return Err(EdgeError::SessionHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }
    let env: Envelope<SessionDetail> = serde_json::from_str(&text)
        .map_err(|e| EdgeError::SessionResponse(format!("json: {e}")))?;
    let mut detail = env.data;
    for er in &mut detail.edge_routers {
        er.supported_protocols = sanitize_supported_protocols(&er.supported_protocols);
    }
    Ok(detail)
}

/// Liveness probe + edge-router refresh for a JWT Dial session:
/// `GET /services/{service_id}/edge-routers` with the api-session auth header (`zt-session` for
/// legacy, `Authorization: Bearer` for OIDC, via [`apply_access_header`]) and the per-service session
/// token (a JWT) in `session-token`. A 2xx returns the FRESH edge-router list (alive); a 4xx (404/401)
/// means the session expired or was revoked. We pass the already-resolved `service_id` directly instead
/// of parsing it from the JWT `sub` claim like the oracle (`GetSessionFromJwt`, ziti/client.go:250) —
/// the observable request is identical (`GET /services/{id}/edge-routers`, `session-token` header) and
/// it avoids a JWT-parsing dependency. Since D2 the refreshed list is RETURNED (the caller re-caches
/// it) rather than discarded, mirroring the oracle's `refreshSession` re-cache (`ziti.go:2116`). Each
/// router's `supportedProtocols` is sanitized (`://` → `:`) exactly like `do_create_session` / the
/// oracle's `sanitizeSessionUrls` (`ziti/client.go:530`).
/// Oracle wire: edge-api `ListServiceEdgeRouters` (`service_client.go:205`,
/// `list_service_edge_routers_parameters.go:244,285`).
///
/// # Errors
/// - `EdgeError::SessionResponse` on transport failure or an unparseable body.
/// - `EdgeError::SessionHttp` on a non-2xx status (this is how an expired session surfaces).
pub async fn do_get_service_edge_routers(
    client: &reqwest::Client,
    base_url: &str,
    api_token: &AuthToken,
    service_id: &str,
    session_token: &str,
) -> Result<Vec<SessionEdgeRouter>, EdgeError> {
    let url = format!("{base_url}/services/{service_id}/edge-routers");
    let resp = apply_access_header(client.get(&url), api_token)
        .header("session-token", session_token)
        .send()
        .await
        // Reuses `SessionResponse` (no new error variant, per spec §5); the detail names the
        // operation since the variant's text is create-session flavored.
        .map_err(|e| EdgeError::SessionResponse(format!("session liveness probe: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| EdgeError::SessionResponse(format!("session liveness probe: {e}")))?;
    if !status.is_success() {
        let (code, message) = parse_error_envelope(&text);
        return Err(EdgeError::SessionHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }
    let env: Envelope<ServiceEdgeRouterList> = serde_json::from_str(&text)
        .map_err(|e| EdgeError::SessionResponse(format!("json: {e}")))?;
    let mut edge_routers = env.data.edge_routers;
    for er in &mut edge_routers {
        er.supported_protocols = sanitize_supported_protocols(&er.supported_protocols);
    }
    Ok(edge_routers)
}

/// Liveness probe + refresh for an OPAQUE/legacy Dial session: `GET {base_url}/sessions/{session_id}`
/// (DetailSession), authorized by the api-session header alone (`apply_access_header`) — no
/// `session-token` header (the session id in the path IS the lookup key). This is STATEFUL: the
/// controller returns 2xx with the refreshed [`SessionDetail`] while the session exists and 404 once it
/// is deleted/revoked, which is what lets `dial_with_refresh_retry` detect a dead opaque session and
/// recover. Since D2 the 2xx body is RETURNED (the caller re-caches it), mirroring the oracle's
/// `refreshSession` re-cache (`ziti.go:2116`); non-2xx ⇒ `Err(EdgeError::SessionHttp{…})` (reuses
/// `SessionResponse`/`SessionHttp`, no new error variant). Mirror of `CtrlClient.GetSession` →
/// `DetailSession` (`ziti/client.go:237-248`; `GET /sessions/{id}`), including the per-router
/// `supportedProtocols` sanitize (`://` → `:`, the oracle's `sanitizeSessionUrls`, `ziti/client.go:530`).
///
/// # Errors
/// - `EdgeError::SessionResponse` on transport failure or an unparseable body.
/// - `EdgeError::SessionHttp` on a non-2xx status (this is how an expired/revoked session surfaces).
pub async fn do_get_session_detail(
    client: &reqwest::Client,
    base_url: &str,
    api_token: &AuthToken,
    session_id: &str,
) -> Result<SessionDetail, EdgeError> {
    let url = format!("{base_url}/sessions/{session_id}");
    let resp = apply_access_header(client.get(&url), api_token)
        .send()
        .await
        .map_err(|e| EdgeError::SessionResponse(format!("session detail probe: {e}")))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| EdgeError::SessionResponse(format!("session detail probe: {e}")))?;
    if !status.is_success() {
        let (code, message) = parse_error_envelope(&text);
        return Err(EdgeError::SessionHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }
    let env: Envelope<SessionDetail> = serde_json::from_str(&text)
        .map_err(|e| EdgeError::SessionResponse(format!("json: {e}")))?;
    let mut detail = env.data;
    for er in &mut detail.edge_routers {
        er.supported_protocols = sanitize_supported_protocols(&er.supported_protocols);
    }
    Ok(detail)
}

impl EdgeClient {
    /// Create a session (dial/bind) for a service. Requires a prior `authenticate()`.
    /// A 401 (expired api-session) triggers a reactive re-auth + retry-once (slice reauth-401);
    /// this is the unit `create_session_with_policy` retries, so the slice-10a backoff sees a
    /// reauth-retried create (a transient 5xx after a successful re-auth is still backed off).
    /// Oracle: ziti/client.go CreateSession + `createSession` on-401 (`ziti.go:2065-2099`).
    pub async fn create_session(
        &self,
        service_id: &str,
        session_type: SessionType,
    ) -> Result<SessionDetail, EdgeError> {
        self.with_reauth_retry(async |token| {
            do_create_session(&self.http, &self.base_url, &token, service_id, session_type).await
        })
        .await
    }

    /// The cached Dial session for `service_id`, if any. Oracle: `getOrCreateSession` cache hit.
    pub(crate) fn cached_dial_session(&self, service_id: &str) -> Option<SessionDetail> {
        self.dial_sessions
            .lock()
            .expect("dial-session cache mutex poisoned")
            .get(service_id)
            .cloned()
    }

    /// Store a Dial session in the cache. Oracle: `cacheSession("create", ...)` (Dial only).
    ///
    /// This is the **`"create"` provenance** and it stays a BLIND insert (C6): a freshly minted session
    /// is the AUTHORITATIVE write — the controller just granted it and there is no snapshot to compare
    /// against. Writes of **`"refresh"` provenance** do NOT come through here any more: they go through
    /// [`recache_refreshed_dial_session`], which only updates a key still held by the same `session.id`.
    /// That is exactly the `"create"` vs `"refresh"` split the oracle's own `cacheSession` makes
    /// (`ziti.go:2124-2137`) — we merely make the `"refresh"` half safe (DV-R1).
    ///
    /// P5 (observability, opción 3 del MENÚ): the raw store is `trace!`-logged AFTER the lock guard
    /// (a statement temporary) has already dropped — never with the mutex held, and never awaited
    /// (`tracing::event!` is synchronous). Beyond-oracle (`cacheSession` calls, `ziti.go:2120-2139`).
    /// `trace!`, not `debug!`: the adjacent decision events (P4 "successfully created session" / P6
    /// "re-cached refreshed dial session") already carry the create-vs-refresh discriminator the
    /// oracle's `op` parameter would (DV-O4). JAMÁS el token: solo `session_id`.
    pub(crate) fn cache_dial_session(&self, service_id: &str, session: SessionDetail) {
        let session_id = session.id.clone();
        self.dial_sessions
            .lock()
            .expect("dial-session cache mutex poisoned")
            .insert(service_id.to_string(), session);
        tracing::trace!(service = %service_id, session_id = %session_id, "cached dial session");
    }

    /// Drop the cached Dial session for `service_id`. Oracle: `deleteServiceSessions` (we only ever
    /// cache Dial, so removing the Dial key is equivalent to the oracle removing both Dial + Bind).
    ///
    /// P7 (observability, opción 3 del MENÚ): logged AFTER the lock guard has dropped. Beyond-oracle
    /// (`deleteServiceSessions` calla, `ziti.go:2141-2144`). Único caller prod: la rama dead del
    /// dial (`edge/conn/retry.rs`), así que la frecuencia es bajísima y siempre relevante ⇒ `debug!`.
    pub(crate) fn evict_dial_session(&self, service_id: &str) {
        self.dial_sessions
            .lock()
            .expect("dial-session cache mutex poisoned")
            .remove(service_id);
        tracing::debug!(service = %service_id, "evicted cached dial session");
    }

    /// Create a Dial/Bind session for `service_id`, retrying transient failures with exponential
    /// backoff (oracle's `createSessionWithBackoff`, `ziti.go:2009`). Transport failures and 5xx are
    /// retried; 4xx (404/401) and everything else fail fast (see [`is_retriable_create_error`]).
    /// `total` is the backoff budget (`MaxElapsedTime`) = the connect-timeout (oracle `ziti.go:2015`,
    /// threaded down from `connect` since slice 10b).
    /// Scope 10a: backoff of transient failures + permanent-on-not-found; re-auth-on-401 and the
    /// "service id changed" re-resolve are follow-ups (they need the local services cache we lack).
    pub(crate) async fn create_session_with_backoff(
        &self,
        service_id: &str,
        session_type: SessionType,
        total: Duration,
    ) -> Result<SessionDetail, EdgeError> {
        self.create_session_with_policy(service_id, session_type, session_backoff(total))
            .await
    }

    /// `create_session_with_backoff` with the backoff policy injected, so tests drive the retry loop
    /// with tiny (sub-millisecond) intervals instead of the production 50ms..15s schedule. Mirrors
    /// the `connect_inner(open_channel)` seam used elsewhere in this crate.
    pub(crate) async fn create_session_with_policy(
        &self,
        service_id: &str,
        session_type: SessionType,
        policy: ExponentialBuilder,
    ) -> Result<SessionDetail, EdgeError> {
        // O4 (observability): log EACH failed create attempt at WARN, on the retried unit itself,
        // mirroring the oracle's `createSession` which `Warnf`s on every failure (`ziti.go:2071`,
        // inside `createSessionWithBackoff`'s retried `operation`). `inspect_err` is purely
        // additive — the `Result` handed to `backon`'s `.retry`/`.when` is unchanged, so the
        // retry behavior is identical. We use `inspect_err` (not `backon`'s `.notify`, which fires
        // only BEFORE a retry sleep) so the FINAL permanent (non-retriable) failure is logged too.
        // DEVIATION: the oracle logs the resolved `*service.Name`; we hold only the id here (the
        // name was resolved one layer up), so the field is the service id.
        //
        // P3/P4 (observability, opción 3 del MENÚ): port of the oracle's `createSession` per-attempt
        // logging (`ziti.go:2068` establishing, `:2099` success + elapsed ms) — the closure IS the
        // retried unit, so both fire once PER ATTEMPT, exactly like the oracle's `operation`. `start`
        // mirrors the oracle's `start := time.Now()` (`:2066`). `.inspect` is purely additive: the
        // `Result` handed to `.retry(...).when(...)` is unchanged, so the backoff behavior is
        // identical (same argument as the O4 comment above for `.inspect_err`).
        (|| async move {
            tracing::debug!(service = %service_id, ?session_type, "establishing session");
            let start = std::time::Instant::now();
            self.create_session(service_id, session_type)
                .await
                .inspect(|s| {
                    tracing::debug!(
                        service = %service_id,
                        ?session_type,
                        session_id = %s.id,
                        elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                        "successfully created session"
                    );
                })
                .inspect_err(|e| {
                    tracing::warn!(
                        service = %service_id,
                        ?session_type,
                        error = %e,
                        "failure creating session"
                    );
                })
        })
        .retry(policy)
        .when(is_retriable_create_error)
        .await
    }

    /// Get the cached Dial session for `service_id`, or create + cache a fresh one (with backoff) on
    /// a miss. Oracle: `getOrCreateSession(serviceId, Dial)` (`ziti.go:1986`) + the
    /// `createSessionWithBackoff` wrapping the create-on-miss in `DialContextWithOptions`
    /// (`ziti.go:1478`). `total` is the backoff budget (= the connect-timeout, oracle `:2015`). The
    /// create await happens OUTSIDE the cache lock (the guard never crosses an await). A benign race
    /// — two concurrent misses both create, last write wins — mirrors the oracle's non-atomic `cmap`.
    pub(crate) async fn get_or_create_dial_session(
        &self,
        service_id: &str,
        total: Duration,
    ) -> Result<SessionDetail, EdgeError> {
        // P1/P2 (observability, opción 3 del MENÚ): the hit/miss DECISION is logged at `debug!`,
        // beyond-oracle (`getOrCreateSession`'s hit/miss are silent, `ziti.go:1993-2006`). The
        // `session_id` field follows the oracle's own dial-path practice (`:1483`) minus the token
        // (DV-O1); the miss fires exactly once here, the per-attempt retry logs live one layer down
        // in `create_session_with_policy` (P3/P4).
        if let Some(session) = self.cached_dial_session(service_id) {
            tracing::debug!(service = %service_id, session_id = %session.id, "dial session cache hit");
            return Ok(session);
        }
        tracing::debug!(service = %service_id, "dial session cache miss, creating session");
        let session = self
            .create_session_with_backoff(service_id, SessionType::Dial, total)
            .await?;
        self.cache_dial_session(service_id, session.clone());
        Ok(session)
    }

    /// Probe whether a Dial session is still alive (the oracle's `refreshSession` liveness role,
    /// `ziti.go:2103`). `Ok(refreshed)` => the controller still recognizes the session, and the
    /// returned [`SessionDetail`] carries its **refreshed edge-routers**; `Err` => it expired/was
    /// revoked. Requires a prior `authenticate()`.
    ///
    /// On `Ok` the refreshed session is re-cached **through the write gate**
    /// ([`recache_refreshed_dial_session`]): it lands ONLY if `session.service_id` is still occupied by
    /// this same `session.id` — so a concurrent DV-C3 eviction is not undone (CN-1) and a NEWER session
    /// under that key is not clobbered (CN-2). The **returned value is unaffected** (C2): the gate rules
    /// the WRITE, not the liveness verdict, so `dial_with_refresh_retry` sees exactly the same `Ok`/`Err`
    /// as before. On `Err` nothing is written (the `?` propagates first), so the dial path still sees the
    /// stale entry and evicts it. The key is the one the entry was CACHED UNDER (`session.service_id`),
    /// never `refreshed.service_id` (CN-3; today identical, see the gate's docs).
    /// Oracle: `cacheSession("refresh")` (`ziti.go:2116`, reached only after the
    /// `if err != nil { return nil, err }` at `:2112-2114`) — but blind, which is the defect DV-R1
    /// diverges from deliberately.
    ///
    /// **No `SessionType::Dial` guard, by construction.** The oracle needs one (`ziti.go:2123`)
    /// because its cache is a MIXED `"{serviceId}:{type}"` map that `getOrCreateSession` writes for
    /// Bind sessions too (`:2005`). Ours (`dial_sessions`) holds **only Dial** sessions and is only
    /// ever reached from Dial-sourced paths, so the guard would be dead code. If you ever cache Bind
    /// sessions here, port `ziti.go:2123` first. (Adversarial review confirmed the literal deviation
    /// and refuted it 3/3 as unreachable.)
    pub(crate) async fn refresh_session(
        &self,
        session: &SessionDetail,
    ) -> Result<SessionDetail, EdgeError> {
        // NOT reauth-wrapped (spec §3.5): the oracle's `refreshSession` does not re-authenticate; a
        // 401 here means "session expired" → `dial_with_refresh_retry` evicts + recreates, and the
        // recreate goes through the reauth-wrapped `create_session`.
        let api_token = self.auth_token().ok_or(EdgeError::NotAuthenticated)?;
        // D1 (dial-sessions-race): branch by session-token prefix exactly like the oracle
        // (`refreshSession`, `ziti/ziti.go:2106`). A JWT-prefixed token probes `ListServiceEdgeRouters`
        // (stateless, bound to the api-session); an OPAQUE/legacy token probes `DetailSession`
        // (stateful `GET /sessions/{id}`) which is what surfaces a revoked/deleted session as `Err`.
        // The fetch + reconstruction lives in the free `Send` core `refresh_session_probe`, which the DIAL
        // path shares with `recover_empty_edge_routers` (4b). ⚠ NOT with the session-refresh timer: since
        // 4a the tick runs `refresh_session_probe_durable`, whose branch is the API-SESSION type (DV-4a-3).
        let branch = if session.token.starts_with(JWT_TOKEN_PREFIX) {
            "jwt"
        } else {
            "opaque"
        };
        let outcome = refresh_session_probe(&self.http, &self.base_url, &api_token, session).await;
        // The branch taken + the probe RESULT (alive/dead) are logged so the liveness decision is
        // observable live. NEVER the token (a credential); an `EdgeError` carries only the
        // controller's status/code/message envelope, never the token.
        match &outcome {
            Ok(_) => tracing::debug!(
                session_id = %session.id, probe = branch, result = "alive",
                "refresh session liveness probe"
            ),
            Err(e) => tracing::debug!(
                session_id = %session.id, probe = branch, result = "dead", error = %e,
                "refresh session liveness probe"
            ),
        }
        // (A) RE-CACHE on success — the oracle's `cacheSession("refresh")` (`ziti.go:2116`), reached
        // ONLY on the alive branch (`if err != nil { return nil, err }` runs FIRST, `:2112-2114`). On
        // error we do NOT re-cache: the `?` propagates before the write, so the cached session is left
        // untouched (the dial path then evicts + recreates).
        //
        // The net effect is NOT the oracle's `sessions.Set(serviceID:Dial, refreshed)` any more: it is a
        // GUARDED UPDATE (DV-R1, beyond-oracle, owner-authorised — spec §4). The probe above is an
        // `.await`, and DV-C3's eviction (or a newer session from the retry's `get_or_create`) can land
        // inside `[snapshot, write]`; a blind `Set` would RESURRECT the corpse we just evicted or CLOBBER
        // the newer session with this stale one. The oracle's `Upsert` callback returns `newValue`
        // unconditionally (`ziti.go:2129-2132`) and so suffers both. `refresh_session`'s RETURN VALUE is
        // unchanged (C2) — only the write is gated — and the key is the SNAPSHOT's (`session.service_id`,
        // CN-3), never `refreshed.service_id`. P5/P6 are emitted by the gate itself.
        let refreshed = outcome?;
        recache_refreshed_dial_session(
            &self.dial_sessions,
            &session.service_id,
            &session.id,
            refreshed.clone(),
        );
        Ok(refreshed)
    }
}
