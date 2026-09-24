use super::JWT_TOKEN_PREFIX;
use super::do_get_service_edge_routers;
use super::sessions::do_get_session_detail;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::edge::auth_token::{ApiSessionType, AuthToken};
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;

/// The free (`Send`) core of session refresh on the **DIAL path**: the D1 liveness branch PLUS the
/// reconstruction of the refreshed [`SessionDetail`]. Does NOT re-cache (the caller decides). Free (not
/// a method) so a caller without `&self` can use it. Mirrors the oracle's `refreshSession` fetch
/// (`ziti/ziti.go:2106-2110`): a JWT token reconstructs from `ListServiceEdgeRouters`, an opaque token
/// from `DetailSession`.
///
/// # Callers (⚠ NOT the tick — since 4a)
/// [`super::EdgeClient::refresh_session`] (the dial path, D2) and `recover_empty_edge_routers` (4b). The
/// background session-refresh timer ([`crate::edge::session_refresh`]) used to share this probe but no
/// longer does: it runs [`refresh_session_probe_durable`], which branches on the **API-SESSION type**
/// instead of the token prefix (DV-4a-3). Keep the two apart — 4b's DV-4b-4 rests on the token prefix.
///
/// JWT branch (DV-A2): reuses the passed `session` for every field EXCEPT `edge_routers`, replaced by
/// the fresh list. The oracle rebuilds the whole `SessionDetail` from the JWT `ServiceAccessClaims`
/// (`ziti/client.go:272-289`), but those claim fields (ID / ApiSessionId / IdentityId / ServiceID /
/// Token / Type) all derive from the SAME token we already hold, so they equal the cached session's —
/// only `EdgeRouters` genuinely refreshes. Reusing `session` is observably equivalent and avoids
/// parsing an unverified JWT.
///
/// # Errors
/// The probe's error (a non-2xx surfaces as [`EdgeError::SessionHttp`]; transport / bad body as
/// [`EdgeError::SessionResponse`]).
pub(crate) async fn refresh_session_probe(
    http: &reqwest::Client,
    base_url: &str,
    api_token: &AuthToken,
    session: &SessionDetail,
) -> Result<SessionDetail, EdgeError> {
    if session.token.starts_with(JWT_TOKEN_PREFIX) {
        let fresh_edge_routers = do_get_service_edge_routers(
            http,
            base_url,
            api_token,
            &session.service_id,
            &session.token,
        )
        .await?;
        Ok(SessionDetail {
            edge_routers: fresh_edge_routers,
            ..session.clone()
        })
    } else {
        // ⚠ MINE (DV-4a-2), deliberately left UNARMED here — do NOT wire this branch to a live path
        // without re-deriving it. This adopts the detail body WHOLESALE, `token` included, and the body's
        // `token` is the **cuid** the controller stored, never the JWT it handed us
        // (`ziti@9bf62f3 controller/internal/routes/session_api_model.go:58-59` — `Token: id`, with the
        // comment *"token is redundant now as these are encoded as JWTs, filled for existing subsystem
        // compatibility"* — echoed back at `:128`). Adopting it would REPLACE the cached JWT with the cuid,
        // and the dial path resolves the session token by JWT-PARSING it, in BOTH régimes
        // (`controller/handler_edge_ctrl/common.go:317` legacy, `:247` OIDC, both → `ValidateServiceAccessToken`
        // → `jwt.ParseWithClaims`, `controller/env/appenv.go:254`); `SessionManager.ReadByToken`
        // (`controller/model/session_manager.go:336`) has NO caller on that path. A cuid does not parse ⇒ the
        // dial would be rejected.
        // It is UNREACHABLE against a `ziti` v2 controller by the very thesis of 4a: `POST /sessions`
        // ALWAYS mints a JWT session token (`session_router.go:191`,`:214`), so `session.token` never
        // fails the `ey` prefix test and this `else` is dead code there. [`refresh_session_probe_durable`]
        // (the tick's probe) takes ONLY `edge_routers` from the body for exactly this reason.
        do_get_session_detail(http, base_url, api_token, &session.id).await
    }
}

/// The TICK's liveness probe (4a) — the one that can PROVE a session dead. Same shape as
/// [`refresh_session_probe`], but the branch is chosen by the **API-SESSION type**, not by the session
/// token's prefix (**DV-4a-3**, beyond-oracle, owner-authorised; spec
/// `docs/superpowers/specs/2026-07-11-4a-purge-and-eviction-key-design.md`).
///
/// # Why the discriminant differs from the oracle's
/// The oracle branches on `strings.HasPrefix(*session.Token, JwtTokenPrefix)` (`ziti/ziti.go:2106`).
/// Against a `ziti` v2 controller that test is **dead code**: `POST /sessions` returns a **JWT** session
/// token ALWAYS (`controller/internal/routes/session_router.go:191`,`:214`) — but it only **PERSISTS** the
/// session when the **api-session** is legacy (`:220-226`, gated by `HasLegacySecurityToken()`,
/// `controller/response/context.go:79-84`). So the durability of a session — the only thing that decides
/// whether `GET /sessions/{id}` can answer 404 for a DELETED session — is a property of the API-SESSION,
/// never of the session token. Branching on the token prefix leaves the tick BLIND to deletions (the
/// stateless probe never reads the session store, `controller/internal/routes/service_router.go:406-450`,
/// and deleting a session writes no Revocation, `controller/model/session_manager.go:365-378`).
///
/// - **Legacy api-session ⇒ DURABLE branch**: `GET /sessions/{id}` ([`do_get_session_detail`]).
///   A **404 is PROOF OF DEATH** (the store says NotFound) ⇒ the tick purges (see [`is_proven_dead`]).
/// - **OIDC api-session ⇒ STATELESS branch** (unchanged): `GET /services/{id}/edge-routers`. Probing the
///   detail here would be a REGRESSION — the session was never stored, so a LIVE one would 404 (exactly
///   the hazard `ziti/client.go:236` warns about). This branch refreshes the edge-routers and **nothing
///   else**: NO error of it proves the session dead ([`is_proven_dead`] ⇒ `false` in this régime), so the
///   tick NEVER purges under OIDC.
///
/// # ⚠ DV-4a-2 (security, load-bearing): only `edge_routers` is taken from the durable body
/// The detail's `token` field is the **cuid** the controller stored, NOT the JWT it handed us
/// (`controller/internal/routes/session_api_model.go:58-59` — `Token: id`, *"token is redundant now as
/// these are encoded as JWTs, filled for existing subsystem compatibility"* — echoed at `:128`). Adopting
/// the body wholesale would replace the cached JWT with the cuid, and the wire `Connect` carries ONLY the
/// session token (`build_connect`, `edge/data/channel.rs`). The controller resolves that token by **JWT-parsing it**,
/// in BOTH régimes (`controller/handler_edge_ctrl/common.go:317` legacy / `:247` OIDC → `ValidateServiceAccessToken`
/// → `jwt.ParseWithClaims`, `controller/env/appenv.go:254`); `SessionManager.ReadByToken`
/// (`controller/model/session_manager.go:336`) is never called on that path ⇒ a cuid does not parse ⇒ the
/// dial is rejected. We therefore rebuild as `SessionDetail { edge_routers: …, ..session.clone() }` — the
/// same shape as the JWT branch's DV-A2.
///
/// [`refresh_session_probe`] is deliberately left UNTOUCHED: it serves the DIAL path
/// ([`super::EdgeClient::refresh_session`], D2) and `recover_empty_edge_routers` (4b), whose DV-4b-4 rests on the
/// token prefix. The blast radius of this new discriminant is **the tick only**.
///
/// # Errors
/// The probe's error (a non-2xx surfaces as [`EdgeError::SessionHttp`]; transport / bad body as
/// [`EdgeError::SessionResponse`]).
pub(crate) async fn refresh_session_probe_durable(
    http: &reqwest::Client,
    base_url: &str,
    api_token: &AuthToken,
    session: &SessionDetail,
) -> Result<SessionDetail, EdgeError> {
    match api_token.session_type() {
        // DURABLE: the controller stored this session ⇒ the detail is STATEFUL ⇒ 404 proves it is gone.
        ApiSessionType::Legacy => {
            let detail = do_get_session_detail(http, base_url, api_token, &session.id).await?;
            // DV-4a-2: ONLY the edge-routers. NEVER the body's `token` (it is the stored cuid).
            Ok(SessionDetail {
                edge_routers: detail.edge_routers,
                ..session.clone()
            })
        }
        // STATELESS: the session was never stored ⇒ the detail would 404 even for a LIVE one (DV-4a-3).
        ApiSessionType::Oidc => {
            let fresh_edge_routers = do_get_service_edge_routers(
                http,
                base_url,
                api_token,
                &session.service_id,
                &session.token,
            )
            .await?;
            Ok(SessionDetail {
                edge_routers: fresh_edge_routers,
                ..session.clone()
            })
        }
    }
}

/// Does this probe error PROVE the SESSION is dead? (4a, §4.2 of the spec.) Only a PROOF purges — a blip
/// must not (**DV-4a-5**). Upstream can mark `toDelete` on ANY error (`ziti.go:839-841`) precisely because
/// its eviction arm is a **no-op**; ours is real, so it purges only on evidence it can name.
///
/// **Exactly ONE quadrant is a proof: (legacy api-session, 404).** Everything else — including every error
/// of the OIDC régime — returns `false`.
///
/// # Durable branch (legacy api-session): a **404** is the proof
/// The probe is `GET /sessions/{id}` and the controller only reaches the store for a session it PERSISTED,
/// which is exactly the legacy régime (`ziti@9bf62f3 controller/internal/routes/session_router.go:220-226`).
/// A 404 there is the store answering NotFound ⇒ the session is gone. A **401 is NOT** proof (see below);
/// 5xx / transport are blips.
///
/// # Stateless branch (OIDC): **NOTHING** the probe can answer proves the session dead
/// The probe is `GET /services/{id}/edge-routers`. Two independent reasons, either sufficient:
///
/// 1. **The 401 is NOT attributable to the session.** The route is registered with
///    `permissions.IsAuthenticated()` (`controller/internal/routes/service_router.go:77-80`), and
///    `AppEnv.IsAllowed` answers `errorz.NewUnauthorized()` — a **401** — the moment that permission fails,
///    BEFORE the handler runs (`controller/env/appenv.go:991-1002`; `controller/permissions/is_authed.go:27-29`).
///    The handler itself then re-derives the same 401 from `rc.SecurityCtx.GetApiSession()`
///    (`service_router.go:407-412`) and only AFTER that reaches `ValidateServiceAccessToken`
///    (`:428-435`), whose failure is *also* a bare `errorz.NewUnauthorized()` — same `AppCode`, same status
///    (`foundation/v2 errorz/helpers.go:91-97`). So a 401 conflates **«the API-SESSION expired»** with
///    «the session token was rejected», and the envelope carries no field that discriminates them. Treating
///    it as proof of death would let an ordinary access-token expiry (or a late proactive refresh) purge the
///    **WHOLE** dial-session cache of LIVE sessions: the tick reads the token ONCE (`read_token`) and does
///    NOT go through `with_reauth_retry`, so it neither refreshes nor retries — it would purge in silence.
///    Symmetric to the legacy branch's own rule, which already says an api-session 401 is the reauth's
///    business (the reauth `clear()`s the cache anyway).
/// 2. **There is no corpse to purge in this régime.** The controller does NOT persist a session minted
///    under an OIDC api-session (`session_router.go:220-226`, gated by `HasLegacySecurityToken()`), so the
///    "deleted session still cached" defect 4a exists to fix **cannot occur** here. A *revoked* OIDC session
///    is still caught where it always was — at the **DIAL** (D3/DV-C3: `invalid session` → evict → recreate
///    → retry, ≤2 dials, never over-permit, never a hang), exactly as before 4a.
///
/// # Direction
/// This purges **strictly LESS** than a rule that trusted the 401 ⇒ it cannot introduce over-permit (an
/// eviction only ever REMOVES keys; refusing to evict only ever keeps a key the DIAL will re-validate
/// against the controller). The price of a session we decline to purge is the **pre-4a** bound above.
///
/// A stateless **404**, likewise, is not proof: on that endpoint it is the **SERVICE** that is not visible
/// (`service_router.go:437-450`), and the svc-poll's `Removed` arm already owns that eviction.
pub(crate) fn is_proven_dead(api_token: &AuthToken, err: &EdgeError) -> bool {
    match api_token.session_type() {
        // The ONLY proof: the session store said NotFound for a session it really stored.
        ApiSessionType::Legacy => matches!(err, EdgeError::SessionHttp { status: 404, .. }),
        // No error of the stateless probe is attributable to the SESSION (the 401 is also the
        // api-session's), and no OIDC session is persisted ⇒ there is no corpse of that kind to purge.
        ApiSessionType::Oidc => false,
    }
}

/// The **PURGE GATE** of the session-refresh tick (4a, **DV-4a-1** + **DV-4a-4**): remove `key` **only if**
/// it is still occupied by the **same `session.id`** the snapshot photographed. Returns `true` iff it
/// evicted. Free (the tick has no `&self`), like [`refresh_session_probe`] / [`recache_refreshed_dial_session`].
///
/// # The KEY is the snapshot's (this is the whole point of the slice)
/// Upstream marks dead sessions with the **bare `*session.ID`** (`ziti.go:841`) and later calls
/// `context.sessions.Remove(id)` (`:854`) on a cache keyed `"{serviceId}:{type}"` (`:2121`) ⇒ upstream's
/// eviction arm is a **guaranteed no-op**. We ported that inert contract (DV-A1) rather than imitate the
/// call, because our cache is keyed by the **bare `service_id`**: `remove(&session.id)` here would be inert
/// only by disjunction of namespaces, and a `session.id`/`service_id` collision would evict **another
/// service's** session — an OVER-PERMIT-adjacent misbehaviour we forbid. 4a fixes the arm for real by
/// evicting under the **key the entry was cached under**. The `session.id` namespace never enters the
/// key-space, so that collision is **impossible by construction**.
///
/// # The IDENTITY guard (DV-4a-4), mirror of the write gate's CN-2
/// The probe is an `.await`: between the snapshot and this call a third party can have EVICTED the entry
/// (DV-C3's dial eviction, the svc-poll's `Removed` arm, the reauth `clear()`) or REPLACED it with a
/// **newer, live** session (the dial's retry evicts + `get_or_create`s under the same key). A blind
/// `remove(key)` would throw that live session away. Absent ⇒ no-op (`reason="absent"`); different
/// `session.id` ⇒ no-op (`reason="id-mismatch"`).
///
/// # Direction of the deviation
/// An eviction can only **REMOVE** keys, so it can never turn a MISS into a HIT: **over-permit is
/// impossible by construction**. The worst case of an eviction too many is ONE extra `POST /sessions` on
/// the next `connect()`, where the **CONTROLLER** decides (C5) — under-permit, benign.
///
/// # Concurrency / observability
/// SYNCHRONOUS (`fn`, not `async fn`) ⇒ an `.await` inside the guard is impossible by construction (C7).
/// The logs are emitted AFTER the guard drops and NEVER carry the token (DV-O1) — only `service` and
/// `session_id`.
pub(crate) fn evict_dead_dial_session(
    dial_sessions: &Mutex<HashMap<String, SessionDetail>>,
    key: &str,
    snapshot_session_id: &str,
) -> bool {
    // THE critical section: decide under the SNAPSHOT's key, then remove only if the identity still matches.
    let skipped: Option<&'static str> = {
        let mut guard = dial_sessions
            .lock()
            .expect("dial-session cache mutex poisoned");
        let reason = match guard.get(key) {
            // Somebody already evicted/cleared it while we probed → nothing to purge.
            None => Some("absent"),
            // Somebody REPLACED it with a different (newer, live) session → do NOT evict theirs.
            Some(existing) if existing.id != snapshot_session_id => Some("id-mismatch"),
            // Still OUR corpse under OUR key → purge it.
            Some(_) => None,
        };
        if reason.is_none() {
            guard.remove(key);
        }
        reason
    };
    match skipped {
        None => {
            tracing::debug!(
                service = %key, session_id = %snapshot_session_id,
                "purged dead dial session"
            );
            true
        }
        Some(reason) => {
            // Same vocabulary as the write gate (`absent` / `id-mismatch`), so both gates read alike.
            tracing::debug!(
                service = %key, session_id = %snapshot_session_id, reason,
                "purge skipped: the cached dial session was evicted or replaced"
            );
            false
        }
    }
}

/// The WRITE GATE for every dial-session write of **`"refresh"` provenance** — the tick
/// ([`crate::edge::session_refresh`], W1) and D2's re-cache inside [`super::EdgeClient::refresh_session`] (W2).
/// Re-caches `refreshed` **only if** the SNAPSHOT's key is still occupied by the **same `session.id`**
/// the snapshot saw; returns `true` iff it wrote. Free (not a method) because the tick has no `&self`,
/// the same reason [`refresh_session_probe`] is free.
///
/// # Why (spec `2026-07-11-refresh-tick-resurrection-design.md`, DV-R1 — beyond-oracle, owner-authorised)
/// Both refresh writers have the shape **snapshot → await (probe) → write**, and three third parties
/// delete under exactly the key this gate consults (`service_id`): DV-C3's dial eviction
/// (`evict_dial_session`), the svc-poll's `Removed` arm (`store_and_process_free`) and the reauth
/// `dial_sessions.clear()` (`edge/refresh`). A BLIND write therefore has two distinct defects:
/// - **(R) resurrection** — the entry was DELETED mid-probe and the write RE-CREATES it. When the
///   deleter was DV-C3, what comes back is a corpse the controller already proved dead.
/// - **(C) clobber** — the entry was REPLACED by a NEWER session (the dial's retry evicts and
///   `get_or_create`s a fresh one under the same key, `edge/conn/retry.rs`) and the write PISA it with the stale
///   one from the snapshot. A gate of mere EXISTENCE does **not** catch this — hence the **identity**
///   comparison.
///
/// The oracle has BOTH defects and we inherit them from it: `cacheSession("refresh")` is an `Upsert`
/// whose callback returns `newValue` UNCONDITIONALLY (`ziti.go:2127-2132`), i.e. a blind Set that
/// inserts even when the key is ABSENT (and its `isUpdate` block, `:2133-2136`, is a self-assignment
/// no-op); `refreshSessions` snapshots with `IterBuffered()` and refreshes outside it (`:830-860`).
///
/// # Why over-permit is impossible (the argument that actually holds)
/// ⚠ It is **NOT** true that the guarded write's effects are a *strict subset* of the blind write's —
/// that claim was written here once and is **FALSE**. In the corner `refreshed.service_id != key`, the
/// blind write would have touched key `refreshed.service_id` and left `key` alone, whereas the gate
/// writes under `key`: the two effect sets are **INCOMPARABLE**, not nested. The property that does hold
/// is narrower and sufficient:
/// 1. **The gate can ADD no key, ever.** `get_mut` does not insert (unlike `entry().or_insert()`), so
///    the set of keys it can create is **∅**, whatever it is handed and however it is keyed. A key that
///    was not in the map cannot become a cache-HIT, so no `connect()` can be handed a session that lets
///    it skip `POST /sessions` — where the CONTROLLER decides (C5). **Over-permit is impossible by
///    construction.** It is not under-permit either: a skipped write costs at most one extra
///    `POST /sessions` on the next `connect()`.
/// 2. **Server-side reinforcement** (belt and braces — it makes even a MIS-KEYED entry harmless). The
///    `Connect` we put on the wire carries **only the session token**, never a service id (`build_connect`,
///    `edge/data/channel.rs`), and the controller **DERIVES the service from the session**:
///    `createCircuitHandler.CreateCircuit` does `loadSession` → `checkSessionType(Dial)` → `loadService`
///    (`ziti@9bf62f3 controller/handler_edge_ctrl/create_circuit.go:88-91`) and `loadService` reads
///    `EdgeService.Read(self.session.ServiceId)` (`.../common.go:418`). So a cache entry filed under the
///    wrong key could not grant NEW access: the worst it could do is **misroute** to a service the
///    controller had **already authorised for this identity** (it minted that very session). Never
///    over-permit.
///
/// The `"create"` provenance ([`super::EdgeClient::cache_dial_session`]) stays a BLIND insert, exactly the
/// `"create"` vs `"refresh"` distinction the oracle itself draws (`ziti.go:2124-2137`).
///
/// # The key is the SNAPSHOT's (CN-3)
/// We key by `key` (the `service_id` the entry was cached UNDER), never by `refreshed.service_id`. The
/// honest and sufficient reason is simply that **the update must land on the entry we photographed**:
/// the snapshot recorded `(key, session)` and it is *that* entry we are refreshing. Today the two ids
/// coincide anyway (the cache's own invariant, DV-R5 below).
///
/// ⚠ Do **not** re-derive this from a "phantom key" hazard — that alibi was written here once and is
/// **FALSE**. A *write gate cannot create any key, however it is keyed* (see point 1 above): a variant
/// doing `guard.get_mut(&refreshed.service_id)` would find that key ABSENT and **skip**. The phantom key
/// was only ever reachable through the **blind `insert`** this slice deleted. And the oracle mechanism
/// the alibi invoked (`service_id` coming out of **unverified JWT claims**, `client.go:254` → `:280`)
/// **does not exist in our port at all**: DV-A2 rebuilds the JWT branch as
/// `SessionDetail { edge_routers: fresh, ..session.clone() }` (`refresh_session_probe` above), so our
/// JWT branch copies the snapshot's `service_id` **bit for bit**.
///
/// # DV-R5: the invariant `key == value.service_id` NEVER held (named deviation, pre-existing)
/// [`super::EdgeClient::get_or_create_dial_session`] keys by the **REQUESTED** `service_id` while the value
/// carries the `serviceId` from the **controller's body** — they are equal only because a conforming
/// controller echoes back the service you asked for. The oracle does NOT do this: `cacheSession` keys by
/// `*session.ServiceID` on **create AND refresh** alike (`ziti.go:2121`). So the invariant already rested
/// on trusting the controller's echo **before and after** this slice: the gate adds **no new trust
/// premise**. Bound if it were ever violated: unreachable with a conforming controller, and the effect
/// would be a **misroute to an already-authorised service — never over-permit** (point 2 above).
///
/// # Scope, re-derived by 4a: this gate stops the UNDO; the PURGE arm is what collects the corpses
/// *Historically this section said a deleted session nobody dials again "stays cached forever", because
/// purging it would need BOTH an existence check in the probe AND a fix to the inert eviction arm's key —
/// "both out of scope". **4a did exactly those two things** (DV-A1 is dead), so that paragraph is gone.*
///
/// The division of labour now:
/// - **This gate** owns the WRITE. It still never PURGES anything — it only declines to write. Its whole
///   job is that a write may not UNDO a third party's eviction (R) nor CLOBBER a newer session (C).
/// - **The PURGE arm** ([`evict_dead_dial_session`], driven by [`is_proven_dead`]) owns the eviction, and
///   it converges the cache with the controller **in the LEGACY régime only** — the one where the session
///   is PERSISTED (`ziti@9bf62f3 controller/internal/routes/session_router.go:220-226`) and a deleted one
///   therefore answers 404 on `GET /sessions/{id}`, which is the only PROOF of death we accept.
///
/// Honest residual (the part that still does not converge): a legacy session REVOKED but not DELETED (the
/// store keeps answering 200), and **anything** under an OIDC api-session — there, no session is persisted,
/// so there is no such corpse in the first place, and no probe error is attributable to the session
/// ([`is_proven_dead`] ⇒ `false`). Both fall back to the pre-4a bound, which is why they are debt and not a
/// hole: the next `connect()` HITs, dial #1 fails `invalid session`, D3 evicts, recreates and retries —
/// ≤2 dials, never over-permit, never a hang.
///
/// # Concurrency (C7)
/// ONE critical section, and the function is SYNCHRONOUS (`fn`, not `async fn`) ⇒ it is IMPOSSIBLE by
/// construction for an `.await` to sit inside the guard. The logs are emitted AFTER the guard drops
/// (P5/P6 of OBS-DIAL-CACHE, `617b3fa`) and NEVER carry the token (DV-O1).
pub(crate) fn recache_refreshed_dial_session(
    dial_sessions: &Mutex<HashMap<String, SessionDetail>>,
    key: &str,
    snapshot_session_id: &str,
    refreshed: SessionDetail,
) -> bool {
    let refreshed_id = refreshed.id.clone();
    // THE critical section: look up by the snapshot's key, compare identity, update IN PLACE (the key
    // itself is never rewritten). `None` = we wrote; `Some(reason)` = we skipped.
    let skipped: Option<&'static str> = {
        let mut guard = dial_sessions
            .lock()
            .expect("dial-session cache mutex poisoned");
        match guard.get_mut(key) {
            // CN-1: somebody EVICTED/CLEARED the entry while we probed → do NOT resurrect it.
            None => Some("absent"),
            // CN-2: somebody REPLACED it with a different session → do NOT clobber the newer one.
            Some(existing) if existing.id != snapshot_session_id => Some("id-mismatch"),
            // Still OUR session under OUR key → refresh it in place (this is the 99.99% path).
            Some(existing) => {
                *existing = refreshed;
                None
            }
        }
    };
    match skipped {
        None => {
            // P5 + P6: the same two events the D2 path emitted before this gate existed, so
            // `refresh_recache_logs_and_never_logs_token` keeps passing untouched. The TICK did not emit
            // them before (it wrote with a raw `.insert()`) and now does — a free observability win
            // (DV-R4; ticks are hourly).
            tracing::trace!(service = %key, session_id = %refreshed_id, "cached dial session");
            tracing::debug!(
                service = %key, session_id = %refreshed_id,
                "re-cached refreshed dial session"
            );
            true
        }
        Some(reason) => {
            // The discriminant that makes the gate observable if it ever fires in production.
            tracing::debug!(
                service = %key, session_id = %snapshot_session_id, reason,
                "refresh re-cache skipped: the cached dial session was evicted or replaced"
            );
            false
        }
    }
}
