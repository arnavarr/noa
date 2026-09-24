//! Background session-refresh timer — the session-refresh arm of the oracle's `runRefreshes` (D2).
//!
//! The oracle's `runRefreshes` (`sdk-golang` v1.7.0 `ziti/ziti.go:1002`) is ONE goroutine with a
//! `select` over THREE independent timers: api-session refresh, service refresh, and session refresh.
//! The api-session arm is ported as [`crate::edge::refresh::run_refreshes`], the service arm as
//! [`crate::edge::service_refresh::run_service_refreshes`]. This module ports the third arm,
//! `refreshSessions` (`ziti.go:830-860` + its timer arm `:1080-1083`), which the earlier port never
//! carried (`refresh/mod.rs` declared it out of scope). It runs as a SIBLING background task sharing the
//! SAME `Arc`s (`token`, `dial_sessions`) as the rest of [`crate::edge::client::EdgeClient`].
//!
//! # Conscious divergence: three tasks vs one goroutine
//! The oracle SERIALIZES all three arms in a single `runRefreshes` goroutine whose `select` fires one
//! timer at a time (`ziti.go:1002`, arms at `:1032-1084`). We run them as INDEPENDENT tokio tasks, so an
//! interleaving exists that the oracle cannot produce: the service arm may evict a `Removed` service's
//! cached Dial session (`store_and_process_free`) while this arm is mid-probe. **That structural
//! divergence REMAINS** — what changed (2026-07-11, the write-gate slice) is that its outcome is now
//! benign **BY CONSTRUCTION** instead of benign by unreachability: our post-probe write goes through
//! [`crate::edge::client::recache_refreshed_dial_session`], which skips when the snapshot's key is no
//! longer occupied by the same `session.id` — and the `Removed` arm deletes by `svc.id`, i.e. EXACTLY
//! the key the gate consults ⇒ the write finds the key ABSENT and writes nothing. **The resurrection no
//! longer happens at all.**
//!
//! *Historical note (superseded, kept because it explains why this was not a defect BEFORE the gate):*
//! the resurrected entry used to be **inert** against the `Removed`-service arm specifically — it was
//! keyed by a `service_id` that no longer resolved, and `connect()` resolves by NAME first (`conn/flow.rs`
//! `connect_inner` → `resolve_service`), returning `ServiceNotFound` BEFORE the dial-session cache is
//! consulted, so the entry was unreachable by any dial and dropped by the next reauth
//! `dial_sessions.clear()`. Do NOT "fix" the structural divergence with a shared lock across arms: that
//! would diverge further from the oracle's own non-atomic `cmap`. (Found by adversarial review; refuted
//! 3/3 as a defect, then closed for real by the write gate.)
//!
//! ## The DIAL's eviction (DV-C3) — CLOSED by the write gate (2026-07-11)
//! `dial_with_refresh_retry` (`conn/retry.rs`) evicts a dial session that the router/controller **proved dead**
//! (2nd dial also rejected `invalid session`). This tick used to be able to UNDO that eviction, and the
//! inertness argument above did **not** cover it: the service still resolves, so a resurrected corpse was
//! fully REACHABLE by the next `connect()`. **The gate closes it** — and it closes BOTH shapes of the
//! damage, which is why the gate compares IDENTITY and not mere existence:
//! - **(R) resurrection** — the entry was DELETED mid-probe; a blind write RE-CREATES the corpse.
//! - **(C) clobber** — the entry was REPLACED by a NEWER session (the dial's retry evicts and
//!   `get_or_create`s a fresh one under the same key); a blind write — *and an existence-only guard* —
//!   PISA the newer session with the stale one from the snapshot.
//!
//! Both mechanisms need the eviction to land inside the `[snapshot, write]` window (an eviction BEFORE
//! the snapshot leaves nothing to resurrect). What the PROBE changes is the WINDOW'S WIDTH, not its
//! existence: the **stateful** probe `GET /sessions/{id}` yields 404 for a delete that beats the
//! controller's answer ⇒ `Err` ⇒ no write (narrow window); the **stateless** probe
//! `ListServiceEdgeRouters` **never checks the session exists**, so it answers `Ok` for an ALREADY-DELETED
//! session and the damaging window widens to the WHOLE RTT. Hence the fix is a gate on the **WRITE**, not
//! on the **PROBE**: a probe-side existence check would not close the stateful window, would not touch (C)
//! at all, and would be a REGRESSION for live stateless (OIDC) sessions.
//!
//! ⚠ **Which probe runs is decided by the API-SESSION, not by the session token** — since 4a, and *in the
//! tick only* (DV-4a-3, [`crate::edge::client::refresh_session_probe_durable`]). The paragraph above used
//! to say "an *opaque* token … a *JWT* token …": that split is the oracle's (`ziti.go:2106`) and it still
//! governs the **DIAL** path ([`crate::edge::client::refresh_session_probe`]), but against a `ziti` v2
//! controller the session token is ALWAYS a JWT, so in the tick it selected the stateless probe
//! unconditionally. With the rig's combination (**legacy** api-session + JWT session token) the tick now
//! takes the **DURABLE** branch and the window is the **narrow** one.
//!
//! ### Evidence that the JWT probe answers `Ok` for a DELETED session (it is CONTROLLER-side)
//! ⚠ Do NOT cite `client.go:236` for this — that comment documents **`GetSession`** (the OPAQUE branch,
//! `GET /sessions/{id}`: *"Does not function with JWT backed sessions"*) and says **nothing** about
//! whether `ListServiceEdgeRouters` checks the session's existence. The SDK side only shows the shape
//! (`GetSessionFromJwt`, `client.go:250-294`, never reads `/sessions/{id}`). The claim itself is TRUE,
//! and its evidence lives in the **controller** (`openziti/ziti` pin `9bf62f3`):
//! - `controller/internal/routes/service_router.go:406-457` (`listClientEdgeRouters`, the handler behind
//!   `GET /services/{id}/edge-routers`): it validates the token (`:428-436`) and reads the SERVICE
//!   (`EdgeService.ReadForIdentity`, `:438`). It **never reads the session store**.
//! - `controller/env/appenv.go:251-300` (`ValidateServiceAccessToken`): checks signature (`:254`),
//!   validity (`:260`), audience (`:264`), token type (`:268`), api-session binding (`:277`) and the
//!   **Revocation** list (`:282`, `:292`) — again, no session-existence check.
//! - `controller/model/session_manager.go:376-377`: `Delete` → `deleteEntity`. Deleting a session writes
//!   **no Revocation**, so nothing the JWT validation looks at ever learns the session is gone.
//!
//! ⇒ the token stays cryptographically valid after the delete; the probe returns `Ok`. Exactly the
//! stateless/stateful asymmetry above.
//!
//! Even before the gate this was **bounded, not a hole** — a re-inserted corpse merely degraded the next
//! `connect()` to its PRE-DV-C3 behaviour (cache HIT → dial #1 fails `invalid session` → D3 evicts,
//! recreates, retries once: still ≤2 dials, no over-permit, no hang). That bound is *why this was debt
//! and not an emergency*, and it remains the cost ceiling if the gate ever regressed.
//! Spec: `docs/superpowers/specs/2026-07-11-refresh-tick-resurrection-design.md` (DV-R1..DV-R5).
//!
//! ### SCOPE, updated by 4a: the tick now PURGES too (the corpses no longer live forever)
//! *Historical (pre-4a):* the write gate stopped the *undo* of an eviction but not the *convergence* of
//! the cache — a deleted session nobody dialled again stayed cached forever, because the probe (chosen by
//! the SESSION TOKEN's prefix, always a JWT against v2) answered `Ok` and the id still matched, so the
//! gate wrote and refreshed the corpse every tick. **4a closes that** (spec
//! `docs/superpowers/specs/2026-07-11-4a-purge-and-eviction-key-design.md`): see «The PURGE arm» below.
//!
//! # What one tick does (`session_refresh_tick`)
//! For every cached Dial session it runs [`crate::edge::client::refresh_session_probe_durable`] (the
//! TICK's probe since 4a — the api-session-typed sibling of the dial path's `refresh_session_probe`;
//! liveness + refreshed-`SessionDetail` reconstruction). An ALIVE session is re-cached with its refreshed
//! edge-routers — but **NOT unconditionally**. The write goes through the GATE
//! ([`crate::edge::client::recache_refreshed_dial_session`]), which lands the update **only if** the
//! snapshot's key is still occupied by the **same `session.id`** the snapshot saw (CN-1/CN-2): if a third
//! party evicted or replaced the entry while we probed, the tick writes **NOTHING**. A session the
//! controller **PROVED dead** goes to the PURGE arm ([`crate::edge::client::evict_dead_dial_session`],
//! identity-guarded, keyed by the snapshot's key). So the tick keeps a long-lived client's cached
//! edge-router set fresh even while idle, **without** undoing anyone else's eviction — and it now also
//! CONVERGES the cache with the controller. (The oracle's counterpart, `cacheSession("refresh")`
//! `ziti.go:2116`, is a BLIND `Upsert` — that is the deliberate divergence, DV-R1.)
//!
//! # The PURGE arm (4a — DV-4a-1..DV-4a-5; DV-A1 is DEAD)
//! *Superseded:* DV-A1 ported the upstream eviction arm's observable contract — *"the timer evicts
//! NOTHING"* — because upstream marks dead sessions with the BARE `*session.ID` (`ziti.go:841`) and then
//! `context.sessions.Remove(id)` (`:854`) against a cache keyed `"{serviceId}:{type}"` (`:2121`): a
//! **guaranteed no-op**. 4a **fixes the arm for real** (beyond-oracle, owner-authorised):
//!
//! - **DV-4a-1** — it evicts, by the **SNAPSHOT'S KEY** (the `service_id` the entry was cached under),
//!   never by `session.id` (the bug) nor by `refreshed.service_id`. The `session.id` namespace never
//!   enters the key-space ⇒ the collision that motivated DV-A1 is **impossible by construction**.
//!   Direction: an eviction can only REMOVE keys ⇒ it can never turn a MISS into a HIT ⇒ **over-permit is
//!   impossible**; an eviction too many costs ONE extra `POST /sessions`, which the CONTROLLER authorises.
//! - **DV-4a-3** — the tick's probe branches on the **API-SESSION type**, not on the session token's
//!   prefix (the oracle's test, `ziti.go:2106`, is DEAD CODE against v2: the session token is ALWAYS a JWT,
//!   `session_router.go:191`,`:214`). The controller only PERSISTS the session when the api-session is
//!   **legacy** (`:220-226`) — so durability, and hence the ability to observe a DELETION as a 404, is a
//!   property of the api-session. Under OIDC the stateless probe stays (a durable probe there would 404
//!   for a session that is perfectly ALIVE — the regression `ziti/client.go:236` warns about).
//! - **DV-4a-2** — the durable branch takes **only the `edge_routers`** from the detail body: its `token`
//!   is the **cuid** the controller stored, not the JWT (`session_api_model.go:58-59` → `:128`), and the
//!   dial path JWT-PARSES the session token in both régimes (`handler_edge_ctrl/common.go:317`/`:247` →
//!   `appenv.go:254`) ⇒ adopting it would poison the cache and get every subsequent dial rejected.
//! - **DV-4a-4** — the eviction is **identity-guarded** (mirror of the write gate's CN-2): it removes the
//!   key only while it still holds the same `session.id` the snapshot saw, so it cannot throw away a
//!   NEWER, live session that DV-C3's retry cached during the probe.
//! - **DV-4a-5** — only a **PROOF of the SESSION's death** purges, and there is exactly ONE:
//!   **(legacy api-session, 404)** — the store answered NotFound for a session it really persisted
//!   ([`crate::edge::client::is_proven_dead`]). Blips (5xx, transport) are not proofs. Neither is a
//!   **401**, in EITHER régime: the stateless route is registered `permissions.IsAuthenticated()`
//!   (`service_router.go:77-80`) and `AppEnv.IsAllowed` answers 401 whenever the API-SESSION is invalid,
//!   BEFORE the handler runs (`appenv.go:991-1002`) — the same bare `errorz.NewUnauthorized()` the
//!   handler's `ValidateServiceAccessToken` failure produces (`:428-435`) ⇒ a 401 is NOT attributable to
//!   the session, and trusting it would let one expired access token purge the WHOLE cache of LIVE
//!   sessions. Nor is a stateless 404 (that one is the **SERVICE**'s, owned by the svc-poll's `Removed`
//!   arm). Upstream marks `toDelete` on ANY error (`:839-841`) — it can afford to, its arm is inert.
//!
//! ⇒ **the purge is confined to the LEGACY régime.** Under OIDC the tick still probes (to refresh the
//! edge-routers) but can never purge — which costs nothing, because the controller does not PERSIST a
//! session minted under an OIDC api-session (`session_router.go:220-226`), so the corpse 4a exists to
//! collect **does not exist** there.
//!
//! What still cannot be purged (honest residual): a **legacy** session REVOKED but not DELETED (the store
//! still answers 200), and any REVOKED **OIDC** session. Both degrade to the pre-DV-C3 bound at the next
//! dial (HIT → `invalid session` → D3 evicts, recreates, retries: ≤2 dials, never over-permit, never a
//! hang) — i.e. to exactly the behaviour of before 4a. See [`session_refresh_tick`] step 3.
//!
//! # Timing (DV-A5, exact parity)
//! Interval 1 h (`DefaultSessionRefreshInterval`, `options.go:17`), jitter ±10% (`DefaultRefreshJitter`,
//! `options.go:19`); the 1 s `MinRefreshInterval` clamp (`:18`) never binds. UNLIKE the service arm this
//! arm has NO error handling and NO backoff (`refreshSessions` returns nothing, `ziti.go:1082-1083`).
//! Reuses [`jittered_duration`](crate::edge::service_refresh::jittered_duration)/[`rand_fraction`](crate::edge::service_refresh::rand_fraction) from [`crate::edge::service_refresh`] (DRY).
//!
//! # Send / concurrency
//! Spawned with `tokio::spawn` (a library must not impose a `LocalSet`), so the task body is `Send`:
//! it uses only free `async fn`s over the shared `Arc`s. A `std::sync::Mutex` guard NEVER crosses the
//! `.await` — the tick SNAPSHOTS the cache under a short guard, PROBES each session with NO guard held
//! (the only await), then re-acquires a short guard to re-cache. The gate is a synchronous `fn` (not an
//! `async fn`), so an `.await` inside the critical section is IMPOSSIBLE by construction (C7).
//!
//! The re-cache is a **GUARDED UPDATE**, no longer a blind insert (2026-07-11, DV-R1). The earlier claim
//! here — *"the non-atomicity (clobber/re-add vs a concurrent `connect`/`clear`) is exactly the oracle's
//! cmap behaviour and is end-state-consistent"* — **no longer holds, and deliberately so**: we now
//! DIVERGE from that `cmap` (the oracle's `Upsert` callback returns `newValue` unconditionally,
//! `ziti.go:2129-2132`, so it inserts even into an ABSENT key). Clobber and re-add are not "accepted as
//! end-state-consistent" any more — they are CLOSED (CN-1/CN-2).
//!
//! ⚠ The divergence is **NOT** a "strict subset of the blind write's effects" — that claim was written
//! here once and is **FALSE**: in the corner `refreshed.service_id != key` the blind write would touch
//! `refreshed.service_id` and leave `key` alone, while the gate writes under `key`, so the two effect
//! sets are **INCOMPARABLE**, not nested. The property that does hold, and that carries the whole
//! conclusion, is: **the gate can ADD no key** — `get_mut` does not insert (unlike `entry().or_insert()`)
//! ⇒ no `connect()` can be handed a cache-HIT that skips `POST /sessions` ⇒ **over-permit is impossible
//! by construction**; the worst case of a skipped write is one extra `POST /sessions` on the next
//! `connect()`, which the CONTROLLER authorises (C5). See
//! [`crate::edge::client::recache_refreshed_dial_session`] for the full argument, including the
//! server-side reinforcement (the wire `Connect` carries only the token and the controller derives the
//! service from the session, `create_circuit.go:88-91` → `common.go:418`) that makes even a mis-keyed
//! entry a **misroute to an already-authorised service, never an over-permit**.
//!
//! The snapshot carries the KEY as well as the value (DV-R3/CN-3), which also brings us CLOSER to the
//! oracle — its `IterBuffered()` yields `entry.Key` (`ziti.go:834-835`).

mod intervals;
mod tick;
mod timer;

pub(crate) use intervals::{PROD_SESSION_INTERVALS, SessionRefreshIntervals};
pub(crate) use tick::session_refresh_tick;
pub(crate) use timer::run_session_refreshes;

#[cfg(test)]
mod tests_intervals;
#[cfg(test)]
mod tests_tick_core;
#[cfg(test)]
mod tests_tick_gate;
#[cfg(test)]
mod tests_tick_purge;
#[cfg(test)]
mod tests_timer;
#[cfg(test)]
mod testsupport;
