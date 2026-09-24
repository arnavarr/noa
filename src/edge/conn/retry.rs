//! `dial_with_refresh_retry`: the oracle's get-or-create → dial → refresh → retry-once
//! orchestration plus the owner-authorised beyond-oracle D3/DV-C3/DV-C4 arms. (F6 tramo 5: movido
//! verbatim del monolito de `edge/conn`.)

use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;

/// Orchestrate the oracle's get-or-create → dial → refresh → retry-once. `T` is the successful
/// dial product (in production `(EdgeConn, EdgeChannel)`). Mirror of `DialContextWithOptions`
/// (`ziti.go:1483-1507`) PLUS a beyond-oracle **widening of the retry TRIGGER** (owner-authorised
/// 2026-07-09): when the router rejects the dial with `invalid session` (`is_dial_invalid_session`),
/// the cached session is dead at dial-authorization even though the controller's liveness probe reports
/// it alive — so skip the probe and go straight to evict + recreate + retry once. For every OTHER dial
/// failure the oracle's probe-gate is preserved verbatim: probe the session's liveness — **alive** ⇒
/// return the ORIGINAL dial error (the failure was not session related, so do not retry); **expired** ⇒
/// evict + recreate + dial exactly once more.
///
/// Precisely what is and is not borrowed (verified at the pins; do not restate this loosely):
/// - The retry **ACTION is the oracle's own DIAL retry**, unchanged: `deleteServiceSessions` +
///   `createSessionWithBackoff` + one `dialSession` (`ziti.go:1495-1505`). Nothing new is invented.
/// - Only the **TRIGGER** is widened. Its justification comes from HOSTING: the controller labels this
///   rejection `RetryHint = RetryStartOver` (`ziti@9bf62f3 handler_edge_ctrl/errors.go:118-120`) and the
///   oracle's hosting path honours that label (`hosting_conn.go:177-179`). The DIAL path ignores it.
/// - We do **not** copy hosting's *mechanism*: `NotifyStartOver` (`ziti.go:2770-2780`) defers the
///   restart by `time.AfterFunc(5s)`. This retry is immediate — and that is **parity, not a gap**
///   (D3-CHURN, 2026-07-11): those 5s are the re-establishment debounce of a long-lived LISTENER
///   (`hosting_conn.go:177-179`), a resource that must be recovered indefinitely. The oracle's DIAL is
///   one-shot: **at most two `dialSession`** (`ziti.go:1484` and `:1502`), **zero wait** between them,
///   **no loop**, and it surrenders with the 2nd dial's error (`:1507`). Under sustained churn the
///   oracle gives up too. Adding a wait or a third attempt here would be invention, and would only
///   insist through an in-progress access revocation. (The transient "stuck ~30 s after `update
///   service`" episode once blamed on this was DISCRIMINATED and its mechanisms REFUTED — see
///   `docs/residual-discrimination-2026-07-10.md`.)
///
/// **DV-C3/DV-C4 (D3-CHURN, beyond-oracle, owner-authorised 2026-07-11) — cache hygiene.** The retry's
/// TAIL evicts the freshly created session **iff** the 2nd dial is ALSO rejected `invalid session`.
///
/// *Why that verdict is PROOF OF DEATH — and what actually guarantees it.* **The guarantee is WHICH
/// HANDLER answers our dial, not the string.** Our dial lands on the controller's
/// `baseSessionRequestContext` (`ziti@9bf62f3 controller/handler_edge_ctrl/create_circuit.go:60-61` →
/// `common.go:329-333`), which mints `InvalidSessionError` (`errors.go:108-112`, `Error() = "invalid
/// session"`) **only** when `Session.Read(id)` comes back NotFound — and a deleted session never
/// resurrects. Two OTHER places in `ziti` emit the very same string with a different meaning; neither is
/// reachable from this dial today, and a future slice must NOT inherit this proof for free:
/// - `router/xgress_edge/listener.go:923-925` — the **ROUTER** (not the controller) replies `invalid
///   session` on the **BIND** path (`processBindV2`, legacy service-session recently removed). D3 is
///   dial-only today (§9-b); routing BIND through this helper would import that arm.
/// - `controller/handler_edge_ctrl/common_tunnel.go:238-243` — `isSessionValid` mints
///   `InvalidSessionError{}` when the read fails and is **NOT** NotFound (`if !boltz.IsErrNotFoundErr`),
///   i.e. "the DB read blew up" — the *opposite* of "the session is dead". Only the router-hosted
///   tunneler handlers reach it.
///
/// `is_dial_invalid_session` matches by **exact equality** (never substring), so no wrapped or foreign
/// message slips in. If a later slice widens the trigger, or plugs BIND / the router's tunneler into
/// this shared tail, the proof of death must be **RE-DERIVED**, not assumed.
///
/// *Direction of the deviation (stated honestly).* The oracle leaves the corpse cached (`ziti.go:2005`
/// caches, `:1507` surrenders without cleaning), so its next `connect()` cache-HITs it and burns its
/// first dial on it — one useful attempt instead of two. Evicting it makes us **beyond-oracle,
/// DELIBERATELY MORE ROBUST** — not "conservative", not "under-permit". With *p* = P(churn kills a
/// brand-new session), the oracle's follow-up `connect()` fails with *p* and ours with *p²*: there ARE
/// runs where the oracle surrenders and **we connect**. That is exactly what this slice buys and what
/// the live gate measures. What stays intact is what fidelity is *defined over*:
/// - **Retry contract (C1): untouched** — still ≤2 dials, no wait, no loop, 2nd dial's error propagated
///   verbatim (`ziti.go:1484` + `:1502` + `:1507`).
/// - **Authorisation (C5): untouched** — every re-creation goes through `POST /sessions`, which the
///   controller denies if dial access was lost ⇒ **never an authorisation over-permit, ever.**
///
/// **Narrow (DV-C4):** any OTHER 2nd-dial failure (`no terminators`, timeout, IO) keeps the fresh
/// session cached — no proof of death.
///
/// **C3: the qualification is LIFTED (2026-07-11, the refresh write-gate slice).** This eviction is no
/// longer undone by any write of `"refresh"` provenance — the hourly session-refresh tick
/// ([`crate::edge::session_refresh`]) and D2's re-cache inside `refresh_session` now go through
/// [`crate::edge::client::recache_refreshed_dial_session`], which writes ONLY IF the snapshot's key is
/// still occupied by the SAME `session.id` (CN-1/CN-2). Since `evict()` below deletes precisely that key,
/// a concurrent refresh finds it ABSENT and writes nothing.
/// Spec: `docs/superpowers/specs/2026-07-11-refresh-tick-resurrection-design.md`.
///
/// ⚠ **Said precisely (do NOT over-claim "nothing can undo it").** The key CAN be repopulated — by a
/// concurrent `connect()`, whose `get_or_create` is a write of `"create"` provenance: a BLIND insert,
/// deliberately so (C6), because a session the controller just minted is authoritative. What can never
/// come back is **the corpse**: a `"refresh"` write cannot re-create it (CN-1) and cannot overwrite the
/// NEWER session with it (CN-2). So the invariant is *"the evicted corpse never returns"*, not *"the key
/// stays empty"*.
///
/// (The old bound is retained only as the reason this was debt and not a hole: a resurrected corpse
/// merely **degraded to pre-fix** — the next `connect()` cache-HITs, D3 evicts and retries, still ≤2
/// dials, **never over-permit, never a hang**. That is also the cost ceiling if the gate ever regressed.)
///
/// NB the dial wire discards the typed error (router `FinishConnect` sends only `err.Error()`,
/// `listener.go:1561`), so the trigger is the exact message string — see `is_dial_invalid_session`.
/// Generic over the async ops so the retry logic is unit-testable with fakes (no controller/router).
/// The exponential backoff on (re)create lives inside the `get_or_create` closure (slice 10a), not here.
pub(super) async fn dial_with_refresh_retry<T>(
    get_or_create: impl AsyncFn() -> Result<SessionDetail, EdgeError>,
    dial: impl AsyncFn(SessionDetail) -> Result<T, EdgeError>,
    refresh: impl AsyncFn(SessionDetail) -> Result<(), EdgeError>,
    evict: impl Fn(),
) -> Result<T, EdgeError> {
    let session = get_or_create().await?;
    match dial(session.clone()).await {
        Ok(connected) => Ok(connected),
        Err(first_err) => {
            // D3 (beyond-oracle, owner-approved): the router's `invalid session` verdict is authority
            // over dialability, so short-circuit the controller's liveness probe (it answers the wrong
            // question — the cached session is alive at the controller yet dead at dial-authorization,
            // spec §2) and go straight to evict + recreate + retry — the same recovery the oracle applies
            // in HOSTING (RetryStartOver, hosting_conn.go:177-179). For EVERY other dial failure the
            // oracle's probe-gate is preserved: `||` short-circuits, so `refresh` runs (exactly as the
            // oracle, ziti.go:1489-1493) only when the rejection is NOT `invalid session`.
            // P8 (observability, opción 3 del MENÚ 2026-07-10): hoist the left operand so the
            // TRIGGER (which arm of the `||` decided death) is capturable for the log below, and
            // clone `session.id` before `refresh(session)` moves `session`. Purely syntactic: `||`
            // stays lazy (`invalid` short-circuits `refresh(...)`, DV-O6), so `session_dead`'s value
            // and the control flow below are bit-for-bit identical to the prior single expression —
            // pinned by the `retry_orch_*`/T4 tests above, which this change does not touch.
            let session_id = session.id.clone();
            let invalid = first_err.is_dial_invalid_session();
            let session_dead = invalid || refresh(session).await.is_err();
            if session_dead {
                // The discriminant the residual analysis needed: `invalid-session` ⇔ the router's
                // verdict short-circuited the probe (D3, beyond-oracle); `probe-dead` ⇔ the oracle's
                // own probe-gate fired (`ziti.go:1490-1495`). `error` is safe to log: an `EdgeError`
                // carries only the controller/router's status/code/message envelope, never a token
                // (invariant already documented at the D1 probe-log above `refresh_session`).
                let trigger = if invalid {
                    "invalid-session"
                } else {
                    "probe-dead"
                };
                tracing::debug!(
                    session_id = %session_id, trigger = %trigger, error = %first_err,
                    "dial session dead; evicting, recreating and retrying once"
                );
                // dead-for-dial → evict, recreate fresh, retry the dial EXACTLY once (no loop); the
                // 2nd dial's result — success OR another `invalid session` — propagates as-is.
                evict();
                let fresh = get_or_create().await?;
                let fresh_id = fresh.id.clone();
                dial(fresh).await.inspect_err(|second_err| {
                    // DV-C3/DV-C4 (D3-CHURN, beyond-oracle, owner-authorised 2026-07-11): if the dial
                    // we just made with the FRESH session is rejected `invalid session` too, THAT
                    // session is PROVEN DEAD. The proof is owed to the HANDLER that answers this dial,
                    // not to the string: `create_circuit.go:60-61` → `common.go:329-333` mints
                    // `InvalidSessionError` (`errors.go:108-112`) ONLY on `Session.Read(id)` NotFound,
                    // and a deleted session never resurrects. (Two other ziti sites emit the same
                    // string with a different meaning — `listener.go:923-925` on BIND and
                    // `common_tunnel.go:238-243` on a NON-NotFound read error — neither reachable from
                    // this dial; see the doc-comment above before widening anything.)
                    //
                    // So drop it from the cache: otherwise the NEXT connect() cache-HITs the corpse and
                    // burns its first dial on it, leaving ONE useful attempt instead of two — under
                    // churn that doubles the failure rate of every subsequent call. The oracle DOES
                    // keep the corpse (`ziti.go:2005` caches, `:1507` gives up without cleaning), so
                    // this is beyond-oracle and deliberately MORE ROBUST than the oracle in RESULT (we
                    // connect on runs where it surrenders) — see the doc-comment. It is NOT
                    // "under-permit": what it cannot do is over-permit AUTHORISATION, because every
                    // re-creation goes through `POST /sessions` and the controller denies it if dial
                    // access was lost (C5). The retry CONTRACT is untouched: still at most 2 dials, no
                    // wait, no loop, error propagated verbatim (`ziti.go:1484` + `:1502` + `:1507`).
                    // (The oracle's 5s `NotifyStartOver` debounce, `ziti.go:2770-2780`, belongs to the
                    // HOSTING listener lifecycle, `hosting_conn.go:177-179` — it is NOT a dial retry
                    // policy; porting it here would be invention and would only slow down a correct
                    // access-denied.)
                    //
                    // DV-C4 (narrowness): ONLY `invalid session` proves death. Any other 2nd-dial
                    // failure (`no terminators`, timeout, IO) KEEPS the fresh session cached — no proof
                    // of death, and evicting would buy a gratuitous session create on every router
                    // hiccup. This sits in the retry's SHARED tail, so it covers D3's arm and the
                    // oracle's probe-dead arm alike: the proof of death is the same in both.
                    if second_err.is_dial_invalid_session() {
                        // DV-O1: the session TOKEN is never logged (the oracle does log it,
                        // `ziti.go:1483`); only the id and the reason.
                        //
                        // ⚠ `session_id` here is the session WE DIALED, which is not necessarily the
                        // one `evict()` removes: `evict()` deletes by SERVICE key, and between
                        // `get_or_create()` and here a concurrent `connect()` on another task may have
                        // replaced the entry under that key (its `get_or_create` is a write of "create"
                        // provenance — a BLIND insert, deliberately so: a freshly minted session is
                        // authoritative). What can NO LONGER replace it is the hourly refresh tick or
                        // D2's re-cache: since 2026-07-11 both are gated by
                        // `recache_refreshed_dial_session` and skip unless the key still holds the same
                        // `session.id` they snapshotted. The eviction stays sound (the `invalid session`
                        // verdict proves the session we dialed is dead, and dropping a *newer* entry
                        // costs at most one extra `POST /sessions`), but this id is a trace of the
                        // DIAL, not a receipt of what left the map. OBS-DIAL-CACHE (`617b3fa`) turned
                        // these traces into product, so the distinction is stated, not assumed.
                        tracing::debug!(
                            session_id = %fresh_id, reason = "dead-at-dial",
                            "freshly created dial session also rejected as invalid; evicting it \
                             (proven dead) so the next connect starts on a cache miss"
                        );
                        evict();
                    }
                })
            } else {
                // session alive & not `invalid session` → the failure was not session related → no retry
                Err(first_err)
            }
        }
    }
}
