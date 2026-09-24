//! Un ciclo del session-refresh (`session_refresh_tick`): SNAPSHOT bajo guard corto → PROBE sin
//! guard (el único await) → re-cache vía el write gate → brazo PURGE (4a, DV-4a-1..5).
//! (F6 tramo 8: movido verbatim del monolito de `edge/session_refresh`.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::edge::auth_token::AuthToken;
use crate::edge::client::{
    evict_dead_dial_session, recache_refreshed_dial_session, refresh_session_probe_durable,
};
use crate::edge::model::SessionDetail;
use crate::edge::refresh::read_token;

/// One session-refresh cycle: the free, `Send` sibling of the oracle's `refreshSessions`
/// (`ziti.go:830-860`). SNAPSHOTS the Dial-session cache under a short guard, PROBES each session with NO
/// guard held (the only await, and since 4a the probe branches on the API-SESSION type — DV-4a-3),
/// RE-CACHES the alive ones through the write gate, and **PURGES** the ones the controller PROVED dead
/// through the identity-guarded eviction gate, under the SNAPSHOT's key (§ module docs, DV-4a-1..6). A
/// `None` token (unreachable post-spawn) means "nothing to refresh" → return and retry next tick (mirrors
/// the svc tick).
///
/// `pub(crate)` since 4a so the live gate (`client/tests_sessions_probe.rs`, `session_refresh_tick_purges_deleted_session_live`)
/// can drive exactly ONE tick against the real controller. No behavioural change from the visibility.
pub(crate) async fn session_refresh_tick(
    http: &reqwest::Client,
    base_url: &str,
    token: &Arc<RwLock<Option<AuthToken>>>,
    dial_sessions: &Mutex<HashMap<String, SessionDetail>>,
) {
    let Some(api_token) = read_token(token) else {
        return;
    };
    // 1. SNAPSHOT the cached sessions under a SHORT guard that does NOT cross the probe await below.
    //    The snapshot carries the KEY as well as the value (DV-R3): the re-cache below must be looked up
    //    and written under the key the entry was CACHED UNDER, not under `refreshed.service_id` (CN-3).
    //    This actually moves us TOWARDS the oracle, whose `IterBuffered()` yields `entry.Key`
    //    (`ziti.go:834-835`).
    let snapshot: Vec<(String, SessionDetail)> = {
        let guard = dial_sessions
            .lock()
            .expect("dial-session cache mutex poisoned");
        guard.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    };
    // 2. PROBE each session with NO guard held (the probe `.await` is the ONLY await, and it happens
    //    BETWEEN critical sections — never inside a held `std::sync::Mutex` guard). The TICK's probe is
    //    `refresh_session_probe_durable` (4a): it branches on the API-SESSION type, not on the session
    //    token's prefix, so a legacy api-session's DURABLE session is probed with `GET /sessions/{id}`
    //    and a DELETION surfaces as a 404 (DV-4a-3). The dial path keeps `refresh_session_probe`.
    //    `to_purge` carries `(key, session.id)` — the SNAPSHOT's key (never the bare id, the upstream
    //    key bug) plus the identity the purge gate must re-check (DV-4a-4).
    let mut to_purge: Vec<(String, String)> = Vec::new();
    for (key, session) in &snapshot {
        match refresh_session_probe_durable(http, base_url, &api_token, session).await {
            // (A) ALIVE → re-cache with the refreshed edge-routers (the oracle's `cacheSession("refresh")`
            // reached via `refreshSession`, `ziti.go:2116`). The write goes through the GATE, which is the
            // whole point of this slice: the probe above is an await, so DV-C3's dial eviction — or a
            // NEWER session cached by the dial's retry — can land between our snapshot and this write. A
            // blind `.insert()` (what we did before, and what the oracle's blind `Upsert` still does,
            // `ziti.go:2129-2132`) would RESURRECT the corpse or CLOBBER the newer session. The gate is
            // synchronous, so the guard cannot cross an await (C7); the return value is ignored on
            // purpose — a skip is a no-op by design, already logged by the gate.
            Ok(refreshed) => {
                recache_refreshed_dial_session(dial_sessions, key, &session.id, refreshed);
            }
            // (B) PROVEN DEAD → queue for the purge arm, under the SNAPSHOT'S KEY. Only a PROOF of the
            // SESSION's death qualifies (`is_proven_dead`, DV-4a-5), and there is exactly ONE: the **404 of
            // the DURABLE probe** (legacy api-session — the store really said NotFound). Nothing the
            // STATELESS probe answers is attributable to the session, so under OIDC this arm never fires.
            // Upstream marks `toDelete` on ANY error (`ziti.go:839-841`) — it can afford that because its
            // arm is INERT; ours evicts for real.
            Err(e) if crate::edge::client::is_proven_dead(&api_token, &e) => {
                to_purge.push((key.clone(), session.id.clone()));
            }
            // (C) NOT a proof (a 5xx / transport blip; ANY error of the OIDC régime, whose 401 is also what
            // an expired API-SESSION produces — `service_router.go:77-80` + `appenv.go:991-1002`): leave the
            // entry ALONE. The dial path still catches a corpse immediately (D3/DV-C3), which is precisely
            // the pre-4a bound.
            Err(e) => tracing::trace!(
                service = %key, session_id = %session.id, error = %e,
                "session refresh: probe failed but did not prove the session dead — keeping it cached"
            ),
        }
    }
    // 3. The PURGE arm (4a, DV-4a-1) — the eviction arm is no longer INERT. Oracle: `for _, id := range
    //    toDelete { context.sessions.Remove(id) }` (`ziti.go:854`), which upstream NEVER matches: it
    //    collects BARE session-IDs (`:841`) against a cache keyed `"{serviceId}:{type}"` (`:2121`), so the
    //    arm is a guaranteed no-op. We deliberately DIVERGE (beyond-oracle, owner-authorised) and evict
    //    for real, by the **SNAPSHOT'S KEY** — never by `session.id` (which would be inert only by
    //    disjunction of namespaces here, and on a collision would evict ANOTHER service's session) and
    //    never by `refreshed.service_id`. Each removal goes through the identity-guarded gate
    //    (`evict_dead_dial_session`), so a corpse a third party already replaced with a NEWER live session
    //    is NOT thrown away (DV-4a-4). An eviction can only REMOVE keys ⇒ it can never turn a MISS into a
    //    HIT ⇒ over-permit is impossible by construction; the worst case is one extra `POST /sessions`,
    //    which the CONTROLLER authorises (C5).
    if !to_purge.is_empty() {
        let purged = to_purge
            .iter()
            .filter(|(key, id)| evict_dead_dial_session(dial_sessions, key, id))
            .count();
        // ⚠ The wording must NOT contain the singular event's message ("purged dead dial session"): this
        // batch line fires whenever `to_purge` is non-empty, EVEN IF the identity gate skipped every
        // eviction, so a `logs_contain("purged dead dial session")` assert would match it and stop
        // discriminating a real purge from a purge that was gated away. Keep the two texts disjoint.
        tracing::debug!(
            purged,
            proven_dead = to_purge.len(),
            "session refresh: purge arm complete"
        );
    }
}
