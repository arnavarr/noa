//! The CONNECT RESULT: `handleRouterConnectResult` (`sdk-golang@4b6a087`
//! `ziti/ziti.go:2445-2476`), the half of the bind loop that turns a finished connect attempt into
//! a listen attempt — or into nothing.
//!
//! The port is SYNCHRONOUS and returns a PLAN, exactly as `super::scan` does: where the oracle does
//! `go mgr.createListener(routerConnection, mgr.session, attemptId)` (`:2475`), this function
//! returns the minted `AttemptId` and lets the caller launch the listen. `createListener` itself
//! (`:2478-2509`) is NOT ported — it calls the real bind (`routerConnection.Listen(...)`, `:2484`)
//! and publishes on `eventChan` — and belongs to the slice `l3-listener-registry`.
//!
//! ⚠ The count read at `:2446` (`listenerCount := mgr.listener.GetListenerCount()`) is **LOG-ONLY**
//! — its only two consumers are the log fields of `:2449` and `:2473` — and the port, which emits
//! no observability, does not make it. The read that DECIDES is the one inside the gate of `:2466`,
//! taken FRESH. Reusing the `:2446` value for the gate would be a stale sampling point, which is
//! why it is forbidden rather than merely skipped.

use super::attempts::{AttemptId, ListenAttempts};
use super::listener_count::{MaxTerminators, needs_more_listeners};
use super::registry::ListenerRegistry;

/// Port of `handleRouterConnectResult` (`ziti/ziti.go:2445-2476`).
///
/// `router_url` is `result.routerUrl` (`:2455`) and `connected_router_name` fuses two things the
/// oracle reads from the same place: `result.routerConnection == nil` (`:2457`) becomes `None`, and
/// `routerConnection.GetRouterName()` (`:2461`) becomes the `Some`. ⚠ `Some("")` is a connection
/// whose router has an empty name, which is NOT the same as `None`.
///
/// The two keys are DIFFERENT strings and the port does not confuse them: the connect mark is
/// cleared by URL (`:2455`) and the pending listen is marked by the name the CONNECTION reports
/// (`:2461`), never by `result.routerName`, which the oracle only logs (`:2450`).
///
/// Returns the minted [`AttemptId`] when a listen should be established — the argument the oracle
/// hands to the `go` of `:2475` — and `None` in each of the three early returns. The counter does
/// NOT advance in any of them (`:2470` sits after all three guards).
///
/// ⚠ **Obligation of the caller (T-15 of the slice spec):** a caller that receives `Some(id)` MUST
/// launch the listen (`createListener`) for it — an unlaunched mint leaves an immortal
/// `pending_listens` entry; see spec §12 T-15. The mint and the `go` of `:2475` are one step in the
/// oracle, and deferring the `go` (D-2) is what splits them: the only cleaner of that entry,
/// `ListenAttempts::clear_pending_if_current`, is fed by the events of `ziti.go:2690-2693` and
/// `:2719-2722`, which exist only if somebody actually launched `createListener`. A router marked
/// pending forever is then skipped forever at `:2523` and `:2462`, and its slot keeps counting
/// against the cap of `:2555` — under-permit that never heals.
///
/// ⚠ **Obligation of the caller (T-12 of the slice spec):** the session `createListener` receives
/// is the one CURRENT at the instant of the `go` of `:2475`
/// (`go mgr.createListener(routerConnection, mgr.session, attemptId)`), not the one in force when
/// the connect started; see spec §12 T-12. Porting `createListener` with any other session would be
/// a silent wire change.
pub(super) fn handle_router_connect_result(
    attempts: &mut ListenAttempts,
    registry: &impl ListenerRegistry,
    max_terminators: MaxTerminators,
    router_url: &str,
    connected_router_name: Option<&str>,
) -> Option<AttemptId> {
    // `:2455` — UNCONDITIONAL, and before looking at whether the connect succeeded: a failed
    // connect also frees the window of its url.
    attempts.clear_connect(router_url);

    // `:2456-2459` — a nil connection ends here, with the ledger already touched by the line above.
    let router_name = connected_router_name?;

    // `:2461-2464` — the registry is asked first, the ledger second.
    let has_listener = registry.has_listener_for_router(router_name);
    if attempts.should_skip_router(has_listener, router_name) {
        return None;
    }

    // `:2466-2468` — the gate, with its own FRESH read of the count.
    if !needs_more_listeners(
        registry.is_closed(),
        registry.listener_count(),
        attempts.pending_count(),
        max_terminators,
    ) {
        return None;
    }

    // `:2470-2472` — mint the id, then mark the router pending, in that order and only here.
    let id = attempts.next_attempt_id();
    attempts.mark_pending(router_name, id);
    Some(id)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::handle_router_connect_result;
    use crate::edge::listener_manager::attempts::ListenAttempts;
    use crate::edge::listener_manager::listener_count::MaxTerminators;
    use crate::edge::listener_manager::registry::{FakeRegistry, RegistryCall};

    fn cap(n: i32) -> MaxTerminators {
        MaxTerminators::resolve(n, 0)
    }

    // ─────────── Group H — `handle_router_connect_result` (12) ───────────

    /// H1 — ⭐ the `delete` of `:2455` runs BEFORE the nil guard of `:2457`, so a FAILED connect
    /// also releases the window of its url. That ordering is the whole observable of the pair.
    /// MUTATION → RED: move `clear_connect` below the nil guard.
    #[test]
    fn the_connect_mark_is_cleared_even_when_the_connection_is_nil() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        ledger.mark_connect_started("tls:r1:443", base);
        let registry = FakeRegistry::new();
        let out = handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", None);
        assert!(out.is_none());
        assert!(!ledger.connect_in_progress("tls:r1:443", base));
    }

    /// H2 — the SCOPE of the delete of `:2455`: only the named url is forgotten. ⚠ TWO live
    /// entries are needed, or `remove(k)` and `clear()` are indistinguishable.
    /// MUTATION → RED: `remove(k)` → `clear()`.
    #[test]
    fn clearing_one_connect_leaves_the_other_urls_in_progress() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        ledger.mark_connect_started("tls:r1:443", base);
        ledger.mark_connect_started("tls:r2:443", base);
        let registry = FakeRegistry::new();
        let _out = handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", None);
        assert!(!ledger.connect_in_progress("tls:r1:443", base));
        assert!(ledger.connect_in_progress("tls:r2:443", base));
    }

    /// H3 — the nil guard of `:2457-2459`: no connection, no attempt.
    /// MUTATION → RED: delete the guard.
    #[test]
    fn a_nil_connection_mints_no_attempt() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new();
        let out = handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", None);
        assert!(out.is_none());
        assert_eq!(ledger.pending_count(), 0);
    }

    /// H4 — first operand of the skip of `:2462`: the router already has a child listener.
    /// MUTATION → RED: drop the `has_listener` operand.
    #[test]
    fn a_router_that_already_has_a_listener_mints_no_attempt() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new().with_listener("r1");
        let out =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", Some("r1"));
        assert!(out.is_none());
        assert_eq!(ledger.pending_count(), 0);
    }

    /// H5 — second operand of the skip of `:2462`: a listen is already pending for the router.
    /// MUTATION → RED: drop the `is_pending` operand.
    #[test]
    fn a_router_with_a_pending_listen_mints_no_attempt() {
        let mut ledger = ListenAttempts::new();
        let id = ledger.next_attempt_id();
        ledger.mark_pending("r1", id);
        let registry = FakeRegistry::new();
        let out =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", Some("r1"));
        assert!(out.is_none());
        assert_eq!(ledger.pending_count(), 1);
    }

    /// H6 — the gate of `:2466-2468`: at the cap, no attempt is minted.
    /// MUTATION → RED: delete the gate.
    #[test]
    fn a_listener_at_the_cap_mints_no_attempt() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new().count(3);
        let out =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", Some("r1"));
        assert!(out.is_none());
        assert_eq!(ledger.pending_count(), 0);
    }

    /// H7 — POSITIVE control of the four guards above: the good path mints the FIRST id (the
    /// oracle pre-increments at `:2470`, so it is 1 and never 0) and marks the router pending
    /// (`:2472`).
    /// MUTATION → RED: delete `mark_pending`.
    #[test]
    fn a_usable_result_mints_an_attempt_and_marks_the_router_pending() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new();
        let out =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", Some("r1"));
        assert_eq!(out.map(super::AttemptId::get), Some(1));
        assert_eq!(ledger.pending_count(), 1);
        assert!(ledger.should_skip_router(false, "r1"));
    }

    /// H8 — POSITIVE control of the counter: consecutive results for DIFFERENT routers get
    /// consecutive ids (`:2470-2471`).
    /// MUTATION → RED: reuse the id.
    #[test]
    fn attempt_ids_advance_across_consecutive_results() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new();
        let first =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", Some("r1"));
        let second =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r2:443", Some("r2"));
        assert_eq!(first.map(super::AttemptId::get), Some(1));
        assert_eq!(second.map(super::AttemptId::get), Some(2));
    }

    /// H9 — ⭐ `:2470` sits AFTER the guards of `:2462` and `:2466`, so a rejected result burns no
    /// id: the next ACCEPTED result still receives 1.
    /// MUTATION → RED: hoist `next_attempt_id()` above the guards ⇒ the accepted one gets 2.
    #[test]
    fn an_early_return_does_not_advance_the_attempt_counter() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new().with_listener("r1");
        let rejected =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", Some("r1"));
        assert!(rejected.is_none());
        let accepted =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r2:443", Some("r2"));
        assert_eq!(accepted.map(super::AttemptId::get), Some(1));
    }

    /// H10 — ⭐ the two keys are different strings and each comes from its own source: the clear
    /// uses `result.routerUrl` (`:2455`) and the pending mark uses the name the CONNECTION reports
    /// (`:2461`).
    /// MUTATION → RED: mark by url ⇒ the router name is no longer pending.
    #[test]
    fn the_pending_mark_uses_the_connection_name_and_the_clear_uses_the_result_url() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        ledger.mark_connect_started("tls:r1:443", base);
        let registry = FakeRegistry::new();
        let out = handle_router_connect_result(
            &mut ledger,
            &registry,
            cap(3),
            "tls:r1:443",
            Some("r-alfa"),
        );
        assert!(out.is_some());
        assert!(ledger.should_skip_router(false, "r-alfa"));
        assert!(!ledger.should_skip_router(false, "tls:r1:443"));
        assert!(!ledger.connect_in_progress("tls:r1:443", base));
    }

    /// H11 — the skip predicate of `:2462` is consulted BEFORE the count gate of `:2466`: when the
    /// router already has a listener the gate is never even read, which the recorder shows.
    /// MUTATION → RED: swap the two guards ⇒ `IsClosed`/`ListenerCount` appear in the record.
    #[test]
    fn the_skip_predicate_is_consulted_before_the_count_gate() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new().with_listener("r1");
        let _out =
            handle_router_connect_result(&mut ledger, &registry, cap(3), "tls:r1:443", Some("r1"));
        assert_eq!(
            registry.calls(),
            vec![RegistryCall::HasListenerForRouter("r1".to_string())]
        );
    }

    /// H12 — the `len(mgr.pendingListens)` operand of `:2555` as the gate of `:2466` reads it: a
    /// listen pending for ANOTHER router (`r9`) plus the one listener the registry reports already
    /// reach a cap of 2, so a perfectly good result mints nothing. ⚠ The pending router is NOT the
    /// one the result names, or the skip of `:2462` would return first (that is H5) and the gate
    /// would never be reached; and the count alone does not fill the cap (that is H6).
    /// MUTATION → RED: pass `0` instead of `attempts.pending_count()` in the gate ⇒ `Some(2)`.
    #[test]
    fn pending_listens_of_other_routers_can_close_the_gate_before_minting() {
        let mut ledger = ListenAttempts::new();
        let id = ledger.next_attempt_id();
        ledger.mark_pending("r9", id);
        let registry = FakeRegistry::new().count(1);
        let out =
            handle_router_connect_result(&mut ledger, &registry, cap(2), "tls:r1:443", Some("r1"));
        assert!(out.is_none());
        assert_eq!(ledger.pending_count(), 1);
    }
}
