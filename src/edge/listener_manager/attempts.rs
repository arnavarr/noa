//! The LEDGER of listen attempts: the three accounting fields of the oracle's `listenerManager`
//! (`sdk-golang@4b6a087` `ziti/ziti.go:2266-2282`) with the EXACT predicates of their use sites.
//!
//! | # | Oracle | Here |
//! |---|--------|------|
//! | L1 | `pendingListens map[string]uint64` (`:2271`) | [`ListenAttempts::pending_listens`] |
//! | L2 | `listenAttemptId uint64` (`:2272`) + the pre-increment of `:2470-2471` | [`ListenAttempts::next_attempt_id`] → [`AttemptId`] |
//! | L3 | `mgr.pendingListens[routerName] = attemptId` (`:2472`) | [`ListenAttempts::mark_pending`] |
//! | L4 | the SKIP predicate, identical at `:2462` and `:2523` | [`ListenAttempts::should_skip_router`] |
//! | L5 | the id-CONDITIONED delete of `:2691-2693` and `:2720-2722` | [`ListenAttempts::clear_pending_if_current`] |
//! | L6 | `len(mgr.pendingListens)`, SECOND addend of `:2555` | [`ListenAttempts::pending_count`] |
//! | L7 | `connects map[string]time.Time` (`:2273`) + the `< 30*time.Second` window of `:2535` | [`ListenAttempts::connect_in_progress`] |
//! | L8 | `mgr.connects[routerUrl] = time.Now()` (`:2544`) | [`ListenAttempts::mark_connect_started`] |
//! | L9 | `delete(mgr.connects, result.routerUrl)` (`:2455`) | [`ListenAttempts::clear_connect`] |
//!
//! Out of scope of THIS module: the loop that consults and mutates all of this. Two of its pieces
//! have LANDED since — `makeMoreListeners` (`:2511-2552`) is `super::scan` and
//! `handleRouterConnectResult` (`:2445-2476`) is `super::connect_result` — and so has the QUERY
//! surface of `MultiListener` (`IsClosed` `ziti/edge/network/listener.go:55-57`,
//! `HasListenerForRouter` `:139-148`, `GetListenerCount` `:150-154`), as the trait-seam
//! `super::registry`. Still elsewhere: `createListener` (`:2478-2509`) in
//! **`l3-listener-registry`**, and `run` (`:2307-2381`) in **`l3-listener-run`**. The registry
//! state still arrives here pre-evaluated, to two DISTINCT consumers: `HasListenerForRouter`
//! reaches [`ListenAttempts::should_skip_router`] as a `bool`, while `IsClosed` and
//! `GetListenerCount` feed `needs_more_listeners` (the count gate) as scalars.
//!
//! ⚠ The citation is the QUERY TRIO and never the whole interface (`:89-101`) on purpose: behind
//! that surface sits the REGISTRY (`AddListener` `:273-303`, `forward` `:305-338`, `accept`
//! `:340-349`, `Close` `:351-376`, the `listeners` map with its `listenerLock` `:116-117`), which
//! belongs to NEITHER half of this arc — T-7 of the spec, now **ADJUDICATED to
//! `l3-listener-registry`** together with `createListener`. Citing the containing range to assign
//! only part of it would re-absorb the rest in silence.
//!
//! # No lock, and that is the oracle's own design
//!
//! All ten accesses to the three fields **after construction** hang off `run()`
//! (`go listenerMgr.run()`, `:2250`), which serializes them through its `select` (`:2362-2379`).
//! The census is bounded to post-construction on a happens-before ground, not for convenience: the
//! struct literal that writes TWO of the three fields (`:2225-2226` — `listenAttemptId` is left at
//! Go's zero because the literal does not mention it) runs in the CREATING goroutine, BEFORE the
//! `go` of `:2250`, so it competes with nobody. The two goroutines the loop spawns do not touch the
//! ledger either (`createListener` takes the `attemptId` BY VALUE, `:2475`, and
//! `handleConnectEdgeRouter` is a method of `mgr.context`, not of `mgr`, `:2545`). The contrast
//! proves it is deliberate rather than an oversight: the same author DOES lock what he really
//! shares (`multiListener.listenerLock`, `ziti/edge/network/listener.go:117`).
//!
//! So this is a plain struct owned by ONE task and mutated through `&mut self`: no `Arc`, no
//! `Mutex`, no interior mutability, no `async`. In Rust the compiler enforces what Go leaves to the
//! discipline of routing everything through `run()` — MORE restrictive than the original, with zero
//! observable change. The clock is INJECTED (`now: Instant` is a parameter, the module never calls
//! `Instant::now()`), which makes every operation deterministic; all nine are also total EXCEPT the
//! counter's fail-CLOSED overflow — see [`ListenAttempts::next_attempt_id`].
//!
//! ⚠ Injecting the clock MOVES an obligation to the caller, it does not remove it (D-6 of the
//! spec): every `now` must be an `Instant::now()` of the pass IN PROGRESS, handed to both
//! [`ListenAttempts::mark_connect_started`] and [`ListenAttempts::connect_in_progress`]. What is
//! pinned is FRESHNESS; monotonicity is only its corollary. The house pattern is the same
//! (`src/tunnel/udp/runner.rs:71`, where `Instant::now()` is read at the call site and passed in).
//!
//! That obligation is **DISCHARGED for the two callers of this arc** (residue R-4, closed for them
//! by §7 D-6 of `docs/superpowers/specs/2026-08-13-l3-listener-loop-scan-design.md`): `super::scan`
//! takes `now: &dyn Fn() -> Instant` and reads it AT EVERY SITE the oracle reads its clock — once
//! per window check (`:2535`) and once per mark (`:2544`) — instead of once per pass. Hoisting the
//! read would store a start EARLIER than the real one, shortening the window: over-permit. R-4
//! stays live only for FUTURE callers of this ledger, `l3-listener-run` first among them.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::time::{Duration, Instant};

/// The window of `:2535` (`30*time.Second`). SINGLE seat of the literal: the loop does not need it
/// because the ledger encapsulates the window.
const CONNECT_IN_PROGRESS_WINDOW: Duration = Duration::from_secs(30);

/// The id of one listen attempt: `attemptId := mgr.listenAttemptId` (`:2471`).
///
/// `NonZeroU64` and not `u64` because the oracle PRE-increments (`:2470-2471`), so the first id it
/// ever hands out is **1** and the `0` never travels. The invariant belongs to the TYPE, not to the
/// discipline of the caller: the field is private and the only way in is
/// [`ListenAttempts::next_attempt_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AttemptId(NonZeroU64);

impl AttemptId {
    /// The raw id, as the oracle's `uint64` carries it inside the listen events
    /// (`routerConnectionListenFailedEvent` `:2685-2688`, `listenSuccessEvent` `:2714-2717`).
    pub(super) const fn get(self) -> u64 {
        self.0.get()
    }
}

/// The three accounting fields of `listenerManager` (`:2271-2273`), and nothing else.
///
/// Built empty, exactly as the struct literal of `:2221-2229` leaves it: both maps start empty and
/// `listenAttemptId` keeps Go's zero value, `0`, because the literal does not mention it.
#[derive(Debug, Default)]
pub(super) struct ListenAttempts {
    /// L1 — router NAME → attempt id (`:2271`).
    pending_listens: BTreeMap<String, AttemptId>,
    /// L2 — the attempt counter (`:2272`); pre-incremented at `:2470`.
    listen_attempt_id: u64,
    /// L7 — router URL → instant the connect started (`:2273`).
    connects: BTreeMap<String, Instant>,
}

impl ListenAttempts {
    /// A fresh ledger: both maps empty and the counter at Go's zero value (`:2221-2229`).
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// The next attempt id: **increment FIRST, read AFTER** (`:2470-2471`).
    ///
    /// That order is the whole reason the `0` never travels, and the `expect` below is what makes
    /// the order FALSIFIABLE: a post-increment panics with a literal of its own instead of quietly
    /// handing out a zero. A fallback there (`unwrap_or`, `NonZeroU64::MIN`,
    /// `new_unchecked`) would make the pre-increment untestable, so there is none.
    ///
    /// Overflow is a plain `+=`: in debug it panics («attempt to add with overflow»), in release it
    /// wraps to `0` and the `expect` panics. Both arms fail CLOSED, unlike the oracle's silent
    /// `uint64` wrap — which would recycle an id and let a stale event clear a live entry, the very
    /// thing [`Self::clear_pending_if_current`] exists to prevent. Reaching it takes `2^64` listen
    /// attempts (~584 years at one per nanosecond).
    pub(super) fn next_attempt_id(&mut self) -> AttemptId {
        self.listen_attempt_id += 1;
        AttemptId(NonZeroU64::new(self.listen_attempt_id).expect(
            "listenerManager attempt ids are pre-incremented, so they are never zero (sdk-golang@4b6a087 ziti/ziti.go:2470-2471)",
        ))
    }

    /// Mark `router` as having a listen in flight under `id`: the ASSIGNMENT of `:2472`.
    ///
    /// `router` is a router NAME (`*edgeRouter.Name` at `:2523`,
    /// `routerConnection.GetRouterName()` at `:2461`), taken as it comes: unlike the connect urls,
    /// nothing normalizes it on the way in — in the port it is `SessionEdgeRouter::name`
    /// (`crate::edge::model`).
    ///
    /// Marking the same router twice REPLACES the id, because `:2472` is an assignment and not an
    /// insert-if-absent. That is not incidental: it is what leaves the previous attempt STALE, and
    /// what [`Self::clear_pending_if_current`] then relies on. The `insert` return is discarded
    /// because the oracle never reads it.
    pub(super) fn mark_pending(&mut self, router: &str, id: AttemptId) {
        self.pending_listens.insert(router.to_string(), id);
    }

    /// `len(mgr.pendingListens)`, the SECOND addend of the sum in `:2555` — and the THIRD state
    /// parameter of the port's gate (`super::listener_count::needs_more_listeners`). The two
    /// ordinals differ because they count over different structures: the oracle's expression adds
    /// exactly two terms (`GetListenerCount()` + `len(pendingListens)`), while the port's signature
    /// takes four arguments.
    ///
    /// A `&self` read with no interior mutability, so two reads of the ledger taken from the SAME
    /// borrow cannot tear against each other: the compiler forbids anyone mutating it while that
    /// borrow lives. What stays open is tearing against the LISTENER REGISTRY: the other two STATE
    /// inputs of `:2555`, `IsClosed()` and `GetListenerCount()`, of which only the SECOND takes a
    /// lock (`ziti/edge/network/listener.go:150-154`; `IsClosed` is `baseListener`'s atomic load,
    /// `:55-57`, no lock involved). That axis was T-5 of the spec and is now **CLOSED**: the QUERY
    /// surface arrived as [`ListenerRegistry`](super::registry::ListenerRegistry), and §7 D-5 of
    /// `docs/superpowers/specs/2026-08-13-l3-listener-loop-scan-design.md` adjudicates the read
    /// order PER OPERAND (both are re-read live at every gate, and the extra read of the «closed»
    /// arm is inert). The REGISTRY behind that surface is **T-7, ADJUDICATED to
    /// `l3-listener-registry`**, so nothing here is waiting on it.
    pub(super) fn pending_count(&self) -> usize {
        self.pending_listens.len()
    }

    /// The SKIP predicate of `:2462` and `:2523`, ported ONCE although the oracle writes it twice.
    ///
    /// `has_listener` arrives already evaluated because `MultiListener` is not ported — the same
    /// shape in which the count gate takes its own state. ⚠ In Go both operands are always
    /// evaluated (the lookup happens in the `if` init statement, `HasListenerForRouter` is the LEFT
    /// operand of the `||`); here `is_pending` short-circuits when `has_listener` is true.
    /// Direction: INERTE, and for a specific reason — a `BTreeMap` lookup has no observable effect,
    /// no callback, no lock and no counter, so there is nobody to count the skipped call. Contrast
    /// with the count gate's own order, which IS normative precisely because its second operand is
    /// a consumer callback.
    ///
    /// ⚠ Taking `has_listener` as a parameter does NOT move the point at which that state is
    /// SAMPLED — it DELEGATES it to the caller. Those callers now EXIST:
    /// `super::scan::make_more_listeners` and
    /// `super::connect_result::handle_router_connect_result`, and they PIN the sampling point where
    /// the oracle has it — one `HasListenerForRouter` read per router, immediately before this
    /// local lookup (`:2523`, `:2462`). That closes the first half of T-5; the read ORDER of the
    /// other two state inputs of `:2555` is §7 D-5 of the same spec.
    pub(super) fn should_skip_router(&self, has_listener: bool, router: &str) -> bool {
        has_listener || self.is_pending(router)
    }

    /// The id-CONDITIONED delete of `:2691-2693` and `:2720-2722`: drop the entry **only if** the
    /// id stored for `router` is EXACTLY `id`.
    ///
    /// The id travels BY VALUE with the listen task (`:2475`) and comes back inside the event
    /// (`:2685-2688`, `:2714-2717`), so a STALE event — one whose attempt was already superseded by
    /// a newer attempt to the same router — must NOT clear the live entry. That is the state-machine
    /// hazard of this module, and no lock would solve it: the attempt id does.
    ///
    /// Returns `()`: both callers in the oracle ignore the outcome and go on to log and notify
    /// unconditionally. ⚠ In Go the missing-key arm compares `0 == attemptId`, which is doubly
    /// inert (no id handed out is ever 0, and `delete` of an absent key is a no-op); in Rust the arm
    /// does not exist, since `None` never equals `Some(id)`. The observable behaviour is identical.
    pub(super) fn clear_pending_if_current(&mut self, router: &str, id: AttemptId) {
        if self.pending_listens.get(router) == Some(&id) {
            self.pending_listens.remove(router);
        }
    }

    /// Does `url` already have a connect in progress? The `ok && time.Since(..) < 30s` of `:2535`.
    ///
    /// `url` is a router url in its POST-normalization form, `tls:host:port` **without** `://`: the
    /// oracle reads it from `edgeRouter.SupportedProtocols` (`:2528`), already through
    /// `sanitizeSessionUrls`, and in the port the owning stage is `sanitize_supported_protocols`
    /// (`crate::edge::model`). A `tls://host:port` key would simply never match.
    ///
    /// The `<` is STRICT, so a start exactly `30 s` old is NO LONGER in progress. A `now` EARLIER
    /// than the start saturates to an elapsed of `0` and therefore reads as in progress — which
    /// COINCIDES with the oracle, where `time.Since` of a future instant is negative and
    /// `negative < 30s` holds too.
    ///
    /// `now` is the caller's obligation, not the ledger's (D-6 of the spec): it must be an
    /// `Instant::now()` of the pass IN PROGRESS. **FRESHNESS is what is pinned**, not sharing one
    /// reading — a stale `now` reused across passes would keep reading an expired start as «in
    /// progress». `super::scan` discharges it the way the oracle does, reading its clock at THIS
    /// site (`:2535`) and again at the mark (`:2544`), one reading per call.
    pub(super) fn connect_in_progress(&self, url: &str, now: Instant) -> bool {
        self.connects
            .get(url)
            .is_some_and(|start| now.saturating_duration_since(*start) < CONNECT_IN_PROGRESS_WINDOW)
    }

    /// Record that a connect to `url` started at `now`: `:2544`. Same url form as
    /// [`Self::connect_in_progress`]. The `insert` return is discarded, as in the oracle.
    ///
    /// `:2544` is an ASSIGNMENT, not an insert-if-absent: marking the same url again REPLACES the
    /// instant and therefore RESTARTS the window. This is the mirror of the seat
    /// [`Self::mark_pending`] has for `:2472`, and unlike that one it is not what any CAS relies
    /// on — it is simply the semantics of the map write. The ordinary path reaches `:2544` again
    /// WITHIN the window (the `delete` of `:2455` runs first on every connect result, so the
    /// re-mark is an insert over an absent key); what needs a stored start of 30 s or more is a
    /// REPLACEMENT — writing over an entry still PRESENT — because the barrier of `:2535`
    /// `continue`s while the stored start is younger than that.
    ///
    /// `now` carries the same caller obligation as in [`Self::connect_in_progress`] (D-6): an
    /// `Instant::now()` of the pass IN PROGRESS. `super::scan` reads its clock at THIS site
    /// (`:2544`) rather than reusing the one it read for the window check, because a hoisted
    /// reading would store a start EARLIER than the real one and shorten the window — over-permit.
    pub(super) fn mark_connect_started(&mut self, url: &str, now: Instant) {
        self.connects.insert(url.to_string(), now);
    }

    /// Forget the connect to `url`: the `delete` of `:2455`, the first thing
    /// `handleRouterConnectResult` does with the ledger, before it even looks at whether the
    /// connect succeeded. An unknown url is a no-op, exactly as Go's `delete` is.
    pub(super) fn clear_connect(&mut self, url: &str) {
        self.connects.remove(url);
    }

    /// The map lookup of `:2462`/`:2523`, on its own. Private: it has no call site of its own in
    /// the oracle — both sites are the WHOLE predicate, which is
    /// [`Self::should_skip_router`].
    fn is_pending(&self, router: &str) -> bool {
        self.pending_listens.contains_key(router)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::ListenAttempts;

    // ─────────────────── Group A — the attempt counter (3) ───────────────────

    #[test]
    fn first_attempt_id_is_one_not_zero() {
        let mut ledger = ListenAttempts::new();
        assert_eq!(ledger.next_attempt_id().get(), 1);
    }

    #[test]
    fn attempt_ids_are_strictly_increasing() {
        let mut ledger = ListenAttempts::new();
        let ids = [
            ledger.next_attempt_id().get(),
            ledger.next_attempt_id().get(),
            ledger.next_attempt_id().get(),
        ];
        assert_eq!(ids, [1, 2, 3]);
    }

    #[test]
    fn next_attempt_id_does_not_mark_the_router_pending() {
        let mut ledger = ListenAttempts::new();
        let _id = ledger.next_attempt_id();
        assert_eq!(ledger.pending_count(), 0);
        assert!(!ledger.should_skip_router(false, "r1"));
    }

    // ─────────────────── Group B — the pending map (8) ───────────────────

    #[test]
    fn mark_pending_makes_the_router_pending() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        assert!(ledger.should_skip_router(false, "r1"));
        assert_eq!(ledger.pending_count(), 1);
    }

    #[test]
    fn an_unmarked_router_is_not_pending() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        assert!(!ledger.should_skip_router(false, "r2"));
    }

    #[test]
    fn pending_count_counts_distinct_routers() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        let id2 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        ledger.mark_pending("r2", id2);
        assert_eq!(ledger.pending_count(), 2);
    }

    #[test]
    fn marking_the_same_router_twice_replaces_the_attempt_id() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        let id2 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        ledger.mark_pending("r1", id2);
        assert_eq!(ledger.pending_count(), 1);
        // The REPLACEMENT itself is observed through the CAS, not by reading `pending_listens`:
        // the field is private, and reading it would pin the representation instead of the
        // contract. `clear_pending_if_current` clears only when the stored id is EXACTLY the one
        // handed in, so a clear that SUCCEEDS with `id2` is proof that the second `mark_pending`
        // overwrote `id1` — which is precisely what `:2472` being an assignment buys, and what the
        // CAS of `:2691`/`:2720` relies on.
        ledger.clear_pending_if_current("r1", id2);
        assert_eq!(ledger.pending_count(), 0);
    }

    #[test]
    fn clear_pending_if_current_clears_the_matching_attempt() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        ledger.clear_pending_if_current("r1", id1);
        assert_eq!(ledger.pending_count(), 0);
        assert!(!ledger.should_skip_router(false, "r1"));
    }

    #[test]
    fn a_stale_attempt_does_not_clear_a_newer_pending_entry() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        let id2 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        ledger.mark_pending("r1", id2);
        ledger.clear_pending_if_current("r1", id1);
        assert_eq!(ledger.pending_count(), 1);
        assert!(ledger.should_skip_router(false, "r1"));
    }

    #[test]
    fn clear_pending_if_current_on_an_unknown_router_is_a_no_op() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        ledger.clear_pending_if_current("r2", id1);
        assert_eq!(ledger.pending_count(), 1);
        assert!(ledger.should_skip_router(false, "r1"));
    }

    #[test]
    fn clear_pending_if_current_only_clears_the_matching_router() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        let id2 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        ledger.mark_pending("r2", id2);
        // TWO live entries at the instant the matching arm fires: with a single one, `remove(k)`
        // and `clear()` are indistinguishable and the SCOPE of the delete of `:2692`/`:2721` has
        // no falsifier at all.
        ledger.clear_pending_if_current("r1", id1);
        assert_eq!(ledger.pending_count(), 1);
        assert!(ledger.should_skip_router(false, "r2"));
        assert!(!ledger.should_skip_router(false, "r1"));
    }

    // ─────────────────── Group C — the connect window (9) ───────────────────

    #[test]
    fn an_unseen_url_has_no_connect_in_progress() {
        let ledger = ListenAttempts::new();
        let t0 = Instant::now();
        assert!(!ledger.connect_in_progress("tls:r1:443", t0));
    }

    #[test]
    fn a_just_started_connect_is_in_progress() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        ledger.mark_connect_started("tls:r1:443", t0);
        assert!(ledger.connect_in_progress("tls:r1:443", t0));
    }

    #[test]
    fn the_connect_window_is_strict_at_exactly_thirty_seconds() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        ledger.mark_connect_started("tls:r1:443", t0);
        // 30 s − 1 ns, written as a literal instead of a subtraction: clippy's
        // `unchecked_time_subtraction` (MEASURED on this toolchain) rejects `t0 + 30s - 1ns`.
        let just_inside = t0 + Duration::new(29, 999_999_999);
        let exactly_at = t0 + Duration::from_secs(30);
        assert!(ledger.connect_in_progress("tls:r1:443", just_inside));
        assert!(!ledger.connect_in_progress("tls:r1:443", exactly_at));
    }

    #[test]
    fn a_connect_past_the_window_is_not_in_progress() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        ledger.mark_connect_started("tls:r1:443", t0);
        assert!(!ledger.connect_in_progress("tls:r1:443", t0 + Duration::from_secs(31)));
    }

    #[test]
    fn clear_connect_forgets_the_url() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        ledger.mark_connect_started("tls:r1:443", t0);
        ledger.clear_connect("tls:r1:443");
        assert!(!ledger.connect_in_progress("tls:r1:443", t0));
    }

    #[test]
    fn clear_connect_on_an_unknown_url_is_a_no_op() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        ledger.mark_connect_started("tls:r1:443", t0);
        ledger.clear_connect("tls:r2:443");
        assert!(ledger.connect_in_progress("tls:r1:443", t0));
    }

    #[test]
    fn connects_are_keyed_by_url_not_shared_across_urls() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        ledger.mark_connect_started("tls:r1:443", t0);
        assert!(!ledger.connect_in_progress("tls:r1:8443", t0));
    }

    #[test]
    fn a_now_earlier_than_the_start_reads_as_in_progress() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        ledger.mark_connect_started("tls:r1:443", t1);
        assert!(ledger.connect_in_progress("tls:r1:443", t0));
    }

    #[test]
    fn marking_a_connect_again_restarts_the_window() {
        let mut ledger = ListenAttempts::new();
        let t0 = Instant::now();
        ledger.mark_connect_started("tls:r1:443", t0);
        // The 60 s gap is not decoration: a REPLACEMENT (writing over an entry still PRESENT)
        // needs a stored start of 30 s or more, because the barrier of `:2535` `continue`s while
        // it is younger than that. The ordinary path (`delete` at `:2455`, then re-mark) reaches
        // `:2544` within the window too, but over an ABSENT key — which `or_insert` cannot
        // distinguish. `:2544` is an assignment, so the second mark REPLACES the instant and the
        // window restarts from it.
        ledger.mark_connect_started("tls:r1:443", t0 + Duration::from_secs(60));
        assert!(ledger.connect_in_progress("tls:r1:443", t0 + Duration::from_secs(61)));
    }

    // ─────────────────── Group D — the skip predicate (4) ───────────────────

    #[test]
    fn skip_a_router_that_already_has_a_listener() {
        let ledger = ListenAttempts::new();
        assert!(ledger.should_skip_router(true, "r1"));
    }

    #[test]
    fn skip_a_router_with_a_pending_listen() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        assert!(ledger.should_skip_router(false, "r1"));
    }

    #[test]
    fn do_not_skip_an_idle_router() {
        let ledger = ListenAttempts::new();
        assert!(!ledger.should_skip_router(false, "r2"));
    }

    #[test]
    fn skip_when_both_conditions_hold() {
        let mut ledger = ListenAttempts::new();
        let id1 = ledger.next_attempt_id();
        ledger.mark_pending("r1", id1);
        assert!(ledger.should_skip_router(true, "r1"));
    }
}
