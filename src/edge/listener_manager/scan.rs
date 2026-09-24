//! The SCAN: `makeMoreListeners` (`sdk-golang@4b6a087` `ziti/ziti.go:2511-2552`), the half of the
//! bind loop that decides which edge-router urls deserve a connect attempt right now.
//!
//! The port is SYNCHRONOUS and returns a PLAN: where the oracle does
//! `go mgr.context.handleConnectEdgeRouter(name, url, mgr.connectChan)` (`:2545`), this function
//! pushes a [`ConnectRequest`] and hands the vector back. That deferral is observably equivalent
//! and the argument is measured, not aesthetic: `connectChan` has exactly ONE reader (`:2363`,
//! inside the `select` of `run`) and `makeMoreListeners` runs in THAT SAME goroutine (`:2329`,
//! `:2376`, `:2704`), so no connect result can be processed while the scan runs; and the spawned
//! goroutine never touches the ledger (`handleConnectEdgeRouter` is a method of `mgr.context`, not
//! of `mgr`, `ziti.go:1735-1744`). What the deferral DOES move is when the network work starts,
//! which is the caller's property — see the T-11 obligation on [`ConnectRequest`].
//!
//! What is NOT here: the connect itself, the child `edgeHostConn`, the event channel and any
//! logging. The oracle emits `Trace` at `:2518`, `:2524`, `:2530-2531`, `:2537-2538` and
//! `:2542-2543`; the port emits nothing, as the two earlier slices of the arc.

use std::time::Instant;

use super::attempts::ListenAttempts;
use super::listener_count::{MaxTerminators, is_url_usable, needs_more_listeners};
use super::registry::ListenerRegistry;
use crate::edge::model::SessionDetail;
use crate::edge::router_filter::EdgeRouterUrlFilter;

/// One connect the scan decided to start: the two arguments of the `go` of `ziti.go:2545` that are
/// not ambient state (`*edgeRouter.Name` and `routerUrl`).
///
/// ⚠ **Obligation of the caller (T-11 of the slice spec):** the returned requests MUST be launched
/// in `Vec` order, before returning to the select loop — see spec §12 T-11. The equivalence
/// argument for deferring the `go` of `:2545` rests on it: the oracle starts each connect at the
/// point of decision, so a caller that reorders them, or postpones them to a later pass, breaks the
/// equivalence rather than the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConnectRequest {
    /// `*edgeRouter.Name` (`:2523`, `:2545`), NOT normalized on the way in — unlike the url. In the
    /// port it is `SessionEdgeRouter::name` (`crate::edge::model`), which is `String` with
    /// `#[serde(default)]`, so a nameless router arrives as `""`.
    pub(super) router_name: String,
    /// `routerUrl` (`:2528`, `:2545`) in its POST-normalization form, `tls:host:port` **without**
    /// `://`: the owning stage is `sanitize_supported_protocols` (`crate::edge::model`).
    pub(super) router_url: String,
}

/// Port of `makeMoreListeners` (`ziti/ziti.go:2511-2552`): scan the session's edge routers and
/// return the connects that should be started, in the order the oracle would have started them.
///
/// The steps are the oracle's, in its order — with ONE declared intra-pair inversion at `:2523`:
/// the `session == nil` guard (`:2512-2514`) BEFORE the entry gate, so a `None` session never
/// queries the registry; the entry gate (`:2517`); the outer loop over the router slice (`:2522`);
/// the per-router skip (`:2523`), which samples the registry once and the ledger once — in the
/// REVERSE intra-pair order to the oracle's, whose `if` init statement reads `pendingListens`
/// BEFORE the condition's left operand queries the registry (adjudicated inert, spec §7 D-5:
/// every operand is sampled in the same pass, no interleaved effects); the inner loop over the
/// protocol map (`:2528`); the
/// usable-url filter (`:2529`); the in-progress window (`:2535`); the mark-then-emit of
/// `:2544-2545`; and the cap re-check of `:2547`, which returns from the FUNCTION and not just from
/// the inner loop.
///
/// ⚠ **Obligation of the caller (T-11 of the slice spec):** the returned requests MUST be launched
/// in `Vec` order, before returning to the select loop — see spec §12 T-11.
///
/// `now` is read AT EVERY SITE the oracle reads its clock — once per window check (`:2535`) and
/// once per mark (`:2544`) — instead of once per pass. Hoisting it would store a start EARLIER than
/// the real one, shortening the window: over-permit, which is the forbidden direction.
pub(super) fn make_more_listeners(
    attempts: &mut ListenAttempts,
    session: Option<&SessionDetail>,
    filter: Option<&EdgeRouterUrlFilter>,
    registry: &impl ListenerRegistry,
    max_terminators: MaxTerminators,
    now: &dyn Fn() -> Instant,
) -> Vec<ConnectRequest> {
    let mut requests = Vec::new();

    // `:2512-2514` — no session, nothing to scan. BEFORE the gate, so the registry stays untouched.
    let Some(session) = session else {
        return requests;
    };

    // `:2517-2520` — the entry gate.
    if !needs_more_listeners(
        registry.is_closed(),
        registry.listener_count(),
        attempts.pending_count(),
        max_terminators,
    ) {
        return requests;
    }

    // `:2522` — the outer loop, over the router SLICE (deterministic order on both sides).
    for edge_router in &session.edge_routers {
        // `:2523-2526` — the registry is asked about this router, and only then the ledger.
        let has_listener = registry.has_listener_for_router(&edge_router.name);
        if attempts.should_skip_router(has_listener, &edge_router.name) {
            continue;
        }

        // `:2528` — the inner loop, over the protocol MAP by VALUE (D-3 determinizes the order).
        for router_url in edge_router.supported_protocols.values() {
            // `:2529-2533` — prune then filter, in that order.
            if !is_url_usable(filter, router_url) {
                continue;
            }

            // `:2535-2540` — a connect to this url is already in flight.
            if attempts.connect_in_progress(router_url, now()) {
                continue;
            }

            // `:2544-2545` — mark FIRST, emit AFTER.
            attempts.mark_connect_started(router_url, now());
            requests.push(ConnectRequest {
                router_name: edge_router.name.clone(),
                router_url: router_url.clone(),
            });

            // `:2547-2549` — re-read the LIVE count; the `return` leaves the whole function.
            if !needs_more_listeners(
                registry.is_closed(),
                registry.listener_count(),
                attempts.pending_count(),
                max_terminators,
            ) {
                return requests;
            }
        }
    }

    requests
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::{ConnectRequest, make_more_listeners};
    use crate::edge::listener_manager::attempts::ListenAttempts;
    use crate::edge::listener_manager::listener_count::MaxTerminators;
    use crate::edge::listener_manager::registry::{FakeRegistry, RegistryCall};
    use crate::edge::model::{SessionDetail, SessionEdgeRouter, SessionType};
    use crate::edge::router_filter::EdgeRouterUrlFilter;

    /// ⚠ The helper TAKES A NAME, unlike the one in `listener_count`: the scan indexes the ledger
    /// by router name (`:2523`), so a fixture that leaves every router nameless would make them
    /// INDISTINGUISHABLE — deviation D-4 of the spec, measured with a probe before writing this.
    fn router(name: &str, protocols: &[(&str, &str)]) -> SessionEdgeRouter {
        SessionEdgeRouter {
            name: name.to_string(),
            hostname: String::new(),
            supported_protocols: protocols
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    fn session(edge_routers: Vec<SessionEdgeRouter>) -> SessionDetail {
        SessionDetail {
            id: "session-1".to_string(),
            token: "token-1".to_string(),
            service_id: "service-1".to_string(),
            session_type: SessionType::Bind,
            api_session_id: String::new(),
            identity_id: String::new(),
            edge_routers,
        }
    }

    /// A deterministic clock that COUNTS its reads: read `n` (zero-based) answers
    /// `base + step * n`. The counter is what makes the number of clock reads an observable, which
    /// is how the «read at every site» decision (D-6) is pinned.
    struct FakeClock {
        base: Instant,
        step: Duration,
        reads: Cell<u32>,
    }

    impl FakeClock {
        fn new(base: Instant, step: Duration) -> Self {
            Self {
                base,
                step,
                reads: Cell::new(0),
            }
        }

        /// A clock frozen at `base`: every read answers the same instant.
        fn frozen(base: Instant) -> Self {
            Self::new(base, Duration::ZERO)
        }

        fn now(&self) -> Instant {
            let n = self.reads.get();
            self.reads.set(n + 1);
            self.base + self.step * n
        }

        fn reads(&self) -> u32 {
            self.reads.get()
        }
    }

    /// A filter that records every url it is offered and accepts them all.
    fn recording_filter() -> (EdgeRouterUrlFilter, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let filter: EdgeRouterUrlFilter = Arc::new(move |u: &str| {
            recorder.lock().unwrap().push(u.to_string());
            true
        });
        (filter, seen)
    }

    fn cap(n: i32) -> MaxTerminators {
        MaxTerminators::resolve(n, 0)
    }

    fn request(name: &str, url: &str) -> ConnectRequest {
        ConnectRequest {
            router_name: name.to_string(),
            router_url: url.to_string(),
        }
    }

    // ─────────────── Group S — `make_more_listeners` (24) ───────────────

    /// S1 — the `mgr.session == nil` guard of `:2512-2514` returns BEFORE the entry gate of
    /// `:2517`, so in this arm the registry is never consulted. That ordering is observable and the
    /// recorder is what observes it.
    /// MUTATION → RED: move the guard below the entry gate ⇒ `calls()` is no longer empty.
    #[test]
    fn no_session_yields_no_requests_and_never_queries_the_registry() {
        let mut ledger = ListenAttempts::new();
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, None, None, &registry, cap(3), &|| clock.now());
        assert!(out.is_empty());
        assert!(registry.calls().is_empty());
    }

    /// S2 — the entry gate of `:2517` with a CLOSED listener: nothing is scanned even though the
    /// session carries two perfectly usable routers.
    /// MUTATION → RED: delete the entry gate.
    #[test]
    fn a_closed_listener_scans_nothing() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![
            router("r1", &[("tls", "tls:r1:443")]),
            router("r2", &[("tls", "tls:r2:443")]),
        ]);
        let registry = FakeRegistry::new().closed();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert!(out.is_empty());
    }

    /// S3 — the other arm of the entry gate of `:2517`: already AT the cap.
    /// MUTATION → RED: delete the entry gate.
    #[test]
    fn a_listener_already_at_the_cap_scans_nothing() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![
            router("r1", &[("tls", "tls:r1:443")]),
            router("r2", &[("tls", "tls:r2:443")]),
        ]);
        let registry = FakeRegistry::new().count(3);
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert!(out.is_empty());
    }

    /// S4 — the happy path of `:2542-2545`: one usable url becomes one connect request, carrying
    /// the router NAME and the router URL in their own fields.
    /// MUTATION → RED: return an empty vector, or swap the two fields.
    #[test]
    fn one_usable_url_yields_one_connect_request() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(out, vec![request("r1", "tls:r1:443")]);
    }

    /// S5 — first operand of the skip of `:2523`: the router already has a child listener.
    /// MUTATION → RED: drop the `has_listener` operand.
    #[test]
    fn a_router_that_already_has_a_listener_is_skipped() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new().with_listener("r1");
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert!(out.is_empty());
    }

    /// S6 — second operand of the skip of `:2523`: a listen is already pending for the router.
    /// MUTATION → RED: drop the `is_pending` operand.
    #[test]
    fn a_router_with_a_pending_listen_is_skipped() {
        let mut ledger = ListenAttempts::new();
        let id = ledger.next_attempt_id();
        ledger.mark_pending("r1", id);
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert!(out.is_empty());
    }

    /// S7 — the `continue` of `:2525` goes to the NEXT ROUTER, it does not abandon the scan.
    /// MUTATION → RED: `continue` → `return` ⇒ `r2` is never reached.
    #[test]
    fn a_skipped_router_does_not_stop_the_scan_of_the_next_router() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![
            router("r1", &[("tls", "tls:r1:443")]),
            router("r2", &[("tls", "tls:r2:443")]),
        ]);
        let registry = FakeRegistry::new().with_listener("r1");
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(out, vec![request("r2", "tls:r2:443")]);
    }

    /// S8 — the `continue` of `:2532` goes to the next URL OF THE SAME ROUTER. ⚠ The fixture is
    /// part of the falsifier: the REJECTED url must order BEFORE the accepted one by key
    /// (`"tls" < "tls2"`), or a `break` would stay green.
    /// MUTATION → RED: `continue` → `break`/`return`.
    #[test]
    fn a_url_the_filter_rejects_does_not_stop_the_scan_of_its_router() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router(
            "r1",
            &[("tls", "tls:r1:443"), ("tls2", "tls:r1:8443")],
        )]);
        let only_second: EdgeRouterUrlFilter = Arc::new(|u: &str| u == "tls:r1:8443");
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(
            &mut ledger,
            Some(&s),
            Some(&only_second),
            &registry,
            cap(3),
            &|| clock.now(),
        );
        assert_eq!(out, vec![request("r1", "tls:r1:8443")]);
    }

    /// S9 — the NORMATIVE order inside the usable predicate: the prune runs FIRST, so the consumer
    /// callback is never offered a url the oracle's `sanitizeSessionUrls` would have dropped. ⚠ The
    /// unparseable entry orders BEFORE the usable one by key (`"http" < "tls"`), so the scan really
    /// reaches it.
    /// MUTATION → RED: evaluate the filter first ⇒ the seen list also carries `http:r1:80`.
    #[test]
    fn an_unparseable_url_is_never_offered_to_the_filter() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router(
            "r1",
            &[("http", "http:r1:80"), ("tls", "tls:r1:443")],
        )]);
        let (recording, seen) = recording_filter();
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(
            &mut ledger,
            Some(&s),
            Some(&recording),
            &registry,
            cap(3),
            &|| clock.now(),
        );
        assert_eq!(out, vec![request("r1", "tls:r1:443")]);
        assert_eq!(*seen.lock().unwrap(), vec!["tls:r1:443".to_string()]);
    }

    /// S10 — the in-progress window of `:2535-2539`: a url whose connect started at the very
    /// instant the scan reads is skipped.
    /// MUTATION → RED: delete the window check.
    #[test]
    fn a_url_with_a_connect_in_progress_is_skipped() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        ledger.mark_connect_started("tls:r1:443", base);
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(base);
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert!(out.is_empty());
    }

    /// S11 — the `continue` of `:2539` goes to the next URL of the same router. ⚠ The in-progress
    /// url orders BEFORE the free one by key (`"tls" < "tls2"`).
    /// MUTATION → RED: `continue` → `return`.
    #[test]
    fn an_in_progress_url_does_not_stop_the_scan_of_its_router() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        ledger.mark_connect_started("tls:r1:443", base);
        let s = session(vec![router(
            "r1",
            &[("tls", "tls:r1:443"), ("tls2", "tls:r1:8443")],
        )]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(base);
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(out, vec![request("r1", "tls:r1:8443")]);
    }

    /// S12 — the FALSE arm of `:2535`: a start older than the 30 s window no longer blocks, so the
    /// url is attempted again.
    /// MUTATION → RED: invert the window comparison.
    #[test]
    fn a_url_whose_connect_started_past_the_window_is_attempted_again() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        ledger.mark_connect_started("tls:r1:443", base);
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(base + Duration::from_secs(31));
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(out, vec![request("r1", "tls:r1:443")]);
    }

    /// S13 — `:2544` is an ASSIGNMENT: re-attempting a url REPLACES its start, so the window
    /// restarts from the re-mark. ⚠ Three passes are needed because the replacement only happens
    /// over an entry still PRESENT (spec §4.5): pass 1 marks, pass 2 (31 s later) re-marks, pass 3
    /// at the SAME instant as pass 2 must find it in progress again.
    /// MUTATION → RED: `insert` → `or_insert` ⇒ pass 3 re-emits.
    #[test]
    fn re_attempting_a_past_window_url_restarts_its_window() {
        let base = Instant::now();
        let later = base + Duration::from_secs(31);
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new();

        let clock1 = FakeClock::frozen(base);
        let first = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock1.now()
        });
        assert_eq!(first, vec![request("r1", "tls:r1:443")]);

        let clock2 = FakeClock::frozen(later);
        let second = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock2.now()
        });
        assert_eq!(second, vec![request("r1", "tls:r1:443")]);

        let clock3 = FakeClock::frozen(later);
        let third = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock3.now()
        });
        assert!(third.is_empty());
    }

    /// S14 — the mark of `:2544` persists in the ledger, so a second pass at the same instant
    /// does not re-attempt the same url. What this test observes is the PERSISTENCE, not the
    /// mark≺emission order: the swap is unobservable (disjoint state, both before the return;
    /// spec §4.1 nº8) — the order is kept for pin fidelity and protected by review.
    /// MUTATION → RED: delete `mark_connect_started`.
    #[test]
    fn a_second_pass_does_not_re_attempt_a_url_the_first_pass_marked() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new();

        let clock1 = FakeClock::frozen(base);
        let first = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock1.now()
        });
        assert_eq!(first.len(), 1);

        let clock2 = FakeClock::frozen(base);
        let second = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock2.now()
        });
        assert!(second.is_empty());
    }

    /// S15 — the cap re-check of `:2547-2549` bites INSIDE a single router. ⚠ `count_step(1)` is
    /// not decoration: the scan mutates neither the registry nor `pendingListens`, so with a STATIC
    /// registry the re-check could never bite and this assert would be unsatisfiable in the good
    /// world. The step models the `AddListener` the real connect fires concurrently.
    /// MUTATION → RED: delete the re-check ⇒ 2 requests.
    #[test]
    fn the_scan_stops_at_the_cap_inside_a_single_router() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router(
            "r1",
            &[("tls", "tls:r1:443"), ("tls2", "tls:r1:8443")],
        )]);
        let registry = FakeRegistry::new().count(0).count_step(1);
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(1), &|| {
            clock.now()
        });
        assert_eq!(out, vec![request("r1", "tls:r1:443")]);
    }

    /// S16 — the `return` of `:2548` leaves the FUNCTION, not just the inner loop: with the cap
    /// reached inside `r1`, the router `r2` is never scanned.
    /// MUTATION → RED: `return` → `break` ⇒ `r2` is emitted too.
    #[test]
    fn the_scan_stops_at_the_cap_across_routers() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![
            router("r1", &[("tls", "tls:r1:443")]),
            router("r2", &[("tls", "tls:r2:443")]),
        ]);
        let registry = FakeRegistry::new().count(0).count_step(1);
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(1), &|| {
            clock.now()
        });
        assert_eq!(out, vec![request("r1", "tls:r1:443")]);
    }

    /// S17 — ⭐ the re-check of `:2547` re-READS the listener count instead of reusing the value the
    /// entry gate saw: the registry is LIVE state (`GetListenerCount()` takes `listenerLock` at
    /// `ziti/edge/network/listener.go:150-154` precisely because it changes underneath). With the
    /// count rising by one per read and a cap of 2, the third url is never emitted.
    /// MUTATION → RED: freeze the count (read it once and reuse it) ⇒ 3 requests.
    #[test]
    fn the_cap_re_check_reads_the_listener_count_live() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router(
            "r1",
            &[
                ("tls", "tls:r1:443"),
                ("tls2", "tls:r1:8443"),
                ("tls3", "tls:r1:9443"),
            ],
        )]);
        let registry = FakeRegistry::new().count(0).count_step(1);
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(2), &|| {
            clock.now()
        });
        assert_eq!(
            out,
            vec![request("r1", "tls:r1:443"), request("r1", "tls:r1:8443"),]
        );
    }

    /// S18 — POSITIVE control of S15/S16/S17: with room to spare, BOTH urls of the same router are
    /// attempted, so the inner loop of `:2528` really iterates.
    /// MUTATION → RED: `break` after the first emission.
    #[test]
    fn two_urls_of_the_same_router_are_both_attempted_when_the_cap_allows() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router(
            "r1",
            &[("tls", "tls:r1:443"), ("tls2", "tls:r1:8443")],
        )]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(
            out,
            vec![request("r1", "tls:r1:443"), request("r1", "tls:r1:8443"),]
        );
    }

    /// S19 — deviation D-3: routers are visited in SESSION order (the oracle ranges a slice at
    /// `:2522`, so the order is deterministic on both sides) and urls in ASCENDING KEY order (the
    /// oracle ranges a map at `:2528`, i.e. at random; our `BTreeMap` determinizes it).
    /// MUTATION → RED: reverse either traversal.
    #[test]
    fn routers_are_visited_in_session_order_and_urls_ascending_by_key() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![
            router("r1", &[("tls", "tls:r1:443"), ("tls2", "tls:r1:8443")]),
            router("r2", &[("tls", "tls:r2:443")]),
        ]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(
            out,
            vec![
                request("r1", "tls:r1:443"),
                request("r1", "tls:r1:8443"),
                request("r2", "tls:r2:443"),
            ]
        );
    }

    /// S20 — ⭐ deviation D-6: the clock is read AT EVERY SITE the oracle reads it, not once per
    /// pass. MEASURED value of this fixture: the pruned url (`http`) never reaches the window
    /// check, so there are 2 checks (`:2535`) + 2 marks (`:2544`) = **4** reads.
    /// MUTATION → RED: hoist the read out of the loop ⇒ 1.
    #[test]
    fn the_clock_is_read_at_every_window_check_and_every_mark() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router(
            "r1",
            &[
                ("http", "http:r1:80"),
                ("tls", "tls:r1:443"),
                ("tls2", "tls:r1:8443"),
            ],
        )]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(out.len(), 2);
        assert_eq!(clock.reads(), 4);
    }

    /// S21 — the per-router sampling point of `:2523` (T-5 of the ledger spec): the registry is
    /// asked about EVERY scanned router, exactly ONCE each, in scan order — not once before the
    /// loop.
    /// MUTATION → RED: sample once before the outer loop ⇒ a single `HasListenerForRouter` entry.
    #[test]
    fn the_registry_is_asked_about_every_scanned_router_exactly_once_in_order() {
        let mut ledger = ListenAttempts::new();
        let s = session(vec![
            router("r1", &[("tls", "tls:r1:443")]),
            router("r2", &[("tls", "tls:r2:443")]),
        ]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let _out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        let asked: Vec<RegistryCall> = registry
            .calls()
            .into_iter()
            .filter(|c| matches!(c, RegistryCall::HasListenerForRouter(_)))
            .collect();
        assert_eq!(
            asked,
            vec![
                RegistryCall::HasListenerForRouter("r1".to_string()),
                RegistryCall::HasListenerForRouter("r2".to_string()),
            ]
        );
    }

    /// S22 — a router whose protocol map is EMPTY: the inner `for` of `:2528` does not iterate, so
    /// nothing is emitted and the ledger stays untouched.
    /// MUTATION → RED: emit with an empty url ⇒ the empty key shows up as in progress.
    #[test]
    fn a_router_with_an_empty_protocol_map_yields_no_request() {
        let base = Instant::now();
        let mut ledger = ListenAttempts::new();
        let s = session(vec![router("r1", &[])]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(base);
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert!(out.is_empty());
        assert_eq!(ledger.pending_count(), 0);
        assert!(!ledger.connect_in_progress("", base));
    }

    /// S23 — the `len(mgr.pendingListens)` operand of `:2555` as the ENTRY gate of `:2517` reads
    /// it: a listen pending for ANOTHER router (`r9`) already fills a cap of 1, so nothing is
    /// scanned even though `r1` is usable and the registry reports zero listeners. ⚠ The pending
    /// router is NOT the scanned one on purpose: `should_skip_router` would swallow the difference
    /// (that is S6), and only a pending entry the per-router skip cannot see reaches the gate.
    /// MUTATION → RED: pass `0` instead of `attempts.pending_count()` in THIS gate ⇒ one request.
    #[test]
    fn the_entry_gate_counts_pending_listens_of_other_routers() {
        let mut ledger = ListenAttempts::new();
        let id = ledger.next_attempt_id();
        ledger.mark_pending("r9", id);
        let s = session(vec![router("r1", &[("tls", "tls:r1:443")])]);
        let registry = FakeRegistry::new();
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(1), &|| {
            clock.now()
        });
        assert!(out.is_empty());
    }

    /// S24 — the same operand at the OTHER site of the same function: the cap re-check of `:2547`.
    /// With the live count rising by one per read, a pending listen for `r9` makes the sum cross a
    /// cap of 3 exactly ONE emission earlier than it would without it, so the third url is never
    /// attempted. ⚠ The entry gate passes either way here (0 + 1 < 3), which is what makes this
    /// test discriminate the re-check site from the entry site.
    /// MUTATION → RED: pass `0` instead of `attempts.pending_count()` in the RE-CHECK ⇒ 3 requests.
    #[test]
    fn the_cap_re_check_counts_pending_listens_of_other_routers() {
        let mut ledger = ListenAttempts::new();
        let id = ledger.next_attempt_id();
        ledger.mark_pending("r9", id);
        let s = session(vec![router(
            "r1",
            &[
                ("tls", "tls:r1:443"),
                ("tls2", "tls:r1:8443"),
                ("tls3", "tls:r1:9443"),
            ],
        )]);
        let registry = FakeRegistry::new().count(0).count_step(1);
        let clock = FakeClock::frozen(Instant::now());
        let out = make_more_listeners(&mut ledger, Some(&s), None, &registry, cap(3), &|| {
            clock.now()
        });
        assert_eq!(
            out,
            vec![request("r1", "tls:r1:443"), request("r1", "tls:r1:8443"),]
        );
    }
}
