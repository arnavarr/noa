//! Service-set change detection + a service-event listener API (the SDK's `ServiceListener`).
//!
//! T5 (svc-poller), slice 1. Ports the SDK's service-change machinery from `sdk-golang` v1.7.0:
//! * [`service_details_equal`] — `serviceDetailsEqual` (`ziti/ziti.go:815-828`): compares only the
//!   dial/host-relevant fields so metadata churn does not fire spurious `Changed` events.
//! * [`diff_services`] — the event computation of `processServiceUpdates` (`ziti.go:694-781`): turns
//!   a freshly-fetched service list into Added/Changed/Removed events against a local name-keyed cache.
//! * [`ServiceWatcher`] — the local `context.services` cache + the `AddService*Listener` registry
//!   (`ziti.go:351-415`), driven by [`crate::edge::client::EdgeClient::poll_services`].
//!
//! # Scope (T5-1) and the rest of the T5 arc (LANDED since; this comment kept current)
//! This module (T5-1) delivers the change-detection diff + the listener/event API + an explicit
//! `poll_services` (the oracle's `RefreshServices(forceRefresh=true)`, `ziti.go:867`, which always
//! fetches). The rest of the T5 arc is DONE (ancestors of HEAD), NOT deferred: **T5-2a** (`7074763`) =
//! the `IsServiceListUpdateAvailable` update-check + its `GET /current-api-session/service-updates` wire
//! (`client.go:148`), exposed as [`crate::edge::client::EdgeClient::poll_services_if_changed`]; **T5-2b**
//! (`6cb0fb9`) = the background svc-refresh timer arm of `runRefreshes` (`ziti.go:1067`) in
//! [`crate::edge::service_refresh`]. The tunneler's intercept/reconciliation cache (`context.intercepts`,
//! `processServiceAddOrUpdated:783-798`; the Go tunneler is parked on darwin → C `ziti_sdk_c_on_service`
//! is the oracle) is the intercept layer (TLAST TUN): its PRIMITIVE (`InterceptResolver::apply_event`)
//! landed in `dfb3b07` and its live WIRING (svc re-feed, the 3rd `select!` arm of the combined runner)
//! in `6537d26`. This SDK module ports the SERVICE cache + the public event API, which the oracle
//! exposes independently of the tunneler.
//!
//! # Form deviation (conscious, same observable)
//! The oracle exposes THREE typed registration methods (`AddServiceAddedListener`/`...Changed...`/
//! `...Removed...`) wired to an events bus, plus a unified `OnServiceUpdate serviceCB` option
//! (`options.go:22,46`). We expose ONE unified callback receiving a [`ServiceEvent`] that carries the
//! change TYPE — the `serviceCB`/`OnServiceUpdate` shape — registered via `add_service_listener` and
//! deregistered with `remove_service_listener` (the oracle's `AddListener` returns a remove-fn,
//! `ziti.go:368`). Same observable: one callback invocation per service change, tagged with its type.
//! Additionally [`crate::edge::client::EdgeClient::poll_services`] RETURNS the events for a pull-style
//! consumer (a superset of the oracle's emit-only contract).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::edge::model::Service;

/// A change to the identity's service set, detected by a [`poll`](crate::edge::client::EdgeClient::poll_services).
/// Oracle: `ServiceEventType` (`options.go:11-14`) + the `*rest_model.ServiceDetail` carried by each
/// `EventService*` emission (`ziti.go:710`/`:767`/`:770`).
#[derive(Debug, Clone)]
pub enum ServiceEvent {
    /// A service now visible to the identity (no prior cache entry for its name). Oracle:
    /// `EventServiceAdded`.
    Added(Service),
    /// An existing service whose dial/host-relevant definition changed. Oracle: `EventServiceChanged`.
    Changed(Service),
    /// A service no longer visible (its id vanished from the fetched set). Oracle: `EventServiceRemoved`.
    Removed(Service),
}

/// Compare two service details on ONLY the dial/host-relevant fields, so metadata churn (timestamps,
/// `_links`, tags, posture queries, role attributes, terminator strategy, max idle time) does NOT
/// spuriously fire a `Changed` event. Byte-faithful field set of the oracle's `serviceDetailsEqual`
/// (`ziti.go:815-828`): id, name, `encryptionRequired`, permissions, configs, config.
///
/// Permissions and configs are compared ORDER-SENSITIVELY (Go `slices.Equal`); config is compared by
/// deep map equality (Go `reflect.DeepEqual`, here `serde_json::Map`'s structural `PartialEq`). Our
/// [`Service`] models exactly this field set, so this is in practice full equality — but the field set
/// is the load-bearing claim (dropping any one would miss a real change or admit a spurious one).
///
/// CONSCIOUS DEVIATION (LOW, unreachable in practice): Go's `reflect.DeepEqual` over the decoded
/// `map[string]any` treats JSON `1` and `1.0` as equal (Go decodes both to `float64`), whereas
/// `serde_json::Number` keeps integer and float variants distinct — so if the controller serialized the
/// SAME numeric config leaf as an int on one poll and a float on the next, this would fire a spurious
/// `Changed` the oracle would not. Not schema-reachable: the standard config types (`host.v1`/`intercept.v1`)
/// have no float leaves and the controller re-serializes config byte-stably poll-to-poll.
#[must_use]
pub fn service_details_equal(a: &Service, b: &Service) -> bool {
    a.id == b.id
        && a.name == b.name
        && a.encryption_required == b.encryption_required
        && a.permissions == b.permissions
        && a.configs == b.configs
        && a.config == b.config
}

/// Compute the Added/Changed/Removed events for a freshly-fetched service list against `cache` (keyed
/// by service NAME, mirroring `context.services`). PURE — does not mutate `cache`; the caller applies
/// [`apply_cache_update`]. Faithful port of `processServiceUpdates` (`ziti.go:694-725`) + the emit
/// logic of `processServiceAddOrUpdated` (`:752-781`):
///
/// * **Removed**: a CACHED entry whose service ID is absent from the fetched ID set. Detection is by
///   ID even though the cache is keyed by NAME — the oracle builds `idMap` from `*s.ID` while the
///   delete loop iterates name-keyed entries (`ziti.go:697-714`). A subtle quirk preserved exactly: a
///   service RENAMED keeps its ID, so its OLD-name cache entry is NOT removed (its id is still
///   present) and the NEW name is reported `Added`, leaving a stale old-name entry until that id truly
///   disappears.
/// * **Added**: a fetched service whose NAME is not in the cache, OR whose same-name cache entry is
///   itself being Removed this poll (its id vanished from the fetched set). The latter — an intra-poll
///   NAME-REUSE (a service deleted and a new one created under the same name, so a fresh id) — is Added,
///   NOT Changed, matching the oracle's remove-before-upsert ORDERING (`processServiceUpdates` removes the
///   deleted name `ziti.go:716-718` BEFORE the `processServiceAddOrUpdated` upsert sees the cache `:756`).
/// * **Changed**: a fetched service whose NAME is in the cache, whose cached id SURVIVED the poll, and
///   whose details differ ([`service_details_equal`] is `false`).
///
/// Order: Removed first (in cache-iteration order, which is unspecified — the oracle's concurrent-map
/// `IterCb` is likewise unordered), then Added/Changed in fetched-slice order (the oracle's
/// `for _, s := range services`, `ziti.go:722`).
#[must_use]
pub(crate) fn diff_services(
    cache: &HashMap<String, Service>,
    fetched: &[Service],
) -> Vec<ServiceEvent> {
    let fetched_ids: HashSet<&str> = fetched.iter().map(|s| s.id.as_str()).collect();
    let mut events = Vec::new();

    // Removed: cached entries whose ID is no longer present in the fetched set.
    for svc in cache.values() {
        if !fetched_ids.contains(svc.id.as_str()) {
            events.push(ServiceEvent::Removed(svc.clone()));
        }
    }

    // Added and Changed, in fetched-slice order. A fetched name is Changed ONLY when its cache entry
    // SURVIVES this poll (its id is still in the fetched set); a cache entry whose id has vanished is
    // itself being Removed above, so a fetched service re-using that freed NAME is Added, not Changed.
    // This reflects the oracle's remove-before-upsert ORDERING (`processServiceUpdates` removes the
    // deleted names `ziti.go:716-718` BEFORE `processServiceAddOrUpdated`'s `Upsert`/`exist` check
    // `:756`/`:769`), so an intra-poll name-reuse (delete + recreate the same name with a new id) is
    // Added on both sides. (`diff_services` stays PURE — it never mutates `cache` — so this gate is
    // what stands in for the oracle's mid-loop cache mutation.)
    for s in fetched {
        match cache.get(&s.name) {
            Some(existing) if fetched_ids.contains(existing.id.as_str()) => {
                if !service_details_equal(existing, s) {
                    events.push(ServiceEvent::Changed(s.clone()));
                }
            }
            _ => events.push(ServiceEvent::Added(s.clone())),
        }
    }

    events
}

/// Apply the cache mutation that mirrors the oracle's post-diff bookkeeping (`processServiceUpdates`:
/// `services.Remove(deletedKey)` for each removed NAME `ziti.go:716-718`, then `Upsert(*s.Name, ...)`
/// for every fetched service `:756` — the upsert ALWAYS replaces the value, even for an unchanged
/// service). Remove-then-upsert order is faithful (so a fetched service reusing a removed name wins).
fn apply_cache_update(
    cache: &mut HashMap<String, Service>,
    fetched: &[Service],
    events: &[ServiceEvent],
) {
    for ev in events {
        if let ServiceEvent::Removed(svc) = ev {
            cache.remove(&svc.name);
        }
    }
    for s in fetched {
        cache.insert(s.name.clone(), s.clone());
    }
}

/// An opaque handle to a registered service-event listener, returned by [`ServiceWatcher::add`]
/// (`EdgeClient::add_service_listener`) and passed to [`ServiceWatcher::remove`]
/// (`EdgeClient::remove_service_listener`). Oracle: the remove-fn returned by `AddServiceAddedListener`
/// (`ziti.go:368`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceListenerId(u64);

/// A unified service-change listener (the `serviceCB`/`OnServiceUpdate` shape). `Send + Sync` so a
/// future background svc-refresh timer (T5-2) can fan out from a spawned task.
type ServiceListener = Arc<dyn Fn(&ServiceEvent) + Send + Sync>;

/// The local service cache (`context.services`) plus the registered listeners. Owned by `EdgeClient`
/// behind an `Arc` so a future background svc-refresh timer (T5-2) can share it. Shared state, but its
/// `std::sync::Mutex`es are NEVER held across an `.await`: the only async work — the HTTP fetch —
/// happens in `EdgeClient::poll_services` BEFORE [`process`](Self::process) is called, and the
/// listener fan-out runs on a snapshot taken AFTER the cache lock is dropped.
pub(crate) struct ServiceWatcher {
    cache: Mutex<HashMap<String, Service>>,
    listeners: Mutex<Vec<(u64, ServiceListener)>>,
    next_id: AtomicU64,
}

impl ServiceWatcher {
    pub(crate) fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            listeners: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// Register `cb`, returning an id to deregister it. Oracle: `AddListener` (`ziti.go:366`).
    pub(crate) fn add(&self, cb: ServiceListener) -> ServiceListenerId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.listeners
            .lock()
            .expect("service listeners mutex poisoned")
            .push((id, cb));
        ServiceListenerId(id)
    }

    /// Deregister the listener with `id`, returning whether one was removed. Oracle: the remove-fn
    /// (`RemoveListener`, `ziti.go:369`).
    pub(crate) fn remove(&self, id: ServiceListenerId) -> bool {
        let mut g = self
            .listeners
            .lock()
            .expect("service listeners mutex poisoned");
        let before = g.len();
        g.retain(|(lid, _)| *lid != id.0);
        g.len() != before
    }

    /// Diff `fetched` against the cache, UPDATE the cache, fan the events out to every registered
    /// listener, and return them. The fan-out runs on a SNAPSHOT of the listener `Arc`s cloned out
    /// under the listeners lock then invoked UNLOCKED, so a listener that re-enters `add`/`remove`
    /// cannot deadlock the (non-reentrant) `std::sync::Mutex`. Each event is delivered to every
    /// listener (the oracle's per-event `Emit` fan-out, `ziti.go:710`/`:767`/`:770`).
    pub(crate) fn process(&self, fetched: &[Service]) -> Vec<ServiceEvent> {
        let events = {
            let mut cache = self.cache.lock().expect("service cache mutex poisoned");
            let events = diff_services(&cache, fetched);
            apply_cache_update(&mut cache, fetched, &events);
            events
        };

        if !events.is_empty() {
            let snapshot: Vec<ServiceListener> = self
                .listeners
                .lock()
                .expect("service listeners mutex poisoned")
                .iter()
                .map(|(_, cb)| cb.clone())
                .collect();
            for ev in &events {
                for cb in &snapshot {
                    cb(ev);
                }
            }
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(id: &str, name: &str) -> Service {
        Service {
            id: id.into(),
            name: name.into(),
            encryption_required: false,
            permissions: vec!["Dial".into()],
            config: serde_json::Map::new(),
            configs: vec![],
        }
    }

    fn cache_of(services: &[Service]) -> HashMap<String, Service> {
        services
            .iter()
            .map(|s| (s.name.clone(), s.clone()))
            .collect()
    }

    // ───────────────────────── service_details_equal: the field set ─────────────────────────

    #[test]
    fn service_details_equal_true_for_identical() {
        assert!(service_details_equal(&svc("i", "a"), &svc("i", "a")));
    }

    #[test]
    fn service_details_equal_compares_each_relevant_field() {
        let base = svc("i", "a");
        // id differs
        assert!(!service_details_equal(&base, &svc("j", "a")));
        // name differs
        assert!(!service_details_equal(&base, &svc("i", "b")));
        // encryptionRequired differs
        let mut enc = base.clone();
        enc.encryption_required = true;
        assert!(!service_details_equal(&base, &enc));
        // permissions differ (order-sensitive set)
        let mut perm = base.clone();
        perm.permissions = vec!["Bind".into()];
        assert!(!service_details_equal(&base, &perm));
        // configs differ
        let mut cfgs = base.clone();
        cfgs.configs = vec!["c1".into()];
        assert!(!service_details_equal(&base, &cfgs));
        // config (the map) differs
        let mut cfg = base.clone();
        cfg.config
            .insert("host.v1".into(), serde_json::json!({"port": 80}));
        assert!(!service_details_equal(&base, &cfg));
    }

    #[test]
    fn service_details_equal_permissions_order_sensitive() {
        // Go `slices.Equal` is order-sensitive; so is our Vec `==`.
        let mut a = svc("i", "a");
        a.permissions = vec!["Dial".into(), "Bind".into()];
        let mut b = svc("i", "a");
        b.permissions = vec!["Bind".into(), "Dial".into()];
        assert!(!service_details_equal(&a, &b));
    }

    // ───────────────────────── diff_services ─────────────────────────

    #[test]
    fn diff_first_poll_reports_all_added() {
        let cache = HashMap::new();
        let fetched = vec![svc("i1", "a"), svc("i2", "b")];
        let events = diff_services(&cache, &fetched);
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], ServiceEvent::Added(s) if s.name == "a"));
        assert!(matches!(&events[1], ServiceEvent::Added(s) if s.name == "b"));
    }

    #[test]
    fn diff_unchanged_yields_no_events() {
        let cache = cache_of(&[svc("i1", "a")]);
        let events = diff_services(&cache, &[svc("i1", "a")]);
        assert!(
            events.is_empty(),
            "identical service must not emit: {events:?}"
        );
    }

    #[test]
    fn diff_detects_changed() {
        let cache = cache_of(&[svc("i1", "a")]);
        let mut changed = svc("i1", "a");
        changed.encryption_required = true;
        let events = diff_services(&cache, &[changed]);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], ServiceEvent::Changed(s) if s.name == "a"));
    }

    #[test]
    fn diff_detects_removed_by_id() {
        let cache = cache_of(&[svc("i1", "a"), svc("i2", "b")]);
        // Only i1 fetched → i2 (name "b") removed.
        let events = diff_services(&cache, &[svc("i1", "a")]);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], ServiceEvent::Removed(s) if s.id == "i2" && s.name == "b"));
    }

    #[test]
    fn diff_rename_keeps_id_so_no_remove_and_new_name_added() {
        // The oracle's name-keyed cache + id-based delete-detection quirk: renaming a service (same
        // id, new name) does NOT remove the old-name entry (its id is still present) and reports the
        // new name Added. Pins the subtle keying preserved from `processServiceUpdates`.
        let cache = cache_of(&[svc("i1", "old")]);
        let events = diff_services(&cache, &[svc("i1", "new")]);
        assert_eq!(
            events.len(),
            1,
            "rename → exactly one Added, no Removed: {events:?}"
        );
        assert!(matches!(&events[0], ServiceEvent::Added(s) if s.name == "new"));
    }

    #[test]
    fn diff_name_reuse_new_id_is_added_not_changed() {
        // Intra-poll NAME-REUSE: a service "x"/i1 is deleted and a NEW "x"/i2 is created between polls.
        // The oracle removes the old NAME from the cache BEFORE the upsert loop, so the re-used name is
        // reported Added, not Changed (`processServiceUpdates` remove `ziti.go:716-718` runs before the
        // `processServiceAddOrUpdated` upsert→`EventServiceAdded` `:756`/`:769`). F1 fix: a fetched name
        // whose cache entry is itself being Removed (its id ∉ fetched set) must be Added.
        let cache = cache_of(&[svc("i1", "x")]);
        let events = diff_services(&cache, &[svc("i2", "x")]);
        assert_eq!(
            events.len(),
            2,
            "name-reuse → Removed(old id) + Added(new id): {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ServiceEvent::Removed(s) if s.id == "i1" && s.name == "x")),
            "the old id is Removed: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ServiceEvent::Added(s) if s.id == "i2" && s.name == "x")),
            "a re-used name carrying a NEW id is Added, NOT Changed: {events:?}"
        );
    }

    #[test]
    fn diff_name_swap_surviving_id_stays_changed() {
        // Guards the F1 fix against over-correction: when the cached entry's id SURVIVES the poll (here
        // i1 is renamed "a"→"b" while a NEW i2 takes the freed name "a"), the fetched "a"/i2 matches a
        // cache entry ("a"/i1) whose id IS still present → it is Changed, NOT spuriously Added. A naive
        // "differing id ⇒ Added" mutant would turn this Changed into Added and go RED here.
        let cache = cache_of(&[svc("i1", "a")]);
        let events = diff_services(&cache, &[svc("i1", "b"), svc("i2", "a")]);
        assert_eq!(
            events.len(),
            2,
            "no Removed (i1 survives); Added(b)+Changed(a): {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ServiceEvent::Added(s) if s.name == "b")),
            "the renamed-to name 'b' is Added: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ServiceEvent::Changed(s) if s.id == "i2" && s.name == "a")),
            "'a' reusing a SURVIVING cache id is Changed, not Added: {events:?}"
        );
    }

    // ───────────────────────── ServiceWatcher: cache update + fan-out ─────────────────────────

    #[test]
    fn process_updates_cache_and_is_idempotent() {
        let w = ServiceWatcher::new();
        let first = w.process(&[svc("i1", "a"), svc("i2", "b")]);
        assert_eq!(first.len(), 2, "first poll = all Added");
        // Second identical poll → no events (cache now populated).
        let second = w.process(&[svc("i1", "a"), svc("i2", "b")]);
        assert!(second.is_empty(), "idempotent re-poll: {second:?}");
        // A removal on the third poll evicts the cache entry → a later re-add is Added again.
        let third = w.process(&[svc("i1", "a")]);
        assert_eq!(third.len(), 1);
        assert!(matches!(&third[0], ServiceEvent::Removed(s) if s.name == "b"));
        let fourth = w.process(&[svc("i1", "a"), svc("i2", "b")]);
        assert_eq!(fourth.len(), 1);
        assert!(matches!(&fourth[0], ServiceEvent::Added(s) if s.name == "b"));
    }

    #[test]
    fn listeners_receive_each_event_and_can_be_removed() {
        let w = ServiceWatcher::new();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_cb = seen.clone();
        let id = w.add(Arc::new(move |ev: &ServiceEvent| {
            let label = match ev {
                ServiceEvent::Added(s) => format!("+{}", s.name),
                ServiceEvent::Changed(s) => format!("~{}", s.name),
                ServiceEvent::Removed(s) => format!("-{}", s.name),
            };
            seen_cb.lock().unwrap().push(label);
        }));

        w.process(&[svc("i1", "a")]);
        assert_eq!(*seen.lock().unwrap(), vec!["+a".to_string()]);

        // Removing the listener stops further delivery.
        assert!(w.remove(id), "remove returns true for a live id");
        assert!(!w.remove(id), "second remove is a no-op (false)");
        w.process(&[svc("i1", "a"), svc("i2", "b")]); // would push "+b" if still registered
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["+a".to_string()],
            "no events after removal"
        );
    }

    #[test]
    fn add_returns_distinct_ids() {
        let w = ServiceWatcher::new();
        let noop = || Arc::new(|_: &ServiceEvent| {}) as ServiceListener;
        let a = w.add(noop());
        let b = w.add(noop());
        assert_ne!(a, b);
    }

    #[test]
    fn empty_diff_does_not_invoke_listeners() {
        // A poll that produces no events must not call listeners at all.
        let w = ServiceWatcher::new();
        w.process(&[svc("i1", "a")]); // seed the cache
        let calls = Arc::new(AtomicU64::new(0));
        let calls_cb = calls.clone();
        w.add(Arc::new(move |_: &ServiceEvent| {
            calls_cb.fetch_add(1, Ordering::Relaxed);
        }));
        let events = w.process(&[svc("i1", "a")]); // identical → no events
        assert!(events.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
