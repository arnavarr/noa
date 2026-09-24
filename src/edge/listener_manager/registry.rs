//! The QUERY surface of the oracle's `MultiListener`, as a SEAM — and **nothing else**.
//!
//! | # | Oracle | Here |
//! |---|--------|------|
//! | Q1 | `IsClosed()` (`sdk-golang@4b6a087` `ziti/edge/network/listener.go:55-57`) | [`ListenerRegistry::is_closed`] |
//! | Q2 | `HasListenerForRouter(routerName)` (`:139-148`) | [`ListenerRegistry::has_listener_for_router`] |
//! | Q3 | `GetListenerCount()` (`:150-154`) | [`ListenerRegistry::listener_count`] |
//!
//! ⚠ The trio is cited instead of the whole `MultiListener` interface (`:89-101`) on purpose:
//! behind that surface sits the REGISTRY (`AddListener` `:273-303`, `forward` `:305-338`, `accept`
//! `:340-349`, `Close` `:351-376`, the `listeners` map with its `listenerLock` `:116-117`), which
//! is **not ported** and belongs to the slice `l3-listener-registry` together with `createListener`
//! (`ziti/ziti.go:2478-2509`). Citing the containing range would assign it here by accident.
//!
//! # Why a trait and not three scalars
//!
//! The two consumers of this seam consult the parent listener at FIVE distinct moments, and NOT all
//! in one pass: the scan reads it at THREE sites of a single pass — `makeMoreListeners` at
//! `ziti.go:2517`, at `:2523` (once per router) and at `:2547` (after every emission) — while
//! `handleRouterConnectResult` reads it at TWO, `:2462` and `:2466`, in a pass of ITS OWN: the two
//! functions are separate arms of the `select` of `run` (`:2362-2379`), never one call.
//!
//! Those reads are of LIVE state: `GetListenerCount()` moves under the loop's feet because
//! `createListener` IS a goroutine — the oracle launches it with `go` at `ziti.go:2475` — and from
//! inside it calls `AddListener` IN LINE (`:2489`), which registers the child under `listenerLock`
//! (`listener.go:287-289`). The single goroutine `AddListener` itself spawns is `forward`
//! (`listener.go:302`), which owns the `closer` of `:291-298` that later removes the child again.
//! Either way the count changes while the loop sits between two of its own reads, which is the
//! property that matters here.
//!
//! Taking `listener_count: usize` as a scalar would freeze the re-check of `:2547` for the whole
//! pass, and the scan would keep emitting connects after the cap was reached — **over-permit**, the
//! direction this repo forbids. The trait is what preserves the re-read. Falsifier:
//! `the_cap_re_check_reads_the_listener_count_live` in `super::scan`, whose `FakeRegistry` (below,
//! `#[cfg(test)]`) raises the count on every read.
//!
//! The pattern is the house's own: `RouteOps` (`crate::tunnel::intercept::routes::ops`, behind the
//! `intercept` feature) is a trait-seam whose production impl is OS-level and whose tests inject a
//! recorder. Here the production impl arrives with `l3-listener-registry`.

/// The three queries the bind loop makes against the parent listener.
///
/// Nothing else of `MultiListener` is here: no registration, no forwarding, no `Close`. Each method
/// is a LIVE read — implementors must not cache, because the two consumers re-read on purpose (see
/// the module doc).
pub(super) trait ListenerRegistry {
    /// `IsClosed()` (`ziti/edge/network/listener.go:55-57`): `listener.closed.Load()`, an atomic
    /// load of `baseListener` with no lock involved.
    fn is_closed(&self) -> bool;

    /// `GetListenerCount()` (`:150-154`): `len(self.listeners)` under `listenerLock`.
    fn listener_count(&self) -> usize;

    /// `HasListenerForRouter(routerName)` (`:139-148`): does any registered child listener belong
    /// to the router NAMED `router_name`? The oracle compares `v.routerInfo.Name == routerName`
    /// under `listenerLock`.
    fn has_listener_for_router(&self, router_name: &str) -> bool;
}

/// One recorded query against a [`FakeRegistry`], in call order.
///
/// The recorder exists because two requirements of the slice are about WHICH queries happen and in
/// WHAT ORDER, not about their values: the once-per-router sampling of `ziti.go:2523` and the
/// precedence of the skip predicate over the count gate (`:2462` ≺ `:2466`).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RegistryCall {
    /// [`ListenerRegistry::is_closed`] was called.
    IsClosed,
    /// [`ListenerRegistry::listener_count`] was called.
    ListenerCount,
    /// [`ListenerRegistry::has_listener_for_router`] was called with this name.
    HasListenerForRouter(String),
}

/// A scriptable double of the parent listener that also RECORDS every query.
///
/// `count` + `count_step` model the LIVE count: the first `listener_count()` answers `count`, and
/// every later read adds `count_step` — which is the `AddListener` a real connect fires
/// concurrently (`ziti/edge/network/listener.go:273-303`). Without a non-zero step the cap gate of
/// `ziti.go:2547` could never bite in a test, because the scan itself mutates neither the registry
/// nor `pendingListens`.
#[cfg(test)]
#[derive(Debug, Default)]
pub(super) struct FakeRegistry {
    closed: bool,
    count: std::cell::Cell<usize>,
    count_step: usize,
    routers_with_listener: std::collections::BTreeSet<String>,
    calls: std::cell::RefCell<Vec<RegistryCall>>,
}

#[cfg(test)]
impl FakeRegistry {
    /// An open registry with no listeners and no scripted growth.
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Make `IsClosed()` answer `true`.
    pub(super) fn closed(mut self) -> Self {
        self.closed = true;
        self
    }

    /// The value the FIRST `GetListenerCount()` answers.
    pub(super) fn count(self, n: usize) -> Self {
        self.count.set(n);
        self
    }

    /// How much every read AFTER the first adds to the count.
    pub(super) fn count_step(mut self, step: usize) -> Self {
        self.count_step = step;
        self
    }

    /// Register a child listener for the router NAMED `router_name`.
    pub(super) fn with_listener(mut self, router_name: &str) -> Self {
        self.routers_with_listener.insert(router_name.to_string());
        self
    }

    /// Every query received so far, in call order.
    pub(super) fn calls(&self) -> Vec<RegistryCall> {
        self.calls.borrow().clone()
    }
}

#[cfg(test)]
impl ListenerRegistry for FakeRegistry {
    fn is_closed(&self) -> bool {
        self.calls.borrow_mut().push(RegistryCall::IsClosed);
        self.closed
    }

    fn listener_count(&self) -> usize {
        self.calls.borrow_mut().push(RegistryCall::ListenerCount);
        let current = self.count.get();
        self.count.set(current + self.count_step);
        current
    }

    fn has_listener_for_router(&self, router_name: &str) -> bool {
        self.calls
            .borrow_mut()
            .push(RegistryCall::HasListenerForRouter(router_name.to_string()));
        self.routers_with_listener.contains(router_name)
    }
}
