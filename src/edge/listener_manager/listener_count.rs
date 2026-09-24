//! The LISTENER COUNT GATE: how many edge routers of a session this client can actually use, and
//! whether the bind path still needs more listeners. Faithful port of three **pure** pieces of the
//! oracle's `listenerManager` (`sdk-golang@4b6a087`), WITHOUT the loop that consults them:
//!
//! | # | Oracle | Here |
//! |---|--------|------|
//! | P1 | `getUsableRouterCount` (`ziti/ziti.go:2428-2443`) | `get_usable_router_count` |
//! | P2 | `needsMoreListeners` (`ziti/ziti.go:2554-2556`) | `needs_more_listeners` |
//! | P3 | `edge.ListenOptions.MaxTerminators` (`ziti/edge/conn.go:271`) as `listenSession` leaves it (`ziti/ziti.go:1628-1632` + `:1642-1644`) | `MaxTerminators` |
//!
//! Out of scope of THIS module, each piece with its owning seat (the arc has moved on since this
//! file was written): `makeMoreListeners` (`ziti.go:2511-2552`) is now `super::scan`,
//! `handleRouterConnectResult` (`:2445-2476`) is `super::connect_result`, and the QUERY surface of
//! `MultiListener` (`IsClosed` `ziti/edge/network/listener.go:55-57`, `HasListenerForRouter`
//! `:139-148`, `GetListenerCount` `:150-154`) is the trait-seam `super::registry`. Still outside
//! the arc's ported set: `createListener` (`:2478-2509`), which belongs to the slice
//! **`l3-listener-registry`**. And `sessionRefreshed` (`ziti.go:2383-2426`), the OTHER consumer of
//! P1 in the oracle, belongs to **cluster L2 of the arc — neither `l3-listener-loop-scan` nor
//! `l3-listener-run`**. P2 therefore takes the state that lives in `mgr` as scalar parameters.
//! ⚠ The trio is cited instead of the whole interface (`:89-101`) because the REGISTRY behind it
//! (`AddListener` `:273-303`, `forward`, `accept`, `Close`, the `listeners` map with its
//! `listenerLock` `:116-117`) is a DIFFERENT unit of work — T-7 of the ledger spec, now ADJUDICATED
//! to **`l3-listener-registry`** — and citing the containing range would assign it here by
//! accident.
//!
//! # DV-L3-PRUNE — the oracle PRUNES before counting, we prune INSIDE the count
//!
//! The oracle counts a session whose urls already went through `sanitizeSessionUrls`
//! (`ziti/client.go:528-543`), which drops every address `transport.ParseAddress` cannot parse. In
//! the native build the SDK registers exactly ONE address parser — `tls`
//! (`ziti/edge/addr_parsers.go:26-28` under `//go:build !js`, installed by the `init` of
//! `ziti/edge/conn.go:43-45`) — so only `tls:host:port` urls survive to be counted.
//!
//! Our `sanitize_supported_protocols` (`crate::edge::model`) deliberately does NOT drop
//! unparseable entries (a slice-2 deviation, still live), so a literal port of the loop at
//! `:2435-2440` would count routers the oracle never counts. P1 therefore applies the pruning
//! itself, as the first conjunct of its `USABLE` predicate, APPROXIMATING the native pipeline
//! (prune + filter) without touching `sanitize_supported_protocols`, which also serves the
//! dial/bind path.
//!
//! ⚠ **Approximating, not reproducing.** `parse_tls_address` is LOOSER than the oracle's parser —
//! measured 2026-08-12 on both sides (Rust probe over the real `src/channel/address.rs`; Go probe
//! with `transport/v2 v2.0.215`, the version of the pin) — and the gap has exactly TWO root causes:
//!
//! 1. `split_host_port` (`src/channel/address.rs:25-34`) does not validate what `net.SplitHostPort`
//!    validates: extra colons and brackets inside the host. Classes **R-1** (`tls:::1:443`) and
//!    **R-5** (`tls:a]b:443`, `tls:a[b:443`) — Go DROPS all three, we KEEP them.
//! 2. `u16::from_str` accepts the leading `+` that Go's `strconv.ParseUint` rejects. Class **R-2**
//!    (`tls:r1:+443`).
//!
//! In those classes — and in any composite of them, e.g. `tls:[::1]:+443`, which the two causes
//! cover without needing its own vector — the direction is **over-report**: P1 counts a router the
//! oracle would not have counted, and the filter is offered a url the oracle would have dropped
//! (pinned as a canary by B11). The residue is PRE-EXISTING, its seat is the shared parser
//! (dial/bind path) and it is declared in §12 of
//! `docs/superpowers/specs/2026-07-30-listener-count-gate-design.md` as R-1/R-2/R-5.
//!
//! Outside those classes the direction is **under-permit** — a non-`tls` url is dead weight here
//! anyway, since the only two sites that turn a session router into a connection candidate read
//! `supported_protocols` for a `tls` address and `open_channel` returns
//! `EdgeError::NoTlsEdgeRouter` when the set comes out empty.
//!
//! # DV-L3-BY-VALUE — we count by parseable VALUE, not by the `"tls"` map key
//!
//! The oracle iterates the VALUES of `SupportedProtocols` (`for _, routerUrl := range …`, `:2435`);
//! the protocol name never participates. Our dial/bind sites index by the `"tls"` key instead (the
//! pre-existing DV-4c-2 deviation). P1 keeps the ORACLE's semantics. The single corner where the
//! two criteria differ — key `"ws"` carrying value `"tls://r:443"` (the PRE-sanitize form, exactly
//! as the controller emits it; test B9 uses the post-sanitize `"tls:r:443"` that actually reaches
//! P1) — is not producible by THAT controller (measured on the emitter chain,
//! `openziti/ziti@9bf62f3` `sync_instant.go:671-685`: key ≡ scheme by construction in both arms;
//! spec §7 D-2). ⚠ NOT a license to drop B9 or the R-4 residue: the port does not control which
//! controller talks to it, and B9 protects fidelity to the oracle's `:2435` value iteration.

use std::num::NonZeroUsize;

use crate::channel::address::parse_tls_address;
use crate::edge::model::SessionDetail;
use crate::edge::router_filter::{EdgeRouterUrlFilter, is_edge_router_url_accepted};

/// The default cap a consumer that configures nothing receives: `ziti.DefaultListenOptions()` sets
/// `MaxTerminators: 3` (`ziti/options.go:147`), and `Listen()` is exactly
/// `ListenWithOptions(serviceName, DefaultListenOptions())` (`ziti/ziti.go:1606-1608`).
///
/// ⚠ NOT the `0` of the other `ListenOptions` variant (`edge.NewListenOptions()`,
/// `ziti/edge/conn.go:263-265`): that zero is the start value of a field `listenSession` assigns
/// unconditionally (both arms of `:1628-1632`) before anyone reads it, so it is never an
/// observable default. Pinning it would give one listener by default instead of three.
pub const DEFAULT_MAX_TERMINATORS: i32 = 3;

/// The terminator cap as `listenSession` leaves it: **already normalized, always ≥ 1**.
///
/// The invariant belongs to the TYPE, not to the discipline of whoever uses it: the field is
/// private and the only way in is [`MaxTerminators::resolve`], which walks the oracle's two steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxTerminators(NonZeroUsize);

impl MaxTerminators {
    /// The two steps `listenSession` applies to the cap, in order.
    ///
    /// 1. **Precedence** (`ziti/ziti.go:1628-1632`): `max_terminators` wins unless it is `0`, in
    ///    which case `max_connections` (the deprecated field, `ziti/options.go:104`) is used. The
    ///    test is `!= 0`, NOT `>= 1`: for a negative `max_terminators` the oracle still takes it
    ///    and lets the floor clamp it, which is what the vector `(-1, 5) → 1` discriminates.
    /// 2. **Floor** (`ziti/ziti.go:1642-1644`): anything below `1` becomes `1`.
    ///
    /// This is the ONLY place in the crate where a default `1` may be born. The two conversions
    /// below are infallible BY CONSTRUCTION and panic with distinct literals on purpose, so that
    /// deleting the floor is detectable and the panic says which half broke: only a negative
    /// `chosen` can trip the first, only a zero `chosen` the second.
    #[must_use]
    pub fn resolve(max_terminators: i32, max_connections: i32) -> Self {
        // Step 1 — precedence (`ziti/ziti.go:1628-1632`).
        let mut chosen = if max_terminators != 0 {
            max_terminators
        } else {
            max_connections
        };

        // Step 2 — floor (`ziti/ziti.go:1642-1644`).
        if chosen < 1 {
            chosen = 1;
        }

        // Steps 3 and 4 are infallible given the floor above, and say so with DISTINCT literals:
        // only a negative `chosen` reaches the first, only a zero `chosen` the second.
        let chosen = usize::try_from(chosen).expect(
            "listenSession floor: chosen must be >= 1 (sdk-golang@4b6a087 ziti/ziti.go:1642-1644)",
        );
        Self(NonZeroUsize::new(chosen).expect(
            "listenSession floor: chosen must be non-zero (sdk-golang@4b6a087 ziti/ziti.go:1642-1644)",
        ))
    }

    /// The normalized cap. Never zero.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl Default for MaxTerminators {
    /// `DefaultListenOptions()` put through `listenSession`: `resolve(3, 0)` → **3**.
    ///
    /// Defined by going THROUGH `resolve` on purpose, so the default cannot drift away from the
    /// two steps it is supposed to be the output of.
    fn default() -> Self {
        Self::resolve(DEFAULT_MAX_TERMINATORS, 0)
    }
}

/// How many edge routers of `session` this client can use. Port of `getUsableRouterCount`
/// (`ziti/ziti.go:2428-2443`), plus the pruning the oracle did upstream (see DV-L3-PRUNE).
///
/// A router counts **at most once**, however many usable urls it has: that is the `break` of
/// `:2438`. `session = None` is the `session == nil` of `:2429-2431` and yields `0`.
///
/// ⚠ NORMATIVE ORDER: `parse_tls_address` is evaluated FIRST and the filter SECOND, with
/// short-circuit. That order now lives in a SINGLE seat — [`is_url_usable`], which P1 INVOKES and
/// which `super::scan` invokes too — so the two copies cannot drift; what follows describes the
/// same predicate, at its new address. The filter is a consumer callback that can count its
/// invocations, and in the oracle it only ever sees urls that already survived the prune — so it
/// must not be offered a url the oracle would have dropped, **except in the residue classes where
/// our parser is looser than the oracle's** (R-1/R-5 stray colons and brackets, R-2 the `+` sign;
/// see DV-L3-PRUNE above): there the filter DOES see such a url, direction over-report, pinned as a
/// canary by B11. The visit order WITHIN a router is ours, not the oracle's (Go ranges a map at
/// random; our `BTreeMap` is ascending by key).
// The oracle's only consumer of P1 is `sessionRefreshed` (`ziti.go:2383-2426`; call sites `:2384`
// and `:2385`), which belongs to cluster L2 of the arc — neither `l3-listener-loop-scan` nor
// `l3-listener-run`.
#[allow(dead_code)] // consumer: `sessionRefreshed` (cluster L2 of the arc; not an L3 slice)
pub(super) fn get_usable_router_count(
    session: Option<&SessionDetail>,
    filter: Option<&EdgeRouterUrlFilter>,
) -> usize {
    let Some(session) = session else {
        return 0;
    };

    session
        .edge_routers
        .iter()
        .filter(|edge_router| {
            edge_router
                .supported_protocols
                .values()
                .any(|router_url| is_url_usable(filter, router_url))
        })
        .count()
}

/// Is this router url USABLE by this client? The SINGLE seat of the predicate the oracle spreads
/// over two stages: the prune `sanitizeSessionUrls` did upstream (`ziti/client.go:528-543`, see
/// DV-L3-PRUNE) and the consumer filter of `isEdgeRouterUrlAccepted` (`ziti/options.go:50-51`),
/// which the oracle consults at `ziti.go:2436` (P1) and `ziti.go:2529` (the scan).
///
/// ⚠ NORMATIVE ORDER: `parse_tls_address` is evaluated FIRST and the filter SECOND, with
/// short-circuit — the filter is a consumer callback that can count its invocations, and in the
/// oracle it only ever sees urls that already survived the prune. Offering it a url the oracle
/// would have dropped is over-report. The measured EXCEPTION is the residue where our parser is
/// LOOSER than the oracle's (R-1/R-5 stray colons and brackets, R-2 the `+` sign; see DV-L3-PRUNE):
/// there the filter DOES see such a url, and `usable_router_count_pins_the_r1_parser_residue` is
/// the canary that pins it.
///
/// Both consumers INVOKE this seat instead of inlining the predicate, which is what stops the two
/// copies from drifting: `get_usable_router_count` here, and `make_more_listeners`
/// (`super::scan`) for the scan of `:2529`.
pub(super) fn is_url_usable(filter: Option<&EdgeRouterUrlFilter>, url: &str) -> bool {
    parse_tls_address(url).is_ok() && is_edge_router_url_accepted(filter, url)
}

/// Does the bind path still need more listeners? Port of `needsMoreListeners`
/// (`ziti/ziti.go:2554-2556`), whose whole body is
/// `!mgr.listener.IsClosed() && mgr.listener.GetListenerCount()+len(mgr.pendingListens) < mgr.options.MaxTerminators`.
///
/// TWO of the three state parameters are the ones `l3-listener-loop-scan` PORTED, as the trait-seam
/// [`ListenerRegistry`](super::registry::ListenerRegistry): `MultiListener::IsClosed()`
/// (`ziti/edge/network/listener.go:55-57`) and `MultiListener::GetListenerCount()` (`:150-154`).
/// The third, `len(mgr.pendingListens)` (`ziti.go:2271`), is
/// [`ListenAttempts::pending_count`](super::attempts::ListenAttempts::pending_count), the ledger
/// slice of the arc.
///
/// The `<` is STRICT: a sum equal to the cap already needs nothing. The sum uses
/// `usize::saturating_add` because Go's `int` wraps while Rust would panic in debug; a saturated
/// sum is never `< max_terminators` (whose ceiling is `i32::MAX`), so the answer degrades to
/// `false` — under-permit.
///
/// ⚠ The oracle's `&&` short-circuits the RESULT (a closed listener means `GetListenerCount()` is
/// never called, so its lock is never taken); here the three state values arrive as scalars, i.e.
/// EAGERLY evaluated by whoever calls us. **That read order is no longer an open question**: it was
/// DECIDED in §7 D-5 of `docs/superpowers/specs/2026-08-13-l3-listener-loop-scan-design.md`, with
/// the inertness argued PER OPERAND — `is_closed` is an atomic load with no lock and is the
/// oracle's own first operand; `listener_count` is a method of an INTERNAL trait, not a consumer
/// callback, so the extra read in the «closed» arm has no observable effect; and the sampling axis
/// has no direction, both being valid samples of a value that moves. What that D-n explicitly
/// FORBIDS is reusing the LOG-ONLY read of `ziti.go:2446` as the gate's input at `:2466`: that one
/// WOULD be a stale sampling point. The oracle is not uniform here either, which is why the lock is
/// not the invariant to protect.
// Consumers in the oracle, complete census: `makeMoreListeners` (`ziti.go:2517` and `:2547`) and
// `handleRouterConnectResult` (`:2466`). All three call sites EXIST in the port already, by path:
// `scan.rs` ×2 (the entry gate and the cap re-check) and `connect_result.rs` ×1.
// ⚠ RE-MEDIDO 2026-08-22 (RB-SDK-06 3.ª, disparada por la supresión que añadió
// `qw-dg1-conninspect` 2b): **el cardinal de esta supresión es HOY 0**, no el que su redacción
// anterior daba por vivo. Quitando SOLO esta línea y corriendo el lint ORDINARIO con
// recompilación forzada delante — `touch src/lib.rs && cargo clippy --all-targets --locked` y su
// gemelo `--lib` — salen **0 diagnósticos** en AMBOS instrumentos (baseline con todas las
// supresiones puestas: 0/0; el detector se acredita con las filas vecinas, RE-CORRIDAS en la
// MISMA tirada 2026-08-22: sin el allow de `get_usable_router_count` ⇒ 1, sin el de
// `mod attempts` ⇒ 2 — épocas propias, no heredadas del 2026-08-21).
// La razón de la deriva es la MISMA transitividad que el texto anterior invocaba, pero al revés:
// `mod scan` y `mod connect_result` llevan su propio `#[allow(dead_code)]` (`mod.rs`), y un ítem
// bajo un `#[allow]` se siembra como LIVE ROOT, así que sus tres call-sites revivieron esta
// función. Es exactamente el caso que `mod registry` documenta como «NO allow aquí, y eso es una
// MEDICIÓN». Se deja la supresión puesta y su retirada se registra como deuda del arco (la decide
// su dueño, `l3-listener-run`); lo que NO se deja es la afirmación falsa.
#[allow(dead_code)] // consumers: `scan.rs` ×2 + `connect_result.rs` ×1 — cardinal MEDIDO hoy: 0
pub(super) fn needs_more_listeners(
    is_closed: bool,
    listener_count: usize,
    pending_count: usize,
    max_terminators: MaxTerminators,
) -> bool {
    !is_closed && listener_count.saturating_add(pending_count) < max_terminators.get()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        DEFAULT_MAX_TERMINATORS, MaxTerminators, get_usable_router_count, is_url_usable,
        needs_more_listeners,
    };
    use crate::edge::model::{SessionDetail, SessionEdgeRouter, SessionType};
    use crate::edge::router_filter::EdgeRouterUrlFilter;

    fn router(protocols: &[(&str, &str)]) -> SessionEdgeRouter {
        SessionEdgeRouter {
            name: String::new(),
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

    // ───────────────────────── Group A — `MaxTerminators` (8) ─────────────────────────

    /// Step 1, arm `mt != 0` TRUE: `MaxTerminators` wins over the deprecated `MaxConnections`
    /// (`ziti.go:1628-1629`). MUTATION → RED: force the `else` arm ⇒ 9.
    #[test]
    fn resolve_prefers_max_terminators_when_nonzero() {
        assert_eq!(MaxTerminators::resolve(3, 9).get(), 3);
    }

    /// Step 1, arm `mt != 0` FALSE: fall back to `MaxConnections` (`ziti.go:1630-1631`).
    /// MUTATION → RED: delete the `else` arm ⇒ the floor yields 1.
    #[test]
    fn resolve_falls_back_to_max_connections_when_max_terminators_is_zero() {
        assert_eq!(MaxTerminators::resolve(0, 5).get(), 5);
    }

    /// Step 2 on the all-zero pair (`ziti.go:1642-1644`). MUTATION → RED: delete the floor ⇒
    /// **panic** with the «must be non-zero» literal (0 survives `try_from`, dies at `new`).
    #[test]
    fn resolve_floors_the_all_zero_pair_to_one() {
        assert_eq!(MaxTerminators::resolve(0, 0).get(), 1);
    }

    /// Step 2 over a NEGATIVE fallback: `mc` is taken and then clamped. MUTATION → RED: delete the
    /// floor ⇒ **panic** with the «must be >= 1» literal (a negative dies at `try_from`).
    #[test]
    fn resolve_floors_a_negative_fallback_to_one() {
        assert_eq!(MaxTerminators::resolve(0, -3).get(), 1);
    }

    /// ⭐ THE discriminating vector of `!= 0` vs `>= 1` (§5.2 of the spec). For `mt ≥ 0` the two
    /// readings agree, so only a negative `mt` with a positive `mc` tells them apart: the oracle
    /// takes the `-1` (precedence) and the floor turns it into 1 — it does NOT fall through to 5.
    /// MUTATION → RED: write `max_terminators >= 1` in step 1 ⇒ 5.
    #[test]
    fn resolve_a_negative_max_terminators_wins_the_precedence_and_is_floored() {
        let resolved = MaxTerminators::resolve(-1, 5);
        assert_eq!(resolved.get(), 1);
        assert_ne!(resolved.get(), 5);
    }

    /// Step 2 with both arguments negative. MUTATION → RED: delete the floor ⇒ panic
    /// «must be >= 1».
    #[test]
    fn resolve_floors_a_negative_pair_to_one() {
        assert_eq!(MaxTerminators::resolve(-1, -1).get(), 1);
    }

    /// Both ends of the `i32` domain (§5.3: the sweep is over the whole type, not a sample).
    ///
    /// MUTATION → RED, stated EXISTENTIALLY (there IS one, it is not «any clamp»): a clamp whose
    /// ceiling is LOWER than `i32::MAX` — e.g. one routed through `u16` — tips the second assert. A
    /// plain fallback does NOT: with the floor standing, `try_from(..).unwrap_or(usize::MAX)` is
    /// UNREACHABLE (MEASURED 2026-08-12: 26/26 green). That axis is watched by rows B3.1/B3.2 of
    /// the §9 census — real reds, each with the floor deleted — with B3.3 as the expected-green
    /// control, not by a test. The second assert also falls under B2.2 and B1.1, both already
    /// censused (MEASURED: their sets carry A7).
    #[test]
    fn resolve_handles_the_i32_extremes_without_panicking() {
        assert_eq!(MaxTerminators::resolve(i32::MIN, i32::MAX).get(), 1);
        assert_eq!(
            MaxTerminators::resolve(i32::MAX, i32::MIN).get(),
            i32::MAX as usize
        );
    }

    /// RB-SDK-03: of the TWO `ListenOptions` variants, the default comes from the one that models
    /// OUR api (`ziti/options.go:147` = 3), not from `edge.NewListenOptions()`
    /// (`ziti/edge/conn.go:264` = 0). MUTATION → RED: pin the edge variant ⇒ 1, not 3.
    #[test]
    fn default_max_terminators_is_three_not_the_edge_variant_zero() {
        assert_eq!(MaxTerminators::default().get(), 3);
        assert_eq!(DEFAULT_MAX_TERMINATORS, 3);
    }

    // ─────────────────── Group B — `get_usable_router_count` (12) ───────────────────

    /// The `session == nil` guard of `:2429-2431`. MUTATION → RED: return `1` for the `None` arm.
    /// (Deleting the guard outright does not compile — the COMPILER is the falsifier there, which
    /// is stronger than a test and is declared as such.)
    #[test]
    fn usable_router_count_is_zero_for_no_session() {
        assert_eq!(get_usable_router_count(None, None), 0);
    }

    /// POSITIVE control of the test above: a session with no routers is also 0, which distinguishes
    /// «0 because None» from «0 always». MUTATION → RED: return a fixed `1`.
    #[test]
    fn usable_router_count_is_zero_for_a_session_with_no_edge_routers() {
        let s = session(vec![]);
        assert_eq!(get_usable_router_count(Some(&s), None), 0);
    }

    /// The `break` of `:2438`: one router with TWO accepted urls still counts once.
    /// MUTATION → RED: drop the `break`/`any` short-circuit ⇒ 2.
    #[test]
    fn usable_router_count_counts_each_router_at_most_once() {
        let s = session(vec![router(&[
            ("tls", "tls:r:443"),
            ("tls2", "tls:r:8443"),
        ])]);
        assert_eq!(get_usable_router_count(Some(&s), None), 1);
    }

    /// The filter conjunct (`:2436`). MUTATION → RED: ignore the filter ⇒ 2.
    #[test]
    fn usable_router_count_skips_a_router_rejected_by_the_filter() {
        let s = session(vec![
            router(&[("tls", "tls:r1:443")]),
            router(&[("tls", "tls:r2:443")]),
        ]);
        let only_r2: EdgeRouterUrlFilter = Arc::new(|u: &str| u == "tls:r2:443");
        assert_eq!(get_usable_router_count(Some(&s), Some(&only_r2)), 1);
    }

    /// The prune conjunct (DV-L3-PRUNE): a router whose only url is not a `tls:` address is not
    /// usable. MUTATION → RED: drop the `parse_tls_address` conjunct ⇒ 1.
    #[test]
    fn usable_router_count_skips_a_router_with_no_tls_parseable_url() {
        let s = session(vec![router(&[("wss", "wss:r:443")])]);
        assert_eq!(get_usable_router_count(Some(&s), None), 0);
    }

    /// The prune is PER URL, not per router: one good `tls:` url among unparseable ones still
    /// counts. ⚠ The unparseable entry orders BEFORE the usable one by key (`"http" < "tls"`), so
    /// the scan really reaches it. MUTATION → RED: prune the whole router if any url fails ⇒ 0.
    #[test]
    fn usable_router_count_counts_a_router_whose_only_tls_url_sits_among_unparseable_ones() {
        let s = session(vec![router(&[("http", "http:r:80"), ("tls", "tls:r:443")])]);
        assert_eq!(get_usable_router_count(Some(&s), None), 1);
    }

    /// The ORDER of the two conjuncts is observable through the consumer callback: the filter is
    /// not offered a url the oracle would have pruned — with the residue classes of DV-L3-PRUNE
    /// (R-1/R-5 stray colons and brackets, R-2 the `+` sign) as the measured EXCEPTION, where our
    /// parser is looser than the oracle's and the filter does see the url (B11 pins it). ⚠ The
    /// fixture IS part of the falsifier — with the unparseable url ordering AFTER the usable one,
    /// the `break` would cut before reaching it and this test would stay green under its own
    /// mutation.
    /// MUTATION → RED: evaluate the filter first ⇒ the seen list also carries `http:r:80`.
    #[test]
    fn usable_router_count_never_offers_an_unparseable_url_to_the_filter() {
        let s = session(vec![router(&[("http", "http:r:80"), ("tls", "tls:r:443")])]);
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let recording: EdgeRouterUrlFilter = Arc::new(move |u: &str| {
            recorder.lock().unwrap().push(u.to_string());
            true
        });
        assert_eq!(get_usable_router_count(Some(&s), Some(&recording)), 1);
        assert_eq!(*seen.lock().unwrap(), vec!["tls:r:443".to_string()]);
    }

    /// POSITIVE control of the filter stage (`options.go:51`, the `== nil ||` arm): with no filter
    /// every `tls:` router counts, which proves the filter stage is not killing everything.
    /// MUTATION → RED: invert the absent-filter default ⇒ 0.
    #[test]
    fn usable_router_count_with_no_filter_counts_every_tls_router() {
        let s = session(vec![
            router(&[("tls", "tls:r1:443")]),
            router(&[("tls", "tls:r2:443")]),
            router(&[("tls", "tls:r3:443")]),
        ]);
        assert_eq!(get_usable_router_count(Some(&s), None), 3);
    }

    /// DV-L3-BY-VALUE: the oracle iterates VALUES (`:2435`), so a `tls:` address parked under a
    /// `"ws"` key still counts. MUTATION → RED: index by the `"tls"` key (the `open.rs` pattern)
    /// ⇒ 0. MEASURED 2026-08-12 (row B6.5 of §9, over the 26-test suite): that implementation kills
    /// THIS test **and B10**; the other 24 stay green — so B9 is not the sole falsifier of the
    /// by-key axis any more, but it is still the only one that names it.
    #[test]
    fn usable_router_count_counts_by_value_not_by_protocol_key() {
        let s = session(vec![router(&[("ws", "tls:r:443")])]);
        assert_eq!(get_usable_router_count(Some(&s), None), 1);
    }

    /// The FALSE arm of the filter does NOT abort the scan of the router: in the oracle the `break`
    /// lives INSIDE the true arm (`:2436-2439`), so a rejected url just continues the `for` of
    /// `:2435`. ⚠ The ORDER of the fixture is part of the falsifier — the REJECTED url must order
    /// BEFORE the accepted one by key (`"tls" < "tls2"`); with the values swapped this test would
    /// stay green under its own mutation, exactly as B6/B7 declare.
    /// MUTATION → RED: find-first (locate the FIRST parseable url and filter only that one) ⇒ 0.
    #[test]
    fn usable_router_count_keeps_scanning_past_a_filter_rejected_url() {
        let s = session(vec![router(&[
            ("tls", "tls:r1:443"),
            ("tls2", "tls:r2:443"),
        ])]);
        let only_r2: EdgeRouterUrlFilter = Arc::new(|u: &str| u == "tls:r2:443");
        assert_eq!(get_usable_router_count(Some(&s), Some(&only_r2)), 1);
    }

    /// CANARY of the R-1/R-5 residue, not a branch of its own: the REUSED parser
    /// (`crate::channel::address::parse_tls_address`) ACCEPTS what the native pipeline PRUNES —
    /// measured 2026-08-12 from BOTH sides (Rust probe: `Ok`; Go probe on `transport/v2 v2.0.215`:
    /// DROPPED). Direction in this class: over-report. The seat of the fix is the R-1/R-2/R-5 debt
    /// (the parser is shared with the dial/bind path ⇒ another slice), NOT this module.
    /// ⚠ When that fix lands THIS test goes RED on purpose: that coupling is the wanted one.
    /// Whoever sees it red re-derives table D-1 of the spec — they do NOT «fix» the test.
    #[test]
    fn usable_router_count_pins_the_r1_parser_residue() {
        let s = session(vec![router(&[("tls", "tls:::1:443")])]);
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let recording: EdgeRouterUrlFilter = Arc::new(move |u: &str| {
            recorder.lock().unwrap().push(u.to_string());
            true
        });
        assert_eq!(get_usable_router_count(Some(&s), Some(&recording)), 1);
        assert_eq!(*seen.lock().unwrap(), vec!["tls:::1:443".to_string()]);
    }

    /// The boundary row of §4.2 «router with an EMPTY protocol map»: the `for` of `:2435` does not
    /// iterate ⇒ `any` over an empty iterator is false ⇒ the router does not count. Completes the
    /// pair of controls with B2 (empty router LIST vs. empty protocol MAP).
    /// ADJUDICATED WITHOUT A CENSUS ROW OF ITS OWN (§9): it exercises the same `any = false` arm as
    /// B5, and the only mutation it would nominate — `any` → `all`, vacuously true on the empty set
    /// — is row B6.7, whose kill is attributed to B6.
    #[test]
    fn usable_router_count_is_zero_for_a_router_with_no_protocols() {
        let s = session(vec![router(&[])]);
        assert_eq!(get_usable_router_count(Some(&s), None), 0);
    }

    // ───────────────────── Group C — `needs_more_listeners` (6) ─────────────────────

    /// The `!mgr.listener.IsClosed() &&` short-circuit of `:2555`. MUTATION → RED: drop it ⇒ true.
    #[test]
    fn needs_more_listeners_is_false_when_the_listener_is_closed() {
        let cap = MaxTerminators::resolve(3, 0);
        assert!(!needs_more_listeners(true, 0, 0, cap));
    }

    /// POSITIVE control of C1/C4: below the cap and open, the answer really is true.
    /// MUTATION → RED: return a fixed `false`.
    #[test]
    fn needs_more_listeners_is_true_below_the_cap() {
        let cap = MaxTerminators::resolve(3, 0);
        assert!(needs_more_listeners(false, 1, 0, cap));
    }

    /// `+ len(mgr.pendingListens)` of `:2555`: in-flight listens count towards the cap.
    /// MUTATION → RED: drop the `pending_count` addend ⇒ the second case turns true.
    #[test]
    fn needs_more_listeners_counts_pending_towards_the_cap() {
        let cap = MaxTerminators::resolve(3, 0);
        assert!(needs_more_listeners(false, 1, 1, cap));
        assert!(!needs_more_listeners(false, 1, 2, cap));
    }

    /// The `<` of `:2555` is STRICT. MUTATION → RED: `<` → `<=` ⇒ the at-the-cap case turns true.
    #[test]
    fn needs_more_listeners_is_false_at_and_above_the_cap() {
        let cap = MaxTerminators::resolve(3, 0);
        assert!(!needs_more_listeners(false, 3, 0, cap));
        assert!(!needs_more_listeners(false, 4, 0, cap));
    }

    /// The floored cap of 1 admits exactly one listener. MUTATION → RED: delete the floor ⇒
    /// **panic** «must be non-zero» while building the cap.
    #[test]
    fn needs_more_listeners_with_the_floored_cap_of_one_allows_exactly_one() {
        let cap = MaxTerminators::resolve(0, 0);
        assert!(needs_more_listeners(false, 0, 0, cap));
        assert!(!needs_more_listeners(false, 1, 0, cap));
    }

    /// Deviation D-3: the sum saturates instead of overflowing, and a saturated sum is never below
    /// a cap capped at `i32::MAX` ⇒ false. MUTATION → RED: `saturating_add` → `+` ⇒ panic
    /// «attempt to add with overflow» in debug.
    #[test]
    fn needs_more_listeners_saturates_instead_of_overflowing() {
        let cap = MaxTerminators::resolve(3, 0);
        assert!(!needs_more_listeners(false, usize::MAX, 1, cap));
    }

    // ─────────────────── Group P — the SINGLE seat of the usable predicate (2) ───────────────────
    //
    // The predicate moved from an inline expression of P1 to `is_url_usable`, which the scan of
    // `ziti.go:2529` also invokes. The tests of P1 that exercised it now do so BY DELEGATION, so
    // these two call the new seat DIRECTLY — otherwise the seat itself would have no falsifier of
    // its own (RB-5).

    /// P1t — the NORMATIVE order of the two conjuncts, observed through the consumer callback: an
    /// unparseable url is rejected by the prune and the filter is never even offered it.
    /// MUTATION → RED: swap the conjuncts ⇒ the recorder carries `http:r:80`.
    #[test]
    fn is_url_usable_rejects_an_unparseable_url_without_consulting_the_filter() {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let recording: EdgeRouterUrlFilter = Arc::new(move |u: &str| {
            recorder.lock().unwrap().push(u.to_string());
            true
        });
        assert!(!is_url_usable(Some(&recording), "http:r:80"));
        assert!(seen.lock().unwrap().is_empty());
    }

    /// P2t — POSITIVE control of the seat: a parseable url is usable when no filter is installed
    /// (the `== nil ||` arm of `options.go:51`) and NOT usable when the filter rejects it. Without
    /// this pair, P1t would be «red by construction».
    /// MUTATION → RED: ignore the filter ⇒ the second assert flips.
    #[test]
    fn is_url_usable_accepts_a_parseable_url_only_when_the_filter_does() {
        let reject_all: EdgeRouterUrlFilter = Arc::new(|_: &str| false);
        assert!(is_url_usable(None, "tls:r:443"));
        assert!(!is_url_usable(Some(&reject_all), "tls:r:443"));
    }
}
