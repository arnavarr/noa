//! The `listenerManager` arc: the per-service state the bind loop keeps, ported piece by piece.
//!
//! Oracle: `sdk-golang@4b6a087` `ziti/ziti.go:2266-2282` (the struct) plus its sites of use. This
//! directory exists because the arc grew module by module: `listener_count` arrived with the count
//! gate, `attempts` with the ledger of listen attempts, and `registry`/`scan`/`connect_result` with
//! the SCAN — the synchronous half of the loop that consults and mutates both.
//!
//! | Module | What it holds | Oracle |
//! |--------|---------------|--------|
//! | [`listener_count`] | the usable-router count, the terminator cap and the «needs more listeners» gate (P1/P2/P3) | `:2428-2443`, `:2554-2556`, `ziti/edge/conn.go:271` |
//! | `attempts` | the LEDGER of listen attempts: `pendingListens`, `listenAttemptId` and `connects` | `:2271-2273` |
//! | `registry` | the QUERY surface of `MultiListener`, as a trait-seam (Q1-Q3) | `ziti/edge/network/listener.go:55-57`, `:139-148`, `:150-154` |
//! | `scan` | `makeMoreListeners`: which urls deserve a connect right now | `:2511-2552` |
//! | `connect_result` | `handleRouterConnectResult`: turning a finished connect into a listen attempt | `:2445-2476` |
//!
//! What is NOT here yet, each piece with its OWNING slice (never by deixis):
//!
//! - `createListener` (`:2478-2509`) and the REGISTRY behind `MultiListener` (`AddListener`
//!   `ziti/edge/network/listener.go:273-303`, `forward` `:305-338`, `accept` `:340-349`, `Close`
//!   `:351-376`, the `listeners` map with its `listenerLock` `:116-117`, and
//!   `UpdateCost`/`UpdatePrecedence`/`SendHealthEvent` `:205-253`) → slice **`l3-listener-registry`**:
//!   both are wire plus `Drop`/`close` and share the child `edgeHostConn`.
//! - `run` (`:2307-2381`), the event types (`:2681-2753`) and the observer machinery (`:2284-2305`)
//!   → slice **`l3-listener-run`**: the asynchronous conductor, which also touches cluster L2
//!   (`refreshSession` `:2703`, `sessionRefreshInterval` `:2699-2702`).

// ⚠ How the surface of each of these allows is re-measured, and how it is NOT: by REMOVING the
// allow and running `cargo clippy --lib` (ordinary), with `touch src/lib.rs` first so the run
// really recompiles — clippy answers an identical re-invocation from cache, and a census over an
// empty output measures nothing. `--force-warn dead_code` does NOT work for this: it ignores EVERY
// `#[allow]`, so it cannot attribute a single item to THIS allow. (It is still the right tool for
// the whole-crate census of spec §10.4, which asks a different question.)
//
// The consumers of the ledger ARE here now — `scan::make_more_listeners` and
// `connect_result::handle_router_connect_result` — and the allow is STILL required, but for a much
// SMALLER surface than the spec declared: an item under an `#[allow]` is seeded as a LIVE ROOT, so
// those two modules revive most of `attempts.rs` through their own allows below.
// Surface it silences, MEASURED 2026-08-21 on the delivered tree: **2 diagnostics** —
// `AttemptId::get` (`attempts.rs:87`) and `ListenAttempts::{new, clear_pending_if_current}`
// (`:108`), whose consumers are the two event handlers of `ziti.go:2690-2693` and `:2719-2722`.
// Removal belongs to `l3-listener-run`, the slice that owns those handlers and gives the loop a
// live root.
#[allow(dead_code)]
mod attempts;

pub mod listener_count;

// ⚠ NO allow here, and that is a MEASUREMENT, not an omission (2026-08-21): with one added, removing
// it leaves `cargo clippy --lib` at **0 diagnostics**. `ListenerRegistry` is used by `scan` and
// `connect_result`, and since their items are seeded as LIVE ROOTS by their own allows, everything
// they use is live too — so an allow here would silence nothing. The double (`FakeRegistry`,
// `RegistryCall`) lives under `#[cfg(test)]` and never enters the `lib` target at all.
// Falsify by adding an item to `registry.rs` that nobody uses: `touch src/lib.rs && cargo clippy --lib`
// then reports it.
mod registry;

// Consumer of production: `run` (`ziti.go:2329`, `:2376` and the handler of `:2704`), all three in
// `l3-listener-run`; until the loop is wired the module is unreachable from a live root of the
// `lib` target. Surface it silences, MEASURED 2026-08-21 on the delivered tree: **2 diagnostics**
// (`ConnectRequest` and `make_more_listeners`). Removal belongs to `l3-listener-run`.
#[allow(dead_code)]
mod scan;

// Consumer of production: `run` (`ziti.go:2364`, the `connectChan` arm of its `select`), in
// `l3-listener-run`; same reason as `scan` above. Surface it silences, MEASURED 2026-08-21 on the
// delivered tree: **1 diagnostic** (`handle_router_connect_result`). Removal belongs to
// `l3-listener-run`.
#[allow(dead_code)]
mod connect_result;
