//! Edge bind: registering this identity as a host (the Bind message + Unbind + the
//! `ServiceBinding` handle). Oracle: sdk-golang ziti/edge/network/hosting_conn.go
//! (edgeHostConn.listen) + ziti/edge/messages.go (NewBindMsg/NewUnbindMsg). Slice 7a:
//! register only, plaintext (crypto + accepting dials are slice 7b).
//!
//! Split by domain (F6 tramo 10): `wire` (the router-observable vocabulary: content-types, header
//! ids, the four message constructors, the reply classifier), `binding` (the `ServiceBinding`
//! handle) and `flow` (the `EdgeClient::bind` flow). The bind MACHINERY (`send_bind`/`accept_next`/
//! `accept_pending`/the rx-loop) is NOT here: it lives in `edge/data/` and is a CONSUMER of this
//! module.

use std::time::Duration;

mod binding;
mod flow;
mod wire;

#[cfg(test)]
mod tests_binding;
#[cfg(test)]
mod tests_flow;
#[cfg(test)]
mod tests_live;
#[cfg(test)]
mod tests_wire;
#[cfg(test)]
mod testsupport;

// Routes preserved from the monolithic `edge/bind` module (F6 tramo 10). These 17 items are public API
// of the crate via `crate::edge::bind::X` (`edge/mod.rs:7` `pub mod bind;`, with no re-export
// anywhere else) and have real consumers in `edge/data/` and `tunnel/host/` — so the re-export is
// obligatory, not a convenience. Internal consumers import them via THIS re-export (`use super::…`),
// never via the submodule path, which keeps the re-export used under `-D warnings` (spec §5.2).
pub use binding::ServiceBinding;
pub use wire::{
    CT_BIND, CT_BIND_SUCCESS, CT_DIAL, CT_DIAL_FAILED, CT_DIAL_SUCCESS, CT_UNBIND, HDR_LISTENER_ID,
    HDR_ROUTER_PROVIDED_CONN_ID, HDR_SUPPORTS_BIND_SUCCESS, HDR_SUPPORTS_INSPECT, build_bind,
    build_dial_failed, build_dial_success, build_unbind, classify_bind_reply, new_listener_id,
};

/// Default bind-timeout for [`EdgeClient::bind`](crate::edge::client::EdgeClient::bind): the whole resolve → create Bind session → open
/// channel → send Bind → StateConnected flow must complete within this budget, else `bind` fails
/// with [`EdgeError::BindTimedOut`](crate::edge::error::EdgeError::BindTimedOut). The value (`time.Minute`) is the oracle's `ListenOptions`
/// establishment budget, defaulted from `==0 → time.Minute` (`ziti/ziti.go:1638-1639`). NOTE the
/// value differs from `connect`'s 15s ([`crate::edge::conn::DEFAULT_CONNECT_TIMEOUT`]): the oracle
/// deliberately gives the listen path (`ListenOptions`, 60s) and the dial path
/// (`DialContextWithOptions`, 15s) different defaults — adopting the listen-path value here is the
/// faithful choice. This is the bind-side sibling of slice 10b.
///
/// LAYERED CONSCIOUS DEVIATION (flagged, not hidden): the oracle applies `ConnectTimeout` to bound
/// establishment ONLY on the opt-in `WaitForN` path (`:2253` `WaitForN(options.ConnectTimeout)`);
/// the DEFAULT `ListenWithOptions` (`waitForN==0`) does `go listenerMgr.run()` and returns
/// immediately, bounding nothing. Our `bind()` ALWAYS waits for the `StateConnected` reply (the 7a
/// synchronous-confirm, itself a deviation from the oracle's async-establish default), so this
/// timeout bounds THAT wait — by the oracle's own listen-path establishment budget (60s), distinct
/// from the 15s dial budget. So: given we already confirm synchronously (7a), we bound that
/// confirm-wait by the value the oracle uses for its establishment wait.
pub const DEFAULT_BIND_TIMEOUT: Duration = Duration::from_secs(60);
