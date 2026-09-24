//! Production connection entry point: `EdgeClient::connect(service_name) -> ServiceConn`.
//! Resolves the service by name, reads `Service.encryption_required`, creates a Dial session,
//! opens the channel and dials, bundling the `EdgeChannel` + `EdgeConn` so the channel's
//! background rx-loop stays alive for the connection's lifetime. Oracle: sdk-golang
//! `ziti/ziti.go` `DialContextWithOptions` (service resolution) + `factory.go:131` (crypto flag).

use std::time::Duration;

mod flow;
mod resolve;
mod retry;
mod service_conn;

#[cfg(test)]
mod tests_flow;
#[cfg(test)]
mod tests_live;
#[cfg(test)]
mod tests_resolve;
#[cfg(test)]
mod tests_retry;
#[cfg(test)]
mod tests_service_conn;
#[cfg(test)]
mod testsupport;

// Routes preserved from the monolithic `edge/conn` module (F6 tramo 5). ⚠ `do_resolve_service` has no
// external consumer in code: `flow.rs` MUST import it via THIS re-export (`use super::…`), never
// via the submodule path — that keeps the re-export used under `-D warnings` and the
// `crate::edge::conn::do_resolve_service` route alive (spec §5.2).
pub use resolve::do_resolve_dial_session;
pub(crate) use resolve::{do_resolve_service, resolve_service};
pub use service_conn::ServiceConn;

/// Default connect-timeout for [`EdgeClient::connect`](crate::edge::client::EdgeClient::connect): the whole resolve → create[+backoff] →
/// dial → refresh → retry flow must complete within this budget, else `connect` fails with
/// [`EdgeError::ConnectTimedOut`](crate::edge::error::EdgeError::ConnectTimedOut). Mirrors the oracle's `DialContextWithOptions`, which defaults
/// `ConnectTimeout` to 15s when unset (`ziti/ziti.go:1449-1451`) and applies it both as a context
/// deadline (`:1453-1460`) and as the session-creation backoff's `MaxElapsedTime` (`:2015`).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
