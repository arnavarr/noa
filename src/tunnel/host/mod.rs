//! Host-TCP tunneler mode (T2): register this identity as a host of a ziti service (`bind`), and
//! for every inbound dial (`accept`) open a local TCP socket to a fixed `target` and splice the
//! accepted `EdgeConn` onto it, bidirectionally, with TCP-style half-close. The REVERSE of T1
//! (proxy): T1 dialed ziti per inbound socket; T2 dials a socket per inbound ziti conn.
//!
//! Oracle: `openziti/ziti` v2.0.0 `tunnel/provider.go:132-180` (`contextProvider.accept`, the host
//! accept loop) + `tunnel/intercept/hosting.go:199-265` (`dialAddress`, `enableHalfClose := isTcp`
//! ⇒ half-close ON for TCP, `dialTimeout` default `5*time.Second` at `:144`) + `tunnel/tunnel.go`
//! `Run`/`myCopy` (the bidirectional splice, ported in T1 as [`crate::tunnel::proxy::splice`]).
//!
//! T2 is PURELY ADDITIVE: it reuses `bind`/`accept` (7a/7b), `EdgeConn::into_split` (T1) and the
//! generic `splice` (T1) UNCHANGED — so the shared-primitive re-validation rule
//! (`noa-sdk-shared-rxloop-reverify`, which triggers on MODIFICATION, not use) does not apply.
//!
//! Two host modes:
//! - [`run_tcp_host`] (T2): the dial `target` is a FIXED argument (CLI/caller-supplied) — T2 does NOT
//!   read the inbound dial's appData nor the service's `host.v1`. Safe by construction (the dialer
//!   cannot influence WHERE the host dials).
//! - [`run_tcp_host_forwarding`] (T4b-1): the host dials a DYNAMIC target resolved per inbound dial
//!   from its `AppData` (header 1011, `dst_*`) against the service's `host.v1` config
//!   (`forwardAddress`/`forwardPort` + allow-lists). A resolution failure → `complete_failed` (the
//!   faithful DialFailed → StateClosed wire from T4a), so a disallowed/malformed dial is rejected
//!   loudly and the accept loop keeps accepting (oracle `provider.go:143-158`, `continue`).
//!
//! Oracle for forwarding: `tunnel/provider.go:143-166` (`AppDataToMap` → `hostCtx.Dial` →
//! `CompleteAcceptSuccess`/`CompleteAcceptFailed`) + `tunnel/intercept/hosting.go` `Dial`/`dialAddress`
//! (`:199-265`, `:385-409`). The resolver lives in [`crate::tunnel::resolve`].

use std::time::Duration;

mod dial;
mod fixed;
mod forward;

#[cfg(test)]
mod tests_fixed;
#[cfg(test)]
mod tests_forward;
#[cfg(test)]
mod tests_source_addr;
#[cfg(test)]
mod testsupport;

pub use fixed::run_tcp_host;
pub use forward::run_tcp_host_forwarding;

/// The host's no-config DEFAULT dial timeout, byte-faithful to the oracle's
/// `config.GetDialTimeout(5 * time.Second)` (`hosting.go:144`) — the `defaultTimeout` argument the oracle
/// passes when the `host.v1` sets no `connectTimeout`/`connectTimeoutSeconds`. A black-holed target
/// therefore does not pin an accepted child forever. Since T4b-2c the forwarding host computes the actual
/// per-service timeout once at startup via [`crate::tunnel::resolve::get_dial_timeout`] (which uses this
/// as its default); the fixed-target T2 host ([`run_tcp_host`]) has no `host.v1`, so it always uses this.
pub const HOST_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
