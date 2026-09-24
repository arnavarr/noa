//! Tunneler layer: maps OS traffic onto ziti services, orchestrating the edge client's
//! `connect()`/`bind()`/`accept()`. Slice T1 ports the proxy-TCP mode: a local TCP listener whose
//! accepted connections are spliced bidirectionally onto a dialed ziti service connection, with
//! TCP-style half-close in each direction.
//!
//! Oracle: `openziti/ziti` v2.0.0 `tunnel/tunnel.go` (`Run`/`myCopy`, the universal bidirectional
//! splice) + `sdk-golang` v1.7.0 `ziti/edge/network/conn.go` (`CloseWrite`, the half-close FIN).
//!
//! Slice T2 adds host-TCP: register this identity as a host (`bind`), and for each inbound dial
//! (`accept`) splice the accepted ziti connection onto a freshly dialed local TCP target.
//!
//! Slice T3 adds proxy-UDP: a local UDP listener whose datagrams are demultiplexed by source address
//! into per-source virtual connections, each dialing the ziti service (no TCP `splice`/half-close —
//! UDP is connectionless; idle vconns are reaped).
//!
//! Slice T4b-1 adds appData → `host.v1` forwarding: the host stops dialing a FIXED target and instead
//! dials a DYNAMIC target carried in the inbound dial's `AppData` (header 1011, the tunneler `dst_*`
//! JSON map), validated against the service's `host.v1` config (`forwardAddress`/`forwardPort` +
//! allow-lists). See [`resolve`].
//!
//! Roadmap (deferred): T4b-2 (full matchers + forwardProtocol + connectTimeout + translations),
//! T5 svc-poller; TLAST TUN (owner fork).

pub mod host;
pub mod proxy;
pub mod resolve;
pub mod udp;

// Capa de intercept de host (utun → flujos → overlay). Gated tras la feature `intercept`
// (opcional, off por defecto) para no arrastrar las deps de plataforma (tun-rs, …) al build
// default. Ver docs/superpowers/specs/2026-06-27-tunnel-intercept-design.md.
#[cfg(feature = "intercept")]
pub mod intercept;

pub use host::{run_tcp_host, run_tcp_host_forwarding};
pub use proxy::{run_tcp_proxy, splice};
pub use resolve::{ResolvedTarget, resolve_target};
pub use udp::run_udp_proxy;
