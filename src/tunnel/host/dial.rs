//! The host's per-dial core: dial the local TCP target, acknowledge the accepted dial, and
//! splice the child onto the socket. Shared by BOTH host modes (fixed T2 and forwarding T4b-1).
//!
//! (F6 tramo 9: movido verbatim del monolito de `tunnel/host`.)

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

use crate::edge::data::PendingAccept;
use crate::tunnel::proxy::splice;

/// Dial the local TCP `target`; on success acknowledge the accepted dial
/// ([`PendingAccept::complete_success`] = DialSuccess + the host crypto stream-header) and splice the
/// child onto the socket; on failure acknowledge with [`PendingAccept::complete_failed`] (DialFailed)
/// so the dialer's `connect()` fails.
///
/// This is the faithful accept-then-dial order (oracle: dial the target, THEN
/// `CompleteAcceptSuccess`/`CompleteAcceptFailed`, `provider.go:154-166` + `hosting.go`
/// `ManualStart=true`). It REPLACES T2's conscious deviation (eager DialSuccess → target-unreachable
/// closed the child with StateClosed); now an unreachable or slow (≥ [`HOST_DIAL_TIMEOUT`](super::HOST_DIAL_TIMEOUT)) target
/// sends DialFailed. It also CLOSES T2's "target-slow HOL" window: because DialSuccess now follows the
/// target dial, the dialer sends no Data during the ≤ `dial_timeout` dial, so a bulk-writing
/// dialer can no longer head-of-line-stall the bind's sibling children on the shared channel.
///
/// `dial_timeout` is the resolved per-service timeout: [`HOST_DIAL_TIMEOUT`](super::HOST_DIAL_TIMEOUT) for the fixed-target T2 host,
/// or the `host.v1` `connectTimeout`/`connectTimeoutSeconds` (T4b-2c) for the forwarding host.
///
/// `source` (T4b-2d-2) is the local address to bind the dial's source to (`net.Dialer{LocalAddr}`), from
/// a per-dial `source_addr` appData. `None` (the fixed-target T2 host, or a forwarding dial without
/// `source_addr`) → a plain default-source connect. See [`dial_target`].
pub(super) async fn handle_host_conn(
    pending: PendingAccept,
    target: String,
    source: Option<SocketAddr>,
    dial_timeout: Duration,
) {
    match tokio::time::timeout(dial_timeout, dial_target(&target, source)).await {
        Ok(Ok(sock)) => {
            // Target reachable: acknowledge (DialSuccess + crypto header), then splice.
            let child = match pending.complete_success().await {
                Ok(child) => child,
                Err(e) => {
                    tracing::warn!(error = %e, "host: completing the accepted dial failed");
                    return;
                }
            };
            let (zr, zw) = child.into_split();
            if let Err(e) = splice(zr, zw, sock).await {
                tracing::warn!(error = %e, "host: connection ended with error");
            }
            // splice already did `zw.close()` (StateClosed + deregister). The `binding` owns the
            // CHANNEL (shared across all children), so it is NOT closed here.
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, %target, "host: target dial failed; sending DialFailed");
            // Carry the real dial error in the DialFailed body, faithful to the oracle's
            // `NewDialFailedMsg(id, err.Error())` (conn.go:971). The elapsed/timeout arm below has
            // no inner error, so it uses a fixed reason (consistent with noa's fixed-reason precedent).
            pending
                .complete_failed(&format!("target dial failed: {e}"))
                .await;
        }
        Err(_elapsed) => {
            tracing::warn!(%target, timeout = ?dial_timeout, "host: target dial timed out; sending DialFailed");
            pending.complete_failed("target dial timed out").await;
        }
    }
}

/// Connect a local TCP socket to `target`. When `source` is `Some`, bind the dial's LOCAL end to it first
/// (the oracle's `net.Dialer{LocalAddr}`, `hosting.go:236-245`) via [`tokio::net::TcpSocket`] — tokio's
/// `TcpStream::connect` has no local-bind; otherwise a plain `TcpStream::connect` (the UNCHANGED non-source
/// path → no regression, keeping `connect`'s native multi-candidate/DNS happy-eyeballs behavior). Wrapped
/// by [`handle_host_conn`]'s `tokio::time::timeout`, so the source bind never weakens the hang-protection.
///
/// FIDELITY — source-bind WITHOUT `allowedSourceAddresses` is faithful: the oracle binds `source_addr`
/// UNCONDITIONALLY in `dialAddress`; it NEVER checks it against `allowedSourceAddresses`.
/// `allowedSourceAddresses` is an ENABLER (`OnClose`/`router.AddLocalAddress` provision the source IPs onto
/// `lo` so a NON-local source IP becomes bindable, `hosting.go:108-122`,`:270-281`), NOT a gate. So for an
/// already-local source IP (e.g. loopback) this bind is byte-identical to the oracle; for a NON-local
/// source IP the `bind` fails (EADDRNOTAVAIL → DialFailed) where the oracle-with-routes would succeed — a
/// safe-direction UNDER-permit until the route setup lands (T4b-2d-3, still deferred via
/// [`crate::tunnel::resolve::check_deferred_config`]). A bind that fails surfaces as the dialer-observable
/// DialFailed via [`handle_host_conn`]'s `Ok(Err(e))` arm, faithful to Go's `dialer.Dial` error →
/// `NewDialFailedMsg`.
///
/// DEVIATION (low severity, named): on the source-bind path we resolve `target` and connect to the FIRST
/// candidate of the source's address family (a `TcpSocket` connects to ONE address, and its family must
/// match the bound local addr), whereas the non-source `TcpStream::connect` tries every candidate. This
/// differs only for a multi-record HOSTNAME target combined with a `source_addr` (an unusual pairing) and
/// is safe-direction (a connect failure → DialFailed, never a wrong dial). A `source_addr` whose family
/// has no matching target candidate is a clean `AddrNotAvailable` → DialFailed. Relatedly, a v4-mapped IPv6
/// `source_addr` (`::ffff:1.2.3.4`) is classified V6 by `IpAddr::from_str` (so it selects the V6 target
/// family here), whereas the oracle's `net.ParseIP` canonicalizes it to V4 — the ONLY bind-vs-bind
/// divergence of this slice, safe-direction (it only narrows the candidates of the SAME allow-checked host;
/// worst case `AddrNotAvailable` → DialFailed), never a forbidden destination, and reachable only from an
/// unusual `dialOptions.sourceIp` template.
async fn dial_target(target: &str, source: Option<SocketAddr>) -> io::Result<TcpStream> {
    let Some(local) = source else {
        return TcpStream::connect(target).await;
    };
    let want_v4 = local.is_ipv4();
    let remote = tokio::net::lookup_host(target)
        .await?
        .find(|a| a.is_ipv4() == want_v4)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "no {} address for target '{target}' to match source_addr {local}",
                    if want_v4 { "IPv4" } else { "IPv6" }
                ),
            )
        })?;
    let socket = if want_v4 {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.bind(local)?;
    socket.connect(remote).await
}
