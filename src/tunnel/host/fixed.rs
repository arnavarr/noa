//! Host mode FIXED (T2): the accept loop whose dial `target` is a FIXED caller-supplied
//! argument — it reads neither the inbound dial's appData nor the service's `host.v1`.
//!
//! (F6 tramo 9: movido verbatim del monolito de `tunnel/host`.)

use crate::edge::bind::ServiceBinding;
use crate::edge::error::EdgeError;

use super::HOST_DIAL_TIMEOUT;
use super::dial::handle_host_conn;

/// Run a host-TCP listener: `accept_pending` each inbound dial on `binding`, dial a freshly opened
/// local TCP `target`, and on success splice the now-acknowledged child `EdgeConn` onto it. One
/// connection per accept, handled concurrently.
///
/// **Faithful accept-then-dial order (T4a):** the target is dialed BEFORE the dial is acknowledged, so
/// an unreachable target yields a `DialFailed` (the dialer's `connect()` fails) instead of the
/// pre-split eager `DialSuccess` then immediate close. The [`PendingAccept`](crate::edge::data::PendingAccept) (from `accept_pending`)
/// owns an `Arc<ChannelState>` clone, so the `&mut binding` borrow ends immediately — the accept loop
/// pulls the next dial while a child's target dial is in flight (the structural isolation T2 had, now
/// also covering the dial→ack window).
///
/// Runs each connection under `tokio::task::spawn_local` (so it MUST be driven inside a
/// `tokio::task::LocalSet`), mirroring [`crate::tunnel::run_tcp_proxy`]. The `binding` owns the
/// edge-router channel, so it stays on the accept-loop stack and keeps the channel's rx-loop alive,
/// feeding every accepted child's read half.
///
/// The accept loop returns when `accept_pending` errors — primarily [`EdgeError::ListenerClosed`] (the
/// router closed the bind or the channel died), faithful to the oracle whose `accept` returns on
/// `AcceptEdge()` error (`provider.go:139-142`). On accept-error teardown the in-flight children do NOT
/// survive: `run_tcp_host` returns → `binding` drops → `EdgeChannel`'s `Drop` aborts the rx-loop and
/// the driving `LocalSet` aborts the in-flight `spawn_local` work (the oracle's already-running
/// connections would survive — the same conscious deviation [`crate::tunnel::run_tcp_proxy`] documents,
/// SHARPER here because T2's children share the ONE binding-owned channel).
///
/// # Errors
/// Returns the [`EdgeError`] from `accept_pending` (typically [`EdgeError::ListenerClosed`]) when the
/// listener is torn down; the loop otherwise never returns.
pub async fn run_tcp_host(mut binding: ServiceBinding, target: String) -> Result<(), EdgeError> {
    loop {
        let pending = binding.accept_pending().await?;
        let target = target.clone();
        tokio::task::spawn_local(async move {
            // The fixed-target T2 host has no `host.v1`, so it uses the no-config default timeout and a
            // default-source dial (no `source_addr` — that is a forwarding/appData capability).
            handle_host_conn(pending, target, None, HOST_DIAL_TIMEOUT).await;
        });
    }
}
