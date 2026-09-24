//! The background rx-loop (hot path, shared by every channel + both UDP twins). Split out of the
//! monolithic `edge/data` module (F6 tramo 1b), byte-identical.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::channel::connect::read_message;
use crate::channel::message::HDR_REPLY_FOR;
use crate::edge::bind::CT_DIAL;
use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, HDR_CONN_ID};

use super::inspect::{self, CT_CONN_INSPECT_REQUEST};
use super::wire::{header_i32, header_u32};
use super::{BoxRead, ChannelState};

/// Background read loop: read a frame, dispatch it. A reply (has `ReplyFor` and a
/// registered waiter) goes to the waiter (priority); else a `ConnInspectRequest` is answered by
/// the responder (classified HERE, replied in its own task — see [`super::inspect`]); else frames
/// are routed by content type: `Dial`→bind accept queue; `Data`→child conn; `StateClosed`→child
/// conn (if any) else bind queue; anything else (incl. async `BindSuccess`) is dropped. On read
/// EOF/error the loop marks the channel closed (clearing all maps, waking every awaiter).
///
/// The per-conn dispatch (`tx.send().await` on a bounded queue) is raced against `close_notify`: a
/// non-draining sibling would otherwise park the loop here forever, masking router death (the rx-loop
/// never returns to `read_message` to observe EOF). The latency probe closes the channel on a stall;
/// `close_notify` then releases the parked dispatch so the loop can tear down. Oracle: the channel rxer
/// (`channel/v4 impl.go:325`) + the per-conn sequencer's `select` over `externalCloseNotify`
/// (`sdk-golang .../network/seq.go:51-57`).
pub(crate) async fn rx_loop(mut read: BoxRead, state: Arc<ChannelState>) {
    loop {
        let Ok(msg) = read_message(&mut read).await else {
            break;
        };
        state.note_read();
        if let Some(reply_for) = header_i32(&msg, HDR_REPLY_FOR) {
            let waiter = state.waiters.lock().unwrap().remove(&reply_for);
            if let Some(tx) = waiter {
                let _ = tx.send(msg);
                continue;
            }
            // reply header but no waiter registered — fall through to conn/bind dispatch
        }
        let Some(conn_id) = header_u32(&msg, HDR_CONN_ID) else {
            continue; // no conn id => nothing to route to
        };
        // The ConnInspect responder is attended BEFORE the routing match and AFTER the conn-id
        // guard (the Invalid outcome needs the id), mirroring `AcceptMessage`, which handles it
        // ahead of its own switch (`ziti/edge/network/conn.go:339-342`). The CLASSIFICATION runs
        // synchronously HERE, in the receiving task — like the oracle's `mux.sinks.Get(connId)`
        // (`ziti/edge/msg_mux.go:369`) — so a conn deregistered between dispatch and task start
        // cannot turn a `Dial`/`Bind` into an `Invalid`; only the REPLY travels in its own task
        // (the oracle's `go …`), which is what keeps the write off this loop.
        if msg.content_type == CT_CONN_INSPECT_REQUEST {
            let conn_type = inspect::classify_conn_inspect(&state, conn_id);
            inspect::spawn_conn_inspect_reply(&state, conn_id, conn_type, msg);
            continue;
        }
        // Pure routing by content type. Dial -> the bind's accept queue; Data -> the child
        // conn; StateClosed -> the child conn if present, else the bind (router closing it).
        // Anything else (incl. the async BindSuccess) is dropped. NO writes/handshake in THIS
        // loop — the accept handshake runs in accept_next (the caller's task) and the ConnInspect
        // reply above runs in a task of its own, so neither can park the read loop.
        let tx = match msg.content_type {
            CT_DIAL => state.binds.lock().unwrap().get(&conn_id).cloned(),
            CT_DATA => state.conns.lock().unwrap().get(&conn_id).cloned(),
            CT_STATE_CLOSED => {
                let child = state.conns.lock().unwrap().get(&conn_id).cloned();
                child.or_else(|| state.binds.lock().unwrap().get(&conn_id).cloned())
            }
            _ => None,
        };
        if let Some(tx) = tx {
            // Race the bounded-queue send (backpressure) against the channel closing. Without the
            // close arm, a full/non-draining sibling parks this loop forever and masks router death.
            // `enable()` registers interest BEFORE the `closed` re-check, closing the missed-notify
            // race (a `mark_closed` between the two is caught by the flag check).
            let notified = state.close_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if state.closed.load(Ordering::Acquire) {
                break;
            }
            tokio::select! {
                biased;
                () = &mut notified => break,
                res = tx.send(msg) => { let _ = res; } // bounded queue => backpressure
            }
        }
    }
    state.mark_closed();
}
