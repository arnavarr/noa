//! `impl Debug/PendingAccept` + the accept-then-dial completion (`complete_success`/`complete_failed`)
//! and the `#[cfg(test)]` constructors. Split out of the monolithic `edge/data` module (F6 tramo 1b),
//! byte-identical.

use std::time::Duration;

use tokio::sync::oneshot;

use crate::channel::connect::write_message;
use crate::channel::message::{HDR_REPLY_FOR, Message};
use crate::edge::bind::build_dial_success;
use crate::edge::dial::{CT_STATE_CONNECTED, build_data, build_state_closed};
use crate::edge::error::EdgeError;

use super::{ChannelState, EdgeConn, PendingAccept};

/// The accept-start reply budget: the oracle sends the `DialSuccess` of a GENERATED conn-id with
/// `reply.WithPriority(channel.Highest).WithTimeout(5 * time.Second).SendForReply(...)`
/// (`ziti/edge/network/conn.go:993`). A PINNED VALUE read from that single site — not a "≥5s" floor.
pub(super) const ACCEPT_START_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use tokio::sync::mpsc;

/// Step (3) of [`PendingAccept::complete_success`] on the GENERATED-conn-id branch: await the
/// router's start acknowledgement, correlated to the `DialSuccess`'s own `sequence`, within
/// [`ACCEPT_START_TIMEOUT`]. Split out of `complete_success` ONLY to keep it under the repo's
/// function-length gate — it is not a second decision site: the ORDER of the four operations still
/// lives in `complete_success`, and this runs strictly between the `DialSuccess` write and the
/// stream-header write.
///
/// The oracle's `dialSucceeded` returns `(err, cleanupHandled)` and its wrapper
/// `CompleteAcceptSuccess` (`conn.go:891-914`) turns that second value into two DIFFERENT wires, so
/// the two failures are NOT interchangeable:
///
/// - reply arrives, not a `StateConnected` (`conn.go:999-1003`): `close(true)` ⇒ a `StateClosed` for
///   the CHILD then deregister (`conn.go:869-877`), and `cleanupHandled = true` ⇒ **no** `DialFailed`;
/// - no reply at all — budget exhausted or channel dead (`conn.go:993-997`): `err, false` ⇒ the
///   wrapper does `close(false)` (deregister ONLY, no `StateClosed`, `conn.go:900`) and sends a
///   best-effort `DialFailed` whose `ConnId` is the CHILD (`conn.Id()`, `conn.go:902` — the measured
///   asymmetry with `complete_failed`, which carries the BIND, `conn.go:971`) and whose `ReplyTo` is
///   the inbound `Dial` (`conn.go:903`).
async fn await_start_reply(
    state: &ChannelState,
    bind_conn_id: u32,
    child_id: u32,
    dial_seq: i32,
    reply_seq: i32,
    start_rx: oneshot::Receiver<Message>,
) -> Result<(), EdgeError> {
    match tokio::time::timeout(ACCEPT_START_TIMEOUT, start_rx).await {
        // The reply arrived and IS the start acknowledgement (conn.go:999).
        Ok(Ok(start_msg)) if start_msg.content_type == CT_STATE_CONNECTED => Ok(()),
        Ok(Ok(start_msg)) => {
            let content_type = start_msg.content_type;
            tracing::error!(
                bind_conn_id,
                child_id,
                content_type,
                "failed to receive start after dial"
            );
            let mut closed = build_state_closed(child_id);
            closed.sequence = state.next_seq();
            {
                let mut w = state.write.lock().await;
                let _ = write_message(&mut *w, &closed).await;
            }
            state.conns.lock().unwrap().remove(&child_id);
            Err(EdgeError::AcceptStartFailed(format!(
                "failed to receive start after dial. got {content_type}"
            )))
        }
        Ok(Err(_)) | Err(_) => {
            tracing::error!(
                bind_conn_id,
                child_id,
                "failed to send reply to dial request"
            );
            state.waiters.lock().unwrap().remove(&reply_seq);
            state.conns.lock().unwrap().remove(&child_id);
            // The literal is the port's OWN (`D-6`): what the oracle puts in the body here is
            // `err.Error()` of the Go `channel` library's transport error (conn.go:902), which has no
            // byte-exact Rust equivalent. It travels in BOTH the wire body and the payload, exactly
            // as the oracle uses one string for both.
            state
                .send_dial_failed(child_id, dial_seq, "start reply not received")
                .await;
            Err(EdgeError::AcceptStartFailed(
                "start reply not received".to_string(),
            ))
        }
    }
}

impl std::fmt::Debug for PendingAccept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAccept")
            .field("bind_conn_id", &self.bind_conn_id)
            .field("child_id", &self.child_id)
            .field("circuit_id", &self.circuit_id)
            .field("source_identity", &self.source_identity)
            .field("has_app_data", &self.app_data.is_some())
            .field("encrypted", &self.crypto_setup.is_some())
            .finish_non_exhaustive()
    }
}

impl PendingAccept {
    /// The child connection id — the one the router provided in the `Dial`'s `RouterProvidedConnId`
    /// header, or the one WE generated when it provided none (`hosting_conn.go:290-296`).
    #[must_use]
    pub fn child_id(&self) -> u32 {
        self.child_id
    }

    /// The inbound dial's opaque `AppData` (header 1011), or `None` if the dial carried none. The
    /// forwarding host (`tunnel::host`) parses this as the tunneler `dst_*` JSON map to resolve a
    /// dynamic dial target against the service's `host.v1`. Oracle: `GetAppData()`
    /// (`ziti/edge/network/conn.go:887`, reading the field populated at `hosting_conn.go:309`) →
    /// `AppDataToMap` (`provider.go:75`, called at `:144`).
    #[must_use]
    pub fn app_data(&self) -> Option<&[u8]> {
        self.app_data.as_deref()
    }

    /// Complete the accept on a REACHABLE target, in the ORDER the oracle observes
    /// (`dialSucceeded`, conn.go:989-1017, via `CompleteAcceptSuccess`, conn.go:891-914):
    ///
    /// 1. **register the reply waiter** — ONLY on the generated-id branch, and BEFORE the write: the
    ///    rx-loop dispatches by `ReplyFor` FIRST (`rxloop.rs:35-42`) and its content-type match has no
    ///    arm for `StateConnected` (`rxloop.rs:63-71` → `_ => None`), so a reply that lands before the
    ///    waiter exists is DISCARDED and the wait burns the whole budget. Same discipline as
    ///    `dial`/`send_bind`/`update_token`;
    /// 2. **`DialSuccess`** (`ReplyFor` = the Dial seq, body = the child id) — `conn.go:989-993`;
    /// 3. **await the `StateConnected`** with [`ACCEPT_START_TIMEOUT`] — but ONLY when the child's
    ///    conn-id was GENERATED by us: the oracle's `if !self.routerProvidedConnId` uses `SendForReply`
    ///    (`conn.go:992-1003`), while the router-provided branch is `SendAndWaitForWire` and does not
    ///    wait for any reply (`conn.go:1004`);
    /// 4. **the 24-byte host stream-header** as the first Data frame, if encrypted — AFTER the
    ///    handshake, because the oracle's `if self.txHeader != nil` block sits past the whole `if/else`
    ///    (`conn.go:1009-1017`). Writing it earlier would send `Data` before a legacy router has built
    ///    its side of the conn (`router/xgress_edge/dialer.go:355`, pin `9bf62f3`).
    ///
    /// Two error branches deviate from the oracle's best-effort cleanup but are INERT (carried verbatim
    /// from slice 7b-1, not introduced here), and the deviation survives ONLY there: a `DialSuccess`
    /// write failure removes the child and returns `Err` (the oracle `CompleteAcceptSuccess` would
    /// `close(false)` plus a best-effort `DialFailed`, conn.go:895-907); a stream-header write failure
    /// removes the child and returns `Err` (the oracle does `close(true)` → StateClosed with
    /// `cleanupHandled=true`,
    /// conn.go:1009-1015). Both are dead-transport-only — these writes fail only when the channel is
    /// already broken, where the follow-up DialFailed/StateClosed writes would also fail — so omitting
    /// them is observably inert.
    ///
    /// ⚠ **Alcance EXACTO de esa premisa, acotado (no la leas de más):** «dead-transport-only» califica
    /// SÓLO a esos dos caminos, los de un `write_message` que devuelve `Err`. NO califica a los fallos
    /// del handshake de arranque (`R-8a`/`R-8b`), cuyo canal puede estar perfectamente VIVO — un techo
    /// de 5 s agotado no implica transporte muerto — y que por eso emiten el wire COMPLETO del oráculo
    /// en vez de omitirlo. Y NO afirma nada sobre la LIVENESS de los writes en sí: ninguno lleva cota
    /// propia, lo que es la desviación `D-7` del spec de esta rebanada (clase PREEXISTENTE repo-wide,
    /// declarada allí y NO cerrada aquí).
    ///
    /// # Errors
    /// - `EdgeError::Channel` if writing the `DialSuccess` or the stream header fails.
    /// - `EdgeError::AcceptStartFailed` if the conn-id was GENERATED and the start reply does not
    ///   arrive within [`ACCEPT_START_TIMEOUT`] / the channel dies first (→ a `DialFailed` for the
    ///   CHILD goes out, no `StateClosed`), or arrives with an unexpected content type (→ a
    ///   `StateClosed` goes out, no `DialFailed`).
    pub async fn complete_success(self) -> Result<EdgeConn, EdgeError> {
        let PendingAccept {
            state,
            bind_conn_id,
            child_id,
            router_provided,
            dial_seq,
            data_rx,
            circuit_id,
            source_identity,
            // appData was consumed by the forwarding host (via `app_data()`) BEFORE this ack to resolve
            // the target; the live EdgeConn does not carry it (the oracle's EdgeConn drops appData too).
            app_data: _,
            crypto_setup,
        } = self;

        // Fast-fail on an already-closed channel BEFORE anything reaches the wire — the same guard
        // `dial` carries (`channel.rs`, "the reply-waiter insert below is NOT guarded"), and
        // load-bearing for the same reason: `mark_closed` clears the waiter map exactly ONCE (it is
        // CAS-gated), so a waiter registered after that clear is an ORPHAN nothing will ever wake and
        // the wait below would burn the whole 5s budget. The oracle fails INSTANTLY here — its
        // `SendForReply` selects on the channel's close-notify and returns `ClosedError` without
        // touching the wire (`channel/v4@v4.3.9 senders.go:61-62`), which is `err, cleanupHandled=false`
        // (conn.go:996) and therefore R-8b's wire, emitted here verbatim. Scoped to the GENERATED
        // branch: the router-provided one registers no waiter, so it has no orphan to create.
        if !router_provided && state.is_closed() {
            tracing::error!(
                bind_conn_id,
                child_id,
                "failed to send reply to dial request"
            );
            state.conns.lock().unwrap().remove(&child_id);
            state
                .send_dial_failed(child_id, dial_seq, "start reply not received")
                .await;
            return Err(EdgeError::AcceptStartFailed(
                "start reply not received".to_string(),
            ));
        }

        // Build the DialSuccess (ReplyFor = Dial seq, body = the child id).
        let mut reply = build_dial_success(bind_conn_id, child_id);
        reply
            .headers
            .insert(HDR_REPLY_FOR, dial_seq.to_le_bytes().to_vec());
        reply.sequence = state.next_seq();
        let reply_seq = reply.sequence;

        // (1) Register the start-reply waiter BEFORE the write — see the doc above. Router-provided
        //     ids do not wait at all, so they register nothing.
        let start_rx = if router_provided {
            None
        } else {
            let (start_tx, start_rx) = oneshot::channel();
            state.waiters.lock().unwrap().insert(reply_seq, start_tx);
            Some(start_rx)
        };

        // (2) Write the DialSuccess.
        let send = {
            let mut w = state.write.lock().await;
            write_message(&mut *w, &reply).await
        };
        if let Err(e) = send {
            if start_rx.is_some() {
                state.waiters.lock().unwrap().remove(&reply_seq);
            }
            state.conns.lock().unwrap().remove(&child_id);
            return Err(e.into());
        }

        // (3) With a GENERATED id the DialSuccess is NOT fire-and-forget: the legacy router builds its
        //     conn AFTER reading our `NewConnId` and acknowledges it with a `StateConnected` correlated
        //     to the DialSuccess's own sequence (oracle `SendForReply`, conn.go:993). Both failure
        //     wires (R-8a's StateClosed, R-8b's DialFailed) live in `await_start_reply`.
        if let Some(start_rx) = start_rx {
            await_start_reply(
                &state,
                bind_conn_id,
                child_id,
                dial_seq,
                reply_seq,
                start_rx,
            )
            .await?;
        }

        // (4) AFTER the start handshake (and after the caller's target dial): write the host stream
        // header as the first Data frame (oracle dialSucceeded, conn.go:1009-1017 — the block sits past
        // the whole if/else). A failure here is terminal — DialSuccess already went out, so remove the
        // child + return Err. The oracle here does close(true) → StateClosed + cleanupHandled=true
        // (conn.go:1009-1015); we omit it — INERT, the header write only fails on an already-dead
        // transport where StateClosed would also fail.
        let crypto = match crypto_setup {
            Some((cc, tx_header)) => {
                let mut hdr_msg = build_data(child_id, &tx_header, true);
                hdr_msg.sequence = state.next_seq();
                let send_hdr = {
                    let mut w = state.write.lock().await;
                    write_message(&mut *w, &hdr_msg).await
                };
                if let Err(e) = send_hdr {
                    state.conns.lock().unwrap().remove(&child_id);
                    return Err(e.into());
                }
                Some(cc)
            }
            None => None,
        };

        // Oracle hosting_conn.go:393 `newConnLogger.Debug("dial succeeded")` (connId=child +
        // parentConnId + circuitId). `?circuit_id` borrows — moved into EdgeConn::new just after.
        tracing::debug!(
            bind_conn_id,
            child_id,
            circuit_id = ?circuit_id,
            "dial succeeded"
        );
        Ok(EdgeConn::new(
            child_id,
            circuit_id,
            source_identity,
            data_rx,
            state,
            crypto,
        ))
    }

    /// Complete the accept on an UNREACHABLE target — the faithful failure ack, so the dialer's
    /// `connect()` fails (vs the pre-split eager-DialSuccess, where it succeeded then saw EOF). Emits
    /// the oracle's full failure wire IN ORDER: `DialFailed` (`ReplyFor` = the Dial seq, body =
    /// `reason`) THEN `StateClosed` for the child, THEN deregister from the mux. Oracle:
    /// `provider.go:154-158` (`CompleteAcceptFailed(err)` then `conn.Close()`) → `CompleteAcceptFailed`
    /// → `dialFailed` = `NewDialFailedMsg(id, err)` (`conn.go:919-932`, DialFailed only, no StateClosed)
    /// THEN `Close()` → `close(true)` → `NewStateClosedMsg(conn.Id())` (`conn.go:847,869-877`, fired
    /// because our dialer sends `UseXgressToSdk=0` → `xgCircuit==nil`, the StateClosed branch).
    pub async fn complete_failed(self, reason: &str) {
        // 1. DialFailed (CompleteAcceptFailed → dialFailed).
        self.state
            .send_dial_failed(self.bind_conn_id, self.dial_seq, reason)
            .await;
        // 2. StateClosed for the child (conn.Close → close(true) → NewStateClosedMsg), mirroring
        //    `EdgeWriteHalf::close`'s frame — so the failure wire matches the oracle, not DialFailed
        //    alone. Best-effort (a closing channel may legitimately fail the write).
        let mut closed = build_state_closed(self.child_id);
        closed.sequence = self.state.next_seq();
        {
            let mut w = self.state.write.lock().await;
            let _ = write_message(&mut *w, &closed).await;
        }
        // 3. Deregister from the mux (msgMux.Remove).
        self.state.conns.lock().unwrap().remove(&self.child_id);
    }
}

#[cfg(test)]
impl PendingAccept {
    /// Construct a PLAINTEXT pending accept for tests outside this module (e.g. the tunneler host
    /// tests, which can't reach the private fields). The child must already be registered in `state`.
    ///
    /// `router_provided` is fixed to `true` HERE, inside the constructor, so the signature does not
    /// change and the single call-site (`src/tunnel/host/testsupport.rs:47`) stays untouched: those
    /// tests model the router-provided path, where `complete_success` does NOT wait for a
    /// `StateConnected` (`conn.go:1004`). With `false` they would each burn the full 5s budget.
    pub(crate) fn new_for_test(
        state: Arc<ChannelState>,
        bind_conn_id: u32,
        child_id: u32,
        dial_seq: i32,
        data_rx: mpsc::Receiver<Message>,
    ) -> Self {
        Self {
            state,
            bind_conn_id,
            child_id,
            router_provided: true,
            dial_seq,
            data_rx,
            circuit_id: None,
            source_identity: None,
            app_data: None,
            crypto_setup: None,
        }
    }

    /// Set the appData bytes on a test `PendingAccept` (so the forwarding-host tests can drive the
    /// resolver without a live router emitting header 1011).
    #[must_use]
    pub(crate) fn with_app_data(mut self, app_data: Vec<u8>) -> Self {
        self.app_data = Some(app_data);
        self
    }
}
