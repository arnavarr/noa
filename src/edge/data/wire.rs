//! Pure wire builders/classifiers + the latency-probe driver and channel-write shutdown. Free
//! functions split out of the monolithic `edge/data` module (F6 tramo 1b), byte-identical. Helpers used
//! from sibling submodules are `pub(super)` (intra-crate, inocuo).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::channel::message::{CT_LATENCY, HDR_PROBE_TIME, Message};
use crate::edge::error::EdgeError;

use super::{
    CT_UPDATE_TOKEN, CT_UPDATE_TOKEN_FAILURE, CT_UPDATE_TOKEN_SUCCESS, ChannelState, ProbeOutcome,
};

/// Build an `UpdateToken` (ct 60803) carrying the raw token BYTES as the body, with NO headers. The
/// caller sets `sequence` at send time (the reply is correlated by `ReplyFor` = this sequence, exactly
/// like the Bind/Dial reply path). Oracle: `NewUpdateTokenMsg(token)` = `channel.NewMessage(60803, token)`
/// (`ziti/edge/messages.go:529`).
#[must_use]
pub fn build_update_token(token: &[u8]) -> Message {
    Message::new(CT_UPDATE_TOKEN, token.to_vec())
}

/// Classify the `UpdateToken` reply (correlated by sequence): `UpdateTokenSuccess` (60801) → `Ok`;
/// `UpdateTokenFailure` (60802) → `Err` carrying the body reason; any other content type → `Err`
/// ("invalid content type"). Oracle: `routerConn.UpdateToken` (`factory.go:160-177`).
pub(super) fn classify_update_token_reply(reply: &Message) -> Result<(), EdgeError> {
    match reply.content_type {
        CT_UPDATE_TOKEN_SUCCESS => Ok(()),
        CT_UPDATE_TOKEN_FAILURE => Err(EdgeError::UpdateTokenFailed {
            reason: String::from_utf8_lossy(&reply.body).into_owned(),
        }),
        other => Err(EdgeError::UpdateTokenFailed {
            reason: format!(
                "invalid content type {other}, expected one of [{CT_UPDATE_TOKEN_SUCCESS}, {CT_UPDATE_TOKEN_FAILURE}]"
            ),
        }),
    }
}

/// Read a `u32` header. `Some` **only** when the header is present AND its value is EXACTLY 4 bytes
/// long; every other case — absent, shorter, LONGER — is `None`. Nothing is truncated: a 5-byte value
/// is rejected, not read as its first 4 bytes.
///
/// The length predicate belongs to the oracle's own getter, `Headers.GetUint32Header`
/// (`channel/v4@v4.3.9 message.go:216-223`): `if !ok || len(encoded) != 4 { return 0, false }`, whose
/// failure is INDISTINGUISHABLE from an absent header — which is what this `None` reproduces. Exact
/// length is the rule of the fixed-width INTEGER getters, one width per type (`GetUint64Header`
/// `:201-208`, `GetUint32Header` `:216-223`, `GetUint16Header` `:231-238`) — NOT of the whole package:
/// the width-1 getters `GetByteHeader` (`:248-254`, `len < 1`) and `GetBoolHeader` (`:264-271`,
/// `len > 0`) take a MINIMUM, not an exact width. Its canonical writer always emits exactly the type's
/// width (`make([]byte, 4)` + `PutUint32`, `message.go:210-214`).
pub(super) fn header_u32(msg: &Message, key: i32) -> Option<u32> {
    msg.headers
        .get(&key)
        .filter(|v| v.len() == 4)
        .map(|v| u32::from_le_bytes(v[..4].try_into().unwrap()))
}

/// Read an `i32` header. `Some` **only** when the header is present AND its value is EXACTLY 4 bytes
/// long; absent, shorter and LONGER all yield `None`, with no truncation.
///
/// `channel` has no `GetInt32Header` (`grep Int32Header` over `channel/v4@v4.3.9` ⇒ 0 hits, against 7
/// for `Uint32Header`), so the predicate is adjudicated by TWO citations, not one: the exact-width
/// class of the fixed-width INTEGER getters (`message.go:201-208`, `:216-223`, `:231-238`; the width-1
/// getters `GetByteHeader`/`GetBoolHeader` are minimum-length, NOT part of it) and this helper's only real
/// consumer, the `ReplyFor` correlation, whose oracle reader also requires exactly 4 bytes.
///
/// Defensive check (deliberate, permanent): the header length is validated BEFORE the value is used
/// for correlation; any value outside the exact 4-byte width is rejected (`None`) and the frame is not
/// correlated to a pending request. `None` is strictly MORE restrictive than the previous `>= 4`,
/// which let a malformed reply wake a live waiter.
pub(super) fn header_i32(msg: &Message, key: i32) -> Option<i32> {
    msg.headers
        .get(&key)
        .filter(|v| v.len() == 4)
        .map(|v| i32::from_le_bytes(v[..4].try_into().unwrap()))
}

/// Monotonic milliseconds since `base`, saturating at `u64::MAX` (well past any real channel lifetime;
/// avoids a lossy `u128 as u64`). Used for the latency probe's read-idle bookkeeping.
pub(super) fn elapsed_millis(base: Instant) -> u64 {
    u64::try_from(base.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Build a latency probe (`CT_LATENCY`=3) carrying the send time in the `probeTime` header. The caller
/// sets `sequence` at send time (the reply is correlated by `ReplyFor` = this sequence). Oracle:
/// `latency.ProbeLatencyConfigurable` request (`channel/v4 latency/latency.go:82-83`).
#[must_use]
pub fn build_latency_probe(now_nanos: u64) -> Message {
    let mut msg = Message::new(CT_LATENCY, Vec::new());
    msg.headers
        .insert(HDR_PROBE_TIME, now_nanos.to_le_bytes().to_vec());
    msg
}

/// Independent death detector: the latency probe. Spawned alongside [`super::rxloop::rx_loop`] by
/// [`super::EdgeChannel::from_halves`]. Periodically sends a probe and, when no reply arrives AND no frame has
/// been read for longer than the interval, closes the channel — releasing a dispatch-stalled rx-loop
/// (via `close_notify`) and EOFing every reader (via the map clear in [`ChannelState::mark_closed`]).
/// This is the mechanism that makes a healthy sibling observe router death even while another sibling
/// HOL-stalls the rx-loop. Sleeps BEFORE the first probe (oracle `latency.go:77`), which also keeps the
/// probe dormant for the first interval so fast unit tests never see a probe frame. Oracle:
/// `go latency.ProbeLatencyConfigurable(...)` + `TimeoutHandler` (`ziti.go:1890-1912`).
pub(crate) async fn run_latency_probe(
    state: Arc<ChannelState>,
    interval: Duration,
    timeout: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        if state.closed.load(Ordering::Acquire) {
            return; // oracle latency.go:78: bail if the channel closed during the sleep
        }
        match state.send_latency_probe(timeout).await {
            // A reply arrived → alive. `send_latency_probe` has already recorded the round-trip into the
            // scoring accumulator (oracle `ResultHandler`, `ziti.go:1890`). Continue probing.
            ProbeOutcome::Alive => {}
            // No reply within the budget → mirror the oracle's TimeoutHandler (ziti.go:1899): close
            // ONLY if there has been no read progress for at least the interval ("no read traffic on
            // channel since before the probe was sent"); otherwise it is just a slow probe on a live
            // channel — keep going.
            ProbeOutcome::Timeout => {
                if state.millis_since_last_read()
                    > u64::try_from(interval.as_millis()).unwrap_or(u64::MAX)
                {
                    // Oracle ziti.go:1897-1901: latency timeout + read-idle → close (byte-exact strings).
                    tracing::error!("latency timeout after [{timeout:?}]");
                    tracing::error!(
                        "no read traffic on channel since before latency probe was sent, closing channel"
                    );
                    state.mark_closed();
                    shutdown_channel_write(&state, timeout).await;
                    return;
                }
                // Slow probe on a still-live channel (there WAS recent read progress): penalize the
                // scoring accumulator with the full timeout, mirroring the oracle's `TimeoutHandler`
                // else-branch `h.Update(int64(LatencyCheckTimeout))` (`ziti.go:1903`). Keep probing.
                state.record_latency(u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX));
            }
            // A probe write failure (transport error OR a wedged/timed-out send) means the transport is
            // dead. The oracle closes on a write error via its INDEPENDENT txer goroutine's deferred
            // `channel.Close()` (impl.go:388); we have no separate txer, so we fold that teardown into the
            // probe (deliberate, same observable). Oracle log: latency.go:84.
            ProbeOutcome::WriteError => {
                tracing::error!("unexpected error sending latency probe, closing channel");
                state.mark_closed();
                shutdown_channel_write(&state, timeout).await;
                return;
            }
            // Someone else already tore the channel down → nothing to do (oracle latency.go:88 logs Info).
            ProbeOutcome::Closed => {
                tracing::debug!("latency probe channel closed, exiting");
                return;
            }
        }
    }
}

/// Best-effort shutdown of the channel's write half so the router observes EOF after a probe-detected
/// death (mirrors the write shutdown in [`super::EdgeChannel::close`]). The read half is independent and is not
/// touched here; readers are EOFed by the map clear in [`ChannelState::mark_closed`], which has ALREADY
/// run by the time we get here. Bounded by `timeout` so a write lock still held by a wedged bulk writer
/// (the F1 case) cannot leak this probe task — the load-bearing teardown is already done.
async fn shutdown_channel_write(state: &ChannelState, timeout: Duration) {
    let _ = tokio::time::timeout(timeout, async {
        let mut w = state.write.lock().await;
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut *w).await;
    })
    .await;
}
