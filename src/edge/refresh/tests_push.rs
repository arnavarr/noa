//! Tests del push OIDC-2 (`push_token_to_live_channels`: update, prune, skip-closed,
//! collect-errors y el gate legacy).
//! (F6 tramo 7: movidos verbatim del monolito de `edge/refresh`.)

use super::*;

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::edge::auth_token::AuthToken;
use crate::edge::data::{CT_UPDATE_TOKEN_FAILURE, CT_UPDATE_TOKEN_SUCCESS, EdgeChannel};

use super::testsupport::push_target;

// ───────────────── OIDC-2: push_token_to_live_channels (updateTokenOnAllErs) ─────────────────

fn oidc_token(access: &str) -> Arc<RwLock<Option<AuthToken>>> {
    Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: access.to_string(),
        refresh: Some("r".to_string()),
    })))
}

/// A live OIDC channel receives the rotated Bearer as the UpdateToken body.
#[tokio::test]
async fn push_updates_a_live_oidc_channel() {
    let (ch, rx) = push_target(CT_UPDATE_TOKEN_SUCCESS);
    let registry: LiveChannels = Arc::new(Mutex::new(vec![ch.state_weak()]));
    let token = oidc_token("rotated-bearer");

    push_token_to_live_channels(&registry, &token).await;

    assert_eq!(
        rx.await.unwrap(),
        Some(b"rotated-bearer".to_vec()),
        "the router received the rotated Bearer as the UpdateToken body"
    );
    drop(ch); // keep ch alive across the push, above
}

/// A dropped connection's channel is NOT pushed to and its dead `Weak` is pruned on iterate.
#[tokio::test]
async fn push_skips_and_prunes_a_dropped_channel() {
    let (ch, rx) = push_target(CT_UPDATE_TOKEN_SUCCESS);
    let registry: LiveChannels = Arc::new(Mutex::new(vec![ch.state_weak()]));
    drop(ch); // the ServiceConn/ServiceBinding is gone → the channel's Drop aborts its rx-loop
    // The rx-loop task held a clone of the channel state `Arc`; let the aborted task be reaped so
    // the strong count reaches 0 and the Weak can no longer upgrade (deterministic prune).
    tokio::time::sleep(Duration::from_millis(50)).await;

    push_token_to_live_channels(&registry, &oidc_token("rotated-bearer")).await;

    assert_eq!(
        rx.await.unwrap(),
        None,
        "a dropped channel is not pushed to"
    );
    assert!(
        registry.lock().unwrap().is_empty(),
        "the dead Weak was pruned on iterate"
    );
}

/// Finding A: a pooled-but-CLOSED channel is SKIPPED by the push and does NOT block on the
/// `update_token` reply timeout. The pool keeps a strong `Arc<EdgeChannel>` for a channel whose
/// router half-closed (its WRITE side → our read EOFs → the rx-loop returns + `mark_closed`, so
/// `closed`=true and the rx-loop is GONE) while its READ side stays open (CLOSE_WAIT → our writes
/// still succeed). Its registry `Weak` still upgrades, so without the `!is_closed()` filter
/// `update_token` would write the UpdateToken then block the full `UPDATE_TOKEN_TIMEOUT` (~10s)
/// awaiting a reply the dead rx-loop can never route. Assert the push returns FAST. MUTATION:
/// remove the `!ch.is_closed()` filter → the push blocks ~10s → the 2s timeout fires → RED.
#[tokio::test]
async fn push_skips_a_closed_pooled_channel_without_blocking() {
    // CLOSE_WAIT: the read half EOFs (`empty()`) → the rx-loop exits + `mark_closed` (closed=true,
    // rx-loop GONE), while the write half still accepts writes (`sink()`). This is the pooled-dead
    // channel a graceful router half-close leaves: its registry `Weak` still upgrades (the pool
    // holds the `EdgeChannel`), so without the `!is_closed()` filter `update_token` would write the
    // UpdateToken (sink accepts it) then block the full `UPDATE_TOKEN_TIMEOUT` (~10s) on a reply the
    // gone rx-loop can never route.
    let ch = EdgeChannel::from_halves(
        Box::new(tokio::io::empty()),
        Box::new(tokio::io::sink()),
        std::collections::BTreeMap::new(),
    );
    // Let the rx-loop observe EOF and mark the channel closed.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let state = ch
        .state_weak()
        .upgrade()
        .expect("state alive (the EdgeChannel is held)");
    assert!(
        state.is_closed(),
        "precondition: the channel is closed but its state Arc is alive"
    );

    let registry: LiveChannels = Arc::new(Mutex::new(vec![ch.state_weak()]));
    tokio::time::timeout(
        Duration::from_secs(2),
        push_token_to_live_channels(&registry, &oidc_token("rotated")),
    )
    .await
    .expect("the push must SKIP the closed pooled channel, not block on update_token's 10s reply");
    drop(ch); // keep ch (the EdgeChannel) alive across the push, above
}

/// EVERY live channel is attempted even when one fails: the FAILING channel is registered FIRST, so
/// if the push aborted on its error the OK channel (second) would never be pushed. MUTATION: replace
/// the warn-and-continue with a `return` after the first failure → the OK channel's `rx` is `None`
/// → RED. Mirrors the oracle's `errors.Join` (collect, do not abort).
#[tokio::test]
async fn push_attempts_every_channel_and_collects_errors() {
    let (ch_fail, rx_fail) = push_target(CT_UPDATE_TOKEN_FAILURE);
    let (ch_ok, rx_ok) = push_target(CT_UPDATE_TOKEN_SUCCESS);
    let registry: LiveChannels =
        Arc::new(Mutex::new(vec![ch_fail.state_weak(), ch_ok.state_weak()]));

    push_token_to_live_channels(&registry, &oidc_token("rotated-bearer")).await;

    assert!(
        rx_fail.await.unwrap().is_some(),
        "the failing channel was attempted"
    );
    assert!(
        rx_ok.await.unwrap().is_some(),
        "the OK channel was ALSO attempted, despite the earlier failure"
    );
    drop((ch_fail, ch_ok));
}

/// A LEGACY refresh pushes NOTHING (the `RequiresRouterTokenUpdate` gate). MUTATION: drop the gate
/// → a legacy session emits an UpdateToken → `rx` is `Some` → RED. Oracle: `updateTokenOnAllErs`'s
/// `if apiSession.RequiresRouterTokenUpdate()`.
#[tokio::test]
async fn push_is_a_noop_for_a_legacy_session() {
    let (ch, rx) = push_target(CT_UPDATE_TOKEN_SUCCESS);
    let registry: LiveChannels = Arc::new(Mutex::new(vec![ch.state_weak()]));
    let token = Arc::new(RwLock::new(Some(AuthToken::Legacy("a-uuid".into()))));

    push_token_to_live_channels(&registry, &token).await;

    assert_eq!(
        rx.await.unwrap(),
        None,
        "a legacy session does NOT push a token to the routers"
    );
    drop(ch);
}
