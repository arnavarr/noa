//! Unit tests for `flow.rs`: `EdgeClient::bind` / `bind_with_timeout` / `bind_inner` — the
//! not-authenticated guard and the bind-timeout contract, driven over a fake router.

use super::DEFAULT_BIND_TIMEOUT;
use super::testsupport::{fast_bind_channel, hanging_bind_channel, mount_bind_resolve_and_create};
use crate::edge::client::EdgeClient;
use crate::edge::data::EdgeChannel;
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;
use std::time::Duration;
use wiremock::MockServer;

#[tokio::test]
async fn bind_without_auth_is_not_authenticated() {
    use crate::edge::client::EdgeClient;
    let client = EdgeClient::from_identity_for_test();
    let err = client.bind("bindsvc").await.unwrap_err();
    assert!(matches!(err, EdgeError::NotAuthenticated));
}

// ----- bind-timeout (bind-side sibling of slice 10b): the internal deadline over bind's flow -----

#[tokio::test]
async fn bind_inner_times_out_when_bind_never_replies() {
    let server = MockServer::start().await;
    mount_bind_resolve_and_create(&server).await; // REST resolves + creates fine; the Bind hangs
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let timeout = Duration::from_millis(150);
    let start = std::time::Instant::now();
    let err = client
        .bind_inner("bindsvc", timeout, async |_d: &SessionDetail| {
            Ok::<EdgeChannel, EdgeError>(hanging_bind_channel())
        })
        .await
        .expect_err("a router that never replies to the Bind must trip the bind-timeout");
    let elapsed = start.elapsed();
    assert!(
        matches!(&err, EdgeError::BindTimedOut { service, timeout: t }
            if service == "bindsvc" && *t == timeout),
        "expected BindTimedOut for bindsvc, got: {err:?}"
    );
    // The test itself must finish fast: the deadline fired, not a real router timeout.
    assert!(
        elapsed < Duration::from_secs(2),
        "bind-timeout did not bound wall-clock: {elapsed:?}"
    );
}

#[tokio::test]
async fn bind_with_timeout_succeeds_well_within_a_generous_budget() {
    let server = MockServer::start().await;
    mount_bind_resolve_and_create(&server).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    // A fast fake router replies StateConnected immediately → no spurious timeout.
    let binding = client
        .bind_inner(
            "bindsvc",
            Duration::from_secs(30),
            async |_d: &SessionDetail| Ok::<EdgeChannel, EdgeError>(fast_bind_channel()),
        )
        .await
        .expect("a fast bind succeeds well within the generous bind-timeout");
    assert_eq!(binding.conn_id(), 1, "bind conn id allocated");
    // Drop the binding without close(): no live router to receive an Unbind here.
    drop(binding);
}

/// Pins the bind-timeout contract: `bind()`'s default budget is the oracle's `time.Minute` (60s,
/// `ListenOptions.ConnectTimeout` default, `ziti.go:1638-1639`) — DISTINCT from connect's 15s.
/// `bind()` delegates to `bind_with_timeout(.., DEFAULT_BIND_TIMEOUT)`, which can't be unit-tested
/// without a live router (it wires `self.open_channel`), so this pins the constant the glue passes.
#[test]
fn default_bind_timeout_is_the_oracle_60s() {
    assert_eq!(DEFAULT_BIND_TIMEOUT, Duration::from_secs(60));
    // Faithful to the oracle's DIFFERENT listen/dial defaults: bind 60s != connect 15s.
    assert_ne!(
        DEFAULT_BIND_TIMEOUT,
        crate::edge::conn::DEFAULT_CONNECT_TIMEOUT,
        "the oracle gives listen (60s) and dial (15s) different defaults; do not collapse them"
    );
}

/// Normalization consistency with connect (slice 10b §5): `bind_with_timeout(name, d)` treats `d`
/// as the resolved deadline and does NOT normalize it (the `==0 → time.Minute` normalization is on
/// the defaulted-option path `bind()` only). A near-zero explicit budget therefore trips almost
/// immediately — same conscious deviation 10b documents for `connect_with_timeout`.
#[tokio::test]
async fn bind_inner_does_not_normalize_a_tiny_budget() {
    let server = MockServer::start().await;
    mount_bind_resolve_and_create(&server).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = EdgeClient::for_test_with(&base, "API-TOK");

    let timeout = Duration::from_millis(1);
    let err = client
        .bind_inner("bindsvc", timeout, async |_d: &SessionDetail| {
            Ok::<EdgeChannel, EdgeError>(hanging_bind_channel())
        })
        .await
        .expect_err("a ~zero explicit budget is NOT normalized → it trips");
    assert!(
        matches!(&err, EdgeError::BindTimedOut { service, timeout: t }
            if service == "bindsvc" && *t == timeout),
        "expected BindTimedOut (no normalization of the explicit arg), got: {err:?}"
    );
}
