//! The bind module's live test (`#[ignore]`): OIDC-2 — a binding survives Bearer rotation and the
//! router accepts a direct token push (`UpdateTokenSuccess`). In-crate (not `tests/`) because it
//! asserts through the `pub(crate)` test hooks `channel_for_test`/`update_token`.

use std::time::Duration;

// ───────────────────────── OIDC-2 LIVE: bind survives a token push ─────────────────────────
//
// NEW wire (`UpdateToken` ct 60803 to the live edge-router channel) → live validation is
// obligatory (project rule: every new wire exchange gets a live test). This must be an IN-CRATE test (not `tests/`) because
// it asserts the hard `UpdateTokenSuccess` (60801) observation via the `pub(crate)` test hooks
// `channel_for_test`/`update_token`, which a separate integration-test crate cannot reach.
//
// Setup (single-use OTT identities; delete after each run — an enrolment cert binds 1 identity):
//   ziti edge login localhost:1280 -u admin -p admin -y
//   ziti edge create identity oidc2host   -o /tmp/oidc2host.jwt
//   ziti edge create identity oidc2dialer -o /tmp/oidc2dialer.jwt
//   (policies: bindsvc Bind for oidc2host, Dial for oidc2dialer; both bind+dial on the er1 router)
//   export ZITI_EDGE_JWT_OIDC2_HOST=/tmp/oidc2host.jwt ZITI_EDGE_JWT_OIDC2_DIALER=/tmp/oidc2dialer.jwt
#[tokio::test]
#[ignore = "requires a live OIDC-capable controller + online router + bindsvc + 2 JWTs; OIDC-2; pre-flight: scripts/rig-fixtures.sh"]
async fn oidc_bind_survives_token_push_live() {
    use crate::edge::auth_token::ApiSessionType;
    use crate::edge::client::EdgeClient;
    use crate::enroll::ott::{EnrollOptions, enroll};

    fn env_jwt(k: &str) -> String {
        let path = std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
        std::fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("read {k}"))
            .trim()
            .to_string()
    }

    // Host: OIDC cert grant → bind(bindsvc). The binding registers its channel in the live-channel
    // registry, so an OIDC refresh will push the rotated Bearer to it.
    let host_cfg = enroll(
        &env_jwt("ZITI_EDGE_JWT_OIDC2_HOST"),
        EnrollOptions::default(),
    )
    .await
    .expect("host enrolment");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("host client builds");
    host.authenticate_oidc()
        .await
        .expect("host OIDC authenticate (Bearer api-session)");
    let mut binding = host.bind("bindsvc").await.expect("bind(bindsvc) succeeds");
    println!("host OIDC-bound 'bindsvc' conn_id={}", binding.conn_id());

    let bearer_before = host
        .auth_token()
        .expect("token present")
        .channel_token()
        .to_string();

    // Force the Bearer to ROTATE ×2 — the WIRED push fires through `refresh()` each time (the
    // proactive/reactive seams funnel through the same `oidc_session_refresh`).
    host.refresh().await.expect("oidc forced refresh #1");
    host.refresh().await.expect("oidc forced refresh #2");
    let token_after = host.auth_token().expect("token present after refresh");
    assert_eq!(
        token_after.session_type(),
        ApiSessionType::Oidc,
        "still an OIDC session after refresh (no degrade to legacy)"
    );
    let bearer_after = token_after.channel_token().to_string();
    assert_ne!(
        bearer_before, bearer_after,
        "the Bearer rotated across the two forced refreshes"
    );

    // HARD 60801 OBSERVATION: push the current Bearer DIRECTLY to the bind's live channel and assert
    // the edge router ACCEPTS it (UpdateTokenSuccess). This is the direct proof OIDC-2 is about, and
    // it also proves rx_loop routes the 60801 reply by ReplyFor with NO change.
    binding
        .channel_for_test()
        .update_token(&bearer_after, crate::edge::data::UPDATE_TOKEN_TIMEOUT)
        .await
        .expect("the edge router replies UpdateTokenSuccess (60801) for the rotated Bearer");
    println!("OIDC-2: edge router accepted the token push (UpdateTokenSuccess 60801)");

    // The binding SURVIVED the rotation: a dialer round-trips THROUGH our host.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let host_task = tokio::spawn(async move {
        let mut conn = binding.accept().await.expect("host accepts a dial");
        let data = conn
            .read()
            .await
            .expect("host reads from dialer")
            .expect("dialer sent data");
        conn.write(&data).await.expect("host echoes");
        let _ = done_rx.await; // keep the binding (rx-loop) alive until the dialer is done
        let _ = conn.close().await;
        let _ = binding.close().await;
    });

    let dialer_cfg = enroll(
        &env_jwt("ZITI_EDGE_JWT_OIDC2_DIALER"),
        EnrollOptions::default(),
    )
    .await
    .expect("dialer enrolment");
    let mut dialer = EdgeClient::from_identity(&dialer_cfg).expect("dialer client builds");
    dialer.authenticate().await.expect("dialer authenticate");
    let mut dconn = dialer
        .connect("bindsvc")
        .await
        .expect("dialer connect(bindsvc)");
    dconn.write(b"hello-oidc2\n").await.expect("dialer writes");
    let echo = tokio::time::timeout(Duration::from_secs(20), dconn.read())
        .await
        .expect("dialer read did not time out")
        .expect("dialer reads echo");
    assert_eq!(
        echo.as_deref(),
        Some(&b"hello-oidc2\n"[..]),
        "round-trip THROUGH our host survived the 2 Bearer rotations + token push"
    );
    dconn.close().await.ok();

    let _ = done_tx.send(());
    tokio::time::timeout(Duration::from_secs(20), host_task)
        .await
        .expect("host task finishes in time")
        .expect("host task ok");
    println!(
        "OIDC-2 LIVE OK: bind survived 2 Bearer rotations + token push; dialer round-trip works"
    );
}
