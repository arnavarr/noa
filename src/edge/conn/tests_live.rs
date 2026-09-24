//! Test LIVE de renovación de session-cert (F6 tramo 5: movido verbatim del monolito de `edge/conn`).

// ----- session-cert renewal: LIVE proofs (a `#[cfg(test)]` unit test because the renewal-proof
// drives `session_cert_holder()`/`force_renew_from_now()`, which are pub(crate)/test-only) -----

/// Build a READY `updb` `EdgeClient` from a fresh updb identity's JWT, for the live renewal tests.
/// Reuses the S2 env contract (`ZITI_EDGE_JWT_UPDB_S2` + `ZITI_EDGE_UPDB_S2_PASS`). Setup:
///   ziti edge login localhost:1280 -u admin -p admin -y
///   ziti edge create identity scr1 --updb -o /tmp/scr1.jwt
///   export ZITI_EDGE_JWT_UPDB_S2=/tmp/scr1.jwt ZITI_EDGE_UPDB_S2_PASS=scr1password123
/// (delete the identity after: `ziti edge delete identity scr1`).
#[cfg(test)]
async fn updb_client_from_env() -> crate::edge::client::EdgeClient {
    let jwt_path = std::env::var("ZITI_EDGE_JWT_UPDB_S2")
        .expect("set ZITI_EDGE_JWT_UPDB_S2 to a fresh updb identity JWT");
    let jwt = std::fs::read_to_string(&jwt_path).expect("read updb JWT");
    let username = std::env::var("ZITI_EDGE_UPDB_S2_USER").unwrap_or_default();
    let password =
        std::env::var("ZITI_EDGE_UPDB_S2_PASS").unwrap_or_else(|_| "scr1password123".into());
    let cfg = crate::enroll::updb::enroll_updb(
        jwt.trim(),
        &username,
        &password,
        crate::enroll::ott::EnrollOptions::default(),
    )
    .await
    .expect("updb enrolment sets the password");
    crate::edge::client::EdgeClient::from_updb(&cfg)
        .await
        .expect("from_updb: password-auth + session-cert + ready client")
}

// REGRESSION of the shared `open_channel_to` mTLS path through the renewal seam (fresh updb
// connect, NO re-mint) is covered by the EXISTING S2 `enrol_updb_then_connect`
// (`tests/edge_integration.rs`) — same enrol→from_updb→connect→round-trip — re-run because the
// rx-loop is shared by every connection, plus the wiremock `ensure_fresh_does_not_remint_when_fresh`
// (`expect(0)`). The cert-identity + bind neighbors are `enrol_then_connect_both` /
// `bind_then_serve_roundtrip`. We do NOT clone them here; only the forced-remint proof below
// needs the `pub(crate)` holder accessors and so lives in-lib.

/// LIVE PROOF OF THE IMPROVEMENT (beyond the oracle, which never renews): force the holder's clock
/// past `NotAfter`, then `connect("testsvc-noenc")` → the channel's `open_channel_to` seam
/// RE-MINTS the session-cert (reusing the ephemeral key) and the connect STILL round-trips →
/// re-mint + reconnect end-to-end, live. The leaf changes (proves a real re-mint, not a no-op).
#[tokio::test]
#[ignore = "requires a live controller + router + a fresh updb identity (--updb) + testsvc-noenc"]
async fn updb_connect_remints_session_cert_when_forced_live() {
    let client = updb_client_from_env().await;

    // Capture the ORIGINAL leaf, then force the holder to always-renew on the next ensure.
    let leaf_before = {
        let holder = client
            .session_cert_holder()
            .expect("updb client carries a renewable session-cert holder");
        let mut guard = holder.lock().await;
        let before = guard.leaf_pem().to_string();
        guard.force_renew_from_now(); // advance the clock past NotAfter → next ensure re-mints
        before
    };

    // connect() → open_channel_to → channel_client_config → ensure_fresh RE-MINTS, then dials.
    let mut conn = client
        .connect("testsvc-noenc")
        .await
        .expect("updb connect re-mints the session-cert and still connects");
    assert!(
        conn.circuit_id().is_some(),
        "circuit established post-re-mint"
    );
    conn.write(b"hello-renew-forced\n").await.expect("write");
    assert_eq!(
        conn.read().await.expect("read echo").as_deref(),
        Some(&b"hello-renew-forced\n"[..]),
        "round-trip works AFTER a forced session-cert re-mint (re-mint + reconnect, live)"
    );
    conn.close().await.expect("close");

    // The holder's leaf changed → a real re-mint happened (not a silent no-op).
    let leaf_after = {
        let holder = client.session_cert_holder().unwrap();
        let guard = holder.lock().await;
        guard.leaf_pem().to_string()
    };
    assert_ne!(
        leaf_before, leaf_after,
        "the forced ensure RE-MINTED the session-cert (leaf changed)"
    );
    println!(
        "session-cert renewal PROOF OK live: forced re-mint + reconnect round-trips (leaf {} B -> {} B)",
        leaf_before.len(),
        leaf_after.len()
    );
}
