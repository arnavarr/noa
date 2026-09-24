//! Split test module (F6 tramo 1b), byte-identical bodies.
use super::testsupport::*;
use super::*;

#[tokio::test]
#[traced_test]
async fn accept_next_accepts_dial_and_round_trips() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        // 1. reply StateConnected to the bind (ReplyFor = bind seq)
        let bind = read_message(&mut router).await.unwrap();
        assert_eq!(bind.content_type, crate::edge::bind::CT_BIND);
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();

        // 2. incoming Dial for the bind conn-id: child id = 42, circuit, seq = 99
        let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"bind-jwt".to_vec());
        dial.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        dial.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            42u32.to_le_bytes().to_vec(),
        );
        dial.headers.insert(HDR_CIRCUIT_ID, b"circ-bind".to_vec());
        dial.sequence = 99;
        write_message(&mut router, &dial).await.unwrap();

        // 3. read the DialSuccess (ct 60788, ConnId=bind, body=42, ReplyFor=99)
        let ds = read_message(&mut router).await.unwrap();
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(ds.headers.get(&HDR_CONN_ID).unwrap(), &bind_conn_id);
        assert_eq!(ds.body, 42u32.to_le_bytes());
        assert_eq!(ds.headers.get(&1).unwrap().as_slice(), &99i32.to_le_bytes());

        // 4. round-trip: send Data to child 42, read the host's echo (first frame MULTIPART)
        let mut data = Message::new(CT_DATA, b"ping-host".to_vec());
        data.headers
            .insert(HDR_CONN_ID, 42u32.to_le_bytes().to_vec());
        write_message(&mut router, &data).await.unwrap();
        let echo = read_message(&mut router).await.unwrap();
        assert_eq!(echo.content_type, CT_DATA);
        assert_eq!(echo.body, b"ping-host");
        // Oracle-verified (NOT assumed): MsgChannel.WriteTraced (`ziti/edge/conn.go:186-202`) sets
        // MULTIPART on the first message sent via ConnFlagIdxFirstMsgSent, and the host's
        // child uses the same NewEdgeMsgChannel (hosting_conn.go:304); plaintext sends no
        // frame before the first user write, so the host's first Data carries MULTIPART.
        assert_eq!(
            echo.headers.get(&HDR_FLAGS).unwrap().as_slice(),
            &[4, 0, 0, 0],
            "host first write advertises MULTIPART"
        );
    });

    let (bind_id, mut bind_rx) = ch
        .send_bind("bind-jwt", "lid-acc", None)
        .await
        .expect("bind ok");
    let mut conn = ch
        .accept_next(bind_id, "bind-jwt", None, &mut bind_rx)
        .await
        .expect("accept ok");
    assert_eq!(conn.conn_id(), 42);
    assert_eq!(conn.circuit_id(), Some("circ-bind"));
    assert_eq!(conn.read().await.unwrap(), Some(b"ping-host".to_vec()));
    conn.write(b"ping-host").await.unwrap();
    // Point 4: a successful accept emits a DEBUG (oracle hosting_conn.go:393
    // `newConnLogger.Debug("dial succeeded")`), carrying the child conn-id.
    assert!(
        logs_contain("dial succeeded"),
        "successful accept must debug-log"
    );
    // NEGATIVE: the happy plaintext accept emits NO warn/error (none of the three
    // reject/downgrade phrases). Absence of "dial succeeded" is NOT asserted — the
    // happy path now emits it.
    assert!(
        !logs_contain("invalid token")
            && !logs_contain("failed to establish crypto session")
            && !logs_contain("client did not send its key"),
        "happy accept must not emit any warn/error"
    );

    router_task.await.unwrap();
    ch.close().await.unwrap();
}

/// T4a CRUX: `accept_pending` validates + registers the child but sends NOTHING on the wire — the
/// DialSuccess appears ONLY after `complete_success` (the faithful accept-then-dial order, so a
/// host can dial its target in between). A regression that acked inside accept_pending would make
/// the "no DialSuccess yet" timeout RED (a DialSuccess would arrive before complete_success).
#[tokio::test]
async fn accept_pending_does_not_ack_until_complete_success() {
    let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
        bound_channel_with_router().await;
    send_inbound_dial(&mut router, &bind_conn_id_hdr).await;

    let pending = ch
        .accept_pending(bind_id, "bind-jwt", None, &mut bind_rx)
        .await
        .expect("pending");
    assert_eq!(pending.child_id(), 42);
    assert_eq!(
        ch.state.conn_count(),
        1,
        "the child is registered at accept_pending"
    );

    // CRUX: no DialSuccess is on the wire yet — a read must TIME OUT (nothing was written).
    let nothing = tokio::time::timeout(Duration::from_millis(150), read_message(&mut router)).await;
    assert!(
        nothing.is_err(),
        "accept_pending must NOT send DialSuccess before complete_success (the split)"
    );

    // complete_success now acks: DialSuccess (body=child 42, ReplyFor=99) goes out.
    let _conn = pending.complete_success().await.expect("complete ok");
    let ds = tokio::time::timeout(Duration::from_secs(2), read_message(&mut router))
        .await
        .expect("DialSuccess within timeout")
        .unwrap();
    assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
    assert_eq!(ds.body, 42u32.to_le_bytes());
    assert_eq!(
        ds.headers.get(&HDR_REPLY_FOR).unwrap().as_slice(),
        &99i32.to_le_bytes(),
        "DialSuccess correlates to the inbound Dial seq"
    );
    ch.close().await.unwrap();
}

/// T4a: `complete_failed` (the faithful failure ack for an unreachable target) emits the oracle's
/// full failure wire IN ORDER — `DialFailed` (ReplyFor = the Dial seq, body = the reason) THEN
/// `StateClosed` for the child — then deregisters the child. So the dialer's `connect()` fails (vs
/// the pre-split eager-DialSuccess-then-close), AND the trailing StateClosed matches the oracle
/// (`conn.Close()` → `close(true)` → `NewStateClosedMsg`, fired for our `UseXgressToSdk=0` profile).
/// Reads are bounded so a dropped-frame regression fails clean (not a hang).
#[tokio::test]
async fn complete_failed_sends_dial_failed_then_state_closed_and_deregisters() {
    let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
        bound_channel_with_router().await;
    send_inbound_dial(&mut router, &bind_conn_id_hdr).await;

    let pending = ch
        .accept_pending(bind_id, "bind-jwt", None, &mut bind_rx)
        .await
        .expect("pending");
    assert_eq!(
        ch.state.conn_count(),
        1,
        "child registered before completion"
    );

    pending.complete_failed("target dial failed").await;

    // 1. DialFailed FIRST (ReplyFor = Dial seq, body = reason).
    let df = tokio::time::timeout(Duration::from_secs(2), read_message(&mut router))
        .await
        .expect("DialFailed within timeout")
        .unwrap();
    assert_eq!(df.content_type, crate::edge::bind::CT_DIAL_FAILED);
    assert_eq!(df.body, b"target dial failed");
    assert_eq!(
        df.headers.get(&HDR_REPLY_FOR).unwrap().as_slice(),
        &99i32.to_le_bytes(),
        "DialFailed correlates to the inbound Dial seq"
    );
    // 2. StateClosed for the child SECOND (the faithful trailing frame the oracle's close(true) emits).
    let sc = tokio::time::timeout(Duration::from_secs(2), read_message(&mut router))
        .await
        .expect("StateClosed within timeout")
        .unwrap();
    assert_eq!(
        sc.content_type, CT_STATE_CLOSED,
        "complete_failed sends StateClosed AFTER DialFailed (faithful order: DialFailed -> StateClosed)"
    );
    assert_eq!(
        sc.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
        &42u32.to_le_bytes(),
        "the StateClosed targets the child conn-id"
    );
    assert_eq!(
        ch.state.conn_count(),
        0,
        "complete_failed deregisters the child"
    );
    ch.close().await.unwrap();
}

#[traced_test]
#[tokio::test]
async fn accept_next_rejects_bad_token_then_accepts() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();

        // bad-token dial (seq 5) -> expect DialFailed, listener survives
        let mut bad = Message::new(crate::edge::bind::CT_DIAL, b"WRONG".to_vec());
        bad.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        bad.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            7u32.to_le_bytes().to_vec(),
        );
        bad.sequence = 5;
        write_message(&mut router, &bad).await.unwrap();
        let df = read_message(&mut router).await.unwrap();
        assert_eq!(df.content_type, crate::edge::bind::CT_DIAL_FAILED);
        assert_eq!(df.headers.get(&1).unwrap().as_slice(), &5i32.to_le_bytes());

        // good dial (seq 6, child 8)
        let mut good = Message::new(crate::edge::bind::CT_DIAL, b"bind-jwt".to_vec());
        good.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        good.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            8u32.to_le_bytes().to_vec(),
        );
        good.sequence = 6;
        write_message(&mut router, &good).await.unwrap();
        let ds = read_message(&mut router).await.unwrap();
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(ds.body, 8u32.to_le_bytes());
    });

    let (bind_id, mut bind_rx) = ch
        .send_bind("bind-jwt", "lid-rej", None)
        .await
        .expect("bind ok");
    let conn = ch
        .accept_next(bind_id, "bind-jwt", None, &mut bind_rx)
        .await
        .expect("accept ok after reject");
    assert_eq!(conn.conn_id(), 8);
    // Point 2: the invalid-token reject emits a WARN (oracle hosting_conn.go:279
    // `logger.Warn("invalid token")`), carrying the bind conn-id as a field.
    assert!(
        logs_contain("invalid token"),
        "invalid-token reject must warn"
    );
    // O5: the `accept_pending` span (the instrument moved here in T4a — it's where the
    // validation/reject logs are emitted) records `bind_conn_id`, so the host logs above are
    // correlated to the connection. And CRITICALLY — the session token passed in ("bind-jwt") is
    // SKIPPED in the instrument, so it is NEVER rendered as a span field (security). We pin the
    // SPAN shape (`accept_pending{bind_conn_id`), not the bare field name: the O2 events already
    // emit `bind_conn_id` themselves, so a bare `logs_contain("bind_conn_id")` would pass even if
    // the span dropped the field (`skip_all`). The `name{field` prefix is span-only.
    assert!(
        logs_contain("accept_pending{bind_conn_id"),
        "the accept span itself must record bind_conn_id (span prefix, not the O2 event field)"
    );
    assert!(
        !logs_contain("bind-jwt"),
        "SECURITY: the session token must never appear in logs (skip(token) in the instrument)"
    );
    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
async fn accept_next_returns_listener_closed_on_bind_state_closed() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        // router closes the bind
        let mut closed = Message::new(CT_STATE_CLOSED, b"bind closed".to_vec());
        closed.headers.insert(HDR_CONN_ID, bind_conn_id);
        write_message(&mut router, &closed).await.unwrap();
    });
    let (bind_id, mut bind_rx) = ch
        .send_bind("bind-jwt", "lid-c1", None)
        .await
        .expect("bind ok");
    let err = ch
        .accept_next(bind_id, "bind-jwt", None, &mut bind_rx)
        .await
        .unwrap_err();
    assert!(matches!(err, EdgeError::ListenerClosed));
    router_task.await.unwrap();
}

#[tokio::test]
async fn accept_next_returns_listener_closed_on_channel_death() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        // router dropped here -> rx-loop EOF -> binds cleared -> bind_rx yields None
    });
    let (bind_id, mut bind_rx) = ch
        .send_bind("bind-jwt", "lid-c2", None)
        .await
        .expect("bind ok");
    router_task.await.unwrap();
    let err = ch
        .accept_next(bind_id, "bind-jwt", None, &mut bind_rx)
        .await
        .unwrap_err();
    assert!(matches!(err, EdgeError::ListenerClosed));
}

#[tokio::test]
async fn accept_next_encrypted_round_trip() {
    use crate::edge::crypto::{Decryptor, Encryptor, KeyPair};
    use crate::edge::dial::{HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY};

    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let host = KeyPair::generate();
    let host_pk = host.public_key();

    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();

        // Fake dialer: REAL CLIENT kx against the host pubkey (NOT server — else the
        // invariant is bypassed and the test passes for the wrong reason).
        let dialer = KeyPair::generate();
        let (d_rx, d_tx) = dialer.client_session_keys(&host_pk).unwrap();

        let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"bind-jwt".to_vec());
        dial.headers.insert(HDR_CONN_ID, bind_conn_id);
        dial.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            77u32.to_le_bytes().to_vec(),
        );
        dial.headers
            .insert(HDR_PUBLIC_KEY, dialer.public_key().to_vec());
        dial.headers.insert(HDR_CRYPTO_METHOD, vec![0u8]);
        dial.headers.insert(HDR_CIRCUIT_ID, b"circ-enc".to_vec());
        dial.sequence = 21;
        write_message(&mut router, &dial).await.unwrap();

        // DialSuccess: ct 60788, body=child=77, ReplyFor=21.
        let ds = read_message(&mut router).await.unwrap();
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(ds.body, 77u32.to_le_bytes());
        assert_eq!(ds.headers.get(&1).unwrap().as_slice(), &21i32.to_le_bytes());

        // Host stream header (first Data, 24B, MULTIPART) -> our decryptor.
        let hhdr = read_message(&mut router).await.unwrap();
        assert_eq!(hhdr.content_type, CT_DATA);
        assert_eq!(hhdr.body.len(), 24);
        assert_eq!(
            hhdr.headers.get(&HDR_FLAGS).unwrap().as_slice(),
            &[4, 0, 0, 0]
        );
        let host_header: [u8; 24] = hhdr.body.as_slice().try_into().unwrap();
        let mut dialer_dec = Decryptor::new(&d_rx, &host_header);

        // Dialer's stream header (first Data on child) then an encrypted payload.
        let (mut dialer_enc, dialer_header) = Encryptor::new(&d_tx);
        let mut dh = Message::new(CT_DATA, dialer_header.to_vec());
        dh.headers.insert(HDR_CONN_ID, 77u32.to_le_bytes().to_vec());
        write_message(&mut router, &dh).await.unwrap();
        let secret = dialer_enc.push(b"enc-ping").unwrap();
        let mut dm = Message::new(CT_DATA, secret);
        dm.headers.insert(HDR_CONN_ID, 77u32.to_le_bytes().to_vec());
        write_message(&mut router, &dm).await.unwrap();

        // Host's encrypted echo -> decrypt it.
        let echo = read_message(&mut router).await.unwrap();
        let plain = dialer_dec.pull(&echo.body).unwrap();
        assert_eq!(plain, b"enc-ping");
    });

    let (bind_id, mut bind_rx) = ch
        .send_bind("bind-jwt", "lid-enc", None)
        .await
        .expect("bind ok");
    let mut conn = ch
        .accept_next(bind_id, "bind-jwt", Some(&host), &mut bind_rx)
        .await
        .expect("accept enc");
    assert_eq!(conn.conn_id(), 77);
    assert_eq!(conn.circuit_id(), Some("circ-enc"));
    let got = conn.read().await.unwrap().unwrap();
    assert_eq!(got, b"enc-ping");
    conn.write(&got).await.unwrap();

    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
#[traced_test]
async fn accept_next_bad_crypto_method_fails_dial_and_keeps_accepting() {
    use crate::edge::crypto::KeyPair;
    use crate::edge::dial::{HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY};

    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let host = KeyPair::generate();

    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        let dialer = KeyPair::generate();

        // Bad-method dial (seq 5): PublicKey present, CryptoMethod = 1 (unsupported).
        let mut bad = Message::new(crate::edge::bind::CT_DIAL, b"bind-jwt".to_vec());
        bad.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        bad.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            9u32.to_le_bytes().to_vec(),
        );
        bad.headers
            .insert(HDR_PUBLIC_KEY, dialer.public_key().to_vec());
        bad.headers.insert(HDR_CRYPTO_METHOD, vec![1u8]);
        bad.sequence = 5;
        write_message(&mut router, &bad).await.unwrap();
        // DialFailed (NOT DialSuccess), ReplyFor=5.
        let df = read_message(&mut router).await.unwrap();
        assert_eq!(df.content_type, crate::edge::bind::CT_DIAL_FAILED);
        assert_eq!(df.headers.get(&1).unwrap().as_slice(), &5i32.to_le_bytes());

        // A subsequent valid encrypted dial (seq 6, child 10) succeeds: listener survived.
        let mut good = Message::new(crate::edge::bind::CT_DIAL, b"bind-jwt".to_vec());
        good.headers.insert(HDR_CONN_ID, bind_conn_id);
        good.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            10u32.to_le_bytes().to_vec(),
        );
        good.headers
            .insert(HDR_PUBLIC_KEY, dialer.public_key().to_vec());
        good.headers.insert(HDR_CRYPTO_METHOD, vec![0u8]);
        good.sequence = 6;
        write_message(&mut router, &good).await.unwrap();
        let ds = read_message(&mut router).await.unwrap();
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(ds.body, 10u32.to_le_bytes());
        let _hdr = read_message(&mut router).await.unwrap(); // drain the host header
    });

    let (bind_id, mut bind_rx) = ch
        .send_bind("bind-jwt", "lid-badm", None)
        .await
        .expect("bind ok");
    let conn = ch
        .accept_next(bind_id, "bind-jwt", Some(&host), &mut bind_rx)
        .await
        .expect("accept after reject");
    assert_eq!(conn.conn_id(), 10);
    // Point 3: the crypto-setup-fail reject emits an ERROR (oracle hosting_conn.go:367
    // `cleanupAndReportError(desc, err)` -> `logger.WithError(err).Error(desc)`) carrying
    // BOTH the fixed reason AND the captured EdgeError detail the fixed-reason wire
    // `DialFailed` discards. The wire reason stays "failed to establish crypto session".
    assert!(
        logs_contain("failed to establish crypto session"),
        "crypto-fail reject must error-log the fixed reason"
    );
    assert!(
        logs_contain("unsupported crypto method"),
        "crypto-fail reject must log the captured EdgeError detail"
    );
    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
async fn accept_next_encrypted_service_no_client_key_falls_back_to_plaintext() {
    use crate::edge::crypto::KeyPair;

    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let host = KeyPair::generate();

    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();

        // Dial with NO PublicKey, even though the host has a keypair (encrypted service).
        let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"bind-jwt".to_vec());
        dial.headers.insert(HDR_CONN_ID, bind_conn_id);
        dial.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            12u32.to_le_bytes().to_vec(),
        );
        dial.sequence = 3;
        write_message(&mut router, &dial).await.unwrap();

        // DialSuccess, then NO host header (plaintext). Round-trip a PLAIN frame; the host's
        // first write carries MULTIPART because crypto=None.
        let ds = read_message(&mut router).await.unwrap();
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        let mut data = Message::new(CT_DATA, b"plain-ping".to_vec());
        data.headers
            .insert(HDR_CONN_ID, 12u32.to_le_bytes().to_vec());
        write_message(&mut router, &data).await.unwrap();
        let echo = read_message(&mut router).await.unwrap();
        assert_eq!(echo.body, b"plain-ping");
        assert_eq!(
            echo.headers.get(&HDR_FLAGS).unwrap().as_slice(),
            &[4, 0, 0, 0]
        );
    });

    let (bind_id, mut bind_rx) = ch
        .send_bind("bind-jwt", "lid-nokey", None)
        .await
        .expect("bind ok");
    let mut conn = ch
        .accept_next(bind_id, "bind-jwt", Some(&host), &mut bind_rx)
        .await
        .expect("accept plaintext fallback");
    assert_eq!(conn.conn_id(), 12);
    let got = conn.read().await.unwrap().unwrap();
    assert_eq!(got, b"plain-ping");
    conn.write(&got).await.unwrap();
    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
async fn accept_next_exposes_caller_id_as_source_identity() {
    use crate::edge::dial::HDR_CALLER_ID;
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        // bind handshake
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();

        // dial #1 WITH CallerId=b"dialer-x" (child 42)
        let mut d1 = Message::new(crate::edge::bind::CT_DIAL, b"bj".to_vec());
        d1.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        d1.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            42u32.to_le_bytes().to_vec(),
        );
        d1.headers.insert(HDR_CALLER_ID, b"dialer-x".to_vec());
        d1.sequence = 1;
        write_message(&mut router, &d1).await.unwrap();
        let _ = read_message(&mut router).await.unwrap(); // DialSuccess #1

        // dial #2 WITHOUT CallerId (child 43)
        let mut d2 = Message::new(crate::edge::bind::CT_DIAL, b"bj".to_vec());
        d2.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        d2.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            43u32.to_le_bytes().to_vec(),
        );
        d2.sequence = 2;
        write_message(&mut router, &d2).await.unwrap();
        let _ = read_message(&mut router).await.unwrap(); // DialSuccess #2
    });

    let (bind_id, mut bind_rx) = ch.send_bind("bj", "lid", None).await.expect("bind ok");
    let c1 = ch
        .accept_next(bind_id, "bj", None, &mut bind_rx)
        .await
        .expect("accept 1");
    assert_eq!(c1.conn_id(), 42);
    assert_eq!(c1.source_identity(), Some("dialer-x"));
    let c2 = ch
        .accept_next(bind_id, "bj", None, &mut bind_rx)
        .await
        .expect("accept 2");
    assert_eq!(c2.conn_id(), 43);
    assert_eq!(c2.source_identity(), None);

    router_task.await.unwrap();
    ch.close().await.unwrap();
}

/// T4b-1: `accept_pending` captures the inbound Dial's AppData header (1011) and exposes it via
/// `PendingAccept::app_data()` (the forwarding host reads it to resolve a dynamic target). A dial
/// with NO AppData → `app_data()` is `None`. `accept_pending` sends NOTHING on the wire (T4a), so no
/// DialSuccess is read here.
#[tokio::test]
async fn accept_pending_exposes_app_data_header() {
    use crate::edge::dial::HDR_APPDATA;
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let app = crate::edge::dial::build_app_data("tcp", "127.0.0.1", "19009", None, None);
    let app_for_router = app.clone();

    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let bind_conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();

        // dial #1 WITH AppData (child 42)
        let mut d1 = Message::new(crate::edge::bind::CT_DIAL, b"bj".to_vec());
        d1.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        d1.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            42u32.to_le_bytes().to_vec(),
        );
        d1.headers.insert(HDR_APPDATA, app_for_router);
        d1.sequence = 1;
        write_message(&mut router, &d1).await.unwrap();

        // dial #2 WITHOUT AppData (child 43)
        let mut d2 = Message::new(crate::edge::bind::CT_DIAL, b"bj".to_vec());
        d2.headers.insert(HDR_CONN_ID, bind_conn_id.clone());
        d2.headers.insert(
            crate::edge::bind::HDR_ROUTER_PROVIDED_CONN_ID,
            43u32.to_le_bytes().to_vec(),
        );
        d2.sequence = 2;
        write_message(&mut router, &d2).await.unwrap();
    });

    let (bind_id, mut bind_rx) = ch.send_bind("bj", "lid", None).await.expect("bind ok");
    let p1 = ch
        .accept_pending(bind_id, "bj", None, &mut bind_rx)
        .await
        .expect("accept_pending 1");
    assert_eq!(p1.child_id(), 42);
    assert_eq!(
        p1.app_data(),
        Some(app.as_slice()),
        "appData header captured verbatim"
    );
    let p2 = ch
        .accept_pending(bind_id, "bj", None, &mut bind_rx)
        .await
        .expect("accept_pending 2");
    assert_eq!(p2.child_id(), 43);
    assert_eq!(p2.app_data(), None, "no AppData header → None");

    router_task.await.unwrap();
    ch.close().await.unwrap();
}

// ────── qw-getnextid-clamp: el accept GENERA el conn-id, y el DialSuccess espera arranque ──────

/// Construye un `Dial` entrante para el bind, con `sequence` 99 y token válido. `router_conn_id`
/// pone el header 1012 tal cual (`None` = SIN header, la clase que el oráculo GENERA).
fn inbound_dial(bind_conn_id_hdr: &[u8], router_conn_id: Option<Vec<u8>>) -> Message {
    let mut dial = Message::new(CT_DIAL, b"bind-jwt".to_vec());
    dial.headers.insert(HDR_CONN_ID, bind_conn_id_hdr.to_vec());
    if let Some(v) = router_conn_id {
        dial.headers.insert(HDR_ROUTER_PROVIDED_CONN_ID, v);
    }
    dial.sequence = 99;
    dial
}

/// `T-6` (`R-4` + `R-6`). Un `Dial` SIN `RouterProvidedConnId` ya no se RECHAZA: el port GENERA el
/// conn-id con el generador clampeado (`hosting_conn.go:290-296`) y, por ser GENERADO, el
/// `DialSuccess` espera el `StateConnected` del router antes de dar la conn por viva
/// (`conn.go:992-1003`).
///
/// El id GENERADO es `2`: el bind consumió el contador (⇒ candidato 2) y además el `1` está en
/// `binds`, así que el skip también lo saltaría.
///
/// MUTACIÓN ASESINA (`F-i` de §12 del spec; la firma va ABREVIADA a propósito — teclear aquí el
/// literal de wire RETIRADO INOCULARÍA el censo del paso 6b, que lo exige a 0 en `src/`): restaurar
/// el `else { send_dial_failed(…) }` con el literal del rechazo ⇒ el primer frame del cable es
/// `CT_DIAL_FAILED` y el test muere en su primer assert.
#[tokio::test]
async fn accept_next_generates_a_conn_id_when_the_dial_has_no_router_provided_conn_id() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        let dial = inbound_dial(&bind_conn_id_hdr, None);
        write_message(&mut router, &dial).await.unwrap();

        let (conn_res, ds) = tokio::join!(
            ch.accept_next(bind_id, "bind-jwt", None, &mut bind_rx),
            async {
                let ds = read_message(&mut router).await.unwrap();
                // El `StateConnected` correla con el `sequence` del DIALSUCCESS, no con el del Dial.
                let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
                sc.headers
                    .insert(HDR_REPLY_FOR, ds.sequence.to_le_bytes().to_vec());
                write_message(&mut router, &sc).await.unwrap();
                ds
            }
        );

        assert_eq!(
            ds.content_type,
            crate::edge::bind::CT_DIAL_SUCCESS,
            "sin el header 1012 el oráculo GENERA: lo primero del cable es DialSuccess, no DialFailed"
        );
        assert_eq!(
            ds.body,
            2u32.to_le_bytes(),
            "el body del DialSuccess es el id GENERADO (2), no uno del router"
        );
        assert_eq!(
            ds.headers.get(&HDR_REPLY_FOR).unwrap().as_slice(),
            &99i32.to_le_bytes(),
            "el DialSuccess correla con el sequence del Dial entrante"
        );
        let conn = conn_res.expect("accept con id generado");
        assert_eq!(conn.conn_id(), 2, "la conn viva lleva el id GENERADO");
        ch.close().await.unwrap();
    })
    .await
    .expect("T-6: accept_next no retornó dentro del presupuesto");
}

/// `T-7` (`R-4`). RENOMBRA y RE-FIXTURA `accept_next_rejects_dial_when_router_provided_conn_id_is_five_bytes`
/// (rebanada `qw-wire-header-len`): un 1012 de 5 bytes sigue siendo ILEGIBLE (`header_u32` ⇒ `None`,
/// longitud EXACTA de 4), pero ahora esa clase GENERA en vez de rechazar — igual que la ausencia,
/// porque `GetUint32Header` no las distingue (`message.go:216-223`).
///
/// **Falsador CONSERVADO de la rebanada anterior** (RB-5: re-fixturar BORRA el falsador previo, así
/// que se dice cuál sobrevive): la mutación `v.len() == 4` → `v.len() >= 4` en `header_u32`
/// (`wire.rs:57`) hace que el port TRUNQUE el prefijo LE a `42` y use `42` como id del hijo ⇒ los
/// asserts `== 2` mueren. `C-2`/`D-1` de `2026-08-22-qw-wire-header-len-design.md` siguen teniendo
/// falsador; sólo cambia lo que discrimina: «truncado» vs «generado» en vez de «truncado» vs
/// «rechazado».
///
/// SEGUNDA MUTACIÓN ASESINA: restaurar el rechazo ⇒ `CT_DIAL_FAILED`.
#[tokio::test]
async fn accept_next_generates_a_conn_id_when_router_provided_conn_id_is_five_bytes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        // 1012 de CINCO bytes, prefijo LE = 42u32: ilegible ⇒ se GENERA.
        let dial = inbound_dial(&bind_conn_id_hdr, Some(vec![42u8, 0, 0, 0, 9]));
        write_message(&mut router, &dial).await.unwrap();

        let (conn_res, ds) = tokio::join!(
            ch.accept_next(bind_id, "bind-jwt", None, &mut bind_rx),
            async {
                let ds = read_message(&mut router).await.unwrap();
                let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
                sc.headers
                    .insert(HDR_REPLY_FOR, ds.sequence.to_le_bytes().to_vec());
                write_message(&mut router, &sc).await.unwrap();
                ds
            }
        );

        assert_eq!(
            ds.content_type,
            crate::edge::bind::CT_DIAL_SUCCESS,
            "un 1012 de 5 bytes ya no se rechaza: GENERA, como la ausencia"
        );
        assert_eq!(
            ds.body,
            2u32.to_le_bytes(),
            "el id es el GENERADO (2), NO el prefijo truncado 42"
        );
        let conn = conn_res.expect("accept con id generado");
        assert_eq!(
            conn.conn_id(),
            2,
            "NO 42: el prefijo de 5 bytes no se trunca"
        );
        ch.close().await.unwrap();
    })
    .await
    .expect("T-7: accept_next no retornó dentro del presupuesto");
}

/// `T-8` (`R-6`). Con el id GENERADO, `complete_success` NO retorna hasta ver el `StateConnected`.
/// Usa `accept_pending` + `complete_success` explícitos para observar el punto MEDIO.
///
/// Asserts a los DOS lados (RB-2): el NEGATIVO (`timeout(150 ms)` sobre la task ⇒ `Err`, no ha
/// retornado) es el que mata la mutación; el POSITIVO (tras el `StateConnected` la task retorna `Ok`
/// con `conn_id() == 2`) impide que el rojo sea un criterio insatisfacible.
///
/// MUTACIÓN ASESINA: borrar la rama `if !router_provided` (fire-and-forget siempre) ⇒ la task
/// retorna ANTES del `StateConnected` y el assert NEGATIVO muere.
///
/// ⚠ Este test NO sostiene la colocación 1 de `R-6` (waiter ANTES del write): el `StateConnected` se
/// envía DESPUÉS de que el router haya leído el `DialSuccess` y de un `timeout(150 ms)` intermedio,
/// muy fuera de la ventana que abriría el amplificador de `F-s`. Esa colocación tiene falsador
/// PROPIO en `T-13`. Lo que este test CONSERVA es su assert NEGATIVO, falsador vivo de `F-k`.
#[tokio::test]
async fn complete_success_waits_for_state_connected_when_the_conn_id_was_generated() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        let dial = inbound_dial(&bind_conn_id_hdr, None);
        write_message(&mut router, &dial).await.unwrap();

        let pending = ch
            .accept_pending(bind_id, "bind-jwt", None, &mut bind_rx)
            .await
            .expect("pending");
        assert_eq!(pending.child_id(), 2, "id GENERADO");

        let mut complete_task = tokio::spawn(async move { pending.complete_success().await });

        let ds = read_message(&mut router).await.unwrap();
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(ds.body, 2u32.to_le_bytes());

        // NEGATIVO: el router NO responde ⇒ complete_success sigue esperando.
        let still_waiting =
            tokio::time::timeout(Duration::from_millis(150), &mut complete_task).await;
        assert!(
            still_waiting.is_err(),
            "con id GENERADO el DialSuccess NO es fire-and-forget: debe esperar el StateConnected"
        );

        // POSITIVO: con el StateConnected correlado, retorna.
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(HDR_REPLY_FOR, ds.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        let conn = complete_task
            .await
            .expect("la task no debe panicar")
            .expect("complete_success ok tras el StateConnected");
        assert_eq!(conn.conn_id(), 2);
        ch.close().await.unwrap();
    })
    .await
    .expect("T-8: complete_success no resolvió dentro del presupuesto");
}

/// `T-9` (`R-7`). Con el id del ROUTER (1012 legible), `complete_success` NO espera nada: la rama
/// `else if … SendAndWaitForWire` del oráculo (`conn.go:1004`) no lee respuesta alguna.
///
/// Existe como test NUEVO, y no «ya lo cubre `accept_next_accepts_dial_and_round_trips`», porque
/// aquél no tiene techo de tiempo: bajo la mutación que invierte la condición se colgaría para
/// siempre en vez de dar un rojo legible (RB-SDK-10).
///
/// MUTACIÓN ASESINA: invertir la condición (`if router_provided { esperar }`) ⇒ `Err(Elapsed)` con el
/// `expect` que NOMBRA la rama.
#[tokio::test]
async fn complete_success_does_not_wait_when_the_router_provided_the_conn_id() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        let dial = inbound_dial(&bind_conn_id_hdr, Some(42u32.to_le_bytes().to_vec()));
        write_message(&mut router, &dial).await.unwrap();

        // El router lee el DialSuccess y NUNCA envía StateConnected.
        let (conn_res, ds) = tokio::join!(
            ch.accept_next(bind_id, "bind-jwt", None, &mut bind_rx),
            read_message(&mut router)
        );
        let ds = ds.unwrap();
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(ds.body, 42u32.to_le_bytes(), "el id lo puso el ROUTER");
        let conn = conn_res.expect("accept con id del router");
        assert_eq!(conn.conn_id(), 42);
        ch.close().await.unwrap();
    })
    .await
    .expect("T-9: con id del ROUTER, complete_success no debe esperar StateConnected");
}

/// `T-10` (`R-8a`). La respuesta de arranque LLEGA dentro del techo pero NO es `StateConnected`:
/// el oráculo hace `self.edgeCh.close(true)` ⇒ `StateClosed` + desregistro, y devuelve
/// `err, cleanupHandled=true`, así que el envoltorio `CompleteAcceptSuccess` **NO** emite
/// `DialFailed` (`conn.go:895,999-1003`).
///
/// ⚠ Se registra un HERMANO (`register_conn(99, …)`) ANTES de completar: es la fila de ALCANCE de
/// RB-9 — sin él, la mutación `conns.remove(&child)` → `conns.clear()` pasaría inadvertida.
///
/// MUTACIONES ASESINAS (tres): borrar la comprobación de content-type ⇒ el retorno es `Ok`;
/// `conns.remove(&child_id)` → `conns.clear()` ⇒ muere el assert del hermano `99`; emitir TAMBIÉN el
/// `DialFailed` en esta rama (tratar `R-8a` como `R-8b`) ⇒ muere el assert de «ningún DialFailed».
#[tokio::test]
async fn complete_success_fails_and_closes_the_child_when_the_start_reply_is_not_state_connected() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        let dial = inbound_dial(&bind_conn_id_hdr, None);
        write_message(&mut router, &dial).await.unwrap();

        let pending = ch
            .accept_pending(bind_id, "bind-jwt", None, &mut bind_rx)
            .await
            .expect("pending");
        assert_eq!(pending.child_id(), 2, "id GENERADO");
        // HERMANO: una conn ajena que el teardown del hijo NO puede tocar.
        let (sib_tx, _sib_rx) = mpsc::channel(1);
        ch.state.register_conn(99, sib_tx);

        let (res, (ds, sc)) = tokio::join!(pending.complete_success(), async {
            let ds = read_message(&mut router).await.unwrap();
            // Respuesta de arranque INESPERADA: StateClosed correlado por el seq del DialSuccess.
            let mut bad = Message::new(CT_STATE_CLOSED, vec![]);
            bad.headers
                .insert(HDR_REPLY_FOR, ds.sequence.to_le_bytes().to_vec());
            write_message(&mut router, &bad).await.unwrap();
            let sc = read_message(&mut router).await.unwrap();
            (ds, sc)
        });

        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert!(
            matches!(res, Err(EdgeError::AcceptStartFailed(_))),
            "una respuesta de arranque que no es StateConnected falla el accept: {res:?}"
        );
        let EdgeError::AcceptStartFailed(payload) = res.unwrap_err() else {
            unreachable!("ya comprobado por el matches! de arriba")
        };
        assert!(
            payload.starts_with("failed to receive start after dial. got "),
            "el payload copia byte a byte la parte ESTÁTICA de conn.go:1002: {payload}"
        );
        // El cable: StateClosed para el HIJO, y NADA más.
        assert_eq!(
            sc.content_type, CT_STATE_CLOSED,
            "close(true) ⇒ StateClosed (conn.go:869-877)"
        );
        assert_eq!(
            sc.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
            &2u32.to_le_bytes(),
            "el StateClosed apunta al hijo GENERADO"
        );
        let nothing =
            tokio::time::timeout(Duration::from_millis(150), read_message(&mut router)).await;
        assert!(
            nothing.is_err(),
            "cleanupHandled=true ⇒ NINGÚN DialFailed tras el StateClosed (es lo que separa R-8a de R-8b)"
        );
        // ALCANCE del teardown: el hijo fuera, el hermano DENTRO.
        assert!(
            !ch.state.conns.lock().unwrap().contains_key(&2),
            "el hijo queda desregistrado"
        );
        assert!(
            ch.state.conns.lock().unwrap().contains_key(&99),
            "el teardown del hijo NO puede tocar las demás conns"
        );
        ch.close().await.unwrap();
    })
    .await
    .expect("T-10: complete_success no resolvió dentro del presupuesto");
}

/// `T-11` (`R-8b`). El reply NO llega (techo de 5 s agotado): el oráculo devuelve `err, false` ⇒
/// `cleanupHandled = false` ⇒ el envoltorio hace `conn.close(false)` (desregistro SIN `StateClosed`,
/// `conn.go:900` + `:869-877`) y emite un `DialFailed` cuyo `ConnId` es **el HIJO** (`conn.Id()`,
/// `conn.go:902`) y cuyo `ReplyTo` es el `Dial` entrante (`conn.go:903`).
///
/// ⚠ **ATRIBUTO DE RELOJ, DECIDIDO MIDIENDO** (no eligiendo): una sonda transitoria bajo
/// `#[tokio::test(start_paused = true)]` midió (a) que `write_message`/`read_message` sobre el
/// `duplex` COMPLETAN (`wall_a = 178 µs`) y (b) que el `timeout(5 s)` dispara sin reloj de pared
/// (`wall_b = 169 µs`) ⇒ `start_paused = true`, y el test no cuesta 5 s de pared.
///
/// ⚠ **Techo del cuerpo: 8 s, EXCEPCIÓN declarada a la forma de 5 s de RB-SDK-10** — la misma razón
/// que `T-13` y MEDIDA aquí (ver la enmienda del 2b, 2026-08-23): el techo INTERIOR del sujeto es
/// `ACCEPT_START_TIMEOUT` = 5 s, así que un techo exterior de 5 s expira en el MISMO instante en que
/// el sujeto agota el suyo y el `Elapsed` del arnés ENSOMBRECE los asserts del cable.
///
/// MUTACIONES ASESINAS (tres): que el brazo del timeout devuelva la conn igualmente ⇒ muere el
/// `matches!`; NO emitir el `DialFailed` (tratar `R-8b` como `R-8a`) ⇒ muere el assert del frame;
/// emitirlo con el `bind_conn_id` en vez del `child_id` ⇒ muere el assert del `ConnId`.
#[tokio::test(start_paused = true)]
async fn complete_success_fails_when_no_start_reply_arrives_within_the_budget() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        let dial = inbound_dial(&bind_conn_id_hdr, None);
        write_message(&mut router, &dial).await.unwrap();

        let pending = ch
            .accept_pending(bind_id, "bind-jwt", None, &mut bind_rx)
            .await
            .expect("pending");
        assert_eq!(pending.child_id(), 2, "id GENERADO");

        // El router lee el DialSuccess y NUNCA responde: el sujeto agota su techo de 5 s.
        let (res, (ds, df)) = tokio::join!(pending.complete_success(), async {
            let ds = read_message(&mut router).await.unwrap();
            let df = read_message(&mut router).await.unwrap();
            (ds, df)
        });

        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert!(
            matches!(res, Err(EdgeError::AcceptStartFailed(_))),
            "sin StateConnected dentro del techo, el accept falla: {res:?}"
        );
        assert!(
            !ch.state.conns.lock().unwrap().contains_key(&2),
            "el hijo queda desregistrado (close(false) ⇒ sólo Remove)"
        );
        assert_eq!(
            df.content_type,
            crate::edge::bind::CT_DIAL_FAILED,
            "cleanupHandled=false ⇒ el envoltorio SÍ emite DialFailed (conn.go:902)"
        );
        assert_eq!(
            df.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
            &2u32.to_le_bytes(),
            "ASIMETRÍA MEDIDA: este DialFailed lleva el conn-id del HIJO (conn.go:902), NO el del bind (conn.go:971)"
        );
        assert_eq!(
            df.headers.get(&HDR_REPLY_FOR).unwrap().as_slice(),
            &99i32.to_le_bytes(),
            "ReplyTo = el Dial entrante (conn.go:903), no el DialSuccess"
        );
        let nothing =
            tokio::time::timeout(Duration::from_millis(150), read_message(&mut router)).await;
        assert!(
            nothing.is_err(),
            "close(false) ⇒ NINGÚN StateClosed (el separador espejo del de T-10)"
        );
        ch.close().await.unwrap();
    })
    .await
    .expect("T-11: complete_success no resolvió dentro del presupuesto");
}

/// `T-12` (`R-6`, colocación 4). El stream-header de cripto se escribe DESPUÉS del handshake de
/// arranque (`conn.go:1009-1017`: el bloque `if self.txHeader != nil` va tras el `if/else` ENTERO),
/// no justo detrás del `DialSuccess`. Con un id GENERADO, escribirlo antes mandaría `Data` a un
/// router legacy que aún no ha construido su conn (`dialer.go:355`).
///
/// Molde: `accept_next_encrypted_round_trip`, al que se le QUITA el header 1012.
///
/// Asserts a los DOS lados (RB-2): el paso (2) da `Err` (**NEGATIVO**, mata la mutación) y el paso
/// (4) da un `CT_DATA` de 24 B con `ConnId = 2` (**POSITIVO**, el criterio es satisfacible).
///
/// MUTACIÓN ASESINA: mover el bloque `crypto_setup` ANTES de la espera del `StateConnected` (el orden
/// que el port tenía) ⇒ el paso (2) LEE el `Data` y el assert NEGATIVO muere.
#[tokio::test]
async fn complete_success_writes_the_crypto_header_after_the_start_reply_when_the_conn_id_was_generated()
 {
    use crate::edge::crypto::KeyPair;

    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, mut router) = tokio::io::duplex(8192);
        let (cr, cw) = tokio::io::split(client);
        let ch = EdgeChannel::from_halves(
            Box::new(cr),
            Box::new(cw),
            std::collections::BTreeMap::new(),
        );
        let host = KeyPair::generate();
        let host_pk = host.public_key();

        // Bind (el router responde StateConnected correlado por el seq del Bind).
        let (bind_res, bind_conn_id_hdr) =
            tokio::join!(ch.send_bind("bind-jwt", "lid-genenc", None), async {
                let bind = read_message(&mut router).await.unwrap();
                let hdr = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
                let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
                sc.headers
                    .insert(HDR_REPLY_FOR, bind.sequence.to_le_bytes().to_vec());
                write_message(&mut router, &sc).await.unwrap();
                hdr
            });
        let (bind_id, mut bind_rx) = bind_res.expect("bind ok");

        // Dial ENCRIPTADO y SIN 1012 ⇒ el id se GENERA (2).
        let dialer = KeyPair::generate();
        let (_d_rx, _d_tx) = dialer.client_session_keys(&host_pk).unwrap();
        let mut dial = inbound_dial(&bind_conn_id_hdr, None);
        dial.headers
            .insert(HDR_PUBLIC_KEY, dialer.public_key().to_vec());
        dial.headers.insert(HDR_CRYPTO_METHOD, vec![0u8]);
        write_message(&mut router, &dial).await.unwrap();

        let (conn_res, (ds, nothing_yet, hhdr)) = tokio::join!(
            ch.accept_next(bind_id, "bind-jwt", Some(&host), &mut bind_rx),
            async {
                // (1) el DialSuccess con el id GENERADO
                let ds = read_message(&mut router).await.unwrap();
                // (2) NEGATIVO: todavía NO hay stream-header en el cable
                let nothing_yet =
                    tokio::time::timeout(Duration::from_millis(150), read_message(&mut router))
                        .await;
                // (3) el StateConnected correlado
                let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
                sc.headers
                    .insert(HDR_REPLY_FOR, ds.sequence.to_le_bytes().to_vec());
                write_message(&mut router, &sc).await.unwrap();
                // (4) POSITIVO: AHORA sí llega el stream-header (24 B, MULTIPART)
                let hhdr = read_message(&mut router).await.unwrap();
                (ds, nothing_yet.is_err(), hhdr)
            }
        );

        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(ds.body, 2u32.to_le_bytes(), "id GENERADO");
        assert!(
            nothing_yet,
            "el stream-header NO puede viajar antes del StateConnected (conn.go:1009-1017)"
        );
        assert_eq!(hhdr.content_type, CT_DATA);
        assert_eq!(hhdr.body.len(), 24, "el host stream-header son 24 bytes");
        assert_eq!(
            hhdr.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
            &2u32.to_le_bytes(),
            "el Data del stream-header va al hijo GENERADO"
        );
        assert_eq!(
            hhdr.headers.get(&HDR_FLAGS).unwrap().as_slice(),
            &[4, 0, 0, 0],
            "MULTIPART en el primer write del host"
        );
        let conn = conn_res.expect("accept encriptado con id generado");
        assert_eq!(conn.conn_id(), 2);
        ch.close().await.unwrap();
    })
    .await
    .expect("T-12: accept_next no retornó dentro del presupuesto");
}

/// `T-13` (`R-6`, colocación 1). El waiter del reply se registra ANTES del write del `DialSuccess`.
/// Falsador PROPIO de esa colocación: el vector es un `StateConnected` **PRE-BUFFEREADO** en el
/// duplex ANTES de llamar a `complete_success`, que es la ÚNICA ventana donde el rx-loop puede
/// procesarlo sin waiter y DESCARTARLO (`rxloop.rs:35-42` despacha por `ReplyFor`, y `:63-71` no
/// tiene arm para `CT_STATE_CONNECTED` ⇒ `_ => None`).
///
/// ⚠ **Techo del cuerpo: 8 s — VALOR PINEADO con su razón, EXCEPCIÓN declarada a la forma de 5 s de
/// RB-SDK-10.** El techo INTERIOR del sujeto es `ACCEPT_START_TIMEOUT` = 5 s: con un techo exterior
/// de 5 s el rojo del falsador COMPETIRÍA con el `Elapsed` del arnés y la firma saldría ambigua. Con
/// 8 s el sujeto agota SU techo primero y el rojo llega como `Err(AcceptStartFailed)` contra un
/// assert `Ok`. El coste de ~5 s de pared lo paga SÓLO la tirada de `F-s`.
///
/// ⚠ **Sin ningún `await` del propio test entre el write del `StateConnected` y la llamada a
/// `complete_success`**: es la condición que hace determinista al vector (el runtime `current_thread`
/// no puede intercalar el rx-loop dentro de un mismo `poll`).
///
/// El `2` PREDICHO sale del contador de SECUENCIA — el campo `seq` de `ChannelState`, sembrado a `0`
/// en `ChannelState::new`, que `ChannelState::next_seq` PRE-INCREMENTA: `EdgeChannel::send_bind`
/// consume el primero y `PendingAccept::complete_success` asigna el segundo. ⚠ Es el contador de
/// `sequence`, AJENO al asignador de conn-ids de esta rebanada. (Citas por SÍMBOLO y no por línea a
/// propósito: una cita por línea al MISMO commit que edita el fichero caduca dentro del commit.)
///
/// MUTACIÓN ASESINA (`F-s`): mover `waiters.insert(seq, tx)` DESPUÉS del `write_message` del
/// `DialSuccess` **+ un `tokio::task::yield_now().await` entre ambos** (amplificador DECLARADO y
/// MEDIDO: sin él la mutación desnuda deja el reply ENTREGADO y NO mata).
///
/// ⚠ Lo que este test NO discrimina: `F-k` (fire-and-forget siempre) lo deja VIVO — con esa mutación
/// `complete_success` devuelve `Ok` con `conn_id == 2`, justo lo que asserta. Su rama la cubren
/// `T-8` (assert NEGATIVO), `T-10`, `T-11` y `T-12`.
#[tokio::test]
async fn complete_success_registers_the_reply_waiter_before_writing_dial_success() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        let dial = inbound_dial(&bind_conn_id_hdr, None);
        write_message(&mut router, &dial).await.unwrap();

        let pending = ch
            .accept_pending(bind_id, "bind-jwt", None, &mut bind_rx)
            .await
            .expect("pending");
        assert_eq!(pending.child_id(), 2, "id GENERADO");

        // PRE-BUFFEREADO: el StateConnected entra al cable ANTES de que el sujeto escriba nada, con
        // el ReplyFor apuntando al `sequence` PREDICHO del DialSuccess (2).
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(HDR_REPLY_FOR, 2i32.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        // ⚠ NINGÚN await entre la línea de arriba y la de abajo.
        let res = pending.complete_success().await;

        let ds = read_message(&mut router).await.unwrap();
        // PIN de la predicción, PRIMERO: si el arnés derivó, el rojo se LEE aquí.
        assert_eq!(ds.content_type, crate::edge::bind::CT_DIAL_SUCCESS);
        assert_eq!(
            ds.sequence, 2,
            "T-13 PREDICE el seq del DialSuccess; si esto falla, el arnés derivó y el ReplyFor del \
             StateConnected pre-buffereado apunta a nadie"
        );
        // El que mata la mutación.
        let conn = res.expect(
            "el StateConnected PRE-BUFFEREADO tiene que llegar al waiter: si el waiter se registra \
             DESPUÉS del write, el rx-loop lo DESCARTA y el sujeto agota los 5 s",
        );
        assert_eq!(conn.conn_id(), 2);
        // Complementos (no cambian de rama).
        assert_eq!(ds.body, 2u32.to_le_bytes());
        assert_eq!(
            ds.headers.get(&HDR_REPLY_FOR).unwrap().as_slice(),
            &99i32.to_le_bytes()
        );
        ch.close().await.unwrap();
    })
    .await
    .expect("T-13: complete_success no resolvió dentro del presupuesto");
}

/// `T-14` (`R-6`, pata de canal YA CERRADO). Si el canal murió ANTES de completar, el port no puede
/// registrar el waiter: `mark_closed` vacía el mapa de waiters UNA sola vez (está gateado por CAS),
/// así que un waiter insertado después de ese barrido es un HUÉRFANO que nadie despertará y la espera
/// quemaría los 5 s ENTEROS. El oráculo falla al INSTANTE: su `SendForReply` selecciona sobre el
/// close-notify del canal y devuelve `ClosedError` sin tocar el cable
/// (`channel/v4@v4.3.9 senders.go:61-62`), que es `err, cleanupHandled = false` (`conn.go:996`) ⇒ la
/// misma salida observable que `R-8b`.
///
/// ⚠ **Techo del cuerpo: 500 ms — VALOR PINEADO con su razón (RB-4).** Es el ÚNICO assert que
/// discrimina: sin la guarda el retorno sigue siendo `Err(AcceptStartFailed(_))`, sólo que **5 s
/// después**, así que un techo holgado dejaría la mutación VIVA. 500 ms es un orden de magnitud por
/// debajo del `ACCEPT_START_TIMEOUT` de 5 s y muy por encima del coste real del camino con guarda
/// (que no espera a nadie).
///
/// MUTACIÓN ASESINA (`F-u` de §12): borrar la guarda `!router_provided && state.is_closed()` ⇒ el
/// waiter se registra huérfano, la espera agota los 5 s y el arnés muere por `Elapsed` a los 500 ms.
#[tokio::test]
async fn complete_success_fails_immediately_when_the_channel_is_already_closed() {
    tokio::time::timeout(Duration::from_millis(500), async {
        let (ch, bind_id, bind_conn_id_hdr, mut bind_rx, mut router) =
            bound_channel_with_router().await;
        let dial = inbound_dial(&bind_conn_id_hdr, None);
        write_message(&mut router, &dial).await.unwrap();

        let pending = ch
            .accept_pending(bind_id, "bind-jwt", None, &mut bind_rx)
            .await
            .expect("pending");
        assert_eq!(pending.child_id(), 2, "id GENERADO");

        // El canal muere ENTRE el accept y la completación: es la ventana que abre el hueco.
        ch.state.mark_closed();
        assert!(ch.state.is_closed(), "precondición del vector");

        let res = pending.complete_success().await;
        assert!(
            matches!(res, Err(EdgeError::AcceptStartFailed(_))),
            "sobre un canal cerrado el arranque falla, y falla YA: {res:?}"
        );
    })
    .await
    .expect(
        "T-14: con el canal ya cerrado, complete_success tiene que fallar AL INSTANTE; si tarda, la \
         guarda is_closed() no está y el waiter quedó huérfano quemando los 5 s",
    );
}
