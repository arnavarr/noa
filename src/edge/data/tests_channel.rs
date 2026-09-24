//! Split test module (F6 tramo 1b), byte-identical bodies.
use super::testsupport::*;
use super::*;

#[traced_test]
#[tokio::test]
async fn dial_then_write_read_round_trip() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    // Fake router: read the Connect, reply StateConnected (ReplyFor=seq, ConnId, Circuit),
    // then read the Data and echo it back.
    let router_task = tokio::spawn(async move {
        let connect = read_message(&mut router).await.unwrap();
        assert_eq!(connect.content_type, crate::edge::dial::CT_CONNECT);
        assert_eq!(connect.body, b"jwt-tok");
        assert!(
            !connect.headers.contains_key(&HDR_CALLER_ID),
            "no CallerId when none supplied"
        );
        let conn_id = connect.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec()); // ReplyFor = Connect seq
        sc.headers.insert(HDR_CONN_ID, conn_id.clone());
        sc.headers.insert(HDR_CIRCUIT_ID, b"circ-9".to_vec());
        write_message(&mut router, &sc).await.unwrap();

        let data = read_message(&mut router).await.unwrap();
        assert_eq!(data.content_type, CT_DATA);
        let mut echo = Message::new(CT_DATA, data.body.clone());
        echo.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &echo).await.unwrap();
    });

    let mut conn = ch
        .dial(&detail(), false, None, None)
        .await
        .expect("dial ok");
    assert_eq!(conn.conn_id(), 1);
    assert_eq!(conn.circuit_id(), Some("circ-9"));
    conn.write(b"hello-data").await.unwrap();
    assert_eq!(conn.read().await.unwrap(), Some(b"hello-data".to_vec()));

    router_task.await.unwrap();
    ch.close().await.unwrap();
    // Plaintext service (encryption_required=false → keypair None) is expected: NO warn.
    assert!(
        !logs_contain("connection is not end-to-end"),
        "plaintext service must NOT warn"
    );
    // O3 point 2 NEGATIVE: a plaintext dial sets up NO client tx encryption → no debug.
    assert!(
        !logs_contain("client tx encryption setup done"),
        "plaintext service must NOT emit the crypto-established debug"
    );
}

#[tokio::test]
async fn dial_sends_caller_id_header_when_provided() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        let connect = read_message(&mut router).await.unwrap();
        assert_eq!(
            connect.headers.get(&HDR_CALLER_ID).map(Vec::as_slice),
            Some(&b"bob"[..]),
            "Connect carries CallerId = the supplied identity name"
        );
        let conn_id = connect.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec());
        sc.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &sc).await.unwrap();
    });

    let _conn = ch
        .dial(&detail(), false, Some("bob"), None)
        .await
        .expect("dial ok");
    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
async fn dial_sends_app_data_header_when_provided() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let app = crate::edge::dial::build_app_data("tcp", "127.0.0.1", "19009", None, None);
    let app_for_assert = app.clone();

    let router_task = tokio::spawn(async move {
        let connect = read_message(&mut router).await.unwrap();
        assert_eq!(
            connect.headers.get(&HDR_APPDATA).map(Vec::as_slice),
            Some(app_for_assert.as_slice()),
            "Connect carries AppData (1011) = the opaque appData bytes"
        );
        let conn_id = connect.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec());
        sc.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &sc).await.unwrap();
    });

    let _conn = ch
        .dial(&detail(), false, None, Some(&app))
        .await
        .expect("dial ok");
    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
async fn dial_maps_state_closed_to_dial_rejected() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let router_task = tokio::spawn(async move {
        let connect = read_message(&mut router).await.unwrap();
        let mut sc = Message::new(CT_STATE_CLOSED, b"no terminators".to_vec());
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec());
        sc.headers.insert(
            HDR_CONN_ID,
            connect.headers.get(&HDR_CONN_ID).unwrap().clone(),
        );
        write_message(&mut router, &sc).await.unwrap();
    });
    let err = ch.dial(&detail(), false, None, None).await.unwrap_err();
    assert!(matches!(err, EdgeError::DialRejected(m) if m == "no terminators"));
    router_task.await.unwrap();
}

#[tokio::test]
async fn dial_returns_channel_closed_when_channel_dies() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    // Router reads the Connect (so the write succeeds), then drops without replying.
    // Dropping the router end makes the rx-loop read EOF and tear down, dropping the
    // dial's reply-waiter sender -> dial's reply_rx.await errors -> ChannelClosed.
    let router_task = tokio::spawn(async move {
        let _connect = read_message(&mut router).await.unwrap();
        // router dropped here
    });
    let err = ch.dial(&detail(), false, None, None).await.unwrap_err();
    assert!(matches!(err, crate::edge::error::EdgeError::ChannelClosed));
    router_task.await.unwrap();
}

#[traced_test]
#[tokio::test]
async fn dial_crypto_handshake_then_round_trip() {
    use crate::edge::crypto::KeyPair;
    use crate::edge::dial::{HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY};

    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        // 1. Read the Connect; it must carry our client public key + libsodium method.
        let connect = read_message(&mut router).await.unwrap();
        assert_eq!(connect.content_type, crate::edge::dial::CT_CONNECT);
        assert_eq!(
            connect.headers.get(&HDR_CRYPTO_METHOD).unwrap().as_slice(),
            &[0u8]
        );
        let client_pk: [u8; 32] = connect
            .headers
            .get(&HDR_PUBLIC_KEY)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();

        // 2. Host kx; reply StateConnected with the host public key + method.
        let host = KeyPair::generate();
        let (h_rx, h_tx) = host.server_session_keys(&client_pk).unwrap();
        let conn_id = connect.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec()); // ReplyFor
        sc.headers.insert(HDR_CONN_ID, conn_id.clone());
        sc.headers.insert(HDR_CIRCUIT_ID, b"circ-x".to_vec());
        sc.headers
            .insert(HDR_PUBLIC_KEY, host.public_key().to_vec());
        sc.headers.insert(HDR_CRYPTO_METHOD, vec![0u8]);
        write_message(&mut router, &sc).await.unwrap();

        // 3. Read the client's stream header (first Data, 24 bytes) -> our decryptor.
        let chdr = read_message(&mut router).await.unwrap();
        assert_eq!(chdr.content_type, CT_DATA);
        assert_eq!(chdr.body.len(), 24);
        let client_header: [u8; 24] = chdr.body.as_slice().try_into().unwrap();
        let mut router_dec = crate::edge::crypto::Decryptor::new(&h_rx, &client_header);

        // 4. Send our stream header (first Data we emit), then echo the client's message.
        let (mut router_enc, host_header) = crate::edge::crypto::Encryptor::new(&h_tx);
        let mut hmsg = Message::new(CT_DATA, host_header.to_vec());
        hmsg.headers.insert(HDR_CONN_ID, conn_id.clone());
        write_message(&mut router, &hmsg).await.unwrap();

        let data = read_message(&mut router).await.unwrap(); // client's encrypted "secret"
        let plain = router_dec.pull(&data.body).unwrap();
        let cipher = router_enc.push(&plain).unwrap();
        let mut echo = Message::new(CT_DATA, cipher);
        echo.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &echo).await.unwrap();
    });

    let detail = detail();
    let mut conn = ch
        .dial(&detail, true, None, None)
        .await
        .expect("crypto dial ok");
    assert_eq!(conn.circuit_id(), Some("circ-x"));
    conn.write(b"secret").await.unwrap();
    assert_eq!(conn.read().await.unwrap(), Some(b"secret".to_vec()));

    router_task.await.unwrap();
    ch.close().await.unwrap();
    // Negative: the encrypted happy path must NOT warn (discriminator unique to the WARN).
    assert!(
        !logs_contain("connection is not end-to-end"),
        "encrypted happy path must NOT warn"
    );
    // O3 point 2: the crypto-success path emits a DEBUG (oracle conn.go:620
    // `logger.Debug("client tx encryption setup done")`), byte-exact message.
    assert!(
        logs_contain("client tx encryption setup done"),
        "crypto-established client must debug-log"
    );
}

// Downgrade: the service is encryptionRequired (we advertise a key) but the host replies
// StateConnected WITHOUT a PublicKey → plaintext fallback AND a security WARN (oracle
// conn.go:622). The fake router does NOT echo a host key and reads NO client stream header
// (establish_client_crypto returns Ok(None) before writing one).
#[traced_test]
#[tokio::test]
async fn dial_encrypted_service_host_no_key_falls_back_to_plaintext_and_warns() {
    use crate::edge::dial::HDR_PUBLIC_KEY;

    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        // The Connect carries our client key (encryption_required=true), but the host
        // replies StateConnected with NO PublicKey (did not negotiate crypto).
        let connect = read_message(&mut router).await.unwrap();
        assert!(
            connect.headers.contains_key(&HDR_PUBLIC_KEY),
            "client advertised its key"
        );
        let conn_id = connect.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec()); // ReplyFor
        sc.headers.insert(HDR_CONN_ID, conn_id.clone());
        write_message(&mut router, &sc).await.unwrap();

        // Plaintext round-trip (no host stream header, no client header expected): echo Data.
        let data = read_message(&mut router).await.unwrap();
        assert_eq!(data.content_type, CT_DATA);
        let mut echo = Message::new(CT_DATA, data.body.clone());
        echo.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &echo).await.unwrap();
    });

    let mut conn = ch
        .dial(&detail(), true, None, None)
        .await
        .expect("dial falls back to plaintext");
    // Plaintext: a write produces cleartext on the wire (round-trips byte-for-byte).
    conn.write(b"plain").await.unwrap();
    assert_eq!(conn.read().await.unwrap(), Some(b"plain".to_vec()));

    router_task.await.unwrap();
    ch.close().await.unwrap();
    assert!(
        logs_contain("connection is not end-to-end-encrypted"),
        "silent downgrade to plaintext must warn"
    );
    // O3 point 2 NEGATIVE: the downgrade path returns Ok(None) BEFORE building the
    // encryptor, so it must NOT emit the crypto-established debug.
    assert!(
        !logs_contain("client tx encryption setup done"),
        "downgrade-to-plaintext must NOT emit the crypto-established debug"
    );
}

#[tokio::test]
async fn send_bind_succeeds_on_state_connected() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        assert_eq!(bind.content_type, crate::edge::bind::CT_BIND);
        assert_eq!(bind.body, b"bind-jwt");
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec()); // ReplyFor = Bind seq
        write_message(&mut router, &sc).await.unwrap();
    });

    let (conn_id, _bind_rx) = ch
        .send_bind("bind-jwt", "lid-1", None)
        .await
        .expect("bind ok");
    assert_eq!(conn_id, 1);
    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
async fn send_bind_tolerates_async_bind_success_after_state_connected() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let conn_id = bind.headers.get(&HDR_CONN_ID).unwrap().clone();
        // 1. the sequence-correlated reply
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        // 2. an UNSOLICITED BindSuccess on the bind conn-id (the rx-loop must discard it)
        let mut bs = Message::new(crate::edge::bind::CT_BIND_SUCCESS, vec![]);
        bs.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &bs).await.unwrap();
        // 3. Read the unbind to keep the router alive until after send_unbind returns.
        let _unbind = read_message(&mut router).await.unwrap();
    });

    let (conn_id, _bind_rx) = ch
        .send_bind("bind-jwt", "lid-2", None)
        .await
        .expect("bind ok");
    // The channel still works after the async BindSuccess: unbind + close succeed.
    ch.send_unbind(conn_id, "bind-jwt")
        .await
        .expect("unbind writes");
    router_task.await.unwrap();
    ch.close().await.unwrap();
}

#[tokio::test]
async fn send_bind_maps_state_closed_to_bind_rejected() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        let mut sc = Message::new(CT_STATE_CLOSED, b"no bind".to_vec());
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
    });
    let err = ch.send_bind("bind-jwt", "lid-3", None).await.unwrap_err();
    assert!(matches!(err, EdgeError::BindRejected(m) if m == "no bind"));
    router_task.await.unwrap();
}

#[tokio::test]
async fn send_bind_returns_channel_closed_when_channel_dies() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let router_task = tokio::spawn(async move {
        let _bind = read_message(&mut router).await.unwrap();
        // router drops without replying -> rx-loop EOF -> waiter sender dropped
    });
    let err = ch.send_bind("bind-jwt", "lid-4", None).await.unwrap_err();
    assert!(matches!(err, EdgeError::ChannelClosed));
    router_task.await.unwrap();
}

#[tokio::test]
async fn send_bind_advertises_pubkey_when_encrypted() {
    use crate::edge::dial::{HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY};
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let pk = [7u8; 32];
    let router_task = tokio::spawn(async move {
        let bind = read_message(&mut router).await.unwrap();
        assert_eq!(
            bind.headers.get(&HDR_PUBLIC_KEY).unwrap().as_slice(),
            &pk[..]
        );
        assert_eq!(
            bind.headers.get(&HDR_CRYPTO_METHOD).unwrap().as_slice(),
            &[0u8]
        );
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
    });
    let (_id, _rx) = ch
        .send_bind("bind-jwt", "lid-pk", Some(&pk))
        .await
        .expect("bind ok");
    router_task.await.unwrap();
    ch.close().await.unwrap();
}
