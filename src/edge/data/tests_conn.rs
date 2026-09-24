//! Split test module (F6 tramo 1b), byte-identical bodies.
use super::testsupport::*;
use super::*;

/// `close_write` emits EXACTLY ONE empty `Data` frame with the FIN flag, and is IDEMPOTENT
/// (a 2nd call sends nothing). Byte-asserts the frame; mirror of the oracle's `CloseWrite`
/// sending an empty Data + `edge.FIN` once via the `sentFIN` CAS. The router echoes the FIN
/// frame back as a normal Data so the test can also confirm the peer side maps it to EOF.
#[tokio::test]
async fn close_write_sends_one_empty_fin_frame_idempotently() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    // Fake router: StateConnected, then read EXACTLY ONE frame (the FIN) and assert its shape.
    // Return the read FIN frame's bytes via a channel so the test can verify them, and prove a
    // 2nd close_write sent nothing by attempting a 2nd read that must time out.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let router_task = tokio::spawn(async move {
        let connect = read_message(&mut router).await.unwrap();
        let conn_id = connect.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec());
        sc.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &sc).await.unwrap();

        // The single FIN frame the connection sends on close_write.
        let fin = read_message(&mut router).await.unwrap();
        tx.send((fin.content_type, fin.body.clone(), fin.headers.clone()))
            .unwrap();

        // A 2nd frame must NOT arrive (close_write is idempotent): a short read times out.
        let second =
            tokio::time::timeout(Duration::from_millis(120), read_message(&mut router)).await;
        assert!(
            second.is_err(),
            "a 2nd close_write must send NOTHING (idempotent), but a frame arrived: {second:?}"
        );
    });

    let conn = ch
        .dial(&detail(), false, None, None)
        .await
        .expect("dial ok");
    conn.close_write()
        .await
        .expect("first close_write sends FIN");
    // Idempotent: the 2nd call returns Ok and writes nothing.
    conn.close_write()
        .await
        .expect("2nd close_write is a no-op");

    let (ct, body, headers) = rx.await.expect("router captured the FIN frame");
    assert_eq!(ct, CT_DATA, "FIN rides a Data frame (ct 60786)");
    assert!(body.is_empty(), "the FIN frame has an EMPTY body");
    let flags = headers
        .get(&HDR_FLAGS)
        .map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()));
    assert_eq!(
        flags & FLAG_FIN,
        FLAG_FIN,
        "the FIN flag (1) is set on the Data frame"
    );
    assert_eq!(
        flags & FLAG_MULTIPART,
        0,
        "the FIN frame must NOT carry the MULTIPART flag"
    );

    router_task.await.unwrap();
    ch.close().await.unwrap();
}

/// The peer's read side maps an inbound `Data{FIN}` to EOF (the slice-4b behavior the splice
/// relies on to propagate the peer's half-close): a Data frame carrying FIN ends `read()`. This
/// is the receiving counterpart to `close_write` (which sends that frame).
#[tokio::test]
async fn read_maps_inbound_fin_data_to_eof() {
    let (_client, _router) = tokio::io::duplex(8192);
    let (cw, _) = tokio::io::duplex(8192);
    let state = Arc::new(ChannelState::new(Box::new(cw)));
    let (data_tx, data_rx) = mpsc::channel(4);
    state.register_conn(7, data_tx.clone());
    let mut conn = EdgeConn::new_for_test(7, data_rx, state);

    // First, a normal Data frame still yields its body.
    let mut payload = build_data(7, b"chunk", false);
    payload.headers.remove(&HDR_FLAGS);
    data_tx.send(payload).await.unwrap();
    assert_eq!(conn.read().await.unwrap(), Some(b"chunk".to_vec()));

    // An inbound Data with the FIN flag set → read() yields None (EOF) and stays EOF.
    let mut fin = build_data(7, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.send(fin).await.unwrap();
    assert_eq!(conn.read().await.unwrap(), None, "FIN maps to EOF");
    assert_eq!(conn.read().await.unwrap(), None, "EOF is sticky");
}

#[tokio::test]
async fn edge_conn_write_emits_data_frame_first_multipart() {
    let (state, task, mut router) = rig();
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(2, tx);
    let mut conn = EdgeConn::new_for_test(2, rx, state.clone());

    conn.write(b"hi").await.unwrap();
    let frame = read_message(&mut router).await.unwrap();
    assert_eq!(frame.content_type, CT_DATA);
    assert_eq!(
        frame.headers.get(&HDR_CONN_ID).unwrap().as_slice(),
        &[2, 0, 0, 0]
    );
    assert_eq!(
        frame.headers.get(&HDR_FLAGS).unwrap().as_slice(),
        &[4, 0, 0, 0]
    ); // first => MULTIPART
    assert_eq!(frame.body, b"hi");

    conn.write(b"two").await.unwrap();
    let frame2 = read_message(&mut router).await.unwrap();
    assert!(!frame2.headers.contains_key(&HDR_FLAGS)); // no flags after the first
    drop(router);
    let _ = task.await;
}

#[tokio::test]
async fn read_returns_eof_when_channel_closes() {
    let (state, task, router) = rig();
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(3, tx);
    let mut conn = EdgeConn::new_for_test(3, rx, state.clone());
    drop(router); // close the stream -> rx-loop exits -> drops conn senders
    let _ = task.await;
    assert_eq!(conn.read().await.unwrap(), None); // EOF
}

#[tokio::test]
async fn edge_conn_encrypts_writes_and_decrypts_reads() {
    use crate::edge::crypto::{Decryptor, Encryptor, KeyPair};

    // Client + host keypairs; derive session keys (kx invariant: client_tx == host_rx).
    let client = KeyPair::generate();
    let host = KeyPair::generate();
    let (c_rx, c_tx) = client.client_session_keys(&host.public_key()).unwrap();
    let (h_rx, h_tx) = host.server_session_keys(&client.public_key()).unwrap();
    assert_eq!(c_tx, h_rx);
    assert_eq!(c_rx, h_tx);

    let (state, task, mut router) = rig();
    let (tx_q, rx_q) = mpsc::channel(4);
    state.register_conn(1, tx_q);

    // Build a crypto EdgeConn directly (Task 4 builds this via dial). The client's stream
    // header is handed to the router out-of-band so it can decrypt our writes.
    let (sender, client_header) = Encryptor::new(&c_tx);
    let cc = ConnCrypto {
        sender,
        decryptor: None,
        rx_key: Some(c_rx),
    };
    let mut conn = EdgeConn::new(1, None, None, rx_q, state.clone(), Some(cc));

    // --- write encrypts ---
    let mut router_dec = Decryptor::new(&h_rx, &client_header);
    conn.write(b"ping").await.unwrap();
    let frame = read_message(&mut router).await.unwrap();
    assert_eq!(frame.content_type, CT_DATA);
    assert_ne!(frame.body, b"ping", "body is ciphertext");
    assert_eq!(router_dec.pull(&frame.body).unwrap(), b"ping");

    // --- read decrypts: host sends its stream header (first Data), then a cipher frame ---
    let (mut router_enc, host_header) = Encryptor::new(&h_tx);
    let mut hdr = Message::new(CT_DATA, host_header.to_vec());
    hdr.headers.insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
    write_message(&mut router, &hdr).await.unwrap();
    let cipher = router_enc.push(b"pong").unwrap();
    let mut dm = Message::new(CT_DATA, cipher);
    dm.headers.insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
    write_message(&mut router, &dm).await.unwrap();

    assert_eq!(conn.read().await.unwrap(), Some(b"pong".to_vec()));

    drop(router);
    let _ = task.await;
}

#[tokio::test]
async fn read_rejects_wrong_length_crypto_header() {
    use crate::edge::crypto::{Encryptor, KeyPair};

    let client = KeyPair::generate();
    let host = KeyPair::generate();
    let (c_rx, c_tx) = client.client_session_keys(&host.public_key()).unwrap();

    let (state, task, mut router) = rig();
    let (tx_q, rx_q) = mpsc::channel(4);
    state.register_conn(1, tx_q);

    // Build conn with rx_key set (expecting a 24-byte stream header as first frame).
    let (sender, _client_header) = Encryptor::new(&c_tx);
    let cc = ConnCrypto {
        sender,
        decryptor: None,
        rx_key: Some(c_rx),
    };
    let mut conn = EdgeConn::new(1, None, None, rx_q, state.clone(), Some(cc));

    // Router sends a Data frame with only 23 bytes — one byte short of STREAM_HEADER_BYTES.
    let mut short_hdr = Message::new(CT_DATA, vec![0u8; 23]);
    short_hdr
        .headers
        .insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
    write_message(&mut router, &short_hdr).await.unwrap();

    assert!(matches!(
        conn.read().await,
        Err(crate::edge::error::EdgeError::Crypto(_))
    ));

    drop(router);
    let _ = task.await;
}

#[tokio::test]
async fn read_rejects_short_encrypted_frame() {
    use crate::edge::crypto::{Encryptor, KeyPair};

    let client = KeyPair::generate();
    let host = KeyPair::generate();
    let (c_rx, c_tx) = client.client_session_keys(&host.public_key()).unwrap();
    let (_h_rx, h_tx) = host.server_session_keys(&client.public_key()).unwrap();

    let (state, task, mut router) = rig();
    let (tx_q, rx_q) = mpsc::channel(4);
    state.register_conn(1, tx_q);

    let (sender, _client_header) = Encryptor::new(&c_tx);
    let cc = ConnCrypto {
        sender,
        decryptor: None,
        rx_key: Some(c_rx),
    };
    let mut conn = EdgeConn::new(1, None, None, rx_q, state.clone(), Some(cc));

    // Step 1: send a valid 24-byte stream header so the decryptor initialises.
    let (_router_enc, host_header) = Encryptor::new(&h_tx);
    let mut hdr = Message::new(CT_DATA, host_header.to_vec());
    hdr.headers.insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
    write_message(&mut router, &hdr).await.unwrap();

    // Step 2: send a Data frame with only 10 bytes — below ABYTES (17).
    let mut short_frame = Message::new(CT_DATA, vec![0u8; 10]);
    short_frame
        .headers
        .insert(HDR_CONN_ID, 1u32.to_le_bytes().to_vec());
    write_message(&mut router, &short_frame).await.unwrap();

    assert!(matches!(
        conn.read().await,
        Err(crate::edge::error::EdgeError::Crypto(_))
    ));

    drop(router);
    let _ = task.await;
}

// A plaintext SERVICE (keypair None) is the expected, non-downgrade case: NO warning.
// Discriminator "client did not send its key" is unique to the host downgrade WARN line.
#[traced_test]
#[test]
fn server_crypto_setup_none_keypair_is_plaintext() {
    let dial = Message::new(crate::edge::bind::CT_DIAL, b"tok".to_vec());
    assert!(matches!(server_crypto_setup(7, None, &dial), Ok(None)));
    assert!(
        !logs_contain("client did not send its key"),
        "plaintext service must NOT warn"
    );
}

// Downgrade: encrypted bind (keypair Some) but the dialer sent no PublicKey → plaintext
// child AND a security WARN (oracle hosting_conn.go:371).
#[traced_test]
#[test]
fn server_crypto_setup_no_client_key_is_plaintext() {
    use crate::edge::crypto::KeyPair;
    let host = KeyPair::generate();
    let dial = Message::new(crate::edge::bind::CT_DIAL, b"tok".to_vec()); // no PublicKey
    assert!(matches!(
        server_crypto_setup(99, Some(&host), &dial),
        Ok(None)
    ));
    assert!(
        logs_contain("client did not send its key. connection is not end-to-end encrypted"),
        "downgrade to plaintext must warn"
    );
    // Point 1: the downgrade warn now carries the child conn-id as a field (oracle :371 is
    // `newConnLogger.Warnf`, connId = the child id). tracing fmt renders fields inline.
    assert!(
        logs_contain("conn_id=99"),
        "downgrade warn must carry the child conn-id"
    );
}

#[test]
fn server_crypto_setup_bad_method_is_unsupported() {
    use crate::edge::crypto::KeyPair;
    use crate::edge::dial::{HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY};
    let host = KeyPair::generate();
    let client = KeyPair::generate();
    let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"tok".to_vec());
    dial.headers
        .insert(HDR_PUBLIC_KEY, client.public_key().to_vec());
    dial.headers.insert(HDR_CRYPTO_METHOD, vec![1u8]); // not libsodium
    assert!(matches!(
        server_crypto_setup(1, Some(&host), &dial),
        Err(crate::edge::error::EdgeError::UnsupportedCrypto)
    ));
}

#[test]
fn server_crypto_setup_bad_key_length_is_crypto_error() {
    use crate::edge::crypto::KeyPair;
    use crate::edge::dial::{HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY};
    let host = KeyPair::generate();
    let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"tok".to_vec());
    dial.headers.insert(HDR_PUBLIC_KEY, vec![0u8; 31]); // 31 bytes, not 32
    dial.headers.insert(HDR_CRYPTO_METHOD, vec![0u8]);
    assert!(matches!(
        server_crypto_setup(1, Some(&host), &dial),
        Err(crate::edge::error::EdgeError::Crypto(_))
    ));
}

#[traced_test]
#[test]
fn server_crypto_setup_happy_derives_server_keys_and_invariant() {
    use crate::edge::crypto::KeyPair;
    use crate::edge::dial::{HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY};
    let host = KeyPair::generate();
    let client = KeyPair::generate();
    let mut dial = Message::new(crate::edge::bind::CT_DIAL, b"tok".to_vec());
    dial.headers
        .insert(HDR_PUBLIC_KEY, client.public_key().to_vec());
    dial.headers.insert(HDR_CRYPTO_METHOD, vec![0u8]);

    let (cc, hdr) = server_crypto_setup(1, Some(&host), &dial)
        .unwrap()
        .expect("encrypted child");
    assert_eq!(hdr.len(), STREAM_HEADER_BYTES);
    // kx invariant: host rx == client tx; the host's encryptor used host tx == client rx.
    let (h_rx, _h_tx) = host.server_session_keys(&client.public_key()).unwrap();
    let (_c_rx, c_tx) = client.client_session_keys(&host.public_key()).unwrap();
    assert_eq!(cc.rx_key, Some(h_rx));
    assert_eq!(h_rx, c_tx, "server_rx == client_tx");
    assert!(
        !logs_contain("client did not send its key"),
        "encrypted happy path must NOT warn"
    );
}

// ───────────────────── DV-11-SC: the FIN-vs-StateClosed write discriminant ─────────────────────
// The oracle's `sentFIN` (`ziti/edge/network/conn.go:111-113`): a `StateClosed` (conn dead) sets it
// and the next `Write` FAILS (`:216-220`), while a FIN (half-close) sets only `readFIN` so `Write`
// keeps working. We port it as ONE shared `Arc<AtomicBool>` across the two halves. All `read`/
// `read_message` run under a timeout so a regression is RED, not a hang.

/// **U1 — the discriminant, StateClosed side.** An inbound `StateClosed` maps `read()` to EOF AND
/// sets `sent_fin`, so the next `write()` returns `WriteAfterClose` BEFORE serializing — no `Data`
/// reaches the router. Oracle: `AcceptMessage` StateClosed stores `sentFIN` (`conn.go:361`) and
/// `Write` consults it (`conn.go:216`). MUTATION → RED: drop the `write()` check (§3.1.4) or the
/// StateClosed `store` (§3.1.3) ⇒ `write` returns `Ok` and a `Data` frame hits the router.
#[tokio::test]
async fn read_state_closed_then_write_fails() {
    let (state, task, mut router) = rig();
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(5, tx.clone());
    let mut conn = EdgeConn::new_for_test(5, rx, state.clone());

    tx.send(build_state_closed(5)).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), conn.read())
        .await
        .expect("read does not hang");
    assert_eq!(r.unwrap(), None, "StateClosed maps to EOF");

    let w = conn.write(b"x").await;
    assert!(
        matches!(w, Err(EdgeError::WriteAfterClose)),
        "write after a StateClosed must fail with WriteAfterClose: {w:?}"
    );
    // And it short-circuited BEFORE the wire: the router got no Data frame.
    let got = tokio::time::timeout(Duration::from_millis(200), read_message(&mut router)).await;
    assert!(
        got.is_err(),
        "no Data frame may reach the router after a StateClosed: {got:?}"
    );

    drop(router);
    let _ = task.await;
}

/// **U2 — the discriminant, FIN side (non-regression of half-close).** An inbound FIN maps `read()`
/// to EOF but leaves `sent_fin` FALSE, so the OTHER direction keeps writing (true half-close).
/// Oracle: a FIN sets only `readFIN` (`conn.go:761`), never `sentFIN`. MUTATION → RED: make the FIN
/// branch (`conn.rs:189-192`) set `sent_fin` ⇒ `write` would fail (breaks half-close).
#[tokio::test]
async fn read_fin_then_write_still_succeeds() {
    let (state, task, mut router) = rig();
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(6, tx.clone());
    let mut conn = EdgeConn::new_for_test(6, rx, state.clone());

    let mut fin = build_data(6, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    tx.send(fin).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), conn.read())
        .await
        .expect("read does not hang");
    assert_eq!(r.unwrap(), None, "FIN maps to EOF");

    conn.write(b"x")
        .await
        .expect("write after a FIN still succeeds (half-close, sent_fin stays false)");
    let frame = read_message(&mut router).await.unwrap();
    assert_eq!(frame.content_type, CT_DATA);
    assert_eq!(frame.body, b"x", "the post-FIN write reaches the wire");

    drop(router);
    let _ = task.await;
}

/// **U3 — the third arm: rx-hangup ≡ sequencer-closed (readFIN only).** When the conn's inbound
/// queue hangs up (all senders dropped), `read()` is EOF but `sent_fin` stays FALSE, so `write()`
/// still ATTEMPTS (the live channel sink accepts it). Oracle: a closed sequencer sets only `readFIN`
/// (`conn.go:751`), never `sentFIN`. MUTATION → RED: make the rx-`None` branch (`conn.rs:184-186`)
/// set `sent_fin` ⇒ `write` would fail.
#[tokio::test]
async fn rx_hangup_then_write_still_attempts() {
    let (state, task, mut router) = rig();
    // Do NOT register the conn: we want its inbound queue to hang up (rx recv → None) while the
    // channel WRITE half stays live, so write() can still reach the sink.
    let (tx, rx) = mpsc::channel(4);
    let mut conn = EdgeConn::new_for_test(8, rx, state.clone());
    drop(tx); // all senders gone ⇒ rx.recv() → None

    let r = tokio::time::timeout(Duration::from_secs(5), conn.read())
        .await
        .expect("read does not hang");
    assert_eq!(r.unwrap(), None, "rx hangup maps to EOF");

    conn.write(b"x")
        .await
        .expect("write after an rx hangup still attempts (sent_fin not set by rx-close)");
    let frame = read_message(&mut router).await.unwrap();
    assert_eq!(frame.body, b"x");

    drop(router);
    let _ = task.await;
}

/// **U4 — `write()` consults the SAME flag `close_write` sets (one-flag design).** After our own
/// `close_write()` (which CAS-sets `sent_fin` and sends the FIN), `write()` fails — parity with the
/// oracle, whose `Write` consults the same `sentFIN` that `CloseWrite` sets (`conn.go:216`/`:243`).
/// MUTATION → RED: use a SEPARATE `state_closed` flag (not set by `close_write`) instead of the
/// unified `sent_fin` ⇒ `write` would return `Ok`.
#[tokio::test]
async fn close_write_then_write_fails() {
    let (state, task, mut router) = rig();
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(9, tx);
    let mut conn = EdgeConn::new_for_test(9, rx, state.clone());

    conn.close_write().await.expect("close_write sends the FIN");
    let fin = read_message(&mut router).await.unwrap();
    assert_eq!(fin.content_type, CT_DATA, "the FIN rides a Data frame");
    assert!(fin.body.is_empty(), "the FIN frame is empty");

    let w = conn.write(b"x").await;
    assert!(
        matches!(w, Err(EdgeError::WriteAfterClose)),
        "write after close_write must fail (write consults the same sent_fin): {w:?}"
    );

    drop(router);
    let _ = task.await;
}

/// **U5 — the third setter: our own `close()` (`conn.go:862`).** After `close()` (StateClosed of
/// local close + deregister), `write()` fails — parity with the oracle's `close()` storing `sentFIN`.
/// MUTATION → RED: drop the `sent_fin.store` from `close()` (§3.1.6) ⇒ `write` would return `Ok`.
#[tokio::test]
async fn close_then_write_fails() {
    let (state, task, mut router) = rig();
    let (tx, rx) = mpsc::channel(4);
    state.register_conn(10, tx);
    let mut conn = EdgeConn::new_for_test(10, rx, state.clone());

    conn.close().await.expect("close sends the StateClosed");
    let sc = read_message(&mut router).await.unwrap();
    assert_eq!(
        sc.content_type, CT_STATE_CLOSED,
        "close emits the StateClosed of local close"
    );

    let w = conn.write(b"x").await;
    assert!(
        matches!(w, Err(EdgeError::WriteAfterClose)),
        "write after our own close() must fail (third setter, conn.go:862): {w:?}"
    );
    let got = tokio::time::timeout(Duration::from_millis(200), read_message(&mut router)).await;
    assert!(
        got.is_err(),
        "no Data frame after the close StateClosed: {got:?}"
    );

    drop(router);
    let _ = task.await;
}

// ───────────────── qw-wire-header-len: longitud EXACTA de los headers enteros ─────────────────

/// `T-5` (falsador de `C-3`). Un `Data` cuyo header `Flags` mide 5 bytes ya no marca EOF: `header_u32`
/// da `None`, el `.unwrap_or(0)` de `conn.rs:198` deja `flags == 0` y el bit FIN no está puesto.
/// Converge EXACTAMENTE con el oráculo, que hace `flags, _ := msg.GetUint32Header(edge.FlagsHeader)`
/// y con longitud ≠ 4 se queda en `0` ⇒ `flags & edge.FIN == 0` ⇒ no marca `readFIN`
/// (`sdk-golang@4b6a087 ziti/edge/network/conn.go:759-762`).
///
/// El SEGUNDO `read()` es el aserto que discrimina: el primero devuelve `Some(b"chunk")` en las DOS
/// versiones, porque el FIN de hoy marca la bandera *después* de entregar el cuerpo
/// (`conn.rs:198-205`). Solo el segundo separa «EOF pegajoso» de «sigue leyendo».
///
/// MUTACIÓN ASESINA: `v.len() >= 4` en `header_u32` ⇒ el prefijo `[1,0,0,0]` es `FLAG_FIN`, el primer
/// frame marca `read_eof` y el SEGUNDO `read()` devuelve `None`.
#[tokio::test]
async fn read_ignores_fin_when_flags_header_is_five_bytes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (cw, _) = tokio::io::duplex(8192);
        let state = Arc::new(ChannelState::new(Box::new(cw)));
        let (data_tx, data_rx) = mpsc::channel(4);
        state.register_conn(7, data_tx.clone());
        let mut conn = EdgeConn::new_for_test(7, data_rx, state);

        // (1) el frame BAJO PRUEBA: Flags de 5 bytes cuyo prefijo LE es FLAG_FIN (1).
        let mut spurious = build_data(7, b"chunk", false);
        spurious.headers.insert(HDR_FLAGS, vec![1u8, 0, 0, 0, 9]);
        data_tx.send(spurious).await.unwrap();
        assert_eq!(conn.read().await.unwrap(), Some(b"chunk".to_vec()));

        // (2) un Data ordinario SIN Flags: si el FIN espurio hubiera contado, esto sería None.
        data_tx.send(build_data(7, b"more", false)).await.unwrap();
        assert_eq!(
            conn.read().await.unwrap(),
            Some(b"more".to_vec()),
            "un Flags de 5 bytes NO puede marcar EOF: la conn sigue leyendo"
        );
    })
    .await
    .expect("T-5: read() no completó dentro del presupuesto");
}
