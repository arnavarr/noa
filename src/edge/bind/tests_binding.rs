//! Unit tests for `binding.rs`: the `ServiceBinding` handle — close (Unbind then close), accept
//! (plaintext and e2e-encrypted children) and the drop-without-close EOF contract.

use super::{CT_UNBIND, ServiceBinding};
use crate::channel::connect::{read_message, write_message};
use crate::channel::message::Message;
use crate::edge::data::EdgeChannel;
use crate::edge::dial::{CT_STATE_CONNECTED, HDR_CONN_ID};

#[tokio::test]
async fn service_binding_close_sends_unbind_then_closes() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    let router_task = tokio::spawn(async move {
        // reply StateConnected to the bind
        let bind = read_message(&mut router).await.unwrap();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();
        // then read the Unbind that close() sends
        let unbind = read_message(&mut router).await.unwrap();
        assert_eq!(unbind.content_type, CT_UNBIND);
        assert_eq!(unbind.body, b"bind-jwt");
    });

    let (conn_id, bind_rx) = ch
        .send_bind("bind-jwt", "lid-x", None)
        .await
        .expect("bind ok");
    let binding = ServiceBinding {
        conn_id,
        token: "bind-jwt".to_string(),
        channel: ch,
        bind_rx,
        keypair: None,
    };
    assert_eq!(binding.conn_id(), 1);
    // Debug prints conn_id (manual impl; no cascade into edge/data/mod.rs).
    assert!(format!("{binding:?}").contains("conn_id"));
    binding.close().await.expect("unbind + close");
    router_task.await.unwrap();
}

#[tokio::test]
async fn service_binding_accept_returns_child_conn() {
    use crate::edge::dial::HDR_CIRCUIT_ID;
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

        let mut dial = Message::new(super::CT_DIAL, b"bind-jwt".to_vec());
        dial.headers.insert(HDR_CONN_ID, bind_conn_id);
        dial.headers.insert(
            super::HDR_ROUTER_PROVIDED_CONN_ID,
            11u32.to_le_bytes().to_vec(),
        );
        dial.headers.insert(HDR_CIRCUIT_ID, b"circ-sb".to_vec());
        dial.sequence = 3;
        write_message(&mut router, &dial).await.unwrap();
        // read & discard the DialSuccess so the write side stays drained
        let _ = read_message(&mut router).await.unwrap();
    });

    let (conn_id, bind_rx) = ch
        .send_bind("bind-jwt", "lid-sb", None)
        .await
        .expect("bind ok");
    let mut binding = ServiceBinding {
        conn_id,
        token: "bind-jwt".to_string(),
        channel: ch,
        bind_rx,
        keypair: None,
    };
    let conn = binding.accept().await.expect("accept a dial");
    assert_eq!(conn.conn_id(), 11);
    assert_eq!(conn.circuit_id(), Some("circ-sb"));
    router_task.await.unwrap();
    binding.close().await.expect("unbind + close");
}

#[tokio::test]
async fn dropping_binding_without_close_delivers_eof_to_accepted_child() {
    use crate::edge::dial::HDR_CIRCUIT_ID;
    use std::time::Duration;
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

        let mut dial = Message::new(super::CT_DIAL, b"bind-jwt".to_vec());
        dial.headers.insert(HDR_CONN_ID, bind_conn_id);
        dial.headers.insert(
            super::HDR_ROUTER_PROVIDED_CONN_ID,
            44u32.to_le_bytes().to_vec(),
        );
        dial.headers.insert(HDR_CIRCUIT_ID, b"circ-drop".to_vec());
        dial.sequence = 2;
        write_message(&mut router, &dial).await.unwrap();
        let _ds = read_message(&mut router).await.unwrap(); // DialSuccess
        // Keep `router` ALIVE so the child EOF must come from EdgeChannel::Drop clearing
        // `conns`, NOT from a wire EOF (which already worked pre-fix).
        std::future::pending::<()>().await;
    });

    let (conn_id, bind_rx) = ch
        .send_bind("bind-jwt", "lid-drop", None)
        .await
        .expect("bind ok");
    let mut binding = ServiceBinding {
        conn_id,
        token: "bind-jwt".to_string(),
        channel: ch,
        bind_rx,
        keypair: None,
    };
    let mut child = binding.accept().await.expect("accept a child");
    assert_eq!(child.conn_id(), 44);

    // Drop the binding WITHOUT close(): the fix makes EdgeChannel::Drop clear conns+binds,
    // dropping the child's sender -> read() returns None. Pre-fix this hung forever.
    drop(binding);
    let eof = tokio::time::timeout(Duration::from_secs(1), child.read()).await;
    assert!(
        matches!(eof, Ok(Ok(None))),
        "dropped binding must EOF the accepted child, got {eof:?}"
    );

    router_task.abort();
}

#[tokio::test]
async fn service_binding_accept_encrypted_child() {
    use crate::edge::crypto::{Decryptor, Encryptor, KeyPair};
    use crate::edge::dial::{
        CT_DATA, HDR_CIRCUIT_ID, HDR_CRYPTO_METHOD, HDR_FLAGS, HDR_PUBLIC_KEY,
    };
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
        // bind advertises the host pubkey.
        assert_eq!(
            bind.headers.get(&HDR_PUBLIC_KEY).unwrap().as_slice(),
            &host_pk[..]
        );
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        write_message(&mut router, &sc).await.unwrap();

        let dialer = KeyPair::generate();
        let (d_rx, d_tx) = dialer.client_session_keys(&host_pk).unwrap();
        let mut dial = Message::new(super::CT_DIAL, b"bind-jwt".to_vec());
        dial.headers.insert(HDR_CONN_ID, bind_conn_id);
        dial.headers.insert(
            super::HDR_ROUTER_PROVIDED_CONN_ID,
            30u32.to_le_bytes().to_vec(),
        );
        dial.headers
            .insert(HDR_PUBLIC_KEY, dialer.public_key().to_vec());
        dial.headers.insert(HDR_CRYPTO_METHOD, vec![0u8]);
        dial.headers.insert(HDR_CIRCUIT_ID, b"circ-enc-sb".to_vec());
        dial.sequence = 4;
        write_message(&mut router, &dial).await.unwrap();
        let _ds = read_message(&mut router).await.unwrap();
        let hhdr = read_message(&mut router).await.unwrap();
        assert_eq!(
            hhdr.headers.get(&HDR_FLAGS).unwrap().as_slice(),
            &[4, 0, 0, 0]
        );
        let host_header: [u8; 24] = hhdr.body.as_slice().try_into().unwrap();
        let mut dec = Decryptor::new(&d_rx, &host_header);
        let (mut enc, dialer_header) = Encryptor::new(&d_tx);
        let mut dh = Message::new(CT_DATA, dialer_header.to_vec());
        dh.headers.insert(HDR_CONN_ID, 30u32.to_le_bytes().to_vec());
        write_message(&mut router, &dh).await.unwrap();
        let c = enc.push(b"sb-secret").unwrap();
        let mut dm = Message::new(CT_DATA, c);
        dm.headers.insert(HDR_CONN_ID, 30u32.to_le_bytes().to_vec());
        write_message(&mut router, &dm).await.unwrap();
        let echo = read_message(&mut router).await.unwrap();
        assert_eq!(dec.pull(&echo.body).unwrap(), b"sb-secret");
    });

    let (conn_id, bind_rx) = ch
        .send_bind("bind-jwt", "lid-enc-sb", Some(&host_pk))
        .await
        .expect("bind ok");
    let mut binding = ServiceBinding {
        conn_id,
        token: "bind-jwt".to_string(),
        channel: ch,
        bind_rx,
        keypair: Some(host),
    };
    let mut conn = binding.accept().await.expect("accept encrypted child");
    assert_eq!(conn.conn_id(), 30);
    assert_eq!(conn.circuit_id(), Some("circ-enc-sb"));
    let got = conn.read().await.unwrap().unwrap();
    assert_eq!(got, b"sb-secret");
    conn.write(&got).await.unwrap();
    router_task.await.unwrap();
    binding.close().await.expect("unbind + close");
}
