//! Tests de `service_conn` (F6 tramo 5: movidos verbatim del monolito de `edge/conn`).

use super::testsupport::detail;
use super::*;
use crate::channel::connect::{read_message, write_message};
use crate::channel::message::Message;
use crate::edge::data::EdgeChannel;
use crate::edge::dial::{CT_DATA, CT_STATE_CONNECTED, HDR_CIRCUIT_ID, HDR_CONN_ID};
use std::collections::BTreeMap;
use std::sync::Arc;

#[tokio::test]
async fn service_conn_delegates_write_read_close() {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );

    // Fake router: reply StateConnected, then echo the one Data frame.
    let router_task = tokio::spawn(async move {
        let connect = read_message(&mut router).await.unwrap();
        let conn_id = connect.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers
            .insert(1, connect.sequence.to_le_bytes().to_vec());
        sc.headers.insert(HDR_CONN_ID, conn_id.clone());
        sc.headers.insert(HDR_CIRCUIT_ID, b"circ-7".to_vec());
        write_message(&mut router, &sc).await.unwrap();

        let data = read_message(&mut router).await.unwrap();
        let mut echo = Message::new(CT_DATA, data.body.clone());
        echo.headers.insert(HDR_CONN_ID, conn_id);
        write_message(&mut router, &echo).await.unwrap();

        // Stay alive to receive the StateClosed that ServiceConn::close sends, so the
        // conn-close write hits a live peer (not a broken pipe) and its error propagates.
        let _ = read_message(&mut router).await;
    });

    let conn = ch
        .dial(&detail(), false, None, None)
        .await
        .expect("dial ok");
    let mut svc_conn = ServiceConn::from_parts(conn, Arc::new(ch));
    // Passthrough getters work through the bundle.
    assert_eq!(svc_conn.conn_id(), 1);
    assert_eq!(svc_conn.circuit_id(), Some("circ-7"));
    // Delegated write/read round-trip — proves the channel (rx-loop) stays alive.
    svc_conn.write(b"hello-bundle").await.unwrap();
    assert_eq!(
        svc_conn.read().await.unwrap(),
        Some(b"hello-bundle".to_vec())
    );

    // Close THROUGH the bundle first (conn.close sends StateClosed to the still-live
    // router), then let the router task finish.
    svc_conn.close().await.unwrap();
    router_task.await.unwrap();
}

/// The close-semantics change of the pool slice: `ServiceConn::close()` deregisters its conn
/// (StateClosed) but must NOT tear the SHARED channel down — a SIBLING conn multiplexed over the
/// same pooled channel keeps working. NON-VACUOUS: dial TWO conns (A and B) over one shared
/// `Arc<EdgeChannel>` (held also by a "pool" `Arc`), `close()` A, then have the router push a Data
/// frame to B AFTER A's close and assert B reads it — proving the rx-loop is still alive routing to
/// the surviving sibling. A regression to the 4b force-close (`channel.close()`, which aborts the
/// rx-loop regardless of other `Arc`s) would abort the loop → B EOFs (reads `None`) → the assert
/// fails. (The earlier guard merely held a bare second `Arc` and checked `is_alive()`, which an
/// `Arc` keeps trivially true; this drives a real sibling conn instead.)
#[tokio::test]
async fn closing_one_conn_keeps_sibling_and_shared_channel_alive() {
    let (client_io, router_io) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client_io);
    let ch = Arc::new(EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        BTreeMap::new(),
    ));
    // Router: StateConnected each of two dials (A then B, correlated by ReplyFor=Connect seq),
    // consume A's StateClosed, then push a Data frame to B and hold its end open.
    let router_task = tokio::spawn(async move {
        let mut router = router_io;
        let connect_a = read_message(&mut router).await.unwrap();
        let a_id = connect_a.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc_a = Message::new(CT_STATE_CONNECTED, vec![]);
        sc_a.headers
            .insert(1, connect_a.sequence.to_le_bytes().to_vec());
        sc_a.headers.insert(HDR_CONN_ID, a_id);
        write_message(&mut router, &sc_a).await.unwrap();

        let connect_b = read_message(&mut router).await.unwrap();
        let b_id = connect_b.headers.get(&HDR_CONN_ID).unwrap().clone();
        let mut sc_b = Message::new(CT_STATE_CONNECTED, vec![]);
        sc_b.headers
            .insert(1, connect_b.sequence.to_le_bytes().to_vec());
        sc_b.headers.insert(HDR_CONN_ID, b_id.clone());
        write_message(&mut router, &sc_b).await.unwrap();

        let _ = read_message(&mut router).await; // A's StateClosed from svc_a.close()
        // Push a Data to B AFTER A's close → proves the shared rx-loop is still alive.
        let mut data = Message::new(CT_DATA, b"sibling-lives".to_vec());
        data.headers.insert(HDR_CONN_ID, b_id);
        write_message(&mut router, &data).await.unwrap();
        std::future::pending::<()>().await; // hold the router end open
    });

    let pool_arc = ch.clone(); // simulate the pool owning the channel
    // Two conns multiplexed over the SAME shared channel (distinct conn-ids).
    let conn_a = ch.dial(&detail(), false, None, None).await.expect("dial A");
    let mut conn_b = ch.dial(&detail(), false, None, None).await.expect("dial B");
    let svc_a = ServiceConn::from_parts(conn_a, ch.clone());
    assert!(pool_arc.is_alive(), "channel alive before close");

    // Close A: StateClosed for A's conn-id + drop A's `Arc`. Must NOT abort the shared rx-loop.
    svc_a.close().await.expect("close A");

    // The surviving sibling B reads the post-close Data → the rx-loop is alive (not torn down).
    assert_eq!(
        conn_b.read().await.expect("read B").as_deref(),
        Some(&b"sibling-lives"[..]),
        "sibling conn B survives conn A's close — the shared/pooled channel is NOT torn down \
         (a 4b force-close would abort the rx-loop and EOF B here)"
    );
    assert!(
        pool_arc.is_alive(),
        "the shared/pooled channel stays alive after one ServiceConn's close (kept for reuse)"
    );
    router_task.abort();
}

/// Finding B: a dial whose Connect write fails on a BROKEN TRANSPORT must mark the channel closed so
/// the pool evicts it on the next get (`is_alive`→false), mirroring the oracle txer's defer-Close —
/// a transport write error always means the channel is broken (a LOGICAL reject arrives as a reply,
/// not a write error). Construct a write-broken/read-alive channel: the router drops its READ side →
/// our writes `BrokenPipe`; it holds its WRITE side → our rx-loop stays parked (no EOF), so only the
/// dial-write-error path can set `closed`. MUTATION: remove the `mark_closed()` in the write-error
/// branch → `closed` stays false, the rx-task is still parked → `is_alive()` stays TRUE → RED (the
/// pool would re-hand-out the broken channel for ~one probe interval).
#[tokio::test]
async fn dial_transport_write_error_marks_channel_closed() {
    // Write-broken / read-alive, built from TWO independent duplexes (a single duplex's split halves
    // share the stream, so dropping one does NOT half-close it): the WRITE half's peer is dropped →
    // our Connect write fails `BrokenPipe`; the READ half's peer is held → our rx-loop parks on read
    // (no EOF), so ONLY the dial-write-error path can set `closed`.
    let (write_half, write_peer) = tokio::io::duplex(64);
    drop(write_peer); // writes to `write_half` now fail BrokenPipe
    let (read_half, _read_peer) = tokio::io::duplex(64); // reads block (peer held: no data, no EOF)
    let ch = EdgeChannel::from_halves(Box::new(read_half), Box::new(write_half), BTreeMap::new());
    assert!(ch.is_alive(), "channel alive before the failed dial");

    let _err = ch
        .dial(&detail(), false, None, None)
        .await
        .expect_err("a write-broken transport must fail the dial");
    assert!(
        !ch.is_alive(),
        "a transport write error on dial must mark the channel closed so the pool evicts it"
    );
}
