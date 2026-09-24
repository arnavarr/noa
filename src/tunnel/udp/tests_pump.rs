// F6 tramo 3b troceo: tests movidos verbatim del monolito de `tunnel/udp` (mod tests).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use crate::channel::connect::read_message;
use crate::edge::dial::{CT_DATA, FLAG_FIN, HDR_FLAGS, build_data};
use crate::tunnel::proxy::PROXY_BUF;

use super::pump::{pump_udp_to_ziti, pump_ziti_to_udp, udp_pieces};
use super::testsupport::*;
use super::{MAX_UDP_PACKET_SIZE, VCONN_QUEUE_DEPTH};

// ───────────────────────── pump_udp_to_ziti (one frame per datagram) ─────────────────────────

#[tokio::test]
async fn pump_udp_to_ziti_writes_one_data_frame_per_whole_datagram() {
    let (_zr, mut zw, _state, _data_tx, mut router) = fake_conn();
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));

    // Two datagrams of different sizes; the second exceeds PROXY_BUF to prove udp→ziti does NOT
    // chunk (one whole Data frame per datagram, unlike ziti→udp).
    let big = vec![0xABu8; PROXY_BUF + 5000];
    in_tx.send(b"datagram-1".to_vec()).await.unwrap();
    in_tx.send(big.clone()).await.unwrap();
    drop(in_tx); // close the queue → pump drains both then returns

    let (_done_tx, mut done_rx) = watch::channel(false); // nunca dispara: el pump acaba por `in_rx`
    let pump = pump_udp_to_ziti(&mut in_rx, &mut zw, &last_use, &mut done_rx);
    let reader = async {
        let m1 = read_message(&mut router).await.unwrap();
        let m2 = read_message(&mut router).await.unwrap();
        (m1, m2)
    };
    let ((), (m1, m2)) = tokio::join!(pump, reader);
    assert_eq!(m1.content_type, CT_DATA);
    assert_eq!(m1.body, b"datagram-1", "datagram 1 forwarded verbatim");
    assert_eq!(m2.content_type, CT_DATA);
    assert_eq!(
        m2.body, big,
        "a >PROXY_BUF datagram is ONE Data frame (udp->ziti is not chunked)"
    );
}

/// **T1 (decisivo):** con `done` YA disparado ANTES de llamar al pump (el `select` biased poléa
/// `done.changed()` primero y gana INCONDICIONALMENTE ⇒ no depende del scheduler), el brazo `done`
/// DRENA el SNAPSHOT de `in_rx` a la conn ziti antes de retornar (espejo del drenado de
/// `udpConn.WriteTo` tras `closeNotify`, conn.go:76-97). Con el brazo `done` pelado (código
/// anterior) salían 0 frames `Data` ⇒ el reader no completa ⇒ RED (por timeout).
#[tokio::test]
async fn pump_udp_to_ziti_drains_snapshot_on_done() {
    let (_zr, mut zw, _state, _data_tx, mut router) = fake_conn();
    let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let old = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
    let last_use = Arc::new(Mutex::new(old));

    // Encolar N=5 datagramas distintos, luego dropear el sender (irrelevante: gana el brazo `done`).
    let expected: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 3]).collect();
    for d in &expected {
        in_tx.try_send(d.clone()).unwrap();
    }
    drop(in_tx);

    // `done` disparado ANTES del pump ⇒ el brazo `done` gana en la 1ª poll (biased); `recv` no se
    // poléa nunca ⇒ el drenado corre con la cola LLENA, sin depender del scheduler. `done_tx` vivo.
    let (done_tx, mut done_rx) = watch::channel(false);
    done_tx.send(true).unwrap();

    let pump = pump_udp_to_ziti(&mut in_rx, &mut zw, &last_use, &mut done_rx);
    let reader = async {
        let mut msgs = Vec::new();
        for _ in 0..5 {
            let m = tokio::time::timeout(Duration::from_secs(5), read_message(&mut router))
                .await
                .expect("los 5 datagramas encolados se FLUSHean en el brazo done")
                .unwrap();
            msgs.push(m);
        }
        msgs
    };
    let ((), msgs) = tokio::join!(pump, reader);

    assert_eq!(msgs.len(), 5, "los 5 datagramas del snapshot salieron");
    for (i, (m, want)) in msgs.iter().zip(&expected).enumerate() {
        assert_eq!(m.content_type, CT_DATA, "frame {i} es Data");
        assert_eq!(&m.body, want, "datagrama {i} verbatim y en orden");
    }
    assert!(
        *last_use.lock().unwrap() > old,
        "last_use bumpeado por datagrama drenado (markUsed, conn.go:93)"
    );
}

// ───────────────────────── pump_ziti_to_udp (LOAD-BEARING: copyBuf chunking) ─────────────────────────

/// Claim 4 (the load-bearing fidelity test, since the live test uses small payloads): a ziti read
/// chunk LARGER than PROXY_BUF is split into PROXY_BUF + remainder pieces, faithful to the
/// oracle's generic `io.CopyBuffer(udpConn, edgeConn)` with `copyBuf=0x4000-17` (`edgeConn` has no
/// `WriteTo`/`ReadFrom`, VERIFIED in sdk-golang v1.7.0). Pure (no socket): loopback UDP `send_to`
/// is capped below PROXY_BUF on macOS (`net.inet.udp.maxdgram=9216`), so a real-socket test cannot
/// observe a 16367-byte datagram — the split is what carries the fidelity. A mutation that drops
/// the chunking (one piece) or changes the split size makes this RED.
#[test]
fn udp_pieces_splits_a_large_chunk_at_proxy_buf_loss_free() {
    let total = PROXY_BUF + 1000;
    let chunk: Vec<u8> = (0..total).map(|i| u8::try_from(i % 251).unwrap()).collect();
    let pieces: Vec<&[u8]> = udp_pieces(&chunk, PROXY_BUF).collect();
    assert_eq!(pieces.len(), 2, "a >PROXY_BUF chunk → exactly 2 datagrams");
    assert_eq!(pieces[0].len(), PROXY_BUF, "first piece == copyBuf size");
    assert_eq!(pieces[1].len(), 1000, "second piece == remainder");
    let reassembled: Vec<u8> = pieces.concat();
    assert_eq!(
        reassembled, chunk,
        "the split is loss-free (just re-chunked)"
    );
}

/// A chunk at exactly PROXY_BUF is one piece; one byte over is two (boundary of the split).
#[test]
fn udp_pieces_boundary_at_proxy_buf() {
    assert_eq!(
        udp_pieces(&vec![0u8; PROXY_BUF], PROXY_BUF).count(),
        1,
        "== PROXY_BUF → 1 piece"
    );
    assert_eq!(
        udp_pieces(&vec![0u8; PROXY_BUF + 1], PROXY_BUF).count(),
        2,
        "PROXY_BUF + 1 → 2 pieces"
    );
    assert_eq!(
        udp_pieces(b"small", PROXY_BUF).count(),
        1,
        "tiny chunk → 1 piece"
    );
}

#[tokio::test]
async fn pump_ziti_to_udp_small_chunk_is_one_datagram() {
    let (mut zr, _zw, _state, data_tx, _router) = fake_conn();
    let dst = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst_addr = dst.local_addr().unwrap();
    let proxy_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let last_use = Arc::new(Mutex::new(Instant::now()));

    data_tx
        .send(build_data(TEST_CONN_ID, b"small", false))
        .await
        .unwrap();
    let mut fin = build_data(TEST_CONN_ID, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.send(fin).await.unwrap();
    drop(data_tx);

    let (_done_tx, mut done_rx) = watch::channel(false); // nunca dispara: el pump acaba por ziti-EOF
    let pump = pump_ziti_to_udp(
        &mut zr,
        &proxy_sock,
        dst_addr,
        &last_use,
        PROXY_BUF,
        &mut done_rx,
    );
    let receiver = async {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), dst.recv_from(&mut buf))
            .await
            .expect("datagram arrives")
            .unwrap();
        buf[..n].to_vec()
    };
    let ((), datagram) = tokio::join!(pump, receiver);
    assert_eq!(datagram, b"small", "a ≤PROXY_BUF chunk → one datagram");
}

/// CALL-SITE pin for claim 4: `pump_ziti_to_udp` (the data plane, not just the pure helper) emits
/// ONE UDP datagram per `split`-sized piece — a chunk LARGER than `split` becomes MULTIPLE
/// datagrams. Drives the real loopback socket with a tiny `split` (4) so the datagrams stay under
/// macOS's `net.inet.udp.maxdgram`=9216 while still exercising the loop. This is what the pure
/// `udp_pieces` test cannot reach: a "drop the loop" mutation (`socket.send_to(&chunk)` instead of
/// `for piece in udp_pieces(&chunk, split)`) makes this RED (one 10-byte datagram, not 4/4/2).
#[tokio::test]
async fn pump_ziti_to_udp_emits_one_datagram_per_split_piece() {
    let (mut zr, _zw, _state, data_tx, _router) = fake_conn();
    let dst = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst_addr = dst.local_addr().unwrap();
    let proxy_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let last_use = Arc::new(Mutex::new(Instant::now()));

    // One ziti Data chunk of 10 bytes; split=4 → pieces of 4, 4, 2 → three datagrams.
    let chunk: Vec<u8> = (0u8..10).collect();
    data_tx
        .send(build_data(TEST_CONN_ID, &chunk, false))
        .await
        .unwrap();
    let mut fin = build_data(TEST_CONN_ID, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.send(fin).await.unwrap();
    drop(data_tx);

    let (_done_tx, mut done_rx) = watch::channel(false); // nunca dispara: el pump acaba por ziti-EOF
    let pump = pump_ziti_to_udp(&mut zr, &proxy_sock, dst_addr, &last_use, 4, &mut done_rx);
    let receiver = async {
        let mut datagrams = Vec::new();
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        for _ in 0..3 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), dst.recv_from(&mut buf))
                .await
                .expect("datagram arrives")
                .unwrap();
            datagrams.push(buf[..n].to_vec());
        }
        datagrams
    };
    let ((), datagrams) = tokio::join!(pump, receiver);
    assert_eq!(
        datagrams.len(),
        3,
        "a >split chunk emits MULTIPLE datagrams from the pump (not one) — kills drop-the-loop"
    );
    assert_eq!(datagrams[0], &[0, 1, 2, 3], "piece 1 == split (4)");
    assert_eq!(datagrams[1], &[4, 5, 6, 7], "piece 2 == split (4)");
    assert_eq!(datagrams[2], &[8, 9], "piece 3 == remainder (2)");
    assert_eq!(datagrams.concat(), chunk, "loss-free across the split");
}
