// F6 tramo 3b troceo: tests movidos verbatim del monolito de `tunnel/udp` (mod tests).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::channel::connect::read_message;
use crate::edge::dial::{
    CT_DATA, CT_STATE_CLOSED, FLAG_FIN, HDR_FLAGS, build_data, build_state_closed,
};

use super::pump::drive_vconn;
use super::testsupport::*;
use super::{MAX_UDP_PACKET_SIZE, VCONN_QUEUE_DEPTH};

// ───────────────────────── drive_vconn (halfClose=false teardown) ─────────────────────────

/// **T-C (gemelo de T-A del arco intercept):** con `pump_udp_to_ziti` APARCADO a mitad de un
/// `zw.write` (canal falso de 64 B ⇒ el `write_all` de 8 KiB se bloquea), el **EOF de ziti** hace
/// retornar al pump LECTOR. Con el `select!` original eso dropeaba al ESCRITOR a medias ⇒ frame
/// TRUNCADO en el canal COMPARTIDO (pooleado, con flujos de OTROS servicios). Con `join!` + `done`
/// el frame en vuelo sale ENTERO y el router parsea frames completos hasta el StateClosed.
///
/// Que `read_message` no se cuelgue ES la aserción de framing.
#[tokio::test]
async fn drive_vconn_ziti_eof_mid_write_never_tears_a_frame() {
    use tokio::io::AsyncReadExt;

    let (zr, zw, _state, data_tx, mut router) = fake_conn_sized(64);
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    let inflight = vec![0xCDu8; 8 * 1024];
    in_tx.try_send(inflight.clone()).unwrap();

    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        proxy_sock,
        src,
        in_rx,
        last_use,
        Arc::clone(&closed),
    ));

    // Rendezvous determinista: leer 1 byte solo puede tener éxito si el escritor ya está DENTRO de
    // `zw.write`, con el frame a medias y el canal de 64 B lleno.
    let mut first = [0u8; 1];
    router
        .read_exact(&mut first)
        .await
        .expect("el pump escribió al menos 1 byte ⇒ está dentro de zw.write");

    // EOF de ziti ⇒ `pump_ziti_to_udp` retorna AHORA, con el escritor aparcado.
    let mut fin = build_data(TEST_CONN_ID, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.send(fin).await.unwrap();

    let mut framed = (&first[..]).chain(router);
    let (mut body, mut datas, mut closeds) = (Vec::new(), 0usize, 0usize);
    loop {
        let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), read_message(&mut framed))
            .await
            .expect("read_message no cuelga ⇒ todos los frames están completos")
        else {
            break;
        };
        match msg.content_type {
            CT_DATA => {
                datas += 1;
                body.extend_from_slice(&msg.body);
            }
            CT_STATE_CLOSED => {
                closeds += 1;
                break;
            }
            _ => {}
        }
    }
    assert_eq!(
        body, inflight,
        "el frame EN VUELO se escribió ENTERO pese al EOF de ziti (invariante ii)"
    );
    assert_eq!(datas, 1, "exactamente el datagrama en vuelo");
    assert_eq!(closeds, 1, "un único StateClosed (full-close, sin FIN)");

    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    assert!(closed.load(Ordering::Acquire));
    drop(in_tx);
}

/// Full round-trip BOTH ways through a vconn, then a ziti EOF tears it down: the vconn full-closes
/// (StateClosed + deregister) and — CRUCIALLY — sends NO FIN (halfClose=false, the discriminator
/// vs the TCP `splice`, which half-closes). `closed` is set. A mutation adding a `close_write`
/// (half-close) would make the `no FIN` assertion RED. Sequenced via the fake ziti peer (read the
/// udp→ziti "ping" FIRST, THEN inject the "pong" reply + FIN) so the round-trip is deterministic;
/// `in_tx` is kept alive so the ziti-EOF (not an eviction race) drives the select! completion.
#[tokio::test]
async fn drive_vconn_round_trips_then_full_closes_without_fin_on_ziti_eof() {
    let (zr, zw, state, data_tx, mut router) = fake_conn();
    let dst = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst_addr = dst.local_addr().unwrap();
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // udp→ziti: one inbound datagram. KEEP in_tx alive (so udp→ziti blocks after draining, and
    // the ziti-EOF — not an eviction — drives teardown).
    in_tx.send(b"ping".to_vec()).await.unwrap();

    // Fake ziti peer: read the udp→ziti "ping" Data FIRST (sequencing), then inject "pong" back +
    // a FIN (ziti EOF), then read on until StateClosed; assert NO FIN was sent by the vconn.
    let router_task = tokio::spawn(async move {
        let mut got_ping = false;
        let mut saw_fin = false;
        let mut saw_state_closed = false;
        // First frame the vconn writes is the forwarded "ping".
        if let Ok(msg) = read_message(&mut router).await
            && msg.content_type == CT_DATA
            && msg.body == b"ping"
        {
            got_ping = true;
        }
        // Now reply "pong" (ziti→udp) then EOF.
        data_tx
            .send(build_data(TEST_CONN_ID, b"pong", false))
            .await
            .unwrap();
        let mut fin = build_data(TEST_CONN_ID, b"", false);
        fin.headers
            .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
        data_tx.send(fin).await.unwrap();
        let _keep = data_tx; // keep the mux sender alive; teardown comes from the FIN, not a drop
        while let Ok(msg) = read_message(&mut router).await {
            match msg.content_type {
                CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => saw_fin = true,
                CT_STATE_CLOSED => {
                    saw_state_closed = true;
                    break;
                }
                _ => {}
            }
        }
        (got_ping, saw_fin, saw_state_closed)
    });

    let drive = drive_vconn(
        zr,
        zw,
        Arc::clone(&proxy_sock),
        dst_addr,
        in_rx,
        Arc::clone(&last_use),
        Arc::clone(&closed),
    );
    // The "pong" goes out the proxy socket to dst.
    let recv_pong = async {
        let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), dst.recv_from(&mut buf))
            .await
            .expect("pong datagram arrives")
            .unwrap();
        buf[..n].to_vec()
    };

    let ((), pong) = tokio::join!(drive, recv_pong);
    drop(in_tx); // done; release after the join (kept alive across it on purpose)
    assert_eq!(pong, b"pong", "ziti→udp datagram delivered to the source");
    let (got_ping, saw_fin, saw_state_closed) = router_task.await.unwrap();
    assert!(got_ping, "udp→ziti datagram forwarded as a Data frame");
    assert!(
        !saw_fin,
        "halfClose=false: a UDP vconn NEVER sends a FIN (discriminator vs the TCP splice)"
    );
    assert!(
        saw_state_closed,
        "the vconn full-closes (StateClosed) on ziti EOF"
    );
    assert!(
        closed.load(Ordering::Acquire),
        "closed flag set at teardown"
    );
    assert_eq!(
        state.conn_count(),
        0,
        "the conn was deregistered from the mux"
    );
}

/// When the manager evicts a vconn (drops its `in_tx`), the udp→ziti direction ends (`recv` →
/// None) → the vconn tears down (full-close, deregister) even with NO ziti EOF. This is the
/// expiration/eviction path (drop_expired drops the handle = the close signal).
#[tokio::test]
async fn drive_vconn_tears_down_when_inbound_queue_is_dropped() {
    let (zr, zw, state, data_tx, mut router) = fake_conn();
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // Manager evicts → drop in_tx. No ziti traffic. Keep data_tx alive so the mux conn stays
    // registered (only the in_tx drop should trigger teardown).
    drop(in_tx);

    let router_task = tokio::spawn(async move {
        let _keep = data_tx;
        let mut saw_state_closed = false;
        while let Ok(msg) = read_message(&mut router).await {
            if msg.content_type == CT_STATE_CLOSED {
                saw_state_closed = true;
                break;
            }
        }
        saw_state_closed
    });

    drive_vconn(
        zr,
        zw,
        proxy_sock,
        addr(9),
        in_rx,
        last_use,
        Arc::clone(&closed),
    )
    .await;

    assert!(
        router_task.await.unwrap(),
        "dropping the inbound queue (eviction) full-closes the vconn"
    );
    assert!(closed.load(Ordering::Acquire), "closed flag set");
    assert_eq!(
        state.conn_count(),
        0,
        "deregistered after eviction teardown"
    );
}

/// **T2 (integración):** EOF de ziti con la cola udp→ziti NO vacía ⇒ los N encolados se FLUSHean
/// como N frames `Data` (verbatim, en orden) ANTES del `StateClosed`, y NO sale FIN
/// (halfClose=false). El FIN es el ÚNICO item del read-queue e inyectado ANTES del spawn ⇒ en la 1ª
/// poll del `join!(biased; z2u, u2z)`, `z2u` (lector, biased primero) devuelve `Ok(None)` y dispara
/// `done` ANTES de que `u2z` saque ningún datagrama ⇒ la 1ª acción de `u2z` es el brazo `done` con
/// la cola LLENA (determinista). Espejo del test T-C pero con cola NO vacía al observar el EOF.
/// Con el brazo `done` pelado (código anterior) los 5 se descartan ⇒ `datas` vacío ⇒ RED.
#[tokio::test]
async fn drive_vconn_flushes_queued_datagrams_on_ziti_eof() {
    let (zr, zw, _state, data_tx, mut router) = fake_conn();
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // Encolar N=5 datagramas udp→ziti ANTES del EOF.
    let expected: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 3]).collect();
    for d in &expected {
        in_tx.try_send(d.clone()).unwrap();
    }
    // El FIN es el ÚNICO item del read-queue de ziti (inyectado ANTES del spawn) ⇒ `z2u` observa el
    // EOF y dispara `done` antes de que `u2z` drene nada.
    let mut fin = build_data(TEST_CONN_ID, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.send(fin).await.unwrap();
    let _keep = data_tx; // mantener vivo el mux sender; el teardown viene del FIN, no de un drop

    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        Arc::clone(&proxy_sock),
        src,
        in_rx,
        Arc::clone(&last_use),
        Arc::clone(&closed),
    ));

    // Leer lo que el vconn escribe a ziti hasta el StateClosed.
    let (mut datas, mut saw_fin, mut saw_state_closed) = (Vec::new(), false, false);
    while let Ok(Ok(msg)) =
        tokio::time::timeout(Duration::from_secs(5), read_message(&mut router)).await
    {
        match msg.content_type {
            CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => saw_fin = true,
            CT_DATA => datas.push(msg.body),
            CT_STATE_CLOSED => {
                saw_state_closed = true;
                break;
            }
            _ => {}
        }
    }

    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    assert_eq!(
        datas, expected,
        "los 5 datagramas encolados se FLUSHean en orden antes del close"
    );
    assert!(saw_state_closed, "full-close (StateClosed) tras el flush");
    assert!(!saw_fin, "halfClose=false: nunca sale un FIN");
    assert!(closed.load(Ordering::Acquire), "closed flag set");
}

/// **T3 (no-regresión):** la EVICCIÓN (drop de `in_tx`, SIN EOF de ziti) sigue drenando toda la
/// cola: `recv()` devuelve `Some` por cada datagrama y `None` solo con la cola VACÍA ⇒ los N salen
/// como N frames `Data` antes del `StateClosed`. Esta rebanada NO toca el brazo de evicción; el
/// test lo PINEA (una mutación que cortocircuitara `recv()→None` antes de vaciar la cola ⇒ RED).
#[tokio::test]
async fn drive_vconn_eviction_still_drains_queued_datagrams() {
    let (zr, zw, _state, data_tx, mut router) = fake_conn();
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    let expected: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 3]).collect();
    for d in &expected {
        in_tx.try_send(d.clone()).unwrap();
    }
    drop(in_tx); // evicción: sin EOF de ziti; `recv()` da `None` solo con la cola VACÍA

    let _keep = data_tx; // mantener el mux conn registrado; el teardown es el drop de in_tx

    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        Arc::clone(&proxy_sock),
        addr(9),
        in_rx,
        Arc::clone(&last_use),
        Arc::clone(&closed),
    ));

    let (mut datas, mut saw_state_closed) = (Vec::new(), false);
    while let Ok(Ok(msg)) =
        tokio::time::timeout(Duration::from_secs(5), read_message(&mut router)).await
    {
        match msg.content_type {
            CT_DATA => datas.push(msg.body),
            CT_STATE_CLOSED => {
                saw_state_closed = true;
                break;
            }
            _ => {}
        }
    }

    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    assert_eq!(
        datas, expected,
        "la evicción sigue drenando todos los datagramas encolados en orden"
    );
    assert!(saw_state_closed, "full-close tras el drenado");
    assert!(closed.load(Ordering::Acquire), "closed flag set");
}

/// **T3-SC (DV-11-SC):** un `StateClosed` ENTRANTE (la conn ENTERA murió, NO un half-close por FIN)
/// hace que el brazo `done` ABORTE el drenado. El lector observa el `StateClosed` (`Ok(None)`), pone
/// la bandera compartida `sent_fin`, y dispara `done`; el brazo `done` hace **1** `zw.write` que da
/// `Err(WriteAfterClose)` sin emitir ⇒ **0 frames `Data`**, seguido del único `StateClosed` de cierre
/// del relay. Gemelo del test intercept `state_closed_aborts_the_drain`; una mutación que solo
/// arreglara un gemelo dejaría el otro ROJO. Contraste con `..._flushes_queued_datagrams_on_ziti_eof`
/// (FIN ⇒ SÍ drena). El `StateClosed` es el ÚNICO item del read-queue e inyectado ANTES del spawn ⇒
/// `biased`: el lector va primero. **Mutación → ROJO:** revertir el check de `write()` (§3.1.4) ⇒ el
/// drenado flushea los 5 ⇒ `datas.len() == 5`.
#[tokio::test]
async fn drive_vconn_state_closed_aborts_the_drain() {
    let (zr, zw, _state, data_tx, mut router) = fake_conn();
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // Encolar N=5 datagramas udp→ziti ANTES del StateClosed.
    for i in 0u8..5 {
        in_tx.try_send(vec![i; 3]).unwrap();
    }
    // El StateClosed es el ÚNICO item del read-queue de ziti (inyectado ANTES del spawn) ⇒ `z2u`
    // observa el cierre, pone `sent_fin` y dispara `done` antes de que `u2z` drene nada.
    data_tx
        .send(build_state_closed(TEST_CONN_ID))
        .await
        .unwrap();
    let _keep = data_tx; // el teardown viene del StateClosed, no de un drop

    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        Arc::clone(&proxy_sock),
        src,
        in_rx,
        Arc::clone(&last_use),
        Arc::clone(&closed),
    ));

    let (mut datas, mut saw_fin, mut saw_state_closed) = (Vec::new(), false, false);
    while let Ok(Ok(msg)) =
        tokio::time::timeout(Duration::from_secs(5), read_message(&mut router)).await
    {
        match msg.content_type {
            CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => saw_fin = true,
            CT_DATA => datas.push(msg.body),
            CT_STATE_CLOSED => {
                saw_state_closed = true;
                break;
            }
            _ => {}
        }
    }

    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    assert!(
        datas.is_empty(),
        "el drenado ABORTA tras el StateClosed: 0 frames Data (write falla al tope)"
    );
    assert!(saw_state_closed, "el único StateClosed de cierre del relay");
    assert!(!saw_fin, "halfClose=false: nunca sale un FIN");
    assert!(closed.load(Ordering::Acquire), "closed flag set");
}
