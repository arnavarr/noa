// F6 tramo 3b troceo: tests movidos verbatim del monolito de `tunnel/udp` (mod tests).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::channel::connect::read_message;
use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, HDR_FLAGS, build_data};

use super::flow::{RouteAction, route_decision};
use super::pump::drive_vconn;
use super::testsupport::*;
use super::vconn::{VconnSpawnParts, create_vconn};
use super::{VCONN_QUEUE_DEPTH, Vconn};

// ────────────── teardown-window: `closed` al ABRIR la ventana ⇒ RE-DIAL (rebanada 5) ──────────────

/// Lee los frames que el vconn escribió a ziti, devolviendo `(body concatenado de los Data, nº de
/// Data, nº de StateClosed, ¿algún FIN?)`. `first` son los bytes ya consumidos por el rendezvous, que
/// se vuelven a encadenar delante.
///
/// **NO para en el primer `StateClosed`**: sigue leyendo con un presupuesto CORTO para que un
/// SEGUNDO `StateClosed` (o cualquier frame de más) sea OBSERVABLE — con un `break` en el primero, el
/// `assert_eq!(closeds, 1)` de los llamantes no podría fallar nunca y una mutación que emitiese dos
/// cierres seguiría verde. El primer frame tiene presupuesto largo (el vconn puede estar drenando un
/// frame grande); tras el cierre, el silencio del duplex es la señal de fin.
async fn read_ziti_frames_until_close(
    first: &[u8],
    router: tokio::io::DuplexStream,
) -> (Vec<u8>, usize, usize, bool) {
    use tokio::io::AsyncReadExt;

    let mut framed = first.chain(router);
    let (mut body, mut datas, mut closeds, mut saw_fin) = (Vec::new(), 0usize, 0usize, false);
    loop {
        // Antes del cierre: presupuesto largo, y agotarlo ES un fallo (frame incompleto ⇒ cuelgue).
        // Después del cierre: presupuesto corto, y agotarlo es la terminación normal (no hay más).
        let budget = if closeds == 0 {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(300)
        };
        let Ok(read) = tokio::time::timeout(budget, read_message(&mut framed)).await else {
            assert!(
                closeds > 0,
                "read_message no cuelga ⇒ todos los frames están completos"
            );
            break; // silencio tras el StateClosed ⇒ no hay más frames
        };
        let Ok(msg) = read else { break }; // EOF del duplex
        match msg.content_type {
            CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => saw_fin = true,
            CT_DATA => {
                datas += 1;
                body.extend_from_slice(&msg.body);
            }
            CT_STATE_CLOSED => closeds += 1,
            _ => {}
        }
    }
    (body, datas, closeds, saw_fin)
}

/// **T-5.1 (ACEPTACIÓN):** `closed` se marca al **ABRIR** la ventana de derribo, no al cerrarla.
/// Espejo literal de `Close()` (`conn.go:161-163`): el `CompareAndSwap` de `closed` (`:162`) precede
/// al `close(closeNotify)` (`:163`) que dispara el drenado de `WriteTo` — ningún observador puede ver
/// el drenado en marcha con `closed == false`.
///
/// **Rendezvous DETERMINISTA (sin relojes ni sleeps):** el canal falso de 64 B APARCA el `write_all`
/// del datagrama de 8 KiB ⇒ la ventana de teardown queda ABIERTA mientras el test no lea del router.
/// **Mutación → ROJO:** devolver el `closed.store` a DESPUÉS del `tokio::join!` (el estado de antes de
/// esta rebanada) ⇒ el escritor sigue aparcado (el test no lee), el `join!` no retorna, `closed` nunca
/// se pone y el `timeout` de 2 s expira. RED determinista: el desbloqueo exige una lectura que el
/// assert decisivo NO hace.
#[tokio::test]
async fn drive_vconn_marks_closed_before_the_drain_completes() {
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

    // Rendezvous: que 1 byte sea legible SOLO puede significar que el escritor está DENTRO de
    // `zw.write`, con el frame a medias y el canal de 64 B lleno. Con `timeout`: una regresión del
    // pump da ROJO, no un cuelgue (`cargo test` no acota el tiempo por test).
    let mut first = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), router.read_exact(&mut first))
        .await
        .expect("el pump escribe sin colgarse")
        .expect("el pump escribió al menos 1 byte ⇒ está dentro de zw.write");

    // EOF de ziti ⇒ se ABRE la ventana de derribo, con el escritor AÚN aparcado.
    let mut fin = build_data(TEST_CONN_ID, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.send(fin).await.unwrap();
    let _keep = data_tx; // el teardown viene del FIN, no de un drop del mux sender

    // ASSERT DECISIVO: `closed` se pone SIN que el test lea un byte más del router, o sea con el
    // drenado (y el `join!`) todavía SIN completar. Es la vista que tendría el manager al enrutar.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !closed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed se marca al ABRIR la ventana de derribo, no al cerrarla (conn.go:162)");

    // CONTROL POSITIVO (anti-no-op): marcar `closed` NO puede lograrse saltándose el drenado ni
    // troceando el frame en vuelo — el datagrama de 8 KiB sale ENTERO, en UN solo Data, con un único
    // StateClosed y CERO FIN (halfClose=false).
    let (body, datas, closeds, saw_fin) = read_ziti_frames_until_close(&first, router).await;
    assert_eq!(
        body, inflight,
        "el frame EN VUELO se escribió ENTERO pese al teardown (invariante ii)"
    );
    assert_eq!(
        datas, 1,
        "exactamente el datagrama en vuelo (drenado intacto)"
    );
    assert_eq!(closeds, 1, "un único StateClosed (full-close)");
    assert!(!saw_fin, "halfClose=false: nunca sale un FIN");

    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    drop(in_tx);
}

/// **T-5.2 (ACEPTACIÓN — la consecuencia de RUTEO):** mientras el vconn moribundo DRENA, un datagrama
/// nuevo para el mismo `src` NO se encola en el cadáver: el manager lo ve `closed`, lo EVICTA
/// (`GetWriteQueue`, `manager.go:83-87`) y CREA una conn fresca (`CreateWriteQueue` → `DialAndRun`,
/// `manager.go:91-116`; llamante `proxy.go:375-388`) ⇒ **RE-DIAL**, y el datagrama viaja por la conn
/// NUEVA. `route_decision` + `create_vconn` es exactamente lo que compone [`route_datagram`].
///
/// Mismo rendezvous determinista que T-5.1 (el `write_all` de 8 KiB APARCA en el canal de 64 B ⇒ el
/// moribundo sigue drenando durante todo el assert). **Mutación → ROJO:** (a) `closed.store` tras el
/// `join!` ⇒ el yield-loop expira; (b) neutralizar el chequeo de `closed` en `route_decision` ⇒ cae el
/// `CreateNew`.
#[tokio::test]
async fn teardown_window_datagram_creates_a_fresh_vconn_while_the_old_one_drains() {
    use tokio::io::AsyncReadExt;

    let (zr, zw, _state, data_tx, mut router) = fake_conn_sized(64);
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let inflight = vec![0xCDu8; 8 * 1024];

    // El vconn se crea POR EL CAMINO DEL MANAGER (`create_vconn` == `CreateWriteQueue`): el primer
    // datagrama queda encolado y el spawn (inyectable) arranca el pump.
    let mut conns: HashMap<SocketAddr, Vconn> = HashMap::new();
    let mut driver = None;
    create_vconn(
        &mut conns,
        src,
        inflight.clone(),
        |(s, in_rx, last_use, closed)| {
            driver = Some(tokio::spawn(drive_vconn(
                zr, zw, proxy_sock, s, in_rx, last_use, closed,
            )));
        },
    );
    let driver = driver.expect("el callback de spawn corrió");

    // Rendezvous: el escritor está DENTRO de `zw.write` (canal de 64 B lleno) ⇒ ventana abierta.
    // Con `timeout`: una regresión del pump da ROJO, no un cuelgue.
    let mut first = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), router.read_exact(&mut first))
        .await
        .expect("el pump escribe sin colgarse")
        .expect("el pump escribió al menos 1 byte ⇒ está dentro de zw.write");

    // EOF de ziti ⇒ se ABRE la ventana de derribo (el moribundo sigue drenando).
    let mut fin = build_data(TEST_CONN_ID, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.send(fin).await.unwrap();
    let _keep = data_tx;

    // La VISTA DEL MANAGER (el handle del mapa) pasa a `closed` sin leer un byte más del router.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !conns
            .get(&src)
            .is_some_and(|v| v.closed.load(Ordering::Acquire))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("el manager ve `closed` MIENTRAS el moribundo drena (conn.go:162)");

    // ASSERT DECISIVO (ruteo): el manager evicta el cadáver y dialearía uno FRESCO.
    assert_eq!(
        route_decision(&mut conns, src),
        RouteAction::CreateNew,
        "un datagrama de la ventana de teardown RE-DIALEA (GetWriteQueue→nil, manager.go:83-87)"
    );
    assert!(
        !conns.contains_key(&src),
        "el cadáver se EVICTA del mapa (manager.go:85)"
    );

    // ... y el datagrama de la ventana entra en la cola de la conn NUEVA (proxy.go:381+:388).
    let d1 = b"teardown-window".to_vec();
    let mut fresh: Option<VconnSpawnParts> = None;
    create_vconn(&mut conns, src, d1.clone(), |parts| fresh = Some(parts));
    let (fresh_src, mut fresh_in_rx, _lu, _c) = fresh.expect("el vconn fresco se creó");
    assert_eq!(fresh_src, src);
    assert_eq!(
        fresh_in_rx.try_recv().unwrap(),
        d1,
        "el datagrama de la ventana viaja por la conn FRESCA, no muere en la cola del cadáver"
    );

    // CONTROL POSITIVO: el cadáver COMPLETA su drenado (no se "arregló" abortándolo): el datagrama de
    // 8 KiB sale ENTERO, un único StateClosed, cero FIN, y el driver converge.
    let (body, datas, closeds, saw_fin) = read_ziti_frames_until_close(&first, router).await;
    assert_eq!(body, inflight, "el moribundo drenó su frame ENTERO");
    assert_eq!(datas, 1);
    assert_eq!(closeds, 1, "un único StateClosed del vconn moribundo");
    assert!(!saw_fin, "halfClose=false: nunca sale un FIN");

    tokio::time::timeout(Duration::from_secs(5), driver)
        .await
        .expect("el vconn moribundo converge (join! no cuelga)")
        .unwrap();
}
