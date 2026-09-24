// F6 tramo 3a troceo: tests movidos verbatim del monolito de `intercept/udp` (mod tests).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt; // `read_exact`/`chain` del rendezvous determinista
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel::intercept::stack::UdpReplySender;

use super::flow::{RouteAction, route_decision};
use super::pump::drive_vconn;
use super::testsupport::*;
use super::{FlowKey, VCONN_QUEUE_DEPTH, Vconn};

/// **T-11.3 (CONTROL POSITIVO del drenado):** EOF de ziti con datagramas ENCOLADOS ⇒ se **FLUSHEAN**
/// a ziti antes del `StateClosed`, un frame `Data` por datagrama ENTERO (espejo del drenado
/// post-`closeNotify` de `udpConn.WriteTo`, `conn.go:71-97`).
///
/// **Este test se INVIRTIÓ en la rebanada DV-11:** antes se llamaba `ziti_eof_discards_queued_datagrams`
/// y pineaba el descarte (*under-permit*, la divergencia). **Mutación → ROJO:** devolver el brazo
/// `done` de [`pump_udp_to_ziti`] a un `return` pelado ⇒ `datas == 0`.
#[tokio::test]
async fn ziti_eof_drains_queued_datagrams() {
    let (zr, zw, _state, data_tx, mut router) = kill_fake_conn(64 * 1024);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // EOF PRIMERO: el lector retorna antes de que el escritor saque nada de la cola ⇒ los dos
    // datagramas SOLO pueden salir por el DRENADO del brazo `done` (`biased`: el lector va primero).
    data_tx.send(fin_frame(KILL_CONN_ID)).await.unwrap();
    in_tx.try_send(vec![0xAA; 8]).unwrap();
    in_tx.try_send(vec![0xAB; 8]).unwrap();

    let kill = Arc::new(CancellationToken::new());
    let flow = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 9999));
    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        reply,
        flow,
        in_rx,
        last_use,
        Arc::clone(&closed),
        kill,
    ));

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn converge")
        .unwrap();
    let (bodies, datas, closeds, saw_fin) = drain_router_strict(&mut router).await;
    assert_eq!(
        datas, 2,
        "los DOS encolados se drenan a ziti (conn.go:71-97)"
    );
    assert_eq!(
        bodies,
        vec![vec![0xAA; 8], vec![0xAB; 8]],
        "salen ENTEROS y EN ORDEN (un Data por datagrama, sin trocear)"
    );
    assert_eq!(closeds, 1, "un único StateClosed (full-close)");
    assert!(!saw_fin, "halfClose=false: jamás sale un FIN");
    assert!(closed.load(Ordering::Acquire));
    drop(in_tx);
}

/// **T-11.1 (el ORDEN — lo que sostiene toda la corrección):** `closed` se pone **al ABRIR** la
/// ventana de derribo (`conn.go:162`, ANTES del `close(closeNotify)` de `:163` que dispara el
/// drenado), no al cerrarla ⇒ ningún observador puede ver el drenado en marcha con `closed == false`.
///
/// **Rendezvous DETERMINISTA (sin relojes ni sleeps):** el canal falso de 64 B APARCA el `write_all`
/// del datagrama de 8 KiB ⇒ la ventana queda ABIERTA mientras el test no lea del router.
/// **Mutación → ROJO:** devolver el `closed.store` a DESPUÉS del `tokio::join!` ⇒ el escritor sigue
/// aparcado (el test no lee), el `join!` no retorna, `closed` nunca se pone y el `timeout` expira.
#[tokio::test]
async fn drive_vconn_marks_closed_before_the_drain_completes() {
    let (zr, zw, _state, data_tx, mut router) = kill_fake_conn(64);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    let inflight = vec![0xCDu8; 8 * 1024];
    in_tx.try_send(inflight.clone()).unwrap();
    in_tx.try_send(vec![0xAA; 8]).unwrap(); // DETRÁS del que se aparca: solo sale por el DRENADO

    let kill = Arc::new(CancellationToken::new());
    let flow = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 9999));
    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        reply,
        flow,
        in_rx,
        last_use,
        Arc::clone(&closed),
        kill,
    ));

    // Rendezvous: que 1 byte sea legible SOLO puede significar que el escritor está DENTRO de
    // `zw.write`, con el frame a medias y el canal de 64 B lleno. Con `timeout`: una regresión da
    // ROJO, no un cuelgue (`cargo test` no acota el tiempo por test).
    let mut first = [0u8; 1];
    tokio::time::timeout(KILL_TIMEOUT, router.read_exact(&mut first))
        .await
        .expect("el pump escribe sin colgarse")
        .expect("el pump escribió al menos 1 byte ⇒ está dentro de zw.write");

    // EOF de ziti ⇒ se ABRE la ventana de derribo, con el escritor AÚN aparcado.
    data_tx.send(fin_frame(KILL_CONN_ID)).await.unwrap();

    // ASSERT DECISIVO: `closed` se pone SIN que el test lea un byte más del router, o sea con el
    // drenado (y el `join!`) todavía SIN completar. Es la vista que tendría el manager al enrutar.
    tokio::time::timeout(Duration::from_secs(2), async {
        while !closed.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed se marca al ABRIR la ventana de derribo, no al cerrarla (conn.go:162)");

    // CONTROL POSITIVO (anti-no-op): marcar `closed` no se logra saltándose el drenado ni troceando
    // el frame en vuelo — el de 8 KiB sale ENTERO y el de detrás sale por el drenado.
    let mut framed = (&first[..]).chain(router);
    let (bodies, datas, closeds, saw_fin) = drain_router_strict(&mut framed).await;
    assert_eq!(datas, 2, "el frame en vuelo + el DRENADO de la cola");
    assert_eq!(
        bodies,
        vec![inflight, vec![0xAA; 8]],
        "el frame EN VUELO sale ENTERO pese al teardown (invariante ii), y el de detrás se drena"
    );
    assert_eq!(closeds, 1, "un único StateClosed");
    assert!(!saw_fin, "halfClose=false");

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    drop(in_tx);
}

/// **T-11.2 (ACEPTACIÓN — la consecuencia de RUTEO: RE-DIAL):** mientras el vconn moribundo DRENA, un
/// datagrama nuevo del mismo flujo NO se encola en el cadáver: el manager lo ve `closed`, lo **EVICTA**
/// (espejo de `GetWriteQueue`, `manager.go:83-87`) y devuelve `CreateNew` ⇒ [`create_vconn`] **RE-DIALEA**
/// y el datagrama viaja por la conn NUEVA. `route_decision` + `create_vconn` es justo lo que compone
/// [`route_datagram`], el camino real del manager.
///
/// Mismo rendezvous determinista que T-11.1 (el `write_all` de 8 KiB APARCA en el canal de 64 B ⇒ el
/// moribundo sigue drenando durante todo el assert). **Mutación → ROJO:** (a) `closed.store` tras el
/// `join!` ⇒ el yield-loop expira; (b) neutralizar el chequeo de `closed` en `route_decision` ⇒ cae el
/// `CreateNew`.
#[tokio::test]
async fn teardown_window_datagram_creates_a_fresh_vconn_while_the_old_one_drains() {
    let (zr, zw, _state, data_tx, mut router) = kill_fake_conn(64);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // La VISTA DEL MANAGER: el handle en el mapa `conns` comparte el MISMO `closed` que el vconn.
    let flow = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 9999));
    let mut conns: HashMap<FlowKey, Vconn> = HashMap::new();
    conns.insert(
        flow,
        Vconn {
            in_tx: in_tx.clone(),
            last_use: Arc::clone(&last_use),
            closed: Arc::clone(&closed),
        },
    );
    assert_eq!(
        route_decision(&mut conns, flow),
        RouteAction::Deliver,
        "precondición: con el vconn VIVO el manager entrega"
    );

    let inflight = vec![0xCDu8; 8 * 1024];
    in_tx.try_send(inflight).unwrap();
    // ⚠ Un 2.º datagrama DETRÁS del que se aparca: sin él, el pump normal habría vaciado la cola y el
    // brazo `done` drenaría un snapshot VACÍO ⇒ el test probaría la ventana abierta pero NO el
    // «re-dial CONCURRENTE con un cadáver que DRENA», que es lo que su nombre afirma (lo cazó la
    // review adversarial). Con él, el `route_decision` de abajo corre con drenado PENDIENTE.
    in_tx.try_send(vec![0xAA; 8]).unwrap();

    let kill = Arc::new(CancellationToken::new());
    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        reply,
        flow,
        in_rx,
        last_use,
        Arc::clone(&closed),
        kill,
    ));

    // Rendezvous: el escritor está DENTRO de `zw.write` (canal de 64 B lleno) ⇒ ventana abierta.
    let mut first = [0u8; 1];
    tokio::time::timeout(KILL_TIMEOUT, router.read_exact(&mut first))
        .await
        .expect("el pump escribe sin colgarse")
        .expect("el pump escribió al menos 1 byte ⇒ está dentro de zw.write");

    // EOF de ziti ⇒ se ABRE la ventana (el moribundo sigue drenando: nadie lee del router aún).
    data_tx.send(fin_frame(KILL_CONN_ID)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !conns
            .get(&flow)
            .is_some_and(|v| v.closed.load(Ordering::Acquire))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("el manager ve `closed` MIENTRAS el moribundo drena (conn.go:162)");

    // ASSERT DECISIVO (ruteo): el manager EVICTA el cadáver y crearía una conn FRESCA ⇒ RE-DIAL.
    assert_eq!(
        route_decision(&mut conns, flow),
        RouteAction::CreateNew,
        "el datagrama de la ventana RE-DIALEA (no se encola en el cadáver)"
    );
    assert!(
        conns.is_empty(),
        "el cadáver quedó EVICTADO del mapa (manager.go:85 `delete`)"
    );

    let mut framed = (&first[..]).chain(router);
    let (_, datas, closeds, _) = drain_router_strict(&mut framed).await;
    assert_eq!(
        datas, 2,
        "el frame en vuelo + el de la cola: el cadáver DRENABA de verdad durante el re-dial"
    );
    assert_eq!(closeds, 1, "un único StateClosed");

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    drop(in_tx);
}

/// **T-11.5 (DV-11-KILL):** un `kill` (servicio retirado) que dispare **a mitad del drenado** lo
/// ABORTA — corte en seco, honrando **DV-4** dentro de la ventana. El chequeo es síncrono al tope de
/// cada iteración, así que **no compite** con `zw.write` (invariante (ii) intacto: el frame EN VUELO
/// sale entero).
///
/// Rendezvous determinista: EOF primero ⇒ el drenado arranca; su PRIMER `zw.write` (8 KiB) se APARCA
/// en el canal de 64 B; ahí se cancela el `kill`; al completarse ese write, la iteración siguiente ve
/// el kill y aborta ⇒ los dos datagramas de detrás se DESCARTAN.
/// **Mutación → ROJO:** quitar el `kill.is_cancelled()` del drenado ⇒ `datas == 3`.
#[tokio::test]
async fn kill_during_the_drain_cuts_it_short() {
    let (zr, zw, _state, data_tx, mut router) = kill_fake_conn(64);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // EOF PRIMERO ⇒ el escritor entra directo al DRENADO (no al loop normal): los 3 datagramas los
    // saca `drain_queued_to_ziti`, y el 1.º (8 KiB) lo aparca el canal de 64 B.
    data_tx.send(fin_frame(KILL_CONN_ID)).await.unwrap();
    let inflight = vec![0xCDu8; 8 * 1024];
    in_tx.try_send(inflight.clone()).unwrap();
    in_tx.try_send(vec![0xAA; 8]).unwrap();
    in_tx.try_send(vec![0xAB; 8]).unwrap();

    let kill = Arc::new(CancellationToken::new());
    let flow = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 9999));
    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        reply,
        flow,
        in_rx,
        last_use,
        Arc::clone(&closed),
        Arc::clone(&kill),
    ));

    let mut first = [0u8; 1];
    tokio::time::timeout(KILL_TIMEOUT, router.read_exact(&mut first))
        .await
        .expect("el drenado escribe sin colgarse")
        .expect("1 byte legible ⇒ el DRENADO está dentro de su primer zw.write");

    kill.cancel(); // el servicio se retira CON el drenado en vuelo

    let mut framed = (&first[..]).chain(router);
    let (bodies, datas, closeds, saw_fin) = drain_router_strict(&mut framed).await;
    assert_eq!(
        datas, 1,
        "solo el frame EN VUELO; el drenado se ABORTA (DV-11-KILL)"
    );
    assert_eq!(
        bodies,
        vec![inflight],
        "y sale ENTERO: el chequeo del kill no parte el frame (invariante ii)"
    );
    assert_eq!(closeds, 1, "un único StateClosed");
    assert!(!saw_fin, "halfClose=false");

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn converge")
        .unwrap();
    drop(in_tx);
}

/// **T-E + T-G (§7) — evicción con el LECTOR APARCADO.** El manager evicta (dropea `in_tx`) mientras
/// `pump_ziti_to_udp` sigue aparcado en `zr.read()` (la conn del mux sigue registrada, no hay EOF).
/// Dos aserciones:
///
/// 1. **Drenaje fiel (T-E):** `in_rx.recv()` devuelve `None` solo con la cola VACÍA ⇒ el escritor
///    escribe los datagramas encolados ANTES de terminar. `done` no ha disparado (el lector vive).
/// 2. **Convergencia (T-G):** al retornar el escritor dispara `done`, que **despierta al lector**;
///    el `join!` converge. Sin la rama `done` en el LECTOR, este test se CUELGA (mutación M3
///    verificada) — es el único test que cubre ese brazo.
#[tokio::test]
async fn evicted_vconn_drains_then_converges_while_reader_is_parked() {
    let (zr, zw, _state, data_tx, mut router) = kill_fake_conn(64 * 1024);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    let queued = vec![0x11u8; 4];
    in_tx.try_send(queued.clone()).unwrap();
    drop(in_tx); // EVICCIÓN: el manager suelta el handle

    let kill = Arc::new(CancellationToken::new()); // JAMÁS se cancela
    let flow = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 9999));
    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        reply,
        flow,
        in_rx,
        last_use,
        Arc::clone(&closed),
        kill,
    ));
    // El lector queda APARCADO: la conn sigue registrada en el mux, no llega ni FIN ni datos.
    let _keep = data_tx;

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el escritor despierta al lector vía `done` ⇒ el join! converge")
        .unwrap();

    let (body, datas, closeds) = drain_router(&mut router).await;
    assert_eq!(datas, 1, "la EVICCIÓN drena la cola (camino fiel)");
    assert_eq!(body, queued);
    assert_eq!(closeds, 1, "un único StateClosed");
    assert!(closed.load(Ordering::Acquire));
}

/// **IC-SC (DV-11-SC):** gemelo intercept de `drive_vconn_state_closed_aborts_the_drain` de T3. Un
/// `StateClosed` ENTRANTE (conn muerta, NO un half-close por FIN) hace que el brazo `done` ABORTE el
/// drenado: el lector observa el `StateClosed`, pone la bandera compartida `sent_fin`, y el primer
/// `zw.write` del drenado FALLA (`WriteAfterClose`) sin emitir ⇒ **0 frames `Data`**, solo el
/// `StateClosed` de cierre del relay. `kill` se crea pero **JAMÁS** se cancela (aísla de DV-11-KILL:
/// el corte lo produce el discriminante, no el kill). **Mutación → ROJO:** revertir el check de
/// `write()` (§3.1.4) ⇒ el drenado flushea los 2 ⇒ `datas == 2`.
#[tokio::test]
async fn state_closed_aborts_the_drain() {
    let (zr, zw, _state, data_tx, mut router) = kill_fake_conn(64 * 1024);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // StateClosed PRIMERO: el lector retorna y pone `sent_fin` antes de que el escritor drene nada
    // (`biased`: el lector va primero). Los dos encolados SOLO podrían salir por el drenado.
    data_tx
        .send(state_closed_frame(KILL_CONN_ID))
        .await
        .unwrap();
    in_tx.try_send(vec![0xAA; 8]).unwrap();
    in_tx.try_send(vec![0xAB; 8]).unwrap();

    let kill = Arc::new(CancellationToken::new()); // JAMÁS se cancela (aísla de DV-11-KILL)
    let flow = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 9999));
    let driver = tokio::spawn(drive_vconn(
        zr,
        zw,
        reply,
        flow,
        in_rx,
        last_use,
        Arc::clone(&closed),
        kill,
    ));

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn converge")
        .unwrap();
    let (bodies, datas, closeds, saw_fin) = drain_router_strict(&mut router).await;
    assert_eq!(
        datas, 0,
        "el drenado ABORTA tras el StateClosed: 0 frames Data (write falla al tope)"
    );
    assert!(bodies.is_empty(), "ningún payload drenado");
    assert_eq!(closeds, 1, "un único StateClosed (full-close)");
    assert!(!saw_fin, "halfClose=false: jamás sale un FIN");
    assert!(closed.load(Ordering::Acquire));
    drop(in_tx);
}
