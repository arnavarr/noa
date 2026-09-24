// F6 tramo 3a troceo: tests movidos verbatim del monolito de `intercept/udp` (mod tests).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::AsyncReadExt; // `read_exact`/`chain` del rendezvous determinista del test 8b
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel::intercept::stack::UdpReplySender;

use super::VCONN_QUEUE_DEPTH;
use super::pump::drive_vconn;
use super::testsupport::*;

/// **Test 8 (§7):** matar un vconn con datagramas ENCOLADOS sin drenar ⇒ full-close inmediato
/// (`closed == true`, un único StateClosed) y los datagramas encolados se **DESCARTAN**: el router
/// falso no ve NINGÚN `CT_DATA` (DV-4, espejo del cierre inmediato del `zclose` del C, que tampoco
/// drena nada de un servicio retirado). El kill se dispara ANTES de arrancar `drive_vconn`, así que
/// pinea además el token nivel-disparado + `biased` en el pump (GWT-8 en su forma UDP).
#[tokio::test]
async fn killed_vconn_full_closes_sets_closed_and_drops_undrained() {
    let (zr, zw, state, _data_tx, mut router) = kill_fake_conn(64 * 1024);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    // Tres datagramas esperando en la cola, sin drenar.
    for i in 0..3u8 {
        in_tx.try_send(vec![i; 8]).expect("cola fresca cap-16");
    }

    let kill = Arc::new(CancellationToken::new());
    kill.cancel(); // ← el servicio se retiró antes de que el pump arrancase

    let flow = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 9999));
    tokio::time::timeout(
        KILL_TIMEOUT,
        drive_vconn(
            zr,
            zw,
            reply,
            flow,
            in_rx,
            last_use,
            Arc::clone(&closed),
            kill,
        ),
    )
    .await
    .expect("el vconn matado cierra de inmediato, no cuelga");

    assert!(closed.load(Ordering::Acquire), "closed queda seteado");
    let (body, datas, closeds) = drain_router(&mut router).await;
    assert_eq!(datas, 0, "los 3 datagramas encolados se DESCARTAN (DV-4)");
    assert!(body.is_empty());
    assert_eq!(closeds, 1, "un único StateClosed (full-close, sin FIN)");
    assert_eq!(state.conn_count(), 0, "deregistrado del mux una sola vez");
}

/// **Test 8b (§7) — el invariante (ii) en el path UDP:** con `pump_udp_to_ziti` APARCADO a mitad de
/// un `zw.write` (canal falso de 64 bytes ⇒ el `write_all` del frame se bloquea), disparar el kill
/// NO parte el frame: el lado router parsea frames ENTEROS hasta un único StateClosed y el payload
/// del datagrama en vuelo llega íntegro. Los datagramas que quedaban DETRÁS sí se descartan.
///
/// **MUTACIÓN-RED (verificada):** poner `kill.cancelled()` a competir con `zw.write(...)` en el
/// `select!` de `pump_udp_to_ziti` ⇒ `write_all` se dropea a medias ⇒ frame parcial ⇒ `read_message`
/// se cuelga (timeout). Ése es el fallo que corromperia el framing de TODOS los flujos del canal
/// pooleado — la razón por la que el diseño rechazó los `AbortHandle`.
///
/// Cubre además el hueco que el test 8 (cancel PRE-arranque) no ejerce: el kill MID-RELAY.
#[tokio::test]
async fn killed_vconn_mid_relay_never_tears_a_frame() {
    // Canal DIMINUTO: el datagrama de 8 KiB no cabe → el `write_all` se aparca a medias.
    let (zr, zw, _state, _data_tx, mut router) = kill_fake_conn(64);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    let inflight = vec![0xCDu8; 8 * 1024];
    in_tx.try_send(inflight.clone()).unwrap(); // éste entra a `zw.write` y se aparca
    in_tx.try_send(vec![0xEE; 16]).unwrap(); // éste queda DETRÁS → debe descartarse

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

    // RENDEZVOUS DETERMINISTA (no un `sleep`): leer UN byte del lado router solo puede tener éxito
    // cuando `pump_udp_to_ziti` ya está DENTRO de `zw.write`, con el frame a medias y el canal de
    // 64 bytes lleno. Un `sleep` fijo era una carrera: bajo carga la task podía no haberse poleado
    // aún, el kill ganaba el primer poll del `biased select!` y el datagrama no se escribía nunca —
    // el test fallaba por scheduling, no por el invariante. El byte leído se re-encadena delante
    // del stream para no desincronizar el parseo.
    let mut first = [0u8; 1];
    router
        .read_exact(&mut first)
        .await
        .expect("el pump escribió al menos 1 byte ⇒ está dentro de zw.write");
    kill.cancel();
    let mut framed = (&first[..]).chain(router);

    let (body, datas, closeds) = drain_router(&mut framed).await;
    assert_eq!(
        body, inflight,
        "el frame EN VUELO se escribió ENTERO pese al kill (invariante ii)"
    );
    assert_eq!(
        datas, 1,
        "solo el datagrama en vuelo; el de detrás se descarta (DV-4)"
    );
    assert_eq!(closeds, 1, "un único StateClosed");

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn matado termina")
        .unwrap();
    assert!(closed.load(Ordering::Acquire));
}

/// **T-A (§7) — el hazard de `drive_vconn`.** Con `pump_udp_to_ziti` APARCADO a mitad de un
/// `zw.write` (canal falso de 64 B ⇒ el `write_all` de 8 KiB se bloquea), el **EOF de ziti** hace
/// retornar al pump LECTOR. Con el `select!` original eso dropeaba al ESCRITOR a medias ⇒ frame
/// TRUNCADO en el canal COMPARTIDO. Con `join!` + `done` el frame en vuelo sale ENTERO.
///
/// Disparador NATURAL (EOF del peer), no un kill: es el hazard pre-existente de §9 de kill-active.
#[tokio::test]
async fn ziti_eof_mid_write_never_tears_a_frame() {
    let (zr, zw, _state, data_tx, mut router) = kill_fake_conn(64);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    let inflight = vec![0xCDu8; 8 * 1024];
    in_tx.try_send(inflight.clone()).unwrap();

    let kill = Arc::new(CancellationToken::new()); // JAMÁS se cancela: el fin es natural
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

    // Rendezvous determinista (el del test 8b): leer 1 byte solo puede tener éxito si el escritor
    // ya está DENTRO de `zw.write`, con el frame a medias y el canal de 64 B lleno.
    let mut first = [0u8; 1];
    router
        .read_exact(&mut first)
        .await
        .expect("el pump escribió al menos 1 byte ⇒ está dentro de zw.write");

    // EOF de ziti ⇒ `pump_ziti_to_udp` retorna AHORA, con el escritor aparcado.
    data_tx.send(fin_frame(KILL_CONN_ID)).await.unwrap();

    let mut framed = (&first[..]).chain(router);
    let (body, datas, closeds) = drain_router(&mut framed).await;
    assert_eq!(
        body, inflight,
        "el frame EN VUELO se escribió ENTERO pese al EOF de ziti (invariante ii)"
    );
    assert_eq!(datas, 1, "exactamente el datagrama en vuelo");
    assert_eq!(closeds, 1, "un único StateClosed (full-close, sin FIN)");

    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    assert!(closed.load(Ordering::Acquire));
    drop(in_tx);
}

/// **T-B (§7) — la aserción LOAD-BEARING: un frame partido corrompe a OTROS flujos.** Dos conns
/// (`A` y el vecino `B`) sobre el MISMO `ChannelState` (mismo mutex, mismo underlay). `A` se aparca
/// mid-`write`; llega su EOF de ziti; `B` escribe su propio datagrama. El router debe recuperar
/// **los tres frames enteros y bien enmarcados** (el de `A`, su StateClosed y el de `B`).
///
/// Con el `select!` original, `A` deja medio frame y el parseo se desincroniza: el frame de `B`
/// —de otro servicio— se lee como basura o `read_message` se cuelga. Éste es el radio de daño real
/// de la rebanada. El orden entre el StateClosed de `A` y el Data de `B` NO es determinista (ambos
/// compiten por el mutex al soltarlo `A`), así que se asserta sobre el CONJUNTO.
#[tokio::test]
async fn torn_frame_does_not_corrupt_sibling_flow() {
    use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED};

    let (zr, zw, state, data_tx, mut router) = kill_fake_conn(64);
    let mut sibling = sibling_write_half(&state);
    let (reply_tx, _reply_rx) = mpsc::channel(16);
    let reply = UdpReplySender::new_for_test(reply_tx);
    let (in_tx, in_rx) = mpsc::channel(VCONN_QUEUE_DEPTH);
    let last_use = Arc::new(Mutex::new(Instant::now()));
    let closed = Arc::new(AtomicBool::new(false));

    let inflight = vec![0xCDu8; 8 * 1024];
    in_tx.try_send(inflight.clone()).unwrap();

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

    let mut first = [0u8; 1];
    router
        .read_exact(&mut first)
        .await
        .expect("A está dentro de zw.write (tiene el mutex del canal)");

    // El vecino intenta escribir: se APARCA en el mutex del canal, que `A` retiene.
    let sibling_payload = vec![0xBBu8; 32];
    let payload = sibling_payload.clone();
    let sibling_task = tokio::spawn(async move { sibling.write(&payload).await });

    // EOF de ziti para `A`, con su escritor aparcado a mitad de frame.
    data_tx.send(fin_frame(KILL_CONN_ID)).await.unwrap();

    let mut framed = (&first[..]).chain(router);
    let msgs = collect_n_messages(&mut framed, 3).await;

    let datas: Vec<_> = msgs.iter().filter(|m| m.content_type == CT_DATA).collect();
    let closeds = msgs
        .iter()
        .filter(|m| m.content_type == CT_STATE_CLOSED)
        .count();
    assert_eq!(datas.len(), 2, "un Data de A y un Data del vecino B");
    assert_eq!(closeds, 1, "el único StateClosed de A");
    assert!(
        datas.iter().any(|m| m.body == inflight),
        "el frame de A llega ENTERO"
    );
    assert!(
        datas.iter().any(|m| m.body == sibling_payload),
        "el frame del VECINO B llega ENTERO y bien enmarcado (no lo corrompe el frame partido de A)"
    );

    sibling_task
        .await
        .expect("la task del vecino termina")
        .expect("la escritura del vecino tiene éxito");
    tokio::time::timeout(KILL_TIMEOUT, driver)
        .await
        .expect("el vconn converge (join! no cuelga)")
        .unwrap();
    assert!(closed.load(Ordering::Acquire));
    drop(in_tx);
}
