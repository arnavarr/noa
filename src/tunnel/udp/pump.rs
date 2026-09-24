//! **El núcleo DV-11** del manager proxy-UDP (T3): los dos pumps de un vconn ya dialeado, el drenado
//! post-`closeNotify`, la apertura de la ventana de derribo y el `join!` que los conduce.
//! (F6 tramo 3b: movido verbatim del monolito de `tunnel/udp`.)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use crate::edge::data::{EdgeReadHalf, EdgeWriteHalf};
use crate::tunnel::proxy::PROXY_BUF;

use super::flow::bump;

/// Split a ziti→udp read chunk into UDP-datagram-sized pieces of at most `max` bytes (production
/// passes [`PROXY_BUF`] = the oracle's `copyBuf = 0x4000-17`). A chunk ≤ `max` yields one piece; a
/// larger one is split (datagram boundaries are NOT preserved above `max`, faithful to the oracle's
/// generic `io.CopyBuffer`). `max` is a parameter (not the const) so the data-plane split is testable
/// over a real loopback socket with a small `max` — loopback UDP `send_to` is capped below `PROXY_BUF`
/// on some platforms (macOS `net.inet.udp.maxdgram` = 9216), so a real-socket test cannot observe a
/// 16367-byte datagram; a pure test pins the `PROXY_BUF`-specific split.
pub(super) fn udp_pieces(chunk: &[u8], max: usize) -> impl Iterator<Item = &[u8]> {
    chunk.chunks(max)
}

/// udp→ziti: forward each queued datagram as ONE ziti `Data` frame (whole datagram, ≤65507 — the
/// oracle's `udpConn.WriteTo` path, no copyBuf chunking). Ends on EVICTION (`in_rx` closes — `recv()`
/// yields `None` only once the queue is EMPTY, so it drains all buffered datagrams first), on ziti-EOF
/// (`done` fires — the brazo `done` then DRAINS a SNAPSHOT of the queue via [`drain_queued_to_ziti`],
/// mirroring `WriteTo`'s post-`closeNotify` drain, conn.go:71-97), or on a ziti write error.
/// **INVARIANTE (ii)** (gemelo del de `intercept::udp` y `intercept::splice_kill`): `zw.write` vive
/// FUERA del `select!` y por tanto **jamás** se cancela — un frame empezado se escribe ENTERO. Un frame
/// truncado en el canal COMPARTIDO (pooleado, multiplexado por conn-id) desincronizaría el parseo de
/// TODOS los flujos, de todos los servicios, que lo comparten.
///
/// `done` = señal LOCAL de convergencia: la dispara el pump gemelo al retornar (ver [`drive_vconn`]).
/// Es un `watch` y no un `CancellationToken` porque `tokio-util` está gateado tras la feature
/// `intercept` y este módulo vive en el build DEFAULT; ambos son nivel-disparados.
///
/// `in_rx` cerrado ⇒ el manager evictó el vconn; `recv()` devuelve `None` solo con la cola VACÍA, así
/// que la evicción **drena** primero (camino fiel), porque `done` no ha disparado (el lector sigue vivo).
pub(super) async fn pump_udp_to_ziti(
    in_rx: &mut mpsc::Receiver<Vec<u8>>,
    zw: &mut EdgeWriteHalf,
    last_use: &Mutex<Instant>,
    done: &mut watch::Receiver<bool>,
) {
    loop {
        let datagram = tokio::select! {
            biased;
            // El gemelo terminó (EOF de ziti / error de lectura ziti / error de send_to): el
            // `closeNotify` del oráculo. Espejo de la parte de `WriteTo` que drena `readC` tras
            // `closeNotify` (conn.go:76-97): vaciar el SNAPSHOT de la cola a la conn ziti ANTES del
            // StateClosed, bump por datagrama, abortar ante error de escritura. El drenado va FUERA de
            // todo `select!` (dentro de este brazo, ya elegido) ⇒ invariante (ii) intacto.
            _ = done.changed() => {
                drain_queued_to_ziti(in_rx, zw, last_use).await;
                return;
            }
            d = in_rx.recv() => match d {
                Some(d) => d,
                None => return, // evicción: `recv()` da `None` solo con la cola VACÍA ⇒ ya drenada (fiel)
            },
        };
        bump(last_use); // oracle markUsed in WriteTo (per datagram drained to ziti)
        // INVARIANTE (ii): la escritura al canal COMPARTIDO no compite con nada.
        if zw.write(&datagram).await.is_err() {
            return;
        }
    }
}

/// Vacía el SNAPSHOT actual de `in_rx` a la conn ziti: espejo del drenado post-`closeNotify` de
/// `udpConn.WriteTo` (`conn.go:76-97`). Un frame `Data` por datagrama ENTERO (no trocea, como
/// `WriteTo` que ignora `copyBuf`, DV-3). Bump por datagrama (`markUsed`, `conn.go:93`). Aborta ante
/// el primer error de escritura (`conn.go:95-96`, DV-2).
///
/// # Por qué el SNAPSHOT (`in_rx.len()` fijo) ES la cola ENTERA — DV-1 CERRADA
/// El drenado solo corre tras el brazo `done`, y `done` lo dispara [`mark_closed`], que pone `closed`
/// **ANTES** de señalarlo (espejo de `conn.go:162-163`). Con `closed == true`, el manager (single-threaded)
/// **ya no puede entregar** a esta conn: la ve cerrada, la evicta (`GetWriteQueue`→nil,
/// `manager.go:83-87`) y rutea el datagrama a una conn FRESCA (`CreateWriteQueue` → `DialAndRun`,
/// `manager.go:91-116`). ⇒ **Nada nuevo entra en la cola moribunda** después de abrirse la ventana ⇒
/// el conteo fijo capturado aquí ES la cola completa, exactamente el conjunto que el oráculo vacía de
/// `readC` (su bucle "drenar hasta vaciar", `conn.go:73-98`). Equivalencia observable, con terminación
/// GARANTIZADA por el conteo fijo (un bucle hasta-vacío no aportaría diferencia observable).
///
/// Antes de la rebanada teardown-window, `closed` se ponía DESPUÉS del `join!` y el manager seguía
/// entregando durante el drenado: esos datagramas caían fuera del snapshot y se perdían (*under-permit*,
/// DV-1) en vez de re-dialear. Ese hueco ya no existe.
///
/// ⚠ **Un invariante ANTERIOR era FALSO — no lo resucites al revertir.** Se afirmaba que entre el
/// `done` del gemelo y este `in_rx.len()` «no hay punto de yield» porque `z2u` y `u2z` son dos ramas del
/// MISMO `tokio::join!` en la MISMA task. **No se sigue:** un `join!` cede la task en cuanto una rama
/// devuelve `Pending`, y `u2z` puede estar aparcado DENTRO de `zw.write` (fuera del `select!`), muy lejos
/// del `in_rx.len()`; en esa ventana el manager corre y puede intentar la entrega. Los tests
/// `drive_vconn_marks_closed_before_the_drain_completes` y
/// `teardown_window_datagram_creates_a_fresh_vconn_while_the_old_one_drains` construyen exactamente ese
/// estado (write de 8 KiB contra un duplex de 64 B) y ejecutan código del manager dentro de la ventana.
/// La corrección la sostiene el ORDEN nuevo (`closed` ANTES del drenado ⇒ el manager no puede entregar
/// al cadáver, lo evicta y re-dialea), **no** una supuesta ausencia de yields.
pub(super) async fn drain_queued_to_ziti(
    in_rx: &mut mpsc::Receiver<Vec<u8>>,
    zw: &mut EdgeWriteHalf,
    last_use: &Mutex<Instant>,
) {
    // Conteo fijo ⇒ terminación GARANTIZADA. Y con `closed` ya puesto (mark_closed) el manager no puede
    // encolar nada más aquí ⇒ el snapshot ES la cola entera (DV-1 CERRADA; no hay nada que "ignorar").
    let snapshot = in_rx.len();
    for _ in 0..snapshot {
        let Ok(datagram) = in_rx.try_recv() else {
            return; // Empty/Disconnected ⇒ fin del snapshot
        };
        bump(last_use); // oracle markUsed en WriteTo (conn.go:93)
        // INVARIANTE (ii): escritura al canal COMPARTIDO, straight-line, jamás cancelada.
        if zw.write(&datagram).await.is_err() {
            return; // aborta el drenado (espejo conn.go:95-96, DV-2)
        }
    }
}

/// ziti→udp: forward ziti read chunks back to `src` as UDP datagrams, splitting each chunk at `split`
/// (production passes [`PROXY_BUF`] = 16367) — faithful to the oracle's generic
/// `io.CopyBuffer(udpConn, edgeConn)` with `copyBuf = 0x4000-17` (`edgeConn` is not an `io.WriterTo`
/// and `udpConn` is not an `io.ReaderFrom`, so the copy falls to the generic loop and a >16367 chunk
/// is split into multiple datagrams). `split` is a parameter so a test can drive the data-plane loop
/// with a small value over a real socket. Returns on ziti EOF, a ziti read error, or a socket send
/// error.
///
/// Observa `done` (`biased`, antes de los awaits) para que el `join!` de [`drive_vconn`] converja
/// cuando el gemelo termina primero (evicción). `zr.read()` y `socket.send_to()` son drop-safe y no
/// tocan el canal compartido.
pub(super) async fn pump_ziti_to_udp(
    zr: &mut EdgeReadHalf,
    socket: &UdpSocket,
    src: SocketAddr,
    last_use: &Mutex<Instant>,
    split: usize,
    done: &mut watch::Receiver<bool>,
) {
    loop {
        let chunk = tokio::select! {
            biased;
            _ = done.changed() => return, // el gemelo terminó (evicción)
            r = zr.read() => match r {
                Ok(Some(chunk)) => chunk,
                Ok(None) => return, // ziti EOF
                Err(e) => {
                    tracing::warn!(error = %e, %src, "ziti->udp: read failed");
                    return;
                }
            },
        };
        bump(last_use); // oracle markUsed in Write (per chunk written to udp)
        for piece in udp_pieces(&chunk, split) {
            tokio::select! {
                biased;
                _ = done.changed() => return,
                r = socket.send_to(piece, src) => if r.is_err() {
                    return;
                },
            }
        }
    }
}

/// ABRE la ventana de derribo del vconn: marca `closed` y, ACTO SEGUIDO, señala la convergencia al pump
/// gemelo. **El ORDEN interno es normativo** y reproduce el del `Close()` del oráculo
/// (`conn.go:161-163`), que hace el `CompareAndSwap(false, true)` de `closed` (`:162`) **ANTES** del
/// `close(closeNotify)` (`:163`) que desbloquea el drenado de `WriteTo`. Ningún observador puede ver el
/// drenado en marcha con `closed == false`.
///
/// Consecuencia observable (la razón de ser del orden): el manager, al enrutar un datagrama que llega
/// DURANTE el drenado, ve la entrada `closed`, la **evicta** (`GetWriteQueue` → nil, `manager.go:83-87`)
/// y **crea una conn FRESCA** (`CreateWriteQueue` → `go DialAndRun`, `manager.go:91-116`; llamante
/// `proxy.go:375-388`) ⇒ el datagrama de la ventana **RE-DIALEA** en vez de morir en la cola del
/// moribundo (fuera de su snapshot). Con la marca DESPUÉS del drenado esos datagramas se perdían en
/// silencio (*under-permit*, acotado a la ventana).
///
/// # ⚠ Espejo del oráculo SOLO en el brazo ziti→udp — **DV-TW** (ver el doc del módulo)
/// [`drive_vconn`] lo llama desde **AMBOS** brazos; el oráculo pone `closed` **solo** desde el brazo
/// ziti→cliente. En `tunnel.go:98-100` `Run` lanza `myCopy(clientConn, zitiConn, …)` (ziti→udp:
/// `dst == udpConn`) y `myCopy(zitiConn, clientConn, …)` (udp→ziti: `dst == zitiConn`), y el `defer` de
/// `myCopy` cierra **su `dst`** (`tunnel.go:126-135`, rama `else` con `halfClose == false`). ⇒ solo la
/// goroutine ziti→udp llama a `udpConn.Close()` (= nuestro `closed`); la udp→ziti cierra la conn ZITI, y
/// el `udpConn` solo se cierra después, por cascada / el `defer` de `Run` (`tunnel.go:102-105`). Por
/// tanto, en el camino «error de escritura a ziti» nosotros marcamos `closed` ANTES que el oráculo (él
/// espera a que el lector observe la conn ziti cerrada). Cota: esa antelación; dirección: estrictamente
/// **MENOS pérdida** (re-dial más pronto), **jamás over-permit** (toda conn nueva pasa por
/// `POST /sessions` + `Connect`).
///
/// Idempotente: un `store(true, Release)` repetido es inocuo (igual que el CAS del oráculo, que solo el
/// primero gana).
pub(super) fn mark_closed(closed: &AtomicBool, done_tx: &watch::Sender<bool>) {
    closed.store(true, Ordering::Release); // conn.go:162 — PRIMERO la bandera...
    let _ = done_tx.send(true); // conn.go:163 — ...y LUEGO el `closeNotify` que dispara el drenado
}

/// Pump both directions of an already-dialed vconn until either ends, then full-close the ziti side.
/// The TESTABLE core (no channel ownership — see `run_vconn`, which owns the channel like T1's
/// `handle_conn`). Disjoint borrows: udp→ziti uses `in_rx`+`zw`, ziti→udp uses `zr`+`socket`.
///
/// halfClose=false (the oracle's UDP `myCopy`): on teardown there is NO FIN — only the single
/// full-close `zw.close()` (StateClosed + deregister). This is the discriminator vs the TCP
/// [`crate::tunnel::splice`], which half-closes (FIN) each direction. `closed` lo pone [`mark_closed`]
/// al **ABRIR** la ventana de derribo — en el brazo que termina primero, ANTES del drenado y del
/// `zw.close()` (espejo de `conn.go:161-163`) —, de modo que el manager (single-threaded) evicta el
/// cadáver y RE-DIALEA los datagramas que lleguen mientras el moribundo drena, en vez de encolárselos.
/// ⚠ Que lo llamen los DOS brazos es **DV-TW** (el oráculo solo cierra el `udpConn` desde el brazo
/// ziti→udp, `tunnel.go:98-100`+`:126-135`): ver [`mark_closed`] y la desviación 4 del doc del módulo.
///
/// # `join!` + `done`: NINGÚN pump se dropea a mitad de una escritura
/// Las direcciones corren bajo un **`join!`**, no un `select!`. Un `select!` dropea el future perdedor
/// **donde esté**: si el perdedor era el ESCRITOR y estaba dentro de `zw.write`, quedaba un **frame
/// PARCIAL en el canal COMPARTIDO** (`write_message` = `write_all`+`flush`, no cancel-safe, bajo el
/// mutex del canal) y el peer desincronizaba el parseo de **todos los conn-id** del canal pooleado —
/// flujos de OTROS servicios incluidos. Ningún oráculo puede emitir un frame parcial (el C entrega el
/// buffer entero a `ziti_write` con callback de completion, `ziti_tunnel_cbs.c:422-434`; la goroutine
/// de `edgeConn.Write` no es cancelable), así que esto era una divergencia introducida por Rust.
///
/// `join!` a secas colgaría (udp→ziti no termina por sí solo), de ahí el `done`: cada pump lo dispara
/// al retornar y el otro lo observa en el tope de su loop, en ramas `biased` cancel-safe.
///
/// `biased;` con el LECTOR primero: por defecto `join!` ROTA qué future poléa antes, lo que convertía
/// «¿se escriben los datagramas encolados cuando llega el EOF de ziti?» en una MONEDA AL AIRE (el
/// `select!` anterior tenía la misma lotería). Con el lector primero, un EOF ya encolado se observa
/// ANTES de que el escritor saque nada de la cola ⇒ la 1ª acción del escritor es el brazo `done`, que
/// **FLUSHea** el snapshot de la cola de forma DETERMINISTA (la desviación #3 del doc del módulo, ahora
/// CERRADA — espejo del drenado de `WriteTo` tras `closeNotify`, conn.go:71-97). Esto NO dropea al
/// escritor: si está dentro de `zw.write`, el `join!` espera a que el frame salga ENTERO.
pub(super) async fn drive_vconn(
    mut zr: EdgeReadHalf,
    mut zw: EdgeWriteHalf,
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    last_use: Arc<Mutex<Instant>>,
    closed: Arc<AtomicBool>,
) {
    let (done_tx, done_rx) = watch::channel(false);
    let (mut done_r, mut done_w) = (done_rx.clone(), done_rx);
    let z2u = async {
        pump_ziti_to_udp(&mut zr, &socket, src, &last_use, PROXY_BUF, &mut done_r).await;
        mark_closed(&closed, &done_tx); // ABRE la ventana (conn.go:162-163) — espejo del dst.Close() del oráculo
    };
    let u2z = async {
        pump_udp_to_ziti(&mut in_rx, &mut zw, &last_use, &mut done_w).await;
        mark_closed(&closed, &done_tx); // idempotente; y DV-TW: el oráculo NO cierra el udpConn desde aquí
    };
    tokio::join!(biased; z2u, u2z);
    // halfClose=false: full-close the ziti conn (StateClosed + deregister). No FIN frame.
    let _ = zw.close().await;
}
