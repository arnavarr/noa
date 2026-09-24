//! **El núcleo DV-11** del manager UDP del intercept: los dos pumps de un vconn establecido, el
//! drenado post-`closeNotify`, la apertura de la ventana de derribo y el `join!` que las conduce.
//! (F6 tramo 3a: movido verbatim del monolito de `intercept/udp`.)

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::edge::data::{EdgeReadHalf, EdgeWriteHalf};
use crate::tunnel::intercept::stack::UdpReplySender;
use crate::tunnel::proxy::PROXY_BUF;

use super::FlowKey;
use super::flow::bump;

/// Split a ziti→udp read chunk into UDP-datagram-sized pieces of at most `max` bytes (production passes
/// [`PROXY_BUF`] = the oracle's `copyBuf = 0x4000-17`). Datagram boundaries are NOT preserved above
/// `max`, faithful to the oracle's generic `io.CopyBuffer`.
fn udp_pieces(chunk: &[u8], max: usize) -> impl Iterator<Item = &[u8]> {
    chunk.chunks(max)
}

/// udp→ziti: forward each queued datagram as ONE ziti `Data` frame (whole datagram, ≤65507 — the
/// oracle's `udpConn.WriteTo` path). Returns when `in_rx` closes (the manager evicted this vconn) —
/// draining all buffered datagrams first — or on a ziti write error. (Mirror of T3's `pump_udp_to_ziti`.)
///
/// Este pump es el ÚNICO escritor del canal COMPARTIDO en un vconn. **INVARIANTE (ii)** (el mismo de
/// [`crate::tunnel::intercept::splice_kill`]): `zw.write` vive FUERA del `select!` y por tanto **jamás** se cancela — un
/// frame empezado se escribe ENTERO. Ningún oráculo puede emitir un frame parcial (el C entrega el
/// buffer entero a `ziti_write` con callback de completion, `ziti_tunnel_cbs.c:422-434`; la goroutine
/// de `edgeConn.Write` no es cancelable), y un frame truncado desincronizaría el parseo de TODOS los
/// conn-id del canal pooleado.
///
/// Termina por TRES caminos, todos cancel-safe y todos en el tope del loop:
/// - `kill` (kill-active) ⇒ retorna SIN drenar la cola: los encolados se DESCARTAN (**DV-4**, espejo del
///   cierre inmediato del `zclose` del C, que tampoco flushea nada de un servicio retirado). El orden
///   `biased` pone `kill` ANTES de `done` ⇒ con ambos disparados gana `kill`, de forma DETERMINISTA.
/// - `done` ⇒ el pump GEMELO ya terminó (EOF/error de ziti). **DRENA** el snapshot de la cola a ziti
///   ([`drain_queued_to_ziti`]) antes del `StateClosed`: es el drenado post-`closeNotify` de
///   `udpConn.WriteTo` (`conn.go:71-97`). **DV-11 CERRADA** (antes retornaba sin drenar ⇒ *under-permit*):
///   los gemelos vuelven a ser SIMÉTRICOS bajo el mismo oráculo (`udp_vconn`). El drenado va DENTRO del
///   brazo, fuera de todo `select!` ⇒ invariante (ii) intacto.
/// - `in_rx` cerrado ⇒ el manager evictó el vconn; `recv()` devuelve `None` solo con la cola VACÍA,
///   así que la evicción **drena** primero (camino fiel; `done` no ha disparado porque el lector vive).
///
/// El orden `biased` es load-bearing: `kill` ≺ `done` ≺ `in_rx.recv()`.
async fn pump_udp_to_ziti(
    in_rx: &mut mpsc::Receiver<Vec<u8>>,
    zw: &mut EdgeWriteHalf,
    last_use: &Mutex<Instant>,
    kill: &CancellationToken,
    done: &CancellationToken,
) {
    loop {
        let datagram = tokio::select! {
            biased;
            () = kill.cancelled() => return, // matado: NO se drena la cola (DV-4)
            // El gemelo terminó (EOF de ziti / error de lectura / error de reply / error de escritura):
            // el `closeNotify` del oráculo. Vaciar el SNAPSHOT de la cola a ziti ANTES del StateClosed.
            () = done.cancelled() => {
                drain_queued_to_ziti(in_rx, zw, last_use, kill).await;
                return;
            }
            d = in_rx.recv() => match d {
                Some(d) => d,
                None => return, // el manager evictó este vconn (removal IS the close signal)
            },
        };
        bump(last_use); // oracle markUsed in WriteTo (per datagram drained to ziti)
        // INVARIANTE (ii): la escritura al canal COMPARTIDO no compite con nada. Un kill/EOF que
        // dispare AHORA espera a que el frame salga entero; se observa arriba, en el siguiente giro.
        if zw.write(&datagram).await.is_err() {
            return;
        }
    }
}

/// Vacía el SNAPSHOT actual de la cola a la conn ziti: espejo del drenado post-`closeNotify` de
/// `udpConn.WriteTo` (`conn.go:71-97`). Un frame `Data` por datagrama ENTERO (no trocea), `bump` por
/// datagrama y aborto al primer error de escritura.
/// Gemelo del [`drain_queued_to_ziti`](crate::tunnel::udp) de T3, con el guard de `kill` que T3 no tiene.
///
/// **Fidelidad, con dos matices HONESTOS (los cazó la review adversarial; no los borres):**
/// - **`bump` ANTES del write**, no después: el oráculo hace `markUsed()` tras el `w.Write` y **aun si
///   falló** (`conn.go:91`≺`:93`≺`:95`). Efecto: `last_use` se estampa un pelín antes ⇒ el reaper podría
///   segar marginalmente antes. Cero efecto en el cable, dirección *under-permit*, y es SIMÉTRICO con el
///   pump normal y con el gemelo T3 ⇒ se deja.
/// - **DV-11-SC (CERRADA, rebanada DV-11-SC):** el «aborta al primer error» del oráculo
///   (`conn.go:95-96`) YA es alcanzable en el cuadrante `StateClosed`.
///   [`EdgeReadHalf::read`](crate::edge::data::EdgeReadHalf) ahora DISTINGUE un `StateClosed` (conn
///   ENTERA muerta) de un FIN (half-close): en el brazo `CT_STATE_CLOSED` pone la bandera compartida
///   `sent_fin` (el `sentFIN` del oráculo, `conn.go:361`), y
///   [`EdgeWriteHalf::write`](crate::edge::data::EdgeWriteHalf) la consulta al tope y devuelve
///   `WriteAfterClose` ANTES de serializar (`conn.go:216`). ⇒ tras un `StateClosed`, el PRIMER
///   `zw.write` de este drenado FALLA y aborta con **0 frames `Data`** al conn-id que el router ya tiró
///   (espejo exacto del `WriteTo` del oráculo, `conn.go:95-96`). Un FIN, en cambio, NO pone `sent_fin`
///   ⇒ el drenado por FIN sigue flusheando (half-close intacto). Simétrico en los DOS gemelos (T3 y
///   este) por construcción: comparten `EdgeWriteHalf::write`.
///
/// # Por qué el SNAPSHOT (`in_rx.len()` fijo) ES la cola ENTERA
/// El drenado solo corre tras el brazo `done`, y `done` lo dispara [`mark_closed`], que pone `closed`
/// **ANTES** de señalarlo (espejo de `conn.go:162` ≺ `:163`). Con `closed == true`, el manager
/// (single-threaded, mismo `LocalSet`) **ya no puede entregar** a este vconn: lo ve cerrado, lo EVICTA
/// ([`super::flow::route_decision`] → `CreateNew`, espejo de `GetWriteQueue`, `manager.go:83-87`) y **RE-DIALEA** una
/// conn fresca (`create_vconn`, espejo de `CreateWriteQueue`) ⇒ **nada nuevo entra en la cola
/// moribunda** ⇒ el conteo fijo capturado aquí ES la cola completa, el mismo conjunto que el oráculo
/// vacía de `readC`. Terminación GARANTIZADA por el conteo fijo.
///
/// ⚠ **NO resucites el invariante FALSO** que la review de la opción 5 borró en el gemelo: NO es cierto
/// que entre el `done` del pump gemelo y este `len()` «no haya punto de yield» (un `join!` cede en cuanto
/// una rama da `Pending`, y este pump puede estar aparcado DENTRO de `zw.write`). Lo que sostiene la
/// corrección es **el ORDEN** (`closed` antes del drenado), no la ausencia de yields.
///
/// **DV-11-KILL (desviación consciente, nombrada):** un `kill` que dispare a MITAD del drenado lo ABORTA
/// (chequeo síncrono al tope de cada iteración; sin `await` ⇒ no compite con `zw.write` ⇒ invariante (ii)
/// intacto). Honra **DV-4** («servicio retirado ⇒ corte en seco») dentro de la ventana.
/// ⚠ **Sé preciso al compararlo con el oráculo** (la review lo afinó): no basta decir «el Go no tiene
/// kill». El caso comparable **sí existe** — al retirarse un servicio, el Go hace `manager.close()` →
/// `conn.Close()` → `closeNotify` ⇒ su `WriteTo` **DRENA**. Nosotros cortamos, siguiendo el `zclose`
/// inmediato del tunneler C (DV-4, ya aceptada). Dirección: relayamos **MENOS** a un servicio para el que
/// **ya no tenemos autorización** — drenar ahí sería lo que rozaría el **over-permit**, no al revés.
///
/// ⚠ **El argumento del snapshot cuelga del SINGLE-THREAD** (todo el relay vive en un `LocalSet`). Un
/// futuro MT-split del pump establecido lo INVALIDA: el manager podría pasar el chequeo de `closed` y
/// aterrizar su `try_send` **después** del snapshot ⇒ ese datagrama se quedaría en la cola moribunda y se
/// perdería (*under-permit*). El oráculo tiene la MISMA carrera, pero no la heredes sin darte cuenta.
async fn drain_queued_to_ziti(
    in_rx: &mut mpsc::Receiver<Vec<u8>>,
    zw: &mut EdgeWriteHalf,
    last_use: &Mutex<Instant>,
    kill: &CancellationToken,
) {
    let snapshot = in_rx.len();
    for _ in 0..snapshot {
        if kill.is_cancelled() {
            return; // DV-11-KILL: el servicio se retiró a mitad del drenado ⇒ corte en seco (DV-4)
        }
        let Ok(datagram) = in_rx.try_recv() else {
            return; // Empty/Disconnected ⇒ fin del snapshot
        };
        bump(last_use); // oracle markUsed en WriteTo (conn.go:93)
        // INVARIANTE (ii): escritura al canal COMPARTIDO, straight-line, jamás cancelada.
        if zw.write(&datagram).await.is_err() {
            return; // aborta el drenado (espejo conn.go:95-96)
        }
    }
}

/// ziti→udp: forward ziti read chunks back to the client via [`UdpReplySender::send_to`], splitting each
/// chunk at `split` (production [`PROXY_BUF`]) — faithful to the oracle's generic `io.CopyBuffer`. The
/// reply goes to `(dst, src)`: `send_to` swaps so the datagram appears FROM the intercepted `dst` TO the
/// client `src`. Returns on ziti EOF, a ziti read error, or a reply-channel error (stack torn down).
///
/// `send_to` applies BACKPRESSURE (await) when the SHARED reply queue (one mpsc, depth 1024) is full. The
/// LOAD-BEARING invariant: this pump runs in the per-vconn task, NOT the manager's `recv_from` loop, so a
/// stalled reply egress NEVER blocks the manager (it keeps accepting datagrams for all flows) nor the
/// udp→ziti direction — the inherited M3-UDP-stack deferral ("do not deadlock the recv loop behind a
/// stalled reply egress") is satisfied by construction. The ONE consumer of the reply queue that DOES
/// run inside the manager — the embedded-DNS branch — must therefore never await it: it enqueues
/// NON-blocking ([`UdpReplySender::try_send_to`], drop-on-full), preserving this invariant. NOTE:
/// because the reply queue is SHARED across vconns, a stalled egress DOES back-pressure the ziti→udp
/// direction of OTHER vconns (they await on the same full queue) — that HOL-coupling is the named
/// scale-deferral (mirror of T3's shared socket / the §7(d) class), NOT per-vconn isolation.
/// Observa `kill` y `done` (`biased`, ambos ANTES de los awaits). Que compita con `reply.send_to()` es
/// load-bearing: un egress de reply atascado dejaría el `join!` de [`drive_vconn`] colgado. Ambos awaits
/// —`zr.read()` (un `rx.recv()` con el estado en `&mut self`) y `send_to` (un `mpsc::send`)— son
/// **drop-safe** y no tocan el canal compartido, así que cancelarlos no corrompe nada.
#[allow(clippy::too_many_arguments)] // el estado completo de la dirección ziti→udp (halves + señales)
async fn pump_ziti_to_udp(
    zr: &mut EdgeReadHalf,
    reply: &UdpReplySender,
    dst: SocketAddr,
    src: SocketAddr,
    last_use: &Mutex<Instant>,
    split: usize,
    kill: &CancellationToken,
    done: &CancellationToken,
) {
    loop {
        let chunk = tokio::select! {
            biased;
            () = kill.cancelled() => return, // corte en seco (espejo de `ziti_close`)
            () = done.cancelled() => return, // el gemelo terminó
            r = zr.read() => match r {
                Ok(Some(chunk)) => chunk,
                Ok(None) => return, // ziti EOF
                Err(e) => {
                    tracing::warn!(error = %e, %dst, %src, "intercept ziti->udp: read failed");
                    return;
                }
            },
        };
        bump(last_use); // oracle markUsed in Write (per chunk written to udp)
        for piece in udp_pieces(&chunk, split) {
            tokio::select! {
                biased;
                () = kill.cancelled() => return,
                () = done.cancelled() => return,
                r = reply.send_to(piece.to_vec(), dst, src) => if r.is_err() {
                    return; // reply queue closed → stack torn down
                },
            }
        }
    }
}

/// ABRE la ventana de derribo del vconn: la bandera `closed` y, tras ella, la señal `done`. Espejo de
/// `udpConn.Close()` del oráculo (`conn.go:162` hace el `closed.CompareAndSwap(false, true)` y **solo
/// entonces** `:163` cierra `closeNotify`, el canal que dispara el drenado de `WriteTo`).
///
/// # Qué es lo LOAD-BEARING aquí (y qué NO)
/// ⚠ **NO** afirmes que «invertir estas dos líneas reabre DV-11»: sería **FALSO** y ningún test podría
/// pinearlo. Entre ambas **no hay punto de yield** (fn síncrona; `cancel()` solo ENCOLA el waker, no
/// poléa a nadie inline) y todo esto vive en un `LocalSet` single-threaded ⇒ **ningún observador puede
/// ver el estado intermedio**. Lo escribimos en el orden del oráculo por fidelidad, no porque el orden
/// *entre las dos líneas* sea observable. (Este fichero ya avisa una vez de no resucitar invariantes
/// falsos; éste habría sido el segundo.)
///
/// Lo que SÍ sostiene la corrección, y lo que los tests pinean:
/// 1. **`done.cancel()` NO existe en ningún otro sitio** ⇒ «`done` disparado ⇒ `closed` YA es `true`» es
///    **incondicional**, no una convención.
/// 2. `mark_closed` corre **antes de cualquier `await` del drenado** ⇒ cuando el manager vuelve a correr
///    (solo puede hacerlo en un `await`), `closed` ya está puesto: lo evicta y **RE-DIALEA**
///    (`manager.go:83-87`) en vez de encolarle. La cola moribunda queda CONGELADA ⇒ el snapshot de
///    [`drain_queued_to_ziti`] ES la cola entera.
///
/// Lo que reabre DV-11 es mover el `store` **después del `join!`** (donde estaba): eso sí lo ponen ROJO
/// `drive_vconn_marks_closed_before_the_drain_completes` y el test de re-dial.
///
/// Idempotente: la llaman los DOS pumps de [`drive_vconn`] al retornar.
fn mark_closed(closed: &AtomicBool, done: &CancellationToken) {
    closed.store(true, Ordering::Release); // conn.go:162 — PRIMERO la bandera...
    done.cancel(); // conn.go:163 — ...y LUEGO el `closeNotify` que dispara el drenado
}

/// Pump both directions of an already-dialed vconn until either ends, then full-close the ziti side.
/// `halfClose=false` (the oracle's UDP `myCopy`): on teardown there is NO FIN — only the single
/// full-close `zw.close()` (StateClosed + deregister).
///
/// # La ventana de derribo — **DV-11 CERRADA** (gemelo de la opción 5 de T3)
/// `closed` se pone **al ABRIR** la ventana, no al cerrarla: lo hace [`mark_closed`] desde el pump que
/// retorne PRIMERO, **antes** de señalar `done` (espejo exacto de `Close()`: `conn.go:162` pone la
/// bandera ≺ `:163` cierra `closeNotify`, la señal que dispara el drenado de `WriteTo`). Consecuencias,
/// las dos del oráculo:
/// - el brazo `done` de [`pump_udp_to_ziti`] **DRENA** la cola a ziti antes del `StateClosed`
///   (`conn.go:71-97`) en vez de descartarla, y
/// - un datagrama que llegue **durante** la ventana ya NO se encola en el cadáver: el manager lo ve
///   `closed`, lo EVICTA y **RE-DIALEA** una conn fresca ([`super::flow::route_decision`] → `CreateNew`,
///   `manager.go:83-87`).
///
/// Antes de esta rebanada `closed` se ponía DESPUÉS del `join!` y el brazo `done` retornaba sin drenar:
/// los encolados se perdían y los de la ventana se entregaban al moribundo (*under-permit* real). Los
/// gemelos (`tunnel::udp` T3 y este) vuelven a ser SIMÉTRICOS bajo el mismo oráculo (`udp_vconn`).
/// **DV-4 intacto:** `kill` ⇒ corte en seco, sin drenar (`biased`: `kill` ≺ `done`).
///
/// **Coste NOMBRADO del drenado (la review lo hizo explícito):** el brazo `done` pasa de retornar tras
/// ≤1 write a hacer hasta 1 + [`super::VCONN_QUEUE_DEPTH`] writes, y **cada uno toma el mutex del canal
/// COMPARTIDO**. Si el peer no drena el socket, un `zw.write` se aparca indefinidamente (no hay timeout,
/// y el `kill` **no rescata** un write en vuelo: meterlo en un `select!` rompería el invariante (ii)) ⇒
/// en un outage con muchos flujos derribándose a la vez, el head-of-line sobre el canal se amplifica
/// ~17×. **No es deadlock** (el mutex se suelta y re-adquiere por frame, y el manager nunca escribe al
/// canal) y es **exactamente lo que hace el oráculo** (`WriteTo` escribe en bucle, sin timeout) y ya el
/// gemelo T3. Se acepta, pero queda DICHO.
///
/// # `join!` + `done`: NINGÚN pump se dropea a mitad de una escritura
/// Las dos direcciones corren bajo un **`join!`** (borrows disjuntos), no un `select!`. Un `select!`
/// dropea el future perdedor **donde esté**: si el perdedor era el ESCRITOR y estaba dentro de
/// `zw.write`, quedaba un **frame PARCIAL en el canal COMPARTIDO** —`write_message` es
/// `write_all`+`flush`, no cancel-safe, bajo el mutex del canal— y el parseo del peer se
/// desincronizaba para **todos los flujos de todos los servicios** que comparten el canal pooleado.
/// Ese era el hazard pre-existente de §9 de kill-active; ésta es la rebanada que lo cierra.
///
/// `join!` a secas colgaría (udp→ziti no termina por sí solo), así que la convergencia es cooperativa:
/// un `CancellationToken` **local**, `done`, que cada pump dispara AL RETORNAR y que el otro observa en
/// el tope de su loop, en ramas `biased` y cancel-safe. Las escrituras al canal quedan SIEMPRE fuera de
/// los `select!` internos. Idéntico idioma al de [`crate::tunnel::intercept::splice_kill`] (`join!` + kill por pump).
///
/// # DV-10 RETIRADO
/// DV-10 (kill-active) forzaba que **solo el escritor** observase `kill`, porque bajo `select!` un
/// lector que retornase primero dropeaba al escritor a mitad de frame. Bajo `join!` esa premisa
/// desaparece: ahora **ambos** pumps observan `kill`, lo que **estrecha** el residual de over-relay
/// —el lector corta en seco, como el `ziti_close` del C, y el `join!` solo espera a que salga entero el
/// frame EN VUELO del escritor (sub-ms salvo contención)—. Más fiel que antes, no menos.
#[allow(clippy::too_many_arguments)] // el estado completo de un vconn establecido (halves + kill)
pub(super) async fn drive_vconn(
    mut zr: EdgeReadHalf,
    mut zw: EdgeWriteHalf,
    reply: UdpReplySender,
    flow: FlowKey,
    mut in_rx: mpsc::Receiver<Vec<u8>>,
    last_use: Arc<Mutex<Instant>>,
    closed: Arc<AtomicBool>,
    kill: Arc<CancellationToken>,
) {
    let (src, dst) = flow;
    // Señal LOCAL de convergencia: la dispara el primer pump que retorne, y el otro la observa en el
    // tope de su loop. Ningún pump se dropea ⇒ ninguna escritura al canal compartido se trunca.
    let done = CancellationToken::new();
    let z2u = async {
        pump_ziti_to_udp(
            &mut zr, &reply, dst, src, &last_use, PROXY_BUF, &kill, &done,
        )
        .await;
        mark_closed(&closed, &done); // ABRE la ventana (conn.go:162-163) — espejo del dst.Close() del oráculo
    };
    let u2z = async {
        pump_udp_to_ziti(&mut in_rx, &mut zw, &last_use, &kill, &done).await;
        // Idempotente. DV-TW (heredada de T3): el oráculo solo pone `closed` desde el brazo ziti→udp (en
        // el udp→ziti su `dst` es el zitiConn), así que en el camino «error de escritura a ziti»
        // re-dialeamos ANTES que él. Menos pérdida, jamás over-permit.
        mark_closed(&closed, &done);
    };
    // `biased;` con el LECTOR primero: por defecto `join!` ROTA qué future poléa antes, lo que hacía del
    // "¿se escriben los datagramas encolados al llegar el EOF de ziti?" una MONEDA AL AIRE. Con el lector
    // primero, un EOF ya encolado se observa ANTES de que el escritor saque nada de la cola ⇒ el brazo
    // `done` corre y **DRENA** la cola de forma DETERMINISTA (igual que el gemelo T3). `join!` poléa AMBOS
    // futures en cada pasada, así que `biased` fija el orden, no la equidad. Ojo: esto NO dropea al
    // escritor — si está dentro de `zw.write`, el `join!` espera a que el frame salga ENTERO.
    tokio::join!(biased; z2u, u2z);
    // halfClose=false: full-close the ziti conn (StateClosed + deregister). No FIN frame. Es el MISMO
    // camino de cierre para el fin natural y para el kill (espejo de `ziti_close`): cero código nuevo.
    // `closed` YA está puesto (mark_closed, al abrir la ventana) — ponerlo aquí sería tarde (DV-11).
    let _ = zw.close().await;
}
