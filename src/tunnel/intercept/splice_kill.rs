//! `splice_until_killed`: el gemelo **kill-aware** de [`crate::tunnel::proxy::splice`] para los flujos
//! TCP interceptados (rebanada `kill-active`).
//!
//! ## Por qué un gemelo y no un parámetro de `splice`
//! `proxy::splice` es el camino T1, validado EN VIVO y compartido con el proxy-TCP. Duplicarlo aquí
//! —duplicación deliberada, misma clase que la maquinaria vconn de [`super::udp`] frente a la de T3—
//! lo deja **byte-intacto**. El precio (un cuerpo casi igual) se paga una vez; el riesgo de tocar un
//! camino live-validado, no.
//!
//! ## Oráculo
//! El camino natural es el `Run`/`myCopy` de `openziti/ziti` v2.0.0 `tunnel/tunnel.go:86-147`, igual
//! que `proxy::splice`. El camino de kill es el `zclose(n->io->ziti_io)` de `tunneler_kill_active`
//! (`ziti-tunnel-sdk-c` v1.15.1 `2addfbb`, `lib/ziti-tunnel/ziti_tunnel.c:445-447`), que a través de
//! `ziti_sdk_c_close` (`lib/ziti-tunnel-cbs/ziti_tunnel_cbs.c:168-176`) hace `ziti_close(conn, …)`:
//! **cierre directo de la conn ziti, SIN `CloseWrite` previo** (sin FIN). El underlay lo desmonta el
//! callback de cierre. Traducción exacta: matado ⇒ ningún `close_write()` (FIN) ni `shutdown()`; solo
//! el `close()` final (StateClosed + deregister) que ambos caminos comparten, y el drop de las mitades
//! del socket (que cierra la conn de netstack).
//!
//! ## El invariante (ii): frontera de frame (LOAD-BEARING)
//! El token de kill compite ÚNICAMENTE con awaits cuyo estado es PER-FLUJO —
//! `sock_r.read` · `zr.read` · `sock_w.write_all`— y **JAMÁS** con `zw.write` / `zw.close_write` /
//! `zw.close`, que escriben al **canal COMPARTIDO** bajo su mutex
//! (`EdgeWriteHalf::write` → `write_message` → `write_all`, `edge/data/conn.rs`). Cancelar una
//! escritura a medias soltaría el guard con un **frame PARCIAL** en un canal pooleado, corrompiendo el
//! framing de TODOS los flujos de TODOS los servicios que lo comparten. Ése es exactamente el motivo
//! por el que el diseño rechazó la alternativa `AbortHandle` (§4.1 del spec); aquí es un invariante del
//! código, no una esperanza: un frame empezado se escribe ENTERO y el kill se observa en el siguiente
//! poll del pump. Coste: a lo sumo UN frame en vuelo por dirección completa su escritura tras el kill
//! (desviación DV-5; el C también deja drenar lo ya entregado a libuv/lwIP).
//!
//! `sock_w.write_all` SÍ compite con el kill, y es load-bearing que lo haga: es estado per-flujo (el
//! socket local, que vamos a cerrar de todos modos), y sin esa rama un cliente que dejó de leer
//! (socket backpressured) colgaría el kill indefinidamente.
//!
//! El `select!` de cada pump es `biased;` con el kill PRIMERO: un token ya cancelado (kill disparado
//! con el dial en vuelo, GWT-8) gana el primer poll y el flujo muere **sin relevar ni un byte**.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::edge::data::{EdgeReadHalf, EdgeWriteHalf};
use crate::tunnel::proxy::PROXY_BUF;

/// Cómo terminó un pump: por su cuenta (EOF del origen o error duro — el oráculo `myCopy` half-cierra
/// el destino en AMBOS casos) o porque lo mató el token (⇒ sin half-close, espejo de `ziti_close`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PumpEnd {
    Natural,
    Killed,
}

/// Pin en tiempo de compilación (gemelo del de [`super::tcp`]): el future del splice kill-aware sigue
/// siendo `Send + 'static`, así que puede correr en el runtime MULTI-THREAD. `Arc<CancellationToken>`
/// es `Send + Sync`, y su future `cancelled()` también — si un cambio futuro lo rompiese, el build
/// falla AQUÍ y no en producción.
const _: fn(
    EdgeReadHalf,
    EdgeWriteHalf,
    super::stream::InterceptTcpStream,
    Arc<CancellationToken>,
) = |zr, zw, stream, kill| {
    fn require_send<T: Send + 'static>(_: T) {}
    require_send(splice_until_killed(zr, zw, stream, kill));
};

/// Como [`crate::tunnel::proxy::splice`], pero el flujo muere también si `kill` se cancela.
///
/// **Camino natural** (token nunca cancelado): idéntico a `splice` — dos pumps concurrentes bajo un
/// `join!`, half-close por dirección al terminar cada una (`zw.close_write()` = FIN, `sock_w.shutdown()`),
/// y un único `zw.close()` final.
///
/// **Camino de kill:** ambos pumps retornan `Killed`, **se saltan sus half-closes** (ni FIN ziti ni
/// shutdown del socket) y convergen en el MISMO `zw.close()` — un solo StateClosed + deregister, como
/// el `ziti_close` del oráculo. Las mitades del socket se dropean al salir (netstack cierra el
/// underlay). Un FIN ya emitido ANTES del kill por un half-close natural previo NO se retira: lo
/// escrito, escrito está (mismo comportamiento que el C).
///
/// El `Arc<CancellationToken>` se toma POR VALOR y no sale de este future: es el invariante de vida del
/// [`super::flows::FlowRegistry`] (su `Weak` debe morir cuando el flujo muere).
///
/// # Errors
/// Devuelve el primer error de copia observado (la conexión se desmonta igualmente). Un kill no es un
/// error: devuelve `Ok(())`.
pub(crate) async fn splice_until_killed<S>(
    mut zr: EdgeReadHalf,
    mut zw: EdgeWriteHalf,
    socket: S,
    kill: Arc<CancellationToken>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut sock_r, mut sock_w) = tokio::io::split(socket);

    let s2z = async {
        let (res, end) = pump_sock_to_ziti(&mut sock_r, &mut zw, &kill).await;
        if let Err(e) = &res {
            tracing::warn!(error = %e, "intercept: socket->ziti copy failed");
        }
        // Oráculo `myCopy`: half-cierra el destino (ziti) en EOF **y** en error. Matado: NO — el
        // `ziti_close` del C va directo al full-close, sin FIN.
        if end == PumpEnd::Natural {
            let _ = zw.close_write().await;
        }
        res
    };
    let z2s = async {
        let (res, end) = pump_ziti_to_sock(&mut zr, &mut sock_w, &kill).await;
        if let Err(e) = &res {
            tracing::warn!(error = %e, "intercept: ziti->socket copy failed");
        }
        if end == PumpEnd::Natural {
            let _ = sock_w.shutdown().await;
        }
        res
    };

    // Oráculo `Run`: espera a AMBAS direcciones (`for count := 2`). Además de fidelidad, el `join!`
    // (frente a un `select!`) es lo que garantiza que NINGÚN pump se dropee a mitad de una escritura
    // al canal compartido — el invariante (ii) del doc del módulo.
    let (r_s2z, r_z2s) = tokio::join!(s2z, z2s);

    // Oráculo `Run` defer: full-close de la conn ziti, UNA vez. Las mitades del socket dropean aquí.
    let _ = zw.close().await;

    r_s2z.and(r_z2s)
}

/// socket→ziti. El kill compite con `sock_r.read` (estado per-flujo, cancel-safe), **nunca** con
/// `zw.write` (canal compartido): un frame empezado se termina y el kill se observa en el siguiente
/// poll.
async fn pump_sock_to_ziti<R>(
    sock_r: &mut R,
    zw: &mut EdgeWriteHalf,
    kill: &CancellationToken,
) -> (io::Result<()>, PumpEnd)
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; PROXY_BUF];
    loop {
        let n = tokio::select! {
            biased;
            () = kill.cancelled() => return (Ok(()), PumpEnd::Killed),
            r = sock_r.read(&mut buf) => match r {
                Ok(n) => n,
                Err(e) => return (Err(e), PumpEnd::Natural),
            },
        };
        if n == 0 {
            return (Ok(()), PumpEnd::Natural); // socket EOF
        }
        // INVARIANTE (ii): fuera del `select!`. Un kill que dispare AHORA espera a que el frame salga
        // entero; se observará arriba, en el siguiente giro.
        if let Err(e) = zw.write(&buf[..n]).await {
            return (Err(io::Error::other(e)), PumpEnd::Natural);
        }
    }
}

/// ziti→socket. El kill compite con `zr.read` **y** con `sock_w.write_all`: ambos son estado per-flujo.
/// Que compita con `write_all` es load-bearing — un cliente que dejó de leer dejaría el kill colgado.
async fn pump_ziti_to_sock<W>(
    zr: &mut EdgeReadHalf,
    sock_w: &mut W,
    kill: &CancellationToken,
) -> (io::Result<()>, PumpEnd)
where
    W: AsyncWrite + Unpin,
{
    loop {
        let chunk = tokio::select! {
            biased;
            () = kill.cancelled() => return (Ok(()), PumpEnd::Killed),
            r = zr.read() => match r {
                Ok(Some(bytes)) => bytes,
                Ok(None) => return (Ok(()), PumpEnd::Natural), // ziti EOF
                Err(e) => return (Err(io::Error::other(e)), PumpEnd::Natural),
            },
        };
        tokio::select! {
            biased;
            () = kill.cancelled() => return (Ok(()), PumpEnd::Killed),
            r = sock_w.write_all(&chunk) => if let Err(e) = r {
                return (Err(e), PumpEnd::Natural);
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::time::Duration;

    use tokio::sync::mpsc;

    use crate::channel::connect::read_message;
    use crate::channel::message::Message;
    use crate::edge::data::{ChannelState, EdgeConn};
    use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, HDR_FLAGS, build_data};

    const TEST_CONN_ID: u32 = 7;
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn flags_of(msg: &Message) -> u32 {
        msg.headers
            .get(&HDR_FLAGS)
            .map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()))
    }

    fn fin_frame() -> Message {
        let mut fin = build_data(TEST_CONN_ID, b"", false);
        fin.headers
            .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
        fin
    }

    /// Conexión ziti falsa partida en halves (espejo del `fake_conn` de `proxy.rs`/`tcp.rs`), con el
    /// tamaño del buffer del canal PARAMETRIZADO: un buffer diminuto hace que `zw.write` se aparque a
    /// medias (backpressure), que es como el test 5 pone al pump MID-FRAME.
    fn fake_conn(
        chan_buf: usize,
    ) -> (
        EdgeReadHalf,
        EdgeWriteHalf,
        StdArc<ChannelState>,
        mpsc::Sender<Message>,
        tokio::io::DuplexStream,
    ) {
        let (cw, router) = tokio::io::duplex(chan_buf);
        let state = StdArc::new(ChannelState::new(Box::new(cw)));
        let (data_tx, data_rx) = mpsc::channel(64);
        state.register_conn(TEST_CONN_ID, data_tx.clone());
        let conn = EdgeConn::new_for_test(TEST_CONN_ID, data_rx, state.clone());
        let (zr, zw) = conn.into_split();
        (zr, zw, state, data_tx, router)
    }

    /// **Test 7 (§7):** el camino NATURAL de `splice_until_killed` (token jamás cancelado) es el de
    /// `proxy::splice`: round-trip de bytes, baile de FIN en ambos sentidos y UN solo StateClosed.
    /// Espejo del test `established_splice_runs_spawned_on_a_multi_thread_runtime` de `tcp.rs`, pero
    /// sobre el gemelo — si el gemelo divergiese del original, este test lo caza.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn natural_path_of_killable_splice_is_byte_identical() {
        let (zr, zw, state, data_tx, mut router) = fake_conn(64 * 1024);
        let (sock_for_splice, mut local) = tokio::io::duplex(64 * 1024);
        let kill = Arc::new(CancellationToken::new()); // NUNCA se cancela

        let echo = tokio::spawn(async move {
            let mut saw_state_closed = false;
            let mut saw_fin = false;
            loop {
                let Ok(msg) = read_message(&mut router).await else {
                    break;
                };
                match msg.content_type {
                    CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => {
                        saw_fin = true;
                        let _ = data_tx.send(fin_frame()).await; // el peer half-cierra de vuelta
                    }
                    CT_DATA => {
                        let echoed = build_data(TEST_CONN_ID, &msg.body, false);
                        if data_tx.send(echoed).await.is_err() {
                            break;
                        }
                    }
                    CT_STATE_CLOSED => {
                        saw_state_closed = true;
                        break;
                    }
                    _ => {}
                }
            }
            (saw_fin, saw_state_closed)
        });

        let splice_task = tokio::spawn(splice_until_killed(zr, zw, sock_for_splice, kill));

        local.write_all(b"hello-intercept").await.unwrap();
        let mut buf = [0u8; 15];
        local.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-intercept", "round-trip por el gemelo");

        local.shutdown().await.unwrap(); // half-close local → FIN a ziti → FIN del peer → EOF ziti
        let mut rest = Vec::new();
        local.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());

        splice_task
            .await
            .unwrap()
            .expect("el gemelo completa limpio");
        let (saw_fin, saw_state_closed) = echo.await.unwrap();
        assert!(saw_fin, "camino natural: SÍ hay FIN (close_write)");
        assert!(saw_state_closed, "…y el full-close final");
        assert_eq!(state.conn_count(), 0, "deregistrado exactamente una vez");
    }

    /// **Test 4 (§7):** matar un splice ESTABLECIDO (tras un round-trip real) hace full-close **sin
    /// FIN** — espejo del `ziti_close` directo del oráculo, que no hace `CloseWrite` — deregistra el
    /// conn del mux exactamente una vez, y el cliente local ve EOF.
    ///
    /// Los tres asserts negativos son load-bearing: NINGÚN frame con `FLAG_FIN`, EXACTAMENTE un
    /// `CT_STATE_CLOSED`, y `conn_count() == 0`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn killed_splice_full_closes_without_fin_and_deregisters() {
        let (zr, zw, state, data_tx, mut router) = fake_conn(64 * 1024);
        let (sock_for_splice, mut local) = tokio::io::duplex(64 * 1024);
        let kill = Arc::new(CancellationToken::new());

        let (relayed_tx, mut relayed_rx) = mpsc::channel::<()>(1);
        let router_task = tokio::spawn(async move {
            let mut fins = 0usize;
            let mut state_closeds = 0usize;
            let mut datas = 0usize;
            loop {
                let Ok(msg) = read_message(&mut router).await else {
                    break;
                };
                match msg.content_type {
                    CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => fins += 1,
                    CT_DATA => {
                        datas += 1;
                        // Echo del primer Data para probar que el flujo está ESTABLECIDO y relevando.
                        let echoed = build_data(TEST_CONN_ID, &msg.body, false);
                        let _ = data_tx.send(echoed).await;
                        let _ = relayed_tx.send(()).await;
                    }
                    CT_STATE_CLOSED => {
                        state_closeds += 1;
                        break;
                    }
                    _ => {}
                }
            }
            (datas, fins, state_closeds)
        });

        let splice_task = tokio::spawn(splice_until_killed(
            zr,
            zw,
            sock_for_splice,
            Arc::clone(&kill),
        ));

        // Flujo ESTABLECIDO y relevando bytes en ambos sentidos.
        local.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        local.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        relayed_rx.recv().await.expect("el router vio el Data");

        // ── EL KILL, a mitad de un flujo vivo ──
        kill.cancel();

        tokio::time::timeout(TEST_TIMEOUT, splice_task)
            .await
            .expect("el splice matado termina (no cuelga)")
            .unwrap()
            .expect("un kill no es un error");

        // El cliente local ve el cierre del socket (las mitades dropearon).
        let mut rest = Vec::new();
        tokio::time::timeout(TEST_TIMEOUT, local.read_to_end(&mut rest))
            .await
            .expect("el extremo cliente ve EOF")
            .unwrap();

        let (datas, fins, state_closeds) = tokio::time::timeout(TEST_TIMEOUT, router_task)
            .await
            .expect("el router falso termina")
            .unwrap();
        assert_eq!(datas, 1, "solo el Data pre-kill; ninguno después");
        assert_eq!(
            fins, 0,
            "el kill va DIRECTO al full-close: ningún FLAG_FIN (espejo de ziti_close)"
        );
        assert_eq!(state_closeds, 1, "exactamente UN StateClosed");
        assert_eq!(state.conn_count(), 0, "deregistrado del mux una sola vez");
    }

    /// **Test 5 (§7) — el invariante (ii) hecho aserción:** con el pump socket→ziti APARCADO a mitad
    /// de un `zw.write` (canal falso de 64 bytes ⇒ el `write_all` del frame se bloquea), disparar el
    /// kill NO parte el frame: el lado router parsea el stream ENTERO con `read_message` —frames
    /// completos— hasta un único StateClosed, y el payload llega íntegro.
    ///
    /// **MUTACIÓN-RED (verificada):** meter `kill.cancelled()` a competir con `zw.write(...)` dentro
    /// de un `select!` en `pump_sock_to_ziti` ⇒ el `write_all` se dropea a medias ⇒ `read_message` lee
    /// un frame truncado ⇒ el payload no casa (o el parseo se desincroniza) ⇒ ROJO. Ése es el fallo que
    /// corrompería el framing de TODOS los flujos que comparten el canal pooleado.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn killed_splice_never_tears_a_frame() {
        // Canal DIMINUTO: el frame (8 KiB + cabecera) no cabe → `write_all` se aparca a medias.
        let (zr, zw, _state, _data_tx, mut router) = fake_conn(64);
        let (sock_for_splice, mut local) = tokio::io::duplex(64 * 1024);
        let kill = Arc::new(CancellationToken::new());

        let payload = vec![0xABu8; 8 * 1024];
        let expected = payload.clone();

        let splice_task = tokio::spawn(splice_until_killed(
            zr,
            zw,
            sock_for_splice,
            Arc::clone(&kill),
        ));

        // El pump lee esto y entra en `zw.write` → se aparca (nadie drena `router` todavía).
        local.write_all(&payload).await.unwrap();

        // RENDEZVOUS DETERMINISTA (no un `sleep`): leer UN byte del lado router solo puede tener
        // éxito cuando el pump ya está DENTRO de `write_all`, con el frame a medias y el canal de 64
        // bytes lleno. Un `sleep` fijo era una carrera: bajo carga la task podía no haberse poleado
        // aún, el kill ganaba el primer poll del `biased select!` y el frame no se escribía nunca —
        // el test fallaba por scheduling, no por el invariante. Los bytes leídos se re-encadenan
        // delante del stream (`chain`) para no desincronizar el parseo.
        let mut first = [0u8; 1];
        router
            .read_exact(&mut first)
            .await
            .expect("el pump escribió al menos 1 byte ⇒ está dentro de write_all");
        kill.cancel();
        let mut framed = (&first[..]).chain(router);

        // Ahora drena el lado router: TODO debe parsear como frames enteros.
        let mut relayed = Vec::new();
        let mut state_closeds = 0usize;
        let mut fins = 0usize;
        loop {
            let Ok(msg) = tokio::time::timeout(TEST_TIMEOUT, read_message(&mut framed))
                .await
                .expect("read_message no cuelga: los frames están completos")
            else {
                break; // EOF del canal
            };
            match msg.content_type {
                CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => fins += 1,
                CT_DATA => relayed.extend_from_slice(&msg.body),
                CT_STATE_CLOSED => {
                    state_closeds += 1;
                    break;
                }
                _ => {}
            }
        }

        assert_eq!(
            relayed, expected,
            "el frame EN VUELO se escribió ENTERO pese al kill (invariante ii)"
        );
        assert_eq!(fins, 0, "matado ⇒ sin FIN");
        assert_eq!(state_closeds, 1, "un único StateClosed cierra el stream");

        tokio::time::timeout(TEST_TIMEOUT, splice_task)
            .await
            .expect("el splice termina")
            .unwrap()
            .expect("kill limpio");
    }

    /// **Test 6 (§7) — GWT-8 (kill mid-dial):** un token cancelado ANTES de arrancar el splice (el kill
    /// disparó con el dial en vuelo) cierra el flujo en el PRIMER poll: el router no ve ni un solo
    /// `CT_DATA`, solo el StateClosed. Pinea a la vez el `biased;` y la naturaleza NIVEL-disparada del
    /// token (un `watch` flanco-disparado relevaría bytes aquí).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_cancelled_before_establish_closes_at_first_poll() {
        let (zr, zw, state, data_tx, mut router) = fake_conn(64 * 1024);
        let (sock_for_splice, mut local) = tokio::io::duplex(64 * 1024);

        let kill = Arc::new(CancellationToken::new());
        kill.cancel(); // ← YA cancelado antes de que el splice exista

        // Datos esperando en AMBOS sentidos: si el splice relevase algo, se vería.
        local.write_all(b"nunca-debe-salir").await.unwrap();
        data_tx
            .send(build_data(TEST_CONN_ID, b"nunca-debe-entrar", false))
            .await
            .unwrap();

        tokio::time::timeout(
            TEST_TIMEOUT,
            splice_until_killed(zr, zw, sock_for_splice, kill),
        )
        .await
        .expect("cierra de inmediato, no cuelga")
        .expect("kill limpio");

        let mut datas = 0usize;
        let mut state_closeds = 0usize;
        while let Ok(msg) = read_message(&mut router).await {
            match msg.content_type {
                CT_DATA => datas += 1,
                CT_STATE_CLOSED => {
                    state_closeds += 1;
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(
            datas, 0,
            "cero bytes relevados tras un kill mid-dial (GWT-8)"
        );
        assert_eq!(state_closeds, 1, "solo el StateClosed");
        assert_eq!(state.conn_count(), 0);

        // Nada se escribió al socket local tampoco.
        let mut inbound = Vec::new();
        local.read_to_end(&mut inbound).await.unwrap();
        assert!(inbound.is_empty(), "el cliente no recibió ningún byte");
    }
}
