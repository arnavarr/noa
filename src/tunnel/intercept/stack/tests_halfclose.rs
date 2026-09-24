//! G2+G3: la glue `InterceptStack`+`MockDevice` (orden de `accept`) + el half-close ACOTADO de M2a
//! (`InterceptTcpStream` + el `splice` REAL de T1), con el lado ziti falso local (F6 tramo 16 troceo).

use super::testsupport::*;
use super::*;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use netstack_smoltcp::smoltcp::wire::TcpControl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// M2a (half-close acotado): el `splice` REAL de T1 + el lado ziti falso para el escenario de cuelgue.
use crate::edge::data::{ChannelState, EdgeConn, EdgeReadHalf, EdgeWriteHalf};
use crate::edge::dial::{FLAG_FIN, HDR_FLAGS, build_data};
use crate::tunnel::intercept::stream::InterceptTcpStream;
use crate::tunnel::proxy::splice;

/// Prueba NUESTRA glue (device↔pila↔accept) end-to-end en memoria, sin root: un SYN entra por el
/// device, `accept()` entrega el flujo con `(dst, src)` BIEN ORDENADOS, y el SYN-ACK sale por el
/// device (prueba que ingress y egress están cableados). Pinea la corrección de orden del §accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_yields_dst_then_src_not_swapped() {
    let (dev, mut host) = MockDevice::new();
    let mut stack = InterceptStack::new(dev).expect("montar pila");

    // SYN del cliente por el device.
    host.ingress_tx
        .send(build_pkt(client(), dst(), TcpControl::Syn, 5000, None, &[]))
        .expect("inyectar SYN");

    let (_stream, got_dst, got_src) = tokio::time::timeout(TEST_TIMEOUT, stack.accept())
        .await
        .expect("timeout en accept")
        .expect("la pila no entregó flujo");
    // El contrato: (stream, dst, src). dst = lo que el cliente quería alcanzar.
    assert_eq!(
        got_dst,
        SocketAddr::V4(dst()),
        "el 2º elemento debe ser el DST interceptado"
    );
    assert_eq!(
        got_src,
        SocketAddr::V4(client()),
        "el 3º elemento debe ser el ORIGEN del cliente"
    );

    // Y la glue de egress entregó el SYN-ACK al device.
    let synack = host.recv_egress_matching(|p| p.syn && p.ack).await;
    assert_eq!(synack.ack_num, 5001);
    assert_eq!(synack.src, dst());
}

// --- M2a: half-close ACOTADO ([`InterceptTcpStream`]) ---

const ZITI_CONN: u32 = 7;

/// Un transporte cuyo `poll_write` SIEMPRE da error en la PRIMERA llamada: modela el lado de
/// escritura del overlay desapareciendo a mitad de sesión (el "error de escritura en `zw`" del
/// escenario de cuelgue). Determinista: un duplex con la mitad de lectura soltada podría
/// bufferizar la primera escritura; este nunca.
struct AlwaysErrWriter;

impl tokio::io::AsyncWrite for AlwaysErrWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "overlay write side gone",
        )))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Lado ziti falso para el escenario de cuelgue de la review de M1: `zr.read()` da EOF de inmediato
/// (un Data inbound con FIN) y `zw.write()` da error en la primera escritura (overlay caído).
fn fake_ziti_eof_and_write_err() -> (EdgeReadHalf, EdgeWriteHalf) {
    let state = Arc::new(ChannelState::new(Box::new(AlwaysErrWriter)));
    let (data_tx, data_rx) = tokio::sync::mpsc::channel(8);
    state.register_conn(ZITI_CONN, data_tx.clone());
    // EOF inmediato: un Data vacío con el flag FIN -> `read()` == `Ok(None)`.
    let mut fin = build_data(ZITI_CONN, b"", false);
    fin.headers
        .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
    data_tx.try_send(fin).expect("encolar el FIN inbound");
    // `data_tx` (el clon local) se suelta al salir; el clon registrado mantiene el mux y el FIN ya
    // está encolado, así que el `read()` lo entrega antes de ver el cierre del canal.
    let conn = EdgeConn::new_for_test(ZITI_CONN, data_rx, state);
    conn.into_split()
}

/// PROPIEDAD (b) del adaptador: su `poll_shutdown` DISPARA el FIN en el momento del half-close (no
/// diferido al `Drop`) y retorna PRONTO, a diferencia del `poll_shutdown` crudo de netstack (que
/// quedaría `Pending` hasta `State::Closed`). El stream se mantiene VIVO durante toda la
/// observación, así que el FIN observado SOLO puede venir de `poll_shutdown`, nunca de `Drop`
/// (`Drop` también pone `Close`). Doble RED bajo mutación: un adaptador que devolviera `Ready` SIN
/// sondear el inner no emitiría FIN aquí (`recv_egress_matching` da timeout); uno que delegara del
/// todo (siempre `Pending`) no retornaría (el `expect` del shutdown da timeout).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_shutdown_returns_promptly_and_emits_fin_while_alive() {
    let (mut stack, mut listener) = raw_stack();
    let (inner, server_isn) = handshake(&mut stack, &mut listener, 7000).await;

    // Barrera de ESTABLISHED (igual que el GATE de M1): 1 byte cliente->servidor, leído por el
    // stream, para que el shutdown corra con el socket firmemente Establecido.
    inject(
        &mut stack,
        build_pkt(
            client(),
            dst(),
            TcpControl::Psh,
            7001,
            Some(server_isn + 1),
            b"x",
        ),
    )
    .await;
    let mut wrapped = InterceptTcpStream::new(inner);
    let mut probe = [0u8; 4];
    let n = tokio::time::timeout(TEST_TIMEOUT, wrapped.read(&mut probe))
        .await
        .expect("timeout en la barrera de ESTABLISHED")
        .expect("read");
    assert_eq!(&probe[..n], b"x");

    // El half-close acotado retorna PRONTO (no espera a `State::Closed`: no mandamos el FIN del
    // cliente, así que el socket nunca alcanza el cierre completo).
    tokio::time::timeout(TEST_TIMEOUT, wrapped.shutdown())
        .await
        .expect("el poll_shutdown acotado retorna pronto (no espera a State::Closed)")
        .expect("shutdown ok");

    // ...y el FIN salió al cable POR `poll_shutdown` (no por `Drop`): el stream sigue VIVO.
    let fin = recv_egress_matching(&mut stack, |p| p.fin).await;
    assert_eq!(fin.src, dst(), "el FIN sale del lado servidor interceptado");
    assert_eq!(fin.dst, client());
    assert_eq!(
        fin.seq,
        server_isn + 1,
        "sin datos del servidor el FIN lleva el ISN+1 (drain-before-FIN intacto)"
    );
    drop(wrapped); // recién AQUÍ: ningún FIN observado pudo venir del Drop.
}

/// PROPIEDAD (a) — EL HEADLINE: `splice` (T1, SIN MODIFICAR) sobre un [`InterceptTcpStream`] NO se
/// cuelga aunque el peer local quede half-open para siempre. Reproduce el escenario de cuelgue de
/// la review de M1: overlay caído (`zr` EOF + error de escritura en `zw`) + app local que nunca
/// manda su FIN. Con el `poll_shutdown` crudo de netstack el `sock_w.shutdown()` de la dirección
/// overlay→socket quedaría `Pending` para siempre y el `join!` de `splice` colgaría; con el
/// adaptado, `splice` retorna. NON-VACUO: delegar del todo en `poll_shutdown` -> el `expect` de
/// abajo da timeout -> RED (verificado por mutación, ver el handoff).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn splice_over_bounded_stream_does_not_hang_on_half_open_peer() {
    let (mut stack, mut listener) = raw_stack();
    let (inner, server_isn) = handshake(&mut stack, &mut listener, 6000).await;
    let wrapped = InterceptTcpStream::new(inner);

    // Lado ziti: EOF inmediato (dispara el `sock_w.shutdown()` de la dirección overlay→socket) +
    // error de escritura (completa la dirección socket→overlay por el camino de error).
    let (zr, zw) = fake_ziti_eof_and_write_err();

    // Un segmento de datos del cliente para que la lectura socket→ziti de `splice` devuelva bytes
    // y dispare la (fallida) escritura ziti. NUNCA mandamos un FIN del cliente -> el socket netstack
    // queda half-open para siempre -> el `poll_shutdown` crudo colgaría el `join!`.
    inject(
        &mut stack,
        build_pkt(
            client(),
            dst(),
            TcpControl::Psh,
            6001,
            Some(server_isn + 1),
            b"hi",
        ),
    )
    .await;

    // Drena el egress en segundo plano para que el Runner no se atasque (fire-and-forget).
    let egress = tokio::spawn(async move { while let Some(Ok(_frame)) = stack.next().await {} });

    // El half-close acotado debe dejar que `splice` RETORNE pese al peer half-open.
    let res = tokio::time::timeout(Duration::from_secs(10), splice(zr, zw, wrapped))
        .await
        .expect("splice retornó (half-close acotado); un poll_shutdown crudo colgaría aquí");
    assert!(
        res.is_err(),
        "el error de escritura ziti (overlay caído) aflora desde el splice, que aun así completó"
    );

    egress.abort();
}
