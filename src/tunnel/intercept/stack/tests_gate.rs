//! G1: el GATE de `poll_shutdown` (emite un FIN real) + round-trip de datos sobre la pila netstack
//! "cruda" (`raw_stack`), sin device (F6 tramo 16 troceo).

use super::testsupport::*;

use futures_util::StreamExt;
use netstack_smoltcp::smoltcp::wire::TcpControl;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// **EL GATE (§4.2.1).** `poll_shutdown` del `TcpStream` de netstack debe emitir un FIN REAL en el
/// cable — el `splice` de T1 lo asume al hacer `sock_w.shutdown()`. El test DISTINGUE el FIN de
/// `poll_shutdown` del FIN de `Drop`: `TcpStream::Drop` TAMBIÉN pone `send_state = Close` (mismo
/// disparador del FIN, netstack tcp.rs:467-469), así que un test que dropeara el stream para
/// observar el FIN sería VACUO (un `poll_shutdown` no-op pasaría igual, vía el FIN de Drop). Por eso
/// aquí mantenemos el `stream` VIVO durante toda la observación (el future de shutdown lo presta; el
/// `stream` no se dropea hasta el final): el FIN observado SOLO puede venir de `poll_shutdown`.
/// Bajo la mutación canónica drop-only (`poll_shutdown` → `Ready` sin tocar `send_state`) el future
/// de shutdown completa SIN que el stream se dropee → no aparece FIN → la rama de shutdown panica;
/// bajo "Pending pero nunca Close" no hay FIN → `recv_egress_matching` da timeout. Ambas → FALLO.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_poll_shutdown_emits_a_real_fin() {
    let (mut stack, mut listener) = raw_stack();
    let (mut stream, server_isn) = handshake(&mut stack, &mut listener, 1000).await;

    // Barrera de ESTABLISHED: el cliente manda 1 byte y el stream lo lee. El `read` solo retorna
    // cuando la pila ya procesó el ACK del handshake + el dato → la conexión está firmemente
    // Establecida y el Runner ha avanzado. Sin esta barrera el shutdown podría correr con el socket
    // aún en SynReceived y el FIN se emitiría de forma no determinista (un flake observado en M1).
    inject(
        &mut stack,
        build_pkt(
            client(),
            dst(),
            TcpControl::Psh,
            1001,
            Some(server_isn + 1),
            b"x",
        ),
    )
    .await;
    let mut probe = [0u8; 4];
    let n = tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut probe))
        .await
        .expect("timeout en la barrera de ESTABLISHED")
        .expect("read");
    assert_eq!(&probe[..n], b"x");

    // Conduce el shutdown con un future PRESTADO (no movido a una task que lo dropearía): así el
    // `stream` permanece vivo y el FIN observado SOLO puede venir de `poll_shutdown`, nunca de Drop.
    // `poll_shutdown` queda Pending hasta el cierre COMPLETO (no mandamos el FIN del cliente), así
    // que la rama de shutdown no debe completar; el FIN aparece por la rama de egress.
    let mut shutdown_fut = std::pin::pin!(stream.shutdown());
    tokio::select! {
        res = &mut shutdown_fut => panic!(
            "poll_shutdown completó sin que apareciera un FIN observable (¿no-op/Drop-only?): {res:?}"
        ),
        // Saltamos el ACK puro del byte de la barrera; buscamos el FIN del lado servidor.
        fin = recv_egress_matching(&mut stack, |p| p.fin) => {
            assert_eq!(fin.src, dst(), "el FIN sale del lado servidor interceptado");
            assert_eq!(fin.dst, client());
            assert_eq!(
                fin.seq,
                server_isn + 1,
                "sin datos del servidor, el FIN lleva el seq inicial del servidor (ISN+1)"
            );
        }
    }
    // `stream` y `shutdown_fut` siguen vivos hasta el fin del scope (shutdown_fut presta &mut stream)
    // → durante TODA la observación el stream no se dropea → ningún FIN observado pudo venir de Drop.
}

/// La otra dirección de RFC 9293: un FIN del peer (cliente) debe entregar EOF al lado de lectura
/// del `TcpStream` (lo que `splice` lee como fin del flujo socket→overlay).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_fin_yields_read_eof() {
    let (mut stack, mut listener) = raw_stack();
    let (mut stream, server_isn) = handshake(&mut stack, &mut listener, 2000).await;

    // FIN del cliente (ack-ea el SYN del servidor).
    inject(
        &mut stack,
        build_pkt(
            client(),
            dst(),
            TcpControl::Fin,
            2001,
            Some(server_isn + 1),
            &[],
        ),
    )
    .await;

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("timeout esperando EOF")
        .expect("read");
    assert_eq!(n, 0, "un FIN del peer debe entregar EOF (read == 0)");
}

/// Round-trip de datos: el `TcpStream` aceptado es un socket usable en ambos sentidos (lo que
/// `splice` necesita). Servidor→cliente (write → segmento de datos en egress) y cliente→servidor
/// (inyectar datos → `read` los entrega).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_stream_round_trips_data() {
    let (mut stack, mut listener) = raw_stack();
    let (mut stream, server_isn) = handshake(&mut stack, &mut listener, 3000).await;

    // Servidor→cliente: escribir en el stream produce un segmento de datos en egress.
    stream.write_all(b"hello").await.expect("write");
    let data = recv_egress_matching(&mut stack, |p| p.payload == b"hello").await;
    assert_eq!(data.src, dst());
    assert_eq!(data.seq, server_isn + 1);

    // Cliente→servidor: inyectar datos → el stream los lee.
    inject(
        &mut stack,
        build_pkt(
            client(),
            dst(),
            TcpControl::Psh,
            3001,
            Some(server_isn + 1),
            b"world",
        ),
    )
    .await;
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut buf))
        .await
        .expect("timeout en read")
        .expect("read");
    assert_eq!(
        &buf[..n],
        b"world",
        "el stream debe entregar los datos inyectados"
    );
}

/// Drain-before-FIN: los datos escritos justo antes del shutdown se VACÍAN antes del FIN (la rama
/// SHUT_WR del Runner solo cierra cuando el send-buffer está vacío). Propiedad relevante para
/// `splice`: un cierre no debe truncar bytes en vuelo. (El ORIGEN del FIN —poll_shutdown vs Drop—
/// es irrelevante AQUÍ: ambos drenan antes; eso lo distingue `gate_poll_shutdown_emits_a_real_fin`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_written_before_shutdown_is_flushed_before_fin() {
    let (mut stack, mut listener) = raw_stack();
    let (mut stream, server_isn) = handshake(&mut stack, &mut listener, 4000).await;

    // Barrera de ESTABLISHED para que el write se despache de forma determinista.
    inject(
        &mut stack,
        build_pkt(
            client(),
            dst(),
            TcpControl::Psh,
            4001,
            Some(server_isn + 1),
            b"x",
        ),
    )
    .await;
    let mut probe = [0u8; 4];
    tokio::time::timeout(TEST_TIMEOUT, stream.read(&mut probe))
        .await
        .expect("timeout en la barrera de ESTABLISHED")
        .expect("read");

    // Escribe 3 bytes y cierra. El shutdown va en una task (el origen del FIN no importa aquí).
    stream.write_all(b"bye").await.expect("write");
    let sd = tokio::spawn(async move {
        let mut stream = stream;
        let _ = stream.shutdown().await;
    });

    // Lee egress hasta el FIN, acumulando si vimos el payload "bye".
    let mut saw_bye = false;
    let fin = loop {
        let frame = tokio::time::timeout(TEST_TIMEOUT, stack.next())
            .await
            .expect("timeout esperando el FIN")
            .expect("egress cerrado")
            .expect("error de egress");
        let p = parse_tcp(&frame);
        if p.payload == b"bye" {
            saw_bye = true;
        }
        if p.fin {
            break p;
        }
    };
    assert!(
        saw_bye || fin.payload == b"bye",
        "los 3 bytes deben transmitirse antes/junto al FIN (no truncados)"
    );
    // El FIN va DESPUÉS de los 3 bytes en el espacio de secuencia (ISN+1 + 3) → se drenaron primero.
    assert_eq!(
        fin.seq,
        server_isn + 1 + 3,
        "el seq del FIN contabiliza los 3 bytes drenados (drain-before-FIN)"
    );
    sd.abort();
}
