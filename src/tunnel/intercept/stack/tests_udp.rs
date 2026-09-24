//! G4+G5: surfacing del read-half UDP + reply-sender (`recv_from`/`send_to`, swap de direcciones,
//! resiliencia de la reply-egress) + la regresión HIGH de UDP opt-in todo-o-nada (F6 tramo 16 troceo).

use super::testsupport::*;
use super::*;

use std::net::SocketAddr;

use netstack_smoltcp::smoltcp::wire::TcpControl;

// --- M3-UDP-stack: surfacing del read-half + reply-sender UDP (categoría C, sin oráculo Ziti;
//     fidelidad = RFC 768 + fuente netstack-smoltcp 0.2.3) ---

/// `recv_from` entrega `(payload, dst, src)` BIEN ORDENADOS (2º = destino interceptado, 3º = origen
/// del cliente), espejo del contrato de `accept`. Inyecta un datagrama UDP cliente→dst por el device
/// y comprueba el payload y el orden. Mutación-RED: si `recv_from` NO reordenase (devolviese el
/// `(payload, src, dst)` crudo de netstack), `got_dst` sería el cliente → falla.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_recv_from_yields_payload_with_dst_then_src() {
    let (dev, host) = MockDevice::new();
    let mut stack = InterceptStack::new_with_udp(dev).expect("montar pila");

    // SYN-equivalente UDP: un único datagrama del cliente al destino interceptado.
    host.ingress_tx
        .send(build_udp_pkt(client(), dst(), b"ping"))
        .expect("inyectar datagrama UDP");

    let (payload, got_dst, got_src) = tokio::time::timeout(TEST_TIMEOUT, stack.recv_from())
        .await
        .expect("timeout en recv_from")
        .expect("la pila no entregó datagrama");
    assert_eq!(payload, b"ping", "payload entregado verbatim");
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
    drop(host); // se mantuvo vivo hasta aquí para no cerrar la ingress antes de procesar el datagrama
}

/// `send_to(payload, dst, src)` produce un datagrama de egress con IP `src = dst` (la respuesta
/// aparece DEL destino interceptado) e IP `dst = src` (entregada al cliente) + puertos espejados.
/// EL PIN del swap. Mutación-RED: si `send_to` NO intercambiase (encolase `(payload, src, dst)`),
/// el egress saldría con IP src = cliente → falla.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_send_to_swaps_addresses_so_the_reply_comes_from_dst() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila");
    let reply = stack
        .udp_reply_sender()
        .expect("new_with_udp expone el reply-sender");

    // El handler responde con el MISMO (dst, src) que recibiría de recv_from.
    reply
        .send_to(
            b"pong".to_vec(),
            SocketAddr::V4(dst()),
            SocketAddr::V4(client()),
        )
        .await
        .expect("encolar la respuesta");

    let (egress_src, egress_dst, payload) = host.recv_udp_egress().await;
    assert_eq!(payload, b"pong", "payload de respuesta verbatim");
    assert_eq!(
        egress_src,
        dst(),
        "IP src de la respuesta = DST interceptado (de quién parece venir)"
    );
    assert_eq!(
        egress_dst,
        client(),
        "IP dst de la respuesta = cliente (a quién va)"
    );
    drop(stack); // mantenido vivo (su task de reply-egress) hasta leer el egress
}

/// Round-trip in-memory completo por la pila REAL: inyecta un datagrama entrante, `recv_from` lo
/// entrega con `(dst, src)`, y el "handler" responde reusando ESE par → el egress sale como una
/// respuesta bien dirigida al cliente desde el destino. Prueba la simetría recv_from↔send_to
/// end-to-end (ingress glue + reply-egress) sin root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_round_trips_inbound_then_reply_through_the_stack() {
    let (dev, mut host) = MockDevice::new();
    let mut stack = InterceptStack::new_with_udp(dev).expect("montar pila");
    let reply = stack
        .udp_reply_sender()
        .expect("new_with_udp expone el reply-sender");

    host.ingress_tx
        .send(build_udp_pkt(client(), dst(), b"q"))
        .expect("inyectar datagrama UDP entrante");
    let (payload, rdst, rsrc) = tokio::time::timeout(TEST_TIMEOUT, stack.recv_from())
        .await
        .expect("timeout en recv_from")
        .expect("la pila no entregó datagrama");
    assert_eq!(payload, b"q");
    assert_eq!(rdst, SocketAddr::V4(dst()));
    assert_eq!(rsrc, SocketAddr::V4(client()));

    // El handler responde reusando el MISMO (dst, src) → swap correcto sin esfuerzo de orden.
    reply
        .send_to(b"r".to_vec(), rdst, rsrc)
        .await
        .expect("encolar respuesta");
    let (egress_src, egress_dst, rpayload) = host.recv_udp_egress().await;
    assert_eq!(rpayload, b"r");
    assert_eq!(
        egress_src,
        dst(),
        "la respuesta sale del destino interceptado"
    );
    assert_eq!(egress_dst, client(), "la respuesta va al cliente");
    drop(stack);
}

/// Resiliencia de la task de reply-egress ante un fallo de codificación POR-DATAGRAMA: familias
/// v4/v6 mezcladas → `InvalidData` en `WriteHalf::start_send`. Se DESCARTA sin derribar la task —
/// una respuesta válida POSTERIOR sigue saliendo. Mutación-RED: estrechar
/// `is_per_datagram_encode_error` para que `InvalidData` deje de contar como por-datagrama (caería
/// en la rama terminal `break`) haría que la 2ª respuesta nunca llegue (timeout). (Defensivo:
/// inalcanzable si el handler reusa el par de `recv_from`, que es siempre misma-familia.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_reply_task_survives_an_uncodable_datagram() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila");
    let reply = stack
        .udp_reply_sender()
        .expect("new_with_udp expone el reply-sender");

    // Par mal formado: dst v4, src v6 → WriteHalf::start_send da InvalidData → la task lo descarta.
    let bad_src = SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::LOCALHOST,
        1234,
        0,
        0,
    ));
    reply
        .send_to(b"bad".to_vec(), SocketAddr::V4(dst()), bad_src)
        .await
        .expect("la cola acepta el encolado (el descarte ocurre en la task)");

    // Una respuesta VÁLIDA posterior debe seguir saliendo → la task sobrevivió al datagrama malo.
    reply
        .send_to(
            b"good".to_vec(),
            SocketAddr::V4(dst()),
            SocketAddr::V4(client()),
        )
        .await
        .expect("encolar la respuesta válida");

    let (egress_src, egress_dst, payload) = host.recv_udp_egress().await;
    assert_eq!(payload, b"good", "la respuesta válida posterior llega");
    assert_eq!(egress_src, dst());
    assert_eq!(egress_dst, client());
    drop(stack);
}

/// Fold-in F1 (broadening): un fallo de codificación POR-DATAGRAMA que NO es `InvalidData` sino
/// `Other` — un payload que desborda el campo de longitud UDP (u16) → `PacketBuilder::write` falla
/// con `Error::other("PacketBuilder::write: …")`, MISMAS familias v4/v4 — también se DESCARTA sin
/// derribar la task. Una respuesta válida POSTERIOR sigue saliendo. Mutación-RED: si
/// `is_per_datagram_encode_error` solo reconociese `InvalidData` (sin el substring `PacketBuilder::
/// write`), el oversize caería en la rama terminal `break` → la task muere → la 2ª respuesta nunca
/// llega (timeout). Pinea que el broadening cubre el `Other` de codificación, no solo el `InvalidData`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_reply_task_survives_an_oversize_datagram() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila");
    let reply = stack
        .udp_reply_sender()
        .expect("new_with_udp expone el reply-sender");

    // Payload que desborda el campo de longitud UDP (u16): familias v4/v4 (pasa el match de
    // familia), pero `PacketBuilder::write` falla → `Other` "PacketBuilder::write: …" → la task lo
    // descarta por la rama POR-DATAGRAMA (broadening), no por `InvalidData`.
    let oversize = vec![0u8; 70_000];
    reply
        .send_to(oversize, SocketAddr::V4(dst()), SocketAddr::V4(client()))
        .await
        .expect("la cola acepta el encolado (el descarte ocurre en la task)");

    // Una respuesta VÁLIDA posterior debe seguir saliendo → la task sobrevivió al oversize.
    reply
        .send_to(
            b"good".to_vec(),
            SocketAddr::V4(dst()),
            SocketAddr::V4(client()),
        )
        .await
        .expect("encolar la respuesta válida");

    let (egress_src, egress_dst, payload) = host.recv_udp_egress().await;
    assert_eq!(
        payload, b"good",
        "la respuesta válida posterior llega pese al oversize"
    );
    assert_eq!(egress_src, dst());
    assert_eq!(egress_dst, client());
    drop(stack);
}

// --- Regresión HIGH de la review de M3-UDP-stack: UDP es opt-in todo-o-nada ---

/// **EL PIN DE LA REGRESIÓN.** `new` monta una pila TCP-only DRENADA-LIBRE: (a) forma TCP-only — 3
/// tasks, `udp` ausente, `udp_reply_sender()`/`recv_from()` dan `None`; y (b) un flujo de datagramas
/// UDP NO drenados NO ejerce backpressure sobre la ingress COMPARTIDA, así que un SYN POSTERIOR sigue
/// llegando a `accept()`. Esta es la prueba que los 4 tests UDP originales NO podían ser (inyectan 1
/// datagrama y lo drenan al instante). Mutación-RED: revertir `new` a `enable_udp(true)` (la
/// regresión) — el canal UDP acotado de netstack (`udp_buffer_size`, 512) que NADIE drena en una pila
/// TCP-only se llena → `Stack::poll_send` Pending para el siguiente UDP → la ingress compartida se
/// aparca → el SYN nunca llega → `accept()` da timeout (RED); y los asserts de forma (3 tasks,
/// `udp.is_none()`) también caen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_only_new_is_drain_free_so_udp_flood_does_not_wedge_tcp() {
    let (dev, host) = MockDevice::new();
    let mut stack = InterceptStack::new(dev).expect("montar pila TCP-only");

    // (a) Forma TCP-only: exactamente 3 tasks, sin surface UDP, sin emisor ni receptor UDP.
    assert_eq!(
        stack.tasks.len(),
        3,
        "TCP-only = runner + ingress + egress, SIN reply-egress"
    );
    assert!(stack.udp.is_none(), "TCP-only no tiene surface UDP");
    assert!(
        stack.udp_reply_sender().is_none(),
        "sin UDP no hay reply-sender (sería un canal sin sumidero)"
    );
    assert!(
        stack.recv_from().await.is_none(),
        "recv_from en TCP-only da None de inmediato"
    );

    // (b) Inunda con >512 datagramas UDP (el `udp_buffer_size` de netstack) que NADIE drena. Con
    // `enable_udp(false)` netstack los descarta sin backpressure; con la regresión `enable_udp(true)`
    // llenarían el canal y aparcarían la ingress COMPARTIDA tras ~512.
    for _ in 0..700u32 {
        host.ingress_tx
            .send(build_udp_pkt(client(), dst(), b"flood"))
            .expect("inyectar datagrama UDP de inundación");
    }
    // Un SYN DESPUÉS de la inundación: debe llegar a accept pese a los 700 UDP por delante.
    host.ingress_tx
        .send(build_pkt(client(), dst(), TcpControl::Syn, 9000, None, &[]))
        .expect("inyectar SYN tras la inundación");

    let (_stream, got_dst, got_src) = tokio::time::timeout(TEST_TIMEOUT, stack.accept())
        .await
        .expect("el SYN llegó pese al flood UDP (sin backpressure); la regresión colgaría aquí")
        .expect("la pila no entregó flujo");
    assert_eq!(got_dst, SocketAddr::V4(dst()));
    assert_eq!(got_src, SocketAddr::V4(client()));
    drop(host); // mantenido vivo hasta procesar la inundación + el SYN
}
