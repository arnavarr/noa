//! G6: `split_mut` — las dos superficies (`TcpHalf`/`UdpHalf`) conducidas CONCURRENTEMENTE sobre la
//! MISMA pila, y el caso TCP-only sin mitad UDP (F6 tramo 16 troceo).

use super::testsupport::*;
use super::*;

use std::net::SocketAddr;

use netstack_smoltcp::smoltcp::wire::TcpControl;

// --- split_mut (subcomando combinado): las dos superficies conducidas CONCURRENTEMENTE ---

/// **EL PIN del split.** `split_mut` presta las DOS superficies de la MISMA pila a la vez y ambas
/// funcionan CONCURRENTEMENTE: un SYN llega a `TcpHalf::accept` y un datagrama a
/// `UdpHalf::recv_from`, conducidos bajo un único `join!` (imposible con los `&mut self` de
/// `accept`/`recv_from` sin el split — esto ni compilaría). Los contratos de orden `(dst, src)` se
/// preservan en ambas vistas (delegación: son el MISMO código que `accept`/`recv_from`).
/// Mutación-RED: si una vista devolviese el orden crudo de netstack (src, dst), los asserts de
/// dst/src caen; si el split no fuese borrow-split real, no compila.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_mut_drives_tcp_and_udp_surfaces_concurrently() {
    let (dev, host) = MockDevice::new();
    let mut stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let (mut tcp, udp) = stack.split_mut();
    let mut udp = udp.expect("new_with_udp da la mitad UDP");

    // Inyecta AMBOS tipos de tráfico antes de conducir las vistas.
    host.ingress_tx
        .send(build_udp_pkt(client(), dst(), b"dgram"))
        .expect("inyectar datagrama UDP");
    host.ingress_tx
        .send(build_pkt(client(), dst(), TcpControl::Syn, 7000, None, &[]))
        .expect("inyectar SYN");

    let (t, u) = tokio::join!(
        tokio::time::timeout(TEST_TIMEOUT, tcp.accept()),
        tokio::time::timeout(TEST_TIMEOUT, udp.recv_from()),
    );
    let (_stream, tdst, tsrc) = t
        .expect("timeout en accept de la mitad TCP")
        .expect("la pila no entregó flujo");
    assert_eq!(tdst, SocketAddr::V4(dst()), "TcpHalf preserva el orden dst");
    assert_eq!(tsrc, SocketAddr::V4(client()), "TcpHalf preserva el src");
    let (payload, udst, usrc) = u
        .expect("timeout en recv_from de la mitad UDP")
        .expect("la pila no entregó datagrama");
    assert_eq!(payload, b"dgram");
    assert_eq!(udst, SocketAddr::V4(dst()), "UdpHalf preserva el orden dst");
    assert_eq!(usrc, SocketAddr::V4(client()), "UdpHalf preserva el src");
    drop(host);
}

/// En una pila TCP-only ([`InterceptStack::new`]) el split da `None` para la mitad UDP (no hay
/// surface que prestar) y la mitad TCP sigue siendo usable — espejo del `recv_from() == None` /
/// `udp_reply_sender() == None` de la forma TCP-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_mut_on_tcp_only_stack_yields_no_udp_half() {
    let (dev, host) = MockDevice::new();
    let mut stack = InterceptStack::new(dev).expect("montar pila TCP-only");
    let (mut tcp, udp) = stack.split_mut();
    assert!(udp.is_none(), "TCP-only no tiene mitad UDP que prestar");

    host.ingress_tx
        .send(build_pkt(client(), dst(), TcpControl::Syn, 7100, None, &[]))
        .expect("inyectar SYN");
    let (_stream, tdst, _tsrc) = tokio::time::timeout(TEST_TIMEOUT, tcp.accept())
        .await
        .expect("timeout en accept")
        .expect("la pila no entregó flujo");
    assert_eq!(tdst, SocketAddr::V4(dst()));
    drop(host);
}

/// Contraparte: la construcción opt-in UDP añade la surface y la 4ª task. `new_with_udp` da 4 tasks
/// y `udp`/`udp_reply_sender()` presentes (mutación-RED: si `new_with_udp` no spawnease la
/// reply-egress o no poblase `udp`, los asserts caen).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_with_udp_adds_the_udp_surface_and_a_fourth_task() {
    let (dev, _host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    assert_eq!(
        stack.tasks.len(),
        4,
        "con UDP = runner + ingress + egress + reply-egress"
    );
    assert!(stack.udp.is_some(), "new_with_udp puebla la surface UDP");
    assert!(
        stack.udp_reply_sender().is_some(),
        "con UDP hay reply-sender"
    );
}
