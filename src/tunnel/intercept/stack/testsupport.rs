//! Rig de test compartido por los `tests_*` de `stack` (F6 tramo 16 troceo): constructores de
//! paquetes IP+TCP/UDP con checksums válidos, la pila "cruda" (`raw_stack`), el `MockDevice`/
//! `MockHost` en memoria y los helpers de handshake/egress. `raw_stack`/`handshake` los comparten
//! `tests_gate` y `tests_halfclose` (NO contiguos), y `MockDevice`/`build_udp_pkt` cruzan varios
//! grupos, así que todo el preamble viaja aquí, `pub(super)`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::smoltcp::phy::ChecksumCapabilities;
use netstack_smoltcp::smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    UdpPacket, UdpRepr,
};
use netstack_smoltcp::{StackBuilder, TcpListener, TcpStream};

use crate::tunnel::intercept::device::IpPacketDevice;

pub(super) const TEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Un segmento TCP parseado de un frame IPv4 de egress (lo que la pila escribiría al utun).
#[derive(Debug)]
pub(super) struct ParsedTcp {
    pub(super) src: SocketAddrV4,
    pub(super) dst: SocketAddrV4,
    pub(super) seq: i32,
    pub(super) ack_num: i32,
    pub(super) syn: bool,
    pub(super) ack: bool,
    pub(super) fin: bool,
    pub(super) payload: Vec<u8>,
}

/// Construye un paquete IPv4+TCP con checksums VÁLIDOS (smoltcp los exige al recibir un paquete por
/// la interfaz; un checksum malo se descartaría silenciosamente y el test colgaría).
pub(super) fn build_pkt(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    control: TcpControl,
    seq: i32,
    ack: Option<i32>,
    payload: &[u8],
) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let tcp = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control,
        seq_number: TcpSeqNumber(seq),
        ack_number: ack.map(TcpSeqNumber),
        window_len: 64_240,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    };
    // smoltcp 0.12: `Ipv4Address` es un alias de `core::net::Ipv4Addr` → sin conversión.
    let src_ip = *src.ip();
    let dst_ip = *dst.ip();
    let ip = Ipv4Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.buffer_len(),
        hop_limit: 64,
    };
    let ip_len = ip.buffer_len();
    let mut buf = vec![0u8; ip_len + tcp.buffer_len()];
    {
        let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut p, &caps);
    }
    {
        let mut p = TcpPacket::new_unchecked(&mut buf[ip_len..]);
        tcp.emit(
            &mut p,
            &IpAddress::Ipv4(src_ip),
            &IpAddress::Ipv4(dst_ip),
            &caps,
        );
    }
    buf
}

/// Parsea un frame IPv4+TCP de egress.
pub(super) fn parse_tcp(frame: &[u8]) -> ParsedTcp {
    let ip = Ipv4Packet::new_checked(frame).expect("egress no es IPv4 válido");
    assert_eq!(ip.next_header(), IpProtocol::Tcp, "egress no es TCP");
    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();
    let tcp = TcpPacket::new_checked(ip.payload()).expect("egress TCP inválido");
    ParsedTcp {
        src: SocketAddrV4::new(src_ip, tcp.src_port()),
        dst: SocketAddrV4::new(dst_ip, tcp.dst_port()),
        seq: tcp.seq_number().0,
        ack_num: tcp.ack_number().0,
        syn: tcp.syn(),
        ack: tcp.ack(),
        fin: tcp.fin(),
        payload: tcp.payload().to_vec(),
    }
}

/// Construye un paquete IPv4+UDP con checksums VÁLIDOS (espejo de [`build_pkt`] para UDP). Lo
/// inyectamos por el device para ejercitar la ruta `recv_from`.
pub(super) fn build_udp_pkt(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let caps = ChecksumCapabilities::default();
    let udp = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let src_ip = *src.ip();
    let dst_ip = *dst.ip();
    let udp_len = udp.header_len() + payload.len();
    let ip = Ipv4Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Udp,
        payload_len: udp_len,
        hop_limit: 64,
    };
    let ip_len = ip.buffer_len();
    let mut buf = vec![0u8; ip_len + udp_len];
    {
        let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.emit(&mut p, &caps);
    }
    {
        let mut p = UdpPacket::new_unchecked(&mut buf[ip_len..]);
        udp.emit(
            &mut p,
            &IpAddress::Ipv4(src_ip),
            &IpAddress::Ipv4(dst_ip),
            payload.len(),
            |b| b.copy_from_slice(payload),
            &caps,
        );
    }
    buf
}

/// Parsea un frame IPv4+UDP de egress → `(src, dst, payload)` (`src`/`dst` son las direcciones del
/// paquete en el cable: tras el swap de la respuesta, `src` debe ser el destino interceptado y `dst`
/// el cliente).
fn parse_udp(frame: &[u8]) -> (SocketAddrV4, SocketAddrV4, Vec<u8>) {
    let ip = Ipv4Packet::new_checked(frame).expect("egress no es IPv4 válido");
    assert_eq!(ip.next_header(), IpProtocol::Udp, "egress no es UDP");
    let src_ip = ip.src_addr();
    let dst_ip = ip.dst_addr();
    let udp = UdpPacket::new_checked(ip.payload()).expect("egress UDP inválido");
    (
        SocketAddrV4::new(src_ip, udp.src_port()),
        SocketAddrV4::new(dst_ip, udp.dst_port()),
        udp.payload().to_vec(),
    )
}

pub(super) fn client() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 5), 54_321)
}
pub(super) fn dst() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80)
}

/// Construye una pila netstack "cruda" (sin glue de device): devuelve el `Stack` (Sink+Stream que
/// hace de "device") y el `TcpListener`, con el Runner ya spawneado. Los tests dirigen el `Stack`
/// directamente: inyectan paquetes por el Sink, leen el egress por el Stream.
pub(super) fn raw_stack() -> (netstack_smoltcp::Stack, TcpListener) {
    let (stack, runner, _udp, listener) = StackBuilder::default()
        .enable_tcp(true)
        .mtu(1500)
        .build()
        .expect("build stack");
    let runner = runner.expect("runner");
    let listener = listener.expect("listener");
    tokio::spawn(async move {
        let _ = runner.await;
    });
    (stack, listener)
}

pub(super) async fn inject(stack: &mut netstack_smoltcp::Stack, pkt: Vec<u8>) {
    stack.send(pkt).await.expect("inyectar paquete en la pila");
}

/// Lee frames de egress de la pila hasta que uno cumple `pred`, devolviéndolo. Ignora los que no
/// (p. ej. ACKs puros). Acotado por timeout para fallar rápido si el paquete esperado nunca llega.
pub(super) async fn recv_egress_matching(
    stack: &mut netstack_smoltcp::Stack,
    pred: impl Fn(&ParsedTcp) -> bool,
) -> ParsedTcp {
    let fut = async {
        loop {
            let frame = stack
                .next()
                .await
                .expect("la pila cerró el egress")
                .expect("error de egress");
            let p = parse_tcp(&frame);
            if pred(&p) {
                return p;
            }
        }
    };
    tokio::time::timeout(TEST_TIMEOUT, fut)
        .await
        .expect("timeout esperando el frame de egress esperado")
}

/// Completa el three-way handshake contra la pila y acepta el flujo. Devuelve `(stream, server_isn)`.
pub(super) async fn handshake(
    stack: &mut netstack_smoltcp::Stack,
    listener: &mut TcpListener,
    client_isn: i32,
) -> (TcpStream, i32) {
    // 1. SYN del cliente.
    inject(
        stack,
        build_pkt(client(), dst(), TcpControl::Syn, client_isn, None, &[]),
    )
    .await;
    // 2. SYN-ACK de la pila.
    let synack = recv_egress_matching(stack, |p| p.syn && p.ack).await;
    assert_eq!(
        synack.ack_num,
        client_isn + 1,
        "el SYN-ACK debe ack-ear ISN+1"
    );
    assert_eq!(
        synack.src,
        dst(),
        "el SYN-ACK sale del lado servidor (dst→cliente)"
    );
    assert_eq!(synack.dst, client());
    let server_isn = synack.seq;
    // 3. ACK del cliente → establece la conexión.
    inject(
        stack,
        build_pkt(
            client(),
            dst(),
            TcpControl::None,
            client_isn + 1,
            Some(server_isn + 1),
            &[],
        ),
    )
    .await;
    // 4. accept: netstack encola el stream al ver el SYN, así que ya está disponible.
    let (stream, local_src, remote_dst) = tokio::time::timeout(TEST_TIMEOUT, listener.next())
        .await
        .expect("timeout en accept")
        .expect("la pila cerró el listener");
    // netstack: local_addr = origen (cliente), remote_addr = destino interceptado.
    assert_eq!(local_src, SocketAddr::V4(client()));
    assert_eq!(remote_dst, SocketAddr::V4(dst()));
    (stream, server_isn)
}

// --- Test de la glue (InterceptStack + device en memoria), sin root ---

/// Device IP en memoria que implementa [`IpPacketDevice`] con dos colas: el test inyecta paquetes
/// (host→pila, los recoge `recv`) y lee el egress (pila→host, lo deposita `send`).
#[derive(Clone)]
pub(super) struct MockDevice {
    ingress_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
    egress_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

/// Lado de control del [`MockDevice`] que conserva el test.
pub(super) struct MockHost {
    pub(super) ingress_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    egress_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
}

impl MockDevice {
    pub(super) fn new() -> (Self, MockHost) {
        let (ingress_tx, ingress_rx) = tokio::sync::mpsc::unbounded_channel();
        let (egress_tx, egress_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                ingress_rx: Arc::new(tokio::sync::Mutex::new(ingress_rx)),
                egress_tx,
            },
            MockHost {
                ingress_tx,
                egress_rx,
            },
        )
    }
}

impl IpPacketDevice for MockDevice {
    fn recv(&self, buf: &mut [u8]) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        let rx = Arc::clone(&self.ingress_rx);
        async move {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(pkt) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok(n)
                }
                None => Ok(0),
            }
        }
    }

    fn send(&self, buf: &[u8]) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        let n = buf.len();
        let pkt = buf.to_vec();
        let tx = self.egress_tx.clone();
        async move {
            tx.send(pkt)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "egress cerrado"))?;
            Ok(n)
        }
    }

    fn name(&self) -> io::Result<String> {
        Ok("mock".to_string())
    }

    fn mtu(&self) -> u16 {
        1500
    }
}

impl MockHost {
    pub(super) async fn recv_egress_matching(
        &mut self,
        pred: impl Fn(&ParsedTcp) -> bool,
    ) -> ParsedTcp {
        let fut = async {
            loop {
                let frame = self.egress_rx.recv().await.expect("egress cerrado");
                let p = parse_tcp(&frame);
                if pred(&p) {
                    return p;
                }
            }
        };
        tokio::time::timeout(TEST_TIMEOUT, fut)
            .await
            .expect("timeout esperando egress del MockDevice")
    }

    /// Lee el primer frame de egress que sea UDP (salta TCP/otros) y lo parsea a `(src, dst, payload)`.
    pub(super) async fn recv_udp_egress(&mut self) -> (SocketAddrV4, SocketAddrV4, Vec<u8>) {
        let fut = async {
            loop {
                let frame = self.egress_rx.recv().await.expect("egress cerrado");
                let ip = Ipv4Packet::new_checked(&frame[..]).expect("egress no es IPv4 válido");
                if ip.next_header() == IpProtocol::Udp {
                    return parse_udp(&frame);
                }
            }
        };
        tokio::time::timeout(TEST_TIMEOUT, fut)
            .await
            .expect("timeout esperando egress UDP del MockDevice")
    }
}
