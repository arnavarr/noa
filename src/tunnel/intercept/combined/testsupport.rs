//! Rig de test compartido por los `tests_*` de `combined` (F6 tramo 17 troceo): el preamble
//! (constantes/servicios/resolver), el `MockDevice`/`MockHost` en memoria, el driver
//! TCP-through-MockDevice y `cidr_service` — todos cruzan ≥2 ficheros de test, así que viajan aquí
//! `pub(super)`.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use netstack_smoltcp::smoltcp::phy::ChecksumCapabilities;
use netstack_smoltcp::smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
    UdpPacket, UdpRepr,
};

use crate::edge::model::Service;
use crate::tunnel::intercept::device::IpPacketDevice;
use crate::tunnel::intercept::dns::DnsMatcher;
use crate::tunnel::intercept::resolve::InterceptResolver;

pub(super) const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// La rig del subcomando combinado: pool `100.64.0.0/24`, utun `.1`, DNS embebido `.2` (espejo de
/// `main.rs::seed_and_reserve_dns_pool`).
pub(super) const UTUN_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
pub(super) const DNS_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

pub(super) fn client_addr() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 200), 54_321)
}

pub(super) fn dns_server_addr() -> SocketAddrV4 {
    SocketAddrV4::new(DNS_IP, 53)
}

/// Un `Service` Dial-permitido cuyo `intercept.v1` intercepta `*.example.com` en tcp+udp:80
/// (espejo del helper de `intercept/resolve/testsupport.rs`).
pub(super) fn wildcard_service() -> Service {
    let config: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
        r#"{"intercept.v1":{"protocols":["tcp","udp"],"addresses":["*.example.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
    )
    .unwrap();
    Service {
        id: "id-wildcard-svc".into(),
        name: "wildcard-svc".into(),
        encryption_required: false,
        permissions: vec!["Dial".into()],
        config,
        configs: vec![],
    }
}

/// Resolver de producción de la rig: matcher sembrado + reservas (como `main.rs`) + el servicio
/// wildcard.
pub(super) fn rig_resolver() -> InterceptResolver {
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("100.64.0.0/24"));
    dns.reserve(UTUN_IP);
    dns.reserve(DNS_IP);
    InterceptResolver::from_services_with_dns(&[wildcard_service()], dns)
}

/// Query A DNS válida para `name` (espejo del helper de `intercept/udp/testsupport.rs`).
pub(super) fn dns_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in name.split('.') {
        pkt.push(u8::try_from(label.len()).unwrap());
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

/// La IP del (único) registro A de una respuesta del server embebido: los últimos 4 bytes antes
/// del OPT de 11 bytes (ARCOUNT=1 siempre — mismo extractor que el test de `intercept/udp/tests_dns.rs`).
pub(super) fn answered_ip(resp: &[u8]) -> Ipv4Addr {
    let ip = &resp[resp.len() - 11 - 4..resp.len() - 11];
    Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])
}

// ───── Rig in-memory del runner REAL (espejo del MockDevice de `stack/`) ─────

/// Device IP en memoria (dos colas): el test inyecta paquetes (ingress) y lee el egress. Espejo
/// consciente del `MockDevice` del test-rig de `stack/` (rigs por-módulo autocontenidas, misma
/// clase de desviación test-DRY que la maquinaria vconn de T3/udp).
#[derive(Clone)]
pub(super) struct MockDevice {
    ingress_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
    egress_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

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
    /// El primer frame de egress que sea UDP, parseado a `(src, dst, payload)`.
    pub(super) async fn recv_udp_egress(&mut self) -> (SocketAddrV4, SocketAddrV4, Vec<u8>) {
        let fut = async {
            loop {
                let frame = self.egress_rx.recv().await.expect("egress cerrado");
                let ip = Ipv4Packet::new_checked(&frame[..]).expect("egress no es IPv4 válido");
                if ip.next_header() == IpProtocol::Udp {
                    let src_ip = ip.src_addr();
                    let dst_ip = ip.dst_addr();
                    let udp = UdpPacket::new_checked(ip.payload()).expect("egress UDP inválido");
                    return (
                        SocketAddrV4::new(src_ip, udp.src_port()),
                        SocketAddrV4::new(dst_ip, udp.dst_port()),
                        udp.payload().to_vec(),
                    );
                }
            }
        };
        tokio::time::timeout(TEST_TIMEOUT, fut)
            .await
            .expect("timeout esperando egress UDP del MockDevice")
    }
}

/// Paquete IPv4+UDP con checksums VÁLIDOS (smoltcp los exige; espejo del helper de `stack/`).
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

// ───── Driver TCP-through-MockDevice (Ciclo 4 #4b: threading del DnsTcpContext) ─────
// Redefinido aquí (los tipos de test no cruzan módulos, misma clase que RecOps): una versión
// compacta del `build_pkt`/`parse_tcp`/`handshake` de `stack/`, sobre el `MockDevice` del runner.

/// Un segmento TCP parseado de un frame IPv4 de egress.
#[derive(Debug)]
pub(super) struct ParsedTcp {
    pub(super) src: SocketAddrV4,
    pub(super) seq: i32,
    pub(super) syn: bool,
    pub(super) ack: bool,
    pub(super) payload: Vec<u8>,
}

/// Construye un paquete IPv4+TCP con checksums VÁLIDOS (smoltcp los exige al recibir).
pub(super) fn build_tcp_pkt(
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
fn parse_tcp(frame: &[u8]) -> ParsedTcp {
    let ip = Ipv4Packet::new_checked(frame).expect("egress no es IPv4 válido");
    let src_ip = ip.src_addr();
    let tcp = TcpPacket::new_checked(ip.payload()).expect("egress TCP inválido");
    ParsedTcp {
        src: SocketAddrV4::new(src_ip, tcp.src_port()),
        seq: tcp.seq_number().0,
        syn: tcp.syn(),
        ack: tcp.ack(),
        payload: tcp.payload().to_vec(),
    }
}

impl MockHost {
    /// El primer frame TCP de egress que cumple `pred` (ignora ACKs puros / no-TCP), acotado por timeout.
    pub(super) async fn recv_tcp_egress_matching(
        &mut self,
        pred: impl Fn(&ParsedTcp) -> bool,
    ) -> ParsedTcp {
        let fut = async {
            loop {
                let frame = self.egress_rx.recv().await.expect("egress cerrado");
                let ip = Ipv4Packet::new_checked(&frame[..]).expect("egress no es IPv4 válido");
                if ip.next_header() == IpProtocol::Tcp {
                    let p = parse_tcp(&frame);
                    if pred(&p) {
                        return p;
                    }
                }
            }
        };
        tokio::time::timeout(TEST_TIMEOUT, fut)
            .await
            .expect("timeout esperando egress TCP del MockDevice")
    }

    /// Acumula los segmentos TCP de egress DESDE `from` hasta reconstruir UN mensaje DNS-over-TCP
    /// enmarcado (prefijo 2B BE + cuerpo), devolviendo el cuerpo (el mensaje DNS).
    ///
    /// # Este cliente falso DEBE ACKear, y ésa es la parte load-bearing
    /// `serve_dns_over_tcp` emite el prefijo y el cuerpo en **dos** `write_all`
    /// (`dns_tcp/framing.rs::write_framed_response`). En el camino rápido netstack los coalesce en un único segmento de 62
    /// bytes y todo funciona sin ACKs. Bajo carga salen SEPARADOS — y entonces **Nagle** (activo por
    /// defecto en smoltcp) retiene el segundo segmento mientras el primero siga sin ACKear. Un
    /// cliente que no ACKea deja el cuerpo atrapado para siempre: netstack retransmite el prefijo
    /// con backoff exponencial (verificado con una sonda: 4 copias del MISMO `seq`) hasta que la
    /// conexión muere, ~20 s después. Por eso ACKeamos cada segmento aceptado.
    ///
    /// # Y el reensamblado va por OFFSET, no por igualdad de `seq`
    /// Una retransmisión puede **solaparse y extender**: la traza real (sonda, 2026-07-09) muestra
    /// `seq=S len=2 [0,60]` y después `seq=S len=62 [0,60]` — netstack reenvía desde `S` el mensaje
    /// ENTERO. Un filtro que exigiese `seq == esperado` descartaría precisamente el segmento que
    /// trae los bytes que faltan, y giraría en el bucle hasta que la conexión muere (los 22,3 s que
    /// delataron el fallo). Por eso aceptamos todo segmento que CUBRA el siguiente byte esperado y
    /// tomamos su cola desde `esperado - seq`; un duplicado exacto no aporta bytes y se descarta.
    ///
    /// Concatenar payloads a ciegas —lo que hacía el original— mezcla la retransmisión con el
    /// cuerpo (`buf = [0,60, 0,60, msg…]`) y devuelve un mensaje desincronizado cuyos 2 primeros
    /// bytes son el prefijo en vez del id.
    ///
    /// (Los tres defectos eran latentes en el harness de #4b; los afloró la carga añadida por los
    /// 15 tests de `kill-active`. El primero se diagnosticó por el id `[0,60]`; los otros dos por
    /// los 22,3 s de duración de la corrida + una sonda de la traza de segmentos. Cero cambio de
    /// producto.)
    ///
    /// `cli`/`client_seq` = el 5-tuple del cliente falso y su número de secuencia actual (no avanza:
    /// nuestros ACKs no llevan payload).
    pub(super) async fn recv_framed_dns_over_tcp(
        &mut self,
        from: SocketAddrV4,
        cli: SocketAddrV4,
        client_seq: i32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut next_seq: Option<i32> = None;
        loop {
            let seg = self
                .recv_tcp_egress_matching(|p| p.src == from && !p.payload.is_empty())
                .await;
            let len = i32::try_from(seg.payload.len()).expect("segmento de test < 2 GiB");
            let ack_to = seg.seq.wrapping_add(len);
            // Offset del siguiente byte que nos falta DENTRO de este segmento. `None` (primer
            // segmento) ⇒ empezamos por su inicio.
            let start = next_seq.map_or(0, |expected| expected.wrapping_sub(seg.seq));
            if start < 0 || start >= len {
                continue; // hueco por delante, o duplicado que no aporta bytes nuevos
            }
            let start = usize::try_from(start).expect("0 <= start < len");
            next_seq = Some(ack_to);
            buf.extend_from_slice(&seg.payload[start..]);
            // ACK del segmento: libera la ventana de Nagle para que salga el resto del mensaje.
            self.ingress_tx
                .send(build_tcp_pkt(
                    cli,
                    from,
                    TcpControl::None,
                    client_seq,
                    Some(ack_to),
                    &[],
                ))
                .expect("ACK del cliente falso");
            if buf.len() >= 2 {
                let msg_len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
                if buf.len() >= 2 + msg_len {
                    return buf[2..2 + msg_len].to_vec();
                }
            }
        }
    }
}

/// Un `Service` Dial-permitido con `intercept.v1` de CIDR literal (RUTAS OS: produce delta).
pub(super) fn cidr_service(name: &str, cidr: &str) -> Service {
    let config: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&format!(
            r#"{{"intercept.v1":{{"protocols":["tcp"],"addresses":["{cidr}"],"portRanges":[{{"low":80,"high":80}}]}}}}"#
        ))
        .unwrap();
    Service {
        id: format!("id-{name}"),
        name: name.into(),
        encryption_required: false,
        permissions: vec!["Dial".into()],
        config,
        configs: vec![],
    }
}
