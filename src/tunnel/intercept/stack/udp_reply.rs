//! El camino de reply-egress UDP: `spawn_udp_reply_egress` (la 4ª task), su clasificador de error
//! por-datagrama `is_per_datagram_encode_error` y el emisor clonable [`UdpReplySender`] que el
//! handler usa para devolver datagramas al cliente (F6 tramo 16 troceo).

use std::io;
use std::net::SocketAddr;

use futures_util::SinkExt;
use netstack_smoltcp::udp::{UdpMsg, WriteHalf as UdpWriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Arranca la task de reply-egress UDP (la 4ª task, solo en [`InterceptStack::new_with_udp`](crate::tunnel::intercept::stack::InterceptStack::new_with_udp)): drena la
/// cola de respuestas (la llenan los vconns del handler vía [`UdpReplySender`]) y la escribe al
/// write-half de netstack, que codifica el IP+UDP y lo encola en la MISMA `stack_tx`/egress Stream que
/// el TCP → la task de egress lo escribe al device. Espejo del egress glue-task pero para el sumidero
/// UDP (el write-half necesita `&mut`, así que lo posee ESTA task y los vconns le hablan por un canal
/// clonable).
pub(super) fn spawn_udp_reply_egress(
    udp_write: UdpWriteHalf,
    mut udp_reply_rx: mpsc::Receiver<UdpMsg>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut udp_write = udp_write;
        while let Some(msg) = udp_reply_rx.recv().await {
            match udp_write.send(msg).await {
                Ok(()) => {}
                // Fallo de codificación POR-DATAGRAMA → se DESCARTA sin derribar el resto de respuestas
                // (familias v4/v6 mezcladas, o un payload que no serializa). Inalcanzable si el handler
                // reusa el `(dst, src)` de `recv_from` (misma familia, tamaño acotado); defensivo ante
                // un handler que construya un par mal formado.
                Err(e) if is_per_datagram_encode_error(&e) => {
                    tracing::warn!(error = %e, "intercept udp: respuesta no codificable, descartada");
                }
                // Solo el egress de la pila CERRADO es terminal (canal `stack_tx` cerrado) → fin de la
                // task.
                Err(e) => {
                    tracing::warn!(error = %e, "intercept udp: egress de respuestas cerrado");
                    break;
                }
            }
        }
    })
}

/// Clasifica un error de [`UdpWriteHalf`]`::send` como fallo de codificación POR-DATAGRAMA (descartar y
/// seguir) frente a egress de la pila cerrado (terminal). netstack-smoltcp 0.2.3 NO los distingue por
/// `ErrorKind` (los fallos de `start_send`/`flush` son ambos `Other`), solo por el mensaje:
///  - `InvalidData` "src or destination type unmatch": familias v4/v6 mezcladas (`start_send`).
///  - `Other` "PacketBuilder::write: …": serialización del frame IP+UDP fallida, p. ej. payload que
///    desborda el campo de longitud (`start_send`, `udp.rs:127-129`).
///
/// El resto de `Other` ("send error" de `start_send_unpin`, "flush error" de `poll_flush`, o el error
/// de `poll_ready`) viene de que el `stack_tx` se cerró → terminal. La clasificación por substring es
/// frágil-por-versión (pineada a 0.2.3) pero es la única señal que la API expone; exhaustiva en ambos
/// sentidos (ningún mensaje terminal contiene "PacketBuilder::write").
fn is_per_datagram_encode_error(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::InvalidData || e.to_string().contains("PacketBuilder::write")
}

/// Emisor clonable de respuestas UDP (ziti→udp) hacia los clientes locales. Obtenido de
/// [`InterceptStack::udp_reply_sender`](crate::tunnel::intercept::stack::InterceptStack::udp_reply_sender); encola en la cola de reply-egress de la pila.
#[derive(Clone)]
pub struct UdpReplySender {
    pub(super) tx: mpsc::Sender<UdpMsg>,
}

impl UdpReplySender {
    /// Rig de test: un emisor conectado a una cola de la que el test lee directamente, sin montar la
    /// pila (los tests de vconn de `intercept/udp/tests_framing.rs`/`intercept/udp/tests_teardown.rs` observan por aquí lo que el pump ziti→udp devolvería al
    /// cliente). Fuera de tests el ÚNICO origen sigue siendo [`InterceptStack::udp_reply_sender`](crate::tunnel::intercept::stack::InterceptStack::udp_reply_sender).
    #[cfg(test)]
    pub(crate) fn new_for_test(tx: mpsc::Sender<UdpMsg>) -> Self {
        Self { tx }
    }

    /// Devuelve `payload` al cliente como un datagrama UDP. `dst`/`src` son EXACTAMENTE el par que
    /// [`InterceptStack::recv_from`](crate::tunnel::intercept::stack::InterceptStack::recv_from) entregó para ese flujo (`dst` = destino interceptado, `src` =
    /// cliente); reusar el mismo par hace la simetría a prueba de errores de orden.
    ///
    /// **Swap de la respuesta (LOAD-BEARING):** el paquete de vuelta debe llevar IP `src = dst` (para
    /// que el cliente vea la respuesta venir DEL destino al que envió) e IP `dst = src` (entregarla al
    /// cliente). El `WriteHalf` de netstack codifica `UdpMsg = (payload, ip_src, ip_dst)`, así que
    /// encolamos `(payload, dst, src)`. Pineado en
    /// `udp_send_to_swaps_addresses_so_the_reply_comes_from_dst`.
    ///
    /// Hace backpressure (await) si la cola de reply-egress está llena — fiel a la dirección ziti→udp
    /// del oráculo (`socket.send_to(...).await`, sin drop). NOTA: el `WriteHalf` de netstack DESCARTA en
    /// silencio un datagrama de payload vacío (`start_send`: `if data.is_empty() { return Ok(()) }`).
    ///
    /// # Errors
    /// [`io::ErrorKind::BrokenPipe`] si la pila se desmontó (la task de reply-egress murió y cerró la
    /// cola). El handler puede tratarlo como "este flujo terminó" (espejo de un error de `send_to` en T3).
    pub async fn send_to(
        &self,
        payload: Vec<u8>,
        dst: SocketAddr,
        src: SocketAddr,
    ) -> io::Result<()> {
        self.tx.send((payload, dst, src)).await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "intercept udp: cola de respuestas cerrada (pila desmontada)",
            )
        })
    }

    /// Variante NO bloqueante de [`send_to`](Self::send_to): encola si hay hueco, o DESCARTA el
    /// datagrama si la cola de reply-egress está llena — `Ok(true)` = encolado, `Ok(false)` =
    /// descartado-por-llena. La usa la rama DNS del manager UDP (`udp_intercept_loop`): el manager NO
    /// puede aparcarse en un `await` de la cola compartida (dejaría de drenar `recv_from` y, con el
    /// canal UDP de netstack lleno, aparcaría la ingress COMPARTIDA congelando también TCP — el
    /// acople HOL que el invariante del manager prohíbe). Descartar una respuesta DNS bajo presión es
    /// seguro: DNS-sobre-UDP es lossy por diseño (el stub del cliente reintenta) y el oráculo tampoco
    /// aparca jamás su uv-loop por una respuesta DNS (encola el write async; su cola es unbounded —
    /// nuestra cola acotada + drop es la desviación consciente de memoria acotada).
    ///
    /// # Errors
    /// [`io::ErrorKind::BrokenPipe`] si la pila se desmontó (cola cerrada), igual que `send_to`.
    pub fn try_send_to(
        &self,
        payload: Vec<u8>,
        dst: SocketAddr,
        src: SocketAddr,
    ) -> io::Result<bool> {
        match self.tx.try_send((payload, dst, src)) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "intercept udp: cola de respuestas cerrada (pila desmontada)",
            )),
        }
    }
}
