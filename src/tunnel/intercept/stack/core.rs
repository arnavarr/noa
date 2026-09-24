//! El stack netstack de intercept y sus vistas: [`InterceptStack`] (struct + `impl` con
//! new/new_with_udp/accept/recv_from/udp_reply_sender/split_mut + los 3 spawn) + su `impl Drop`
//! (abort-on-Drop de las tasks), las vistas de `split_mut` [`TcpHalf`]/[`UdpHalf`] y la surface UDP
//! privada. La fachada del módulo re-exporta los tipos públicos (F6 tramo 16 troceo).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use netstack_smoltcp::udp::{ReadHalf as UdpReadHalf, UdpMsg};
use netstack_smoltcp::{StackBuilder, TcpListener};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::tunnel::intercept::device::IpPacketDevice;
use crate::tunnel::intercept::stream::InterceptTcpStream;

use super::udp_reply::{UdpReplySender, spawn_udp_reply_egress};

/// Profundidad de la cola de respuestas UDP (handler → write-half de netstack). NO es una constante del
/// oráculo: es el buffer de plumbing entre los vconns que emiten respuestas (vía [`UdpReplySender`]) y la
/// task de egress UDP que las escribe a netstack. [`UdpReplySender::send_to`] hace backpressure (await)
/// al llenarse — fiel a la dirección ziti→udp del oráculo (`socket.send_to(...).await`, sin drop), a
/// diferencia del drop-on-full de la cola de ENTRADA por-origen (esa es scope del handler, T3).
const UDP_REPLY_QUEUE_DEPTH: usize = 1024;

/// Buffer de lectura del device: un datagrama IP cabe sobradamente en 64 KiB (el máximo de un paquete
/// IPv4/IPv6 no fragmentado), así que nunca truncamos un paquete entregado por el utun.
const DEVICE_READ_BUF: usize = 65535;

/// Surface UDP de la pila: solo existe cuando la pila se construyó con UDP habilitado
/// ([`InterceptStack::new_with_udp`]). Agrupa el read-half de netstack y la cabeza de la cola de
/// respuestas en UN único `Option` de la pila — un TCP-only [`InterceptStack`] no tiene NINGÚN estado
/// UDP (ni canal, ni task de reply-egress), así que estos campos no pueden existir a medias.
pub(super) struct UdpSurface {
    /// Read-half del socket UDP de netstack: la fuente de datagramas UDP entrantes. Cada
    /// [`recv_from`](InterceptStack::recv_from) entrega un datagrama con su `(dst, src)`.
    read: UdpReadHalf,
    /// Cabeza de la cola de respuestas UDP: sus clones (vía
    /// [`udp_reply_sender`](InterceptStack::udp_reply_sender)) los usan los vconns del handler para
    /// devolver datagramas al cliente; la drena la task de reply-egress, dueña del write-half UDP.
    reply_tx: mpsc::Sender<UdpMsg>,
}

/// Pila TCP/IP de intercept montada sobre un [`IpPacketDevice`].
///
/// Posee sus tasks de fondo (`runner + ingress + egress`, y `+ reply-egress UDP` SOLO si se construyó
/// con [`new_with_udp`](Self::new_with_udp)), el `TcpListener` y —opcionalmente— la surface UDP. Al
/// soltarse (`Drop`) aborta TODAS las tasks que tenga, sean 3 o 4 (espejo del abort-on-Drop del
/// rx-loop/probe del edge): sin esto quedarían huérfanas conduciendo un device ya inservible.
///
/// **UDP es opt-in todo-o-nada.** [`new`](Self::new) monta una pila TCP-only byte-idéntica a la
/// pre-M3 (`enable_udp(false)`, 3 tasks, sin canal UDP); es lo que usa el subcomando `noa intercept`
/// vivo, que solo hace `accept()` y NUNCA drena UDP. Habilitar UDP sin drenarlo encolaría datagramas
/// en el canal acotado de netstack (`udp_buffer_size`, 512) hasta que `Stack::poll_send` devuelve
/// `Pending` para el siguiente datagrama UDP y aparca el ÚNICO task de ingress que comparten TCP y UDP
/// → el datapath TCP vivo se atascaría para siempre. Por eso la surface UDP (read-half + reply_tx + la
/// 4ª task) SOLO existe en [`new_with_udp`](Self::new_with_udp), que el handler M3-UDP (que sí drena
/// con `recv_from`) usará.
///
/// **TCP (M1+):** [`accept`](Self::accept) entrega flujos `(InterceptTcpStream, dst, src)`.
/// **UDP (M3-UDP-stack, opt-in):** con `new_with_udp`, [`recv_from`](Self::recv_from) entrega
/// datagramas entrantes `(payload, dst, src)` y [`udp_reply_sender`](Self::udp_reply_sender) da un
/// emisor clonable para devolver respuestas; en una pila TCP-only `recv_from` da `None` y
/// `udp_reply_sender` da `None`. UDP es connectionless: NO pasa por el Runner ni por sockets smoltcp —
/// netstack reparsea el frame IP+UDP crudo en ambas direcciones (passthrough por canales).
///
/// **Semántica de fallo parcial (consciente, M1):** las tasks son independientes — si UNA muere
/// (p. ej. un error de E/S del device en la ingress) las otras SIGUEN vivas (pila "zombie": ya no
/// procesa tráfico pero no se desmonta sola hasta el `Drop`). Aceptable; un cancel compartido
/// "muere-una → mueren-todas" queda como endurecimiento nombrado para M3 (junto con el seam del DNS).
pub struct InterceptStack {
    listener: TcpListener,
    /// Surface UDP, presente SOLO si la pila se construyó con [`new_with_udp`](Self::new_with_udp).
    /// `None` en una pila TCP-only → sin canal UDP, sin task de reply-egress, sin estado UDP a medias.
    pub(super) udp: Option<UdpSurface>,
    pub(super) tasks: Vec<JoinHandle<()>>,
}

impl InterceptStack {
    /// Monta una pila **TCP-only** sobre `device` y arranca las tres tasks de fondo (runner + ingress
    /// + egress). El MTU se toma del device. **NO habilita UDP**: byte-idéntica a la pila pre-M3.
    ///
    /// `enable_tcp(true)` hace que netstack cree un socket smoltcp por cada SYN entrante con `any_ip`
    /// (acepta CUALQUIER IP destino — justo lo que un interceptor necesita: no conoce de antemano las
    /// IPs de los servicios). Con `enable_udp(false)` netstack DESCARTA los datagramas UDP entrantes en
    /// `Stack::poll_send` SIN backpressure (`udp_tx` es `None` → retorno temprano `Ok`), así que un
    /// consumidor que solo hace `accept()` (el subcomando `noa intercept` vivo) NUNCA puede atascar la
    /// ingress compartida con UDP no drenado. Para interceptar UDP usa
    /// [`new_with_udp`](Self::new_with_udp), que además OBLIGA a drenar con
    /// [`recv_from`](Self::recv_from).
    ///
    /// # Errors
    /// Propaga el error de `StackBuilder::build` (construcción de la interfaz smoltcp).
    pub fn new<D>(device: D) -> io::Result<Self>
    where
        D: IpPacketDevice + 'static,
    {
        Self::build_inner(device, false)
    }

    /// Monta una pila TCP **y UDP** sobre `device` y arranca las CUATRO tasks de fondo (runner +
    /// ingress + egress + reply-egress UDP). Habilita la surface UDP: con esta construcción
    /// [`recv_from`](Self::recv_from) entrega los datagramas entrantes y
    /// [`udp_reply_sender`](Self::udp_reply_sender) da el emisor clonable de respuestas (ambos dan
    /// `None`/`None` en una pila construida con [`new`](Self::new)).
    ///
    /// **Contrato LOAD-BEARING — quien habilite UDP DEBE drenar `recv_from` en bucle.** El canal de
    /// ingreso UDP de netstack está acotado a `udp_buffer_size` (512); si no se drena, al llenarse
    /// `Stack::poll_send` devuelve `Pending` para el siguiente datagrama UDP y aparca el ÚNICO task de
    /// ingress que comparten TCP y UDP → atascaría también el datapath TCP vivo. Por eso UDP es opt-in:
    /// una pila que no vaya a drenar UDP debe usar [`new`](Self::new) (TCP-only, drop-free). Lo usará el
    /// handler M3-UDP (que sí drena con `recv_from`).
    ///
    /// # Errors
    /// Propaga el error de `StackBuilder::build` (construcción de la interfaz smoltcp).
    pub fn new_with_udp<D>(device: D) -> io::Result<Self>
    where
        D: IpPacketDevice + 'static,
    {
        Self::build_inner(device, true)
    }

    /// Constructor compartido: monta la pila y arranca las tasks. Con `enable_udp == false` la pila es
    /// **byte-idéntica a la pre-M3** (3 tasks, sin canal UDP, surface UDP ausente); con `true` añade la
    /// surface UDP y la 4ª task de reply-egress. La rama TCP (1-3) es común a ambos y no toca `udp`.
    fn build_inner<D>(device: D, enable_udp: bool) -> io::Result<Self>
    where
        D: IpPacketDevice + 'static,
    {
        let mtu = usize::from(device.mtu());
        let (stack, runner, udp, listener) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(enable_udp)
            .mtu(mtu)
            .build()?;
        // enable_tcp(true) ⇒ runner y listener son Some; el expect es un invariante del builder, no
        // entrada externa.
        let runner = runner.expect("enable_tcp(true) garantiza un Runner");
        let listener = listener.expect("enable_tcp(true) garantiza un TcpListener");

        let device = Arc::new(device);
        // Sink = ingress (device→pila), Stream = egress (pila→device).
        let (mut sink, mut egress) = stack.split();

        // 1. Runner de la pila (poll de smoltcp). El `Runner` de netstack es `Send` incondicionalmente.
        let runner_task = tokio::spawn(async move {
            if let Err(e) = runner.await {
                tracing::warn!(error = %e, "intercept: el runner de la pila terminó con error");
            }
        });

        // 2. Ingress: device.recv → pila.
        let dev_in = Arc::clone(&device);
        let ingress_task = tokio::spawn(async move {
            let mut buf = vec![0u8; DEVICE_READ_BUF];
            loop {
                match dev_in.recv(&mut buf).await {
                    Ok(0) => break, // EOF del device
                    Ok(n) => {
                        if sink.send(buf[..n].to_vec()).await.is_err() {
                            break; // la pila se cerró
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "intercept: recv del device falló");
                        break;
                    }
                }
            }
        });

        // 3. Egress: pila → device.send.
        let dev_out = device;
        let egress_task = tokio::spawn(async move {
            while let Some(pkt) = egress.next().await {
                match pkt {
                    Ok(pkt) => {
                        if let Err(e) = dev_out.send(&pkt).await {
                            tracing::warn!(error = %e, "intercept: send al device falló");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "intercept: egress de la pila falló");
                        break;
                    }
                }
            }
        });

        let mut tasks = vec![runner_task, ingress_task, egress_task];

        // 4. Surface UDP, SOLO con `enable_udp`: split del socket, canal de respuestas y la 4ª task de
        //    reply-egress. Con `enable_udp == false` NO se toca `udp` (queda `None`, se dropea) → ni
        //    canal, ni task, ni estado UDP a medias: la pila es la TCP-only byte-idéntica a la pre-M3.
        let udp = if enable_udp {
            // enable_udp(true) ⇒ `udp` es Some; el expect es invariante del builder, no entrada externa.
            let (udp_read, udp_write) = udp
                .expect("enable_udp(true) garantiza un UdpSocket")
                .split();
            let (udp_reply_tx, udp_reply_rx) = mpsc::channel::<UdpMsg>(UDP_REPLY_QUEUE_DEPTH);
            tasks.push(spawn_udp_reply_egress(udp_write, udp_reply_rx));
            Some(UdpSurface {
                read: udp_read,
                reply_tx: udp_reply_tx,
            })
        } else {
            None
        };

        Ok(Self {
            listener,
            udp,
            tasks,
        })
    }

    /// Acepta el siguiente flujo TCP interceptado. Devuelve `(stream, dst, src)`:
    /// - `stream` = un [`InterceptTcpStream`] (el `TcpStream` de netstack envuelto con half-close
    ///   ACOTADO, M2a) listo para splicear contra el overlay sin colgarse en el cierre;
    /// - `dst` = la dirección DESTINO ORIGINAL que el cliente local quería alcanzar — la clave que el
    ///   resolver (B) mapeará a un servicio ziti y que el emisor de `AppData` (M2b) pondrá en `dst_*`;
    /// - `src` = la dirección ORIGEN local del cliente.
    ///
    /// `None` cuando la pila se cierra (no llegan más flujos).
    ///
    /// **Half-close acotado (M2a):** se envuelve el `TcpStream` de netstack en [`InterceptTcpStream`]
    /// AQUÍ, en la frontera, para que TODO consumidor (M2b incluido) reciba el stream con el
    /// `poll_shutdown` acotado y `splice` (T1) no se cuelgue nunca en el half-close. Ver `stream.rs`.
    ///
    /// **Corrección de fidelidad sobre el diseño (verificada en fuente):** el `TcpListener` de
    /// netstack-smoltcp 0.2.3 entrega la tupla `(stream, local_addr, remote_addr)` donde
    /// `local_addr == src` (origen del paquete = cliente) y `remote_addr == dst` (destino interceptado)
    /// — al revés de lo que apuntaba el §4 del diseño ("local=dst"). Aquí REORDENAMOS a `(stream, dst,
    /// src)` para que el contrato de salida sea inequívoco: nunca devolvemos el destino y el origen
    /// confundidos (un swap rompería la resolución de servicio). Pineado en
    /// `accept_yields_dst_then_src_not_swapped`.
    pub async fn accept(&mut self) -> Option<(InterceptTcpStream, SocketAddr, SocketAddr)> {
        // Delegado en la vista [`TcpHalf`] (el mismo código que conduce el runner combinado tras
        // `split_mut`): el reorden `(stream, dst, src)` vive en UN único sitio.
        TcpHalf {
            listener: &mut self.listener,
        }
        .accept()
        .await
    }

    /// Acepta el siguiente datagrama UDP interceptado. Devuelve `(payload, dst, src)`:
    /// - `payload` = los bytes del datagrama;
    /// - `dst` = la dirección DESTINO ORIGINAL que el cliente local quería alcanzar — la clave que el
    ///   resolver (B) mapea a un servicio ziti (`resolver.lookup(dst.ip(), dst.port(), Protocol::Udp,
    ///   src.ip())`) y que el emisor de `AppData` (handler) pondrá en `dst_*`;
    /// - `src` = la dirección ORIGEN local del cliente (la clave de demux por-origen del handler, y el
    ///   destino al que [`UdpReplySender::send_to`] devuelve las respuestas).
    ///
    /// **Reordenación de fidelidad (espejo EXACTO de [`accept`](Self::accept)):** el `ReadHalf` de
    /// netstack-smoltcp entrega `UdpMsg = (payload, local_src, remote_dst)` (`src_addr` del paquete =
    /// cliente, `dst_addr` = destino interceptado; ver `netstack_smoltcp::udp::ReadHalf::poll_next`).
    /// REORDENAMOS a `(payload, dst, src)` para que el 2º elemento sea SIEMPRE el destino y el 3º el
    /// origen — el MISMO contrato que `accept` y el MISMO orden de identidades que `send_to` consume, así
    /// el handler no puede confundirlos. Pineado en `udp_recv_from_yields_payload_with_dst_then_src`.
    ///
    /// **Pila TCP-only:** si la pila se construyó con [`new`](Self::new) (UDP NO habilitado) `recv_from`
    /// devuelve `None` de inmediato — no hay surface UDP que drenar. Solo `new_with_udp` la habilita.
    ///
    /// **Contrato de `None` (LOAD-BEARING para el handler):** `None` NO significa inequívocamente "la
    /// pila se cerró". El `Stream` del `ReadHalf` colapsa a `Poll::Ready(None)` también cuando un frame
    /// UDP no parsea (`udp_rx.poll_recv → Some(frame)` pero el `.and_then` del parse da `None`), y
    /// `Stack::start_send` solo valida la capa IP, NO la cabecera UDP — así que un único datagrama UDP
    /// malformado en el utun (IPv4 válido, proto=17, UDP truncado) devuelve `None` AUNQUE queden
    /// datagramas en cola. Consecuencia: un bucle `while let Some(..) = recv_from()` trataría un solo
    /// paquete malo como "cerrar todo" (un mini-DoS de un paquete sobre TODO el UDP). El handler
    /// (M3-UDP-handler) debe diseñar su loop manager teniéndolo en cuenta (no derribar todos los flujos
    /// ante el primer `None`). No se puede distinguir aquí: el `Stream` no da señal que separe cierre de
    /// fallo-de-parse, y el `ReadHalf` solo expone el `Stream`. Diferido NOMBRADO al handler.
    pub async fn recv_from(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        // En una pila TCP-only ([`new`]) NO hay surface UDP → `None` de inmediato (UDP no habilitado),
        // nunca un unwrap. Solo `new_with_udp` puebla `self.udp`. Delegado en la vista [`UdpHalf`]
        // (el mismo código que conduce el runner combinado tras `split_mut`): el reorden
        // `(payload, dst, src)` vive en UN único sitio.
        UdpHalf {
            read: &mut self.udp.as_mut()?.read,
        }
        .recv_from()
        .await
    }

    /// Un emisor clonable de respuestas UDP hacia los clientes, o `None` en una pila TCP-only ([`new`](Self::new)):
    /// ahí no existe la task de reply-egress que drenaría la cola, así que devolver un emisor sería un
    /// canal sin sumidero. Solo `new_with_udp` lo da `Some`. El handler clona uno por vconn (o lo
    /// comparte) para devolver datagramas. Espejo del `Arc<UdpSocket>` compartido de T3
    /// ([`crate::tunnel::udp::run_udp_proxy`]) — aquí el write-half de netstack lo posee la task de
    /// reply-egress y el `UdpReplySender` le habla por el canal.
    #[must_use]
    pub fn udp_reply_sender(&self) -> Option<UdpReplySender> {
        self.udp.as_ref().map(|udp| UdpReplySender {
            tx: udp.reply_tx.clone(),
        })
    }

    /// Parte las dos superficies de la pila en vistas MUTABLES independientes: la TCP ([`TcpHalf`],
    /// `accept`) y la UDP ([`UdpHalf`], `recv_from`; `None` en una pila TCP-only). Es el seam que el
    /// subcomando COMBINADO necesita (diferido nombrado de M3-UDP-handler): [`Self::accept`] y
    /// [`Self::recv_from`] toman ambos `&mut self`, así que sin el split solo UNO de los dos loops
    /// (accept-loop TCP / manager UDP) podría conducirse a la vez. Los campos subyacentes (`listener`
    /// vs `udp.read`) son disjuntos — el split es un borrow-split puro, sin estado nuevo ni cambio de
    /// teardown: la pila sigue siendo la dueña de las tasks de fondo y su `Drop` (cuando el llamante
    /// la suelte, DESPUÉS de que ambas vistas mueran) las aborta igual que antes.
    pub fn split_mut(&mut self) -> (TcpHalf<'_>, Option<UdpHalf<'_>>) {
        (
            TcpHalf {
                listener: &mut self.listener,
            },
            self.udp.as_mut().map(|u| UdpHalf { read: &mut u.read }),
        )
    }
}

/// Vista mutable de la superficie TCP de la pila (obtenida de [`InterceptStack::split_mut`]): conduce
/// el accept-loop CONCURRENTEMENTE con el drenado UDP ([`UdpHalf`]) sobre la MISMA pila. No posee las
/// tasks de fondo (la pila conserva el teardown); solo presta el `TcpListener`.
pub struct TcpHalf<'a> {
    listener: &'a mut TcpListener,
}

impl TcpHalf<'_> {
    /// Idéntico contrato que [`InterceptStack::accept`] (que DELEGA aquí, así el reorden
    /// `(stream, dst, src)` vive en un único sitio): `dst` = destino ORIGINAL interceptado, `src` =
    /// origen del cliente; `None` cuando la pila se cierra. Ver el doc de `accept` para el porqué del
    /// reorden (netstack entrega `(stream, local=src, remote=dst)`) y el half-close acotado (M2a).
    pub async fn accept(&mut self) -> Option<(InterceptTcpStream, SocketAddr, SocketAddr)> {
        self.listener
            .next()
            .await
            .map(|(stream, local_src, remote_dst)| {
                (InterceptTcpStream::new(stream), remote_dst, local_src)
            })
    }
}

/// Vista mutable de la superficie UDP de la pila (obtenida de [`InterceptStack::split_mut`], solo en
/// una pila [`InterceptStack::new_with_udp`]): conduce el drenado de datagramas CONCURRENTEMENTE con
/// el accept-loop TCP ([`TcpHalf`]) sobre la MISMA pila. Solo presta el read-half; el emisor de
/// respuestas se obtiene ANTES del split vía [`InterceptStack::udp_reply_sender`] (toma `&self` y el
/// `UdpReplySender` es clonable/owned, no necesita el split).
pub struct UdpHalf<'a> {
    read: &'a mut UdpReadHalf,
}

impl UdpHalf<'_> {
    /// Idéntico contrato que [`InterceptStack::recv_from`] (que DELEGA aquí, así el reorden
    /// `(payload, dst, src)` vive en un único sitio), INCLUIDO el contrato de `None` ambiguo
    /// (transitorio por datagrama malformado vs cierre — ver el doc de `recv_from`; el manager UDP lo
    /// maneja con bounded-continue).
    pub async fn recv_from(&mut self) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        self.read
            .next()
            .await
            .map(|(payload, local_src, remote_dst)| (payload, remote_dst, local_src))
    }
}

impl Drop for InterceptStack {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
