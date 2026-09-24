//! M3-UDP-handler del arco intercept: el camino de FORWARDING UDP host→overlay — superface **(A)**
//! cara al overlay (`build_app_data` + dial, ya validados en vivo) sobre la fuente de datagramas UDP de
//! la pila netstack ([`InterceptStack::recv_from`](super::InterceptStack::recv_from)/[`new_with_udp`](super::InterceptStack::new_with_udp), M3-UDP-stack).
//!
//! Es el ESPEJO EMISOR de [`run_udp_proxy`](crate::tunnel::udp::run_udp_proxy) (T3) con tres cambios:
//!   1. la fuente de datagramas es [`InterceptStack::recv_from`](super::InterceptStack::recv_from) (utun → netstack), que entrega
//!      `(payload, dst, src)` — el `dst` es el destino ORIGINAL interceptado (T3 lo tenía implícito en
//!      el servicio fijo); y las respuestas salen por [`UdpReplySender::send_to`](super::UdpReplySender::send_to) (un canal hacia la
//!      task de reply-egress de la pila) en vez de un `Arc<UdpSocket>` compartido del SO;
//!   2. el servicio NO es fijo: [`InterceptResolver::lookup`](super::InterceptResolver::lookup) elige el servicio (y su dial-timeout) por
//!      el `(dst_ip, dst_port, Udp, src_ip)` del flujo, y se emite el `AppData` del destino interceptado;
//!   3. el flujo se demultiplexa por **`(src, dst)`** — DESVIACIÓN CONSCIENTE y más-correcta del
//!      oráculo (clase "validación más estricta"). El interceptor Go usa UN `udp_vconn.Manager` POR
//!      SERVICIO (`tproxy_linux.go:generateReadEvents` lee del `self.udpLn` de ESE servicio) keyeado por
//!      `srcAddr.String()` SOLO (`manager.go:79`,`:108`) → clave efectiva `(servicio, src)`; dentro de un
//!      servicio CONFLA un mismo `src` a dsts distintos (reusa el vconn keyeado por src, almacena el
//!      PRIMER `origDest` y responde DESDE ÉL). Nuestra captura es UNA pila netstack para TODOS los
//!      servicios con un resolver por-dst, así que keyamos `(src, dst)`: cada destino es un flujo propio
//!      (servicio correcto + respuesta desde el dst correcto), desambiguando el multi-dst que Go confla.
//!      En el caso COMÚN (un `src` → un `dst`) es IDÉNTICO al oráculo; sólo difiere bajo
//!      multi-dst-mismo-src, donde `(src, dst)` es estrictamente más correcto (no rompe nada que Go haga
//!      bien; refina un caso que Go resuelve mal). Coste: más conns ziti bajo multi-dst (una por dst vs
//!      una por src); el idle-reaper las limpia. Pineado en `flows_are_keyed_by_src_and_dst_not_src_alone`.
//!
//! El resto de la semántica de relay es IDÉNTICA a T3 (drop-on-full, idle-reaping, `halfClose=false`
//! sin FIN, una `Data` por datagrama udp→ziti, split en [`PROXY_BUF`](crate::tunnel::proxy::PROXY_BUF) ziti→udp): los oráculos de
//! relay/vconn son los MISMOS (ver `tunnel/udp` + `tunnel/udp_vconn/*`).
//!
//! **Desviación consciente (DRY):** la maquinaria de vconn (handle, route-decision, deliver, reap,
//! pumps) se DUPLICA aquí en vez de generalizar la de T3 (`crate::tunnel::udp`), para mantener el path
//! T3 ya validado en vivo BYTE-INTACTO (cero riesgo de regresión). Un refactor futuro podría extraer un
//! módulo `udp_vconn` compartido genérico sobre la clave y la fuente/sumidero.
//!
//! ~~**Diferido NOMBRADO (gap de superficie, no de este slice):** el cableado del subcomando para
//! correr TCP (`accept`) y UDP (`recv_from`) CONCURRENTEMENTE necesita partir el
//! [`InterceptStack`](super::InterceptStack).~~ CERRADO por el slice combinado: [`InterceptStack::split_mut`](super::InterceptStack::split_mut) parte las dos
//! superficies y [`super::combined::run_combined_intercept`] conduce ambos loops (este manager +
//! el accept-loop TCP) sobre UNA pila y UN resolver compartido — es lo que `main.rs` monta en
//! producción. [`run_udp_intercept`] sigue disponible como runner UDP-only standalone (lo usa el
//! harness e2e de M3-UDP).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

mod dns_dispatch;
mod flow;
mod pump;
mod runner;
mod upstream;
mod vconn;

#[cfg(test)]
mod tests_appdata;
#[cfg(test)]
mod tests_dns;
#[cfg(test)]
mod tests_flow;
#[cfg(test)]
mod tests_framing;
#[cfg(test)]
mod tests_runner;
#[cfg(test)]
mod tests_teardown;
#[cfg(test)]
mod tests_upstream;
#[cfg(test)]
mod testsupport;

#[cfg(test)]
pub(crate) use dns_dispatch::dns_response;
pub(crate) use runner::udp_intercept_loop;
pub use runner::{run_udp_intercept, run_udp_intercept_with_dns};

/// Per-source inbound queue depth: datagrams waiting to be forwarded to ziti. When full, a new datagram
/// is DROPPED (UDP is lossy — no backpressure). Oracle: `udpConn.readC` = `make(chan .., 16)`.
const VCONN_QUEUE_DEPTH: usize = 16;

/// Idle reaping threshold: a vconn with no traffic in EITHER direction for this long is reaped.
/// Oracle: `defaultExpirationPolicy.IsExpired` = `now − lastUsed > 5*time.Minute` (`policy.go:61`).
/// `pub(crate)`: el runner combinado (`combined`) pasa el MISMO default de producción al loop.
pub(crate) const VCONN_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Cadence of the idle-reaping sweep. Oracle: `defaultExpirationPolicy.PollFrequency` = `30*time.Second`.
/// `pub(crate)`: el runner combinado (`combined`) pasa el MISMO default de producción al loop.
pub(crate) const VCONN_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on consecutive [`super::stack::InterceptStack::recv_from`] `None`s before the manager presumes the stack
/// CLOSED and stops. `recv_from()->None` is AMBIGUOUS (M3-UDP-stack named deferral): a single malformed
/// UDP-in-valid-IP datagram collapses netstack's `ReadHalf` `Stream` to `Poll::Ready(None)` (TRANSIENT —
/// the receiver is NOT latched, the next poll resumes), which is indistinguishable from a genuinely
/// closed stack (`None` forever). We CONTINUE on `None` to recover from a bad datagram (the next
/// `recv_from` awaits or yields the next datagram), but bound consecutive `None`s so a closed/zombie
/// stack does not busy-spin. Set well above netstack's `udp_buffer_size` (512) so a one-shot channel-fill
/// of malformed datagrams cannot trip it (no practical one-shot DoS); only an UNBOUNDED stream of
/// immediate `None`s (a closed stack) reaches it. Residual (named, re-evaluado para el runner
/// COMBINADO): the counter is CONSECUTIVE and resets ONLY on a valid datagram (NOT time-windowed), so
/// 1024 malformed datagrams with no valid datagram interleaved trip it — and under
/// `run_combined_intercept` that tears down the WHOLE tunneler (select!), a data-path-triggered
/// shutdown the oracle does not have (its uv-loop never dies from a packet). Mitigación: el trip
/// retorna **`Err(UnexpectedEof)`** (nunca `Ok`), así el subcomando termina con error/exit≠0 — un
/// teardown RUIDOSO que un supervisor ve como fallo, jamás un éxito silencioso. Reachability sigue
/// estrecha (fabricar UDP-malformado-en-IP-válido sobre el utun exige raw sockets/root o un quirk de
/// netstack). A time-windowed reset (e.g. clearing the counter on the reap tick) would harden it
/// further; deferred. (`pub(crate)`: el test de regresión del teardown ruidoso en `combined` dispara
/// EXACTAMENTE este límite.)
pub(crate) const MAX_CONSECUTIVE_RECV_NONE: u32 = 1024;

/// The per-flow demux key. UNLIKE T3 (keyed by `src` alone, fixed service), the intercept captures
/// MANY destinations, so a flow is `(src, dst)`: the same client `src` may target different `dst`s
/// (different services, different reply origins).
type FlowKey = (SocketAddr, SocketAddr);

/// A per-flow virtual connection handle, held by the manager in its `conns` map. The vconn TASK owns the
/// other ends (`in_rx`, the ziti halves); this handle is the manager's side. (Mirror of T3's `Vconn`.)
struct Vconn {
    /// Inbound datagrams (udp→ziti). Bounded ([`VCONN_QUEUE_DEPTH`]); full ⇒ drop (oracle `Accept`).
    in_tx: mpsc::Sender<Vec<u8>>,
    /// Last activity in EITHER direction (the vconn task bumps it); the manager reads it in the reaper.
    last_use: Arc<Mutex<Instant>>,
    /// Set by the vconn task at teardown (dial failure OR ziti EOF OR write/send error). The manager
    /// treats a `closed` handle as absent (create a fresh vconn) and sweeps it.
    closed: Arc<AtomicBool>,
}

/// El socket + la tabla de requests en vuelo del forwarding a upstream DNS (M3-DNS #1). Vive en el
/// manager UDP; espejo del estado `ziti_dns.upstream`/`ziti_dns.requests` global del oráculo
/// (`ziti_dns.c:113-117`). El socket lo posee ESTE loop (recv en su propia rama del `select!`, envío
/// síncrono no-bloqueante en la rama DNS) — nunca cruza un `await` sostenido ni una task. Lo
/// construye el runner combinado ([`super::combined::run_combined_intercept`]) vía [`Self::bind`].
pub(crate) struct UpstreamDns {
    /// Socket UDP local desde el que se reenvía a los upstreams y por el que llegan sus respuestas
    /// (espejo de `ziti_dns.upstream`, `uv_udp_t`).
    socket: tokio::net::UdpSocket,
    /// Los servidores upstream configurados (`ziti_dns.upstream_addr[..num_dns_up]`). El request se
    /// reenvía a TODOS (`query_upstream:856-865`); la 1ª respuesta que casa el ID gana.
    servers: Vec<SocketAddr>,
    /// Requests en vuelo, keyed por ID DNS (`ziti_dns.requests`): el ID → a quién devolver la
    /// respuesta (`(dns_ip:53, cliente)`, el par de `reply.send_to`) + cuándo se registró (para la
    /// eviction por TTL, ver [`DNS_UPSTREAM_TIMEOUT`]).
    pending: HashMap<u16, PendingUpstream>,
}

/// Un request DNS en vuelo hacia upstream: a dónde devolver su respuesta y cuándo se emitió.
struct PendingUpstream {
    /// `dst` de `reply.send_to` = la dirección del servidor DNS embebido `(dns_ip, 53)` (la respuesta
    /// aparece VENIR de ahí).
    server_addr: SocketAddr,
    /// `src` de `reply.send_to` = el cliente que preguntó (a quién va la respuesta).
    client_addr: SocketAddr,
    /// Instante de registro, para la eviction por TTL.
    at: Instant,
}

/// Tamaño del buffer de recepción de respuestas upstream. El oráculo usa `dns_buf[1024]`
/// (`dns_upstream_alloc:870-874`) y trunca en libuv toda respuesta >1024 (su check
/// `rc <= sizeof(resp)` de 4096 pasa siempre porque rc ≤ 1024). Usamos `DNS_BUF` (4096, el tamaño
/// del buffer de respuesta) → una respuesta de 1025..4096 bytes que el oráculo truncaría a 1024
/// nosotros la pasamos ENTERA. Divergencia CONSCIENTE y estrictamente más correcta (el oráculo
/// mutila respuestas legítimas grandes; nosotros no). Una respuesta >4096 el kernel la TRUNCA a 4096
/// en `recv` (`Ok(4096)`, sin error) y la reenviamos como prefijo (el match del ID por los 2 primeros
/// bytes queda intacto) — NO se descarta; benigno e inalcanzable en la práctica (una respuesta DNS
/// sobre UDP no excede 4096 con EDNS0, y exactamente 4096 es una respuesta máxima válida, así que no
/// tratamos `n == 4096` como truncación para no dropear una respuesta legítima al tope).
const DNS_UPSTREAM_BUF: usize = 4096;

/// TTL de un request upstream en vuelo. El oráculo NO tiene timeout — libera el `dns_req` cuando la
/// respuesta llega (`complete_dns_req`) o cuando el cliente cierra (`on_dns_close`); un request cuya
/// respuesta upstream se pierde vive hasta que el cliente cierra. Nosotros no modelamos el ciclo de
/// vida del cliente DNS (es connectionless sobre netstack), así que un TTL acota el mapa de pending:
/// una respuesta que llega tras el TTL ya no casa (se descarta, como un ID desconocido). Divergencia
/// CONSCIENTE (memoria acotada vs el mapa ligado-al-cliente del oráculo); generoso para no cortar una
/// respuesta upstream lenta legítima.
///
/// `pub(crate)` para que el path DNS-over-TCP (#4b, `super::dns_tcp::forward_tcp::forward_upstream_tcp`) reuse el
/// MISMO horizonte que el forward UDP: cambio de VISIBILIDAD solamente (precedente `PROXY_BUF` en T3).
pub(crate) const DNS_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
