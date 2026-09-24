//! Pila TCP/IP en espacio de usuario (M1 del arco intercept, superface (C) — sin oráculo Ziti,
//! design-correct + RFC 9293 + paridad con onetun/tun2proxy/netstack).
//!
//! Conecta el seam de paquetes crudos ([`IpPacketDevice`](crate::tunnel::intercept::device::IpPacketDevice)) con `netstack-smoltcp`, que convierte el
//! firehose de paquetes IP del utun en flujos lógicos: por cada SYN entrante (a CUALQUIER IP destino,
//! `any_ip` activado dentro de netstack) crea un socket smoltcp y entrega un `TcpStream`
//! (`AsyncRead`+`AsyncWrite`) listo para ser spliceado contra el overlay en M2.
//!
//! Arquitectura (§4 del diseño): tres tasks de fondo cooperan —
//!   1. el **Runner** de la pila (poll de smoltcp);
//!   2. **ingress** `device.recv → Stack` (inyecta el paquete IP crudo del utun en la pila);
//!   3. **egress** `Stack → device.send` (escribe el paquete IP que emite la pila de vuelta al utun).
//!
//! El `Stack` de netstack es a la vez `Sink<Vec<u8>>` (ingress) y `Stream<Vec<u8>>` (egress); se parte
//! con [`StreamExt::split`](futures_util::StreamExt::split) para conducir ambas direcciones en tasks independientes (un único `Stack`
//! no admite dos `&mut`).
//!
//! ## GATE del half-close (§4.2.1) — VERIFICADO EMPÍRICAMENTE en M1
//! El `splice` de T1 ([`crate::tunnel::proxy::splice`]) hace `sock_w.shutdown()` (`poll_shutdown`) para
//! medio-cerrar (FIN) su lado al recibir EOF del overlay. Ese `splice` se validó en vivo contra
//! `EdgeConn` + sockets reales del SO, NUNCA contra el `TcpStream` de netstack → era una suposición sin
//! confirmar y load-bearing. **Confirmado leyendo la fuente de netstack-smoltcp 0.2.3 + fijado con el
//! test `gate_poll_shutdown_emits_a_real_fin`:** `TcpStream::poll_shutdown` pone `send_state = Close`,
//! y el Runner llama entonces a `smoltcp::TcpSocket::close()` (tras drenar el send-buffer) → emite un
//! **FIN real** (no solo en `Drop`). El GATE PASA: el `TcpStream` de netstack encaja directo en el
//! `S: AsyncRead+AsyncWrite+Unpin` de `splice` sin vendorizar ni adaptar.
//!
//! ## ⚠ Matiz LOAD-BEARING para M2 (NO benigno — corregido tras revisión adversarial)
//! `poll_shutdown` de netstack devuelve `Ready` SOLO cuando el cierre es COMPLETO (`send_state ==
//! Closed`, que el Runner fija únicamente cuando el socket smoltcp alcanza `State::Closed`), NO `Ready`
//! justo tras emitir el FIN como hace un socket del SO. Consecuencia para el `splice` de M2 (que hace
//! `sock_w.shutdown().await` en la dirección overlay→socket):
//!  - **Caso común (cierre iniciado por el overlay**, p. ej. HTTP `Connection: close`): el `shutdown()`
//!    del lado socket pasa a ser el límite de vida y BLOQUEA ~10 s en TIME_WAIT (`CLOSE_DELAY` de
//!    smoltcp) antes de que el `join!` y el `zw.close()` (deregister) terminen — un socket del SO
//!    retornaría al instante. Es decir, "socket→overlay es el límite de vida" es FALSO en este sentido.
//!  - **Variante de CUELGUE NO ACOTADO**: si el overlay se cierra a mitad de sesión (`zr` EOF + error
//!    de escritura en `zw`) y la app local sigue viva (ACKea los keepalives) pero NUNCA manda su FIN, el
//!    lado socket queda en FinWait2 PARA SIEMPRE (FinWait2 no arma timer de cierre; el keepalive de 28 s
//!    refresca el last-read, así que el idle de 7200 s tampoco dispara) mientras `s2z` completa por el
//!    error de escritura → el `join!` cuelga y se filtran el conn-id y la task. Un socket del SO no
//!    colgaría aquí.
//!
//! **RESUELTO en M2a** por [`InterceptTcpStream`](super::stream::InterceptTcpStream): el adaptador
//! sondea el `poll_shutdown` del inner UNA vez (fija `send_state = Close` → el Runner dispara el FIN) y
//! retorna `Ready` sin esperar a `State::Closed`, como `shutdown(SHUT_WR)` de un socket del SO. El
//! `splice` de T1 queda INTACTO. [`accept`](InterceptStack::accept) entrega ya el stream ADAPTADO, así
//! que el half-close acotado es el contrato por defecto (M2b no puede olvidarlo). Ver `stream.rs`.

mod core;
mod udp_reply;

#[cfg(test)]
mod tests_gate;
#[cfg(test)]
mod tests_halfclose;
#[cfg(test)]
mod tests_split;
#[cfg(test)]
mod tests_udp;
#[cfg(test)]
mod testsupport;

pub use core::{InterceptStack, TcpHalf, UdpHalf};
pub use udp_reply::UdpReplySender;
