//! Runner COMBINADO del intercept (subcomando TCP+UDP+DNS): conduce el accept-loop TCP
//! ([`super::tcp::tcp_intercept_loop`]) y el manager UDP con el servidor DNS embebido montado
//! ([`super::udp::udp_intercept_loop`]) CONCURRENTEMENTE sobre UNA pila ([`crate::tunnel::intercept::stack::InterceptStack::split_mut`])
//! y UN resolver compartido. Cierra el diferido nombrado de M3-UDP-handler ("la fusión TCP+UDP es un
//! slice combinado") y con él la reachability en producción de M3-DNS entero: un cliente real puede
//! por fin resolver un nombre contra `(dns_ip, 53)` y que el paquete siguiente (TCP o UDP) despache.
//! (El mecanismo completo está validado in-process — el runner REAL sirviendo DNS por un device
//! mock —; la **aceptación LIVE** con utun/root/overlay reales es el gate de
//! `docs/M3-DNS-live-runbook.md`, pendiente.)
//!
//! ## Oráculo
//! `ziti-edge-tunnel run` (`ziti-tunnel-sdk-c` v1.15.1 `2addfbb`, `ziti-edge-tunnel.c`): UN solo
//! tunneler monta el tun, los intercepts de AMBOS protocolos y el DNS embebido sobre el MISMO netif
//! lwIP y el MISMO estado global `ziti_dns` (`run_tunnel:849` → `ziti_dns_setup:940`; `tun_ip` =
//! primera IP del rango, `dns_ip = tun_ip+1`, `:1491-1492`). No existe un modo TCP-only upstream —
//! el subcomando combinado es el análogo fiel; el `noa intercept` TCP-only previo era el andamio de
//! M2b, no el contrato.
//!
//! Nota de la clase all-capture (desviación ya documentada en `intercept/resolve`/`tcp.rs`, extendida aquí
//! a la dirección del propio DNS): un SYN **TCP** a `(dns_ip, 53)` completa el handshake en netstack
//! y se descarta al no casar intercept (la IP está reservada) — el oráculo registra el intercept
//! `ziti:dns-resolver` SOLO con protocolo udp (`ziti_dns.c:188-190`) y lwIP respondería RST sin
//! establecer. Un stub DNS-over-TCP (RFC 7766 / fallback TC=1) ve "conexión aceptada y cortada" en
//! vez de "rechazada"; el servidor embebido es UDP-only en ambos lados.
//!
//! ## El punto load-bearing: el resolver es UNO, compartido entre los dos loops
//! El servidor DNS (camino UDP) ASIGNA una IP sintética al resolver una query bajo un dominio
//! wildcard (`ziti_dns_lookup` LAZY) — y el dispatch per-paquete (camino TCP **y** UDP,
//! `intercept_match_addr`) debe VER esa asignación para despachar el flujo siguiente. Con dos
//! resolvers clonados el dispatch TCP nunca vería las IPs asignadas por queries (under-dispatch
//! divergente del oráculo, cuyo `ziti_dns` es un global único). Por eso ambos loops reciben
//! `&RefCell<InterceptResolver>` del MISMO `RefCell`; ambos corren en el MISMO hilo (un `LocalSet`) y
//! todos sus borrows son síncronos y mueren antes de cualquier `await` (documentado y sostenido en
//! cada loop — un borrow vivo a través de un `await` paniquearía el otro loop).
//!
//! ## Teardown
//! `tokio::select!`: el primer loop que termina derriba el runner ENTERO; al retornar, `stack` (por
//! valor) se dropea → aborta las 4 tasks de fondo → el otro camino muere también. Espejo del modelo
//! mono-loop del oráculo (si el uv-loop / el tun cae, cae todo el tunneler) y de la semántica ya
//! establecida por-loop (el `JoinSet` del accept-loop aborta los splices en vuelo al dropearse; los
//! vconns UDP mueren con el `LocalSet` del subcomando). El CÓMO termina distingue el caso: pila
//! cerrada limpia (`accept → None` / reply-egress cerrado) → `Ok`; el bounded-continue del manager
//! UDP agotado (heurístico de pila-presuntamente-cerrada, el ÚNICO teardown disparable por input del
//! data-path — camino que el oráculo no tiene) → **`Err(UnexpectedEof)`**, para que el subcomando
//! salga con fallo RUIDOSO y no con un éxito silencioso (ver `MAX_CONSECUTIVE_RECV_NONE`).

mod runner;

#[cfg(test)]
mod tests_dns;
#[cfg(test)]
mod tests_dnstcp;
#[cfg(test)]
mod tests_killactive;
#[cfg(test)]
mod tests_seam;
#[cfg(test)]
mod tests_svcpoll;
#[cfg(test)]
mod testsupport;

pub use runner::run_combined_intercept;
