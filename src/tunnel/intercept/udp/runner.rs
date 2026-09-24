//! El loop del manager UDP del intercept y sus entradas públicas (standalone UDP-only) + el cuerpo
//! compartido con el runner combinado. (F6 tramo 3a: movido verbatim del monolito de `intercept/udp`.)

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use crate::edge::client::EdgeClient;
use crate::tunnel::intercept::flows::FlowRegistry;
use crate::tunnel::intercept::proxy_resolve::{ProxyDns, ProxyEvent};
use crate::tunnel::intercept::resolve::InterceptResolver;
use crate::tunnel::intercept::stack::{InterceptStack, UdpHalf, UdpReplySender};

use super::dns_dispatch::{is_dns_server_datagram, send_dns_reply, serve_dns_datagram};
use super::flow::drop_expired;
use super::upstream::recv_upstream;
use super::vconn::route_datagram;
use super::{
    DNS_UPSTREAM_BUF, FlowKey, MAX_CONSECUTIVE_RECV_NONE, UpstreamDns, VCONN_IDLE_TIMEOUT,
    VCONN_POLL_INTERVAL, Vconn,
};

/// Espera el siguiente [`ProxyEvent`] de las conns proxy-resolve, o queda `Pending` PARA SIEMPRE
/// sin servidor DNS (rama inerte, como [`recv_upstream`]). Toma el RECEIVER (separado del manager
/// [`ProxyDns`]) para que este future no retenga un borrow del manager mientras las otras ramas lo
/// mutan. `recv` nunca da `None`: el manager retiene un `events_tx` vivo durante todo el loop.
async fn recv_proxy_event(rx: Option<&mut mpsc::UnboundedReceiver<ProxyEvent>>) -> ProxyEvent {
    match rx {
        Some(rx) => rx
            .recv()
            .await
            .expect("el manager retiene un events_tx: recv nunca da None"),
        None => std::future::pending().await,
    }
}

/// The manager's decision for one `recv_from()` result. Extracted so the bounded-continue `None` handling
/// (the slice's primary NEW safety logic, with no T3 analogue) is deterministically unit-testable.
pub(super) enum RecvStep {
    /// A valid datagram → route it `(payload, dst, src)` (the consecutive-`None` counter was reset).
    Route(Vec<u8>, SocketAddr, SocketAddr),
    /// A `None` below the bound → keep looping (recover from a transient malformed-datagram `None`).
    Continue,
    /// [`MAX_CONSECUTIVE_RECV_NONE`] consecutive `None`s → presume the stack closed; stop the manager.
    Stop,
}

/// Classify a `recv_from()` result, advancing `consecutive_none`: a valid datagram resets the counter and
/// routes; a `None` increments it and either keeps looping (below the bound) or stops (at the bound). See
/// [`MAX_CONSECUTIVE_RECV_NONE`] for why this is bounded-continue rather than break-on-first-`None`.
pub(super) fn classify_recv(
    msg: Option<(Vec<u8>, SocketAddr, SocketAddr)>,
    consecutive_none: &mut u32,
) -> RecvStep {
    let Some((payload, dst, src)) = msg else {
        *consecutive_none += 1;
        return if *consecutive_none >= MAX_CONSECUTIVE_RECV_NONE {
            RecvStep::Stop
        } else {
            RecvStep::Continue
        };
    };
    *consecutive_none = 0;
    RecvStep::Route(payload, dst, src)
}

/// Corre el forwarding UDP de intercept: drena los datagramas de `stack`, demultiplexa por `(src, dst)`
/// en vconns por-flujo (cada uno resuelve el destino a un servicio ziti y lo dial-ea con el `AppData` del
/// destino interceptado), y reap-ea los vconns idle. El manager actor — espejo de
/// [`run_udp_proxy`](crate::tunnel::udp::run_udp_proxy) con la fuente de datagramas cambiada (utun/netstack
/// en vez de un `UdpSocket` del SO) **y** un paso de resolución dst→servicio por flujo.
///
/// La surface UDP debe estar habilitada ([`InterceptStack::new_with_udp`]); si no, retorna un error (un
/// stack TCP-only no tiene reply-sender ni canal UDP). El trabajo por-vconn corre bajo
/// [`tokio::task::spawn_local`] (`connect_with_appdata` es `!Send`, slice 10c) → DEBE conducirse dentro
/// de un [`tokio::task::LocalSet`].
///
/// **Standalone UDP-only:** toma el `stack` POR VALOR (como `run_tcp_intercept`). Para correr TCP y
/// UDP concurrentemente (la vía de producción de `main.rs`) usa
/// [`crate::tunnel::intercept::combined::run_combined_intercept`], que parte el stack ([`InterceptStack::split_mut`]) y
/// comparte el resolver entre ambos loops.
///
/// # Errors
/// `InvalidInput` si el `stack` es TCP-only (UDP no habilitado). `UnexpectedEof` si `recv_from` agota
/// el límite de `None` consecutivos ([`MAX_CONSECUTIVE_RECV_NONE`]: pila presuntamente cerrada o
/// ráfaga de datagramas malformados) — teardown RUIDOSO, nunca un `Ok` silencioso.
pub async fn run_udp_intercept(
    client: Rc<EdgeClient>,
    stack: InterceptStack,
    resolver: InterceptResolver,
) -> io::Result<()> {
    run_udp_intercept_with(
        client,
        stack,
        resolver,
        None,
        VCONN_IDLE_TIMEOUT,
        VCONN_POLL_INTERVAL,
    )
    .await
}

/// Como [`run_udp_intercept`], pero con el servidor DNS embebido (M3-DNS, diferido #4) montado en
/// `(dns_server_ip, 53)`: un datagrama UDP a esa dirección lo resuelve el DNS embebido localmente
/// ([`crate::tunnel::intercept::dns_server::handle_query`] contra el `DnsMatcher` del resolver) en vez de dial-earlo a un
/// servicio — espejo del intercept `ziti:dns-resolver` del oráculo (`ziti_dns_setup`,
/// `ziti_dns.c:185-192`). `dns_server_ip` es típicamente `utun_addr+1` (la IP que
/// `main.rs::seed_and_reserve_dns_pool` reserva como resolver, on-link, entregada al utun sin ruta
/// extra). El resto del tráfico UDP se resuelve dst→servicio como en [`run_udp_intercept`].
///
/// **Alcance:** una query por un hostname EXACTO devuelve la IP `/32` que ya despacha (694366e); una
/// query bajo un dominio wildcard ASIGNA una IP que [`InterceptResolver::lookup`] despacha por el
/// fallback per-paquete (`intercept_match_addr`, #6 CERRADO en `0211810` — ver
/// [`InterceptResolver::dns_mut`]).
///
/// # Errors
/// `InvalidInput` si el `stack` es TCP-only (UDP no habilitado). `UnexpectedEof` en el límite de
/// `None` consecutivos (ver [`run_udp_intercept`]).
pub async fn run_udp_intercept_with_dns(
    client: Rc<EdgeClient>,
    stack: InterceptStack,
    resolver: InterceptResolver,
    dns_server_ip: Ipv4Addr,
) -> io::Result<()> {
    run_udp_intercept_with(
        client,
        stack,
        resolver,
        Some(dns_server_ip),
        VCONN_IDLE_TIMEOUT,
        VCONN_POLL_INTERVAL,
    )
    .await
}

/// [`run_udp_intercept`] with the DNS server address + idle timeout + poll interval injected, so a
/// test/harness can drive a fast reaping cadence while production passes
/// [`VCONN_IDLE_TIMEOUT`]/[`VCONN_POLL_INTERVAL`]. `dns_server_ip == None` disables the embedded DNS
/// server (the datagram routes as normal traffic).
async fn run_udp_intercept_with(
    client: Rc<EdgeClient>,
    mut stack: InterceptStack,
    resolver: InterceptResolver,
    dns_server_ip: Option<Ipv4Addr>,
    idle_timeout: Duration,
    poll_interval: Duration,
) -> io::Result<()> {
    // Derive the reply sender from the stack (guarantees it matches THIS stack's reply-egress task). A
    // TCP-only stack yields `None` → this relay cannot run (no UDP surface).
    let reply = stack.udp_reply_sender().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "run_udp_intercept requires a UDP-enabled stack (InterceptStack::new_with_udp)",
        )
    })?;
    let (_tcp, udp) = stack.split_mut();
    let udp = udp.expect("udp_reply_sender() dio Some ⇒ la surface UDP existe (mismo Option)");
    // Delegación en el loop compartido con el runner COMBINADO: este subcomando standalone es el caso
    // "resolver de un solo consumidor" — el `RefCell` local es puro plumbing (nunca hay un segundo
    // borrower), la semántica es byte-idéntica al loop previo. El standalone NO configura upstream
    // (el forwarding a upstream lo cablea el subcomando combinado); `None` = REFUSE local, RA nunca.
    // Registro de flujos INERTE (DV-8): el standalone no tiene rama svc-poll, así que nadie llama
    // `kill_service`; su tabla de intercept es estática por construcción. Firma uniforme con el
    // runner combinado; la poda amortizada mantiene el registro acotado.
    udp_intercept_loop(
        &client,
        udp,
        reply,
        &RefCell::new(resolver),
        &Rc::new(RefCell::new(FlowRegistry::new())),
        dns_server_ip,
        None,
        idle_timeout,
        poll_interval,
    )
    .await
}

/// El manager-loop UDP real, sobre la mitad UDP ([`UdpHalf`]) y un resolver COMPARTIBLE
/// (`&RefCell<…>`): lo conducen tanto [`run_udp_intercept`]/[`run_udp_intercept_with_dns`]
/// (standalone, RefCell local de un solo consumidor) como el runner combinado
/// (`combined::run_combined_intercept`, donde el MISMO resolver lo consulta concurrentemente el
/// accept-loop TCP — espejo del `ziti_dns` global único del oráculo: una query DNS servida AQUÍ asigna
/// la IP sintética que el dispatch TCP despacha después). Los borrows del `RefCell` son SIEMPRE
/// síncronos y mueren antes de cualquier `await` (ambos loops corren en el MISMO hilo del `LocalSet`;
/// un borrow vivo a través de un `await` paniquearía al otro loop — disciplina load-bearing).
///
/// Los 9 parámetros son el precio de ser el CUERPO COMPARTIDO de dos runners (standalone y combinado)
/// + la cadencia de reap inyectable para los tests — no una firma pública de conveniencia.
///
/// `flows` = el [`FlowRegistry`] compartido (kill-active): `create_vconn` da de alta cada vconn nuevo
/// a nombre de su servicio; la rama svc-poll del runner combinado los mata al retirarse el servicio. El
/// standalone pasa un registro inerte (DV-8).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn udp_intercept_loop(
    client: &Rc<EdgeClient>,
    mut udp: UdpHalf<'_>,
    reply: UdpReplySender,
    resolver: &RefCell<InterceptResolver>,
    flows: &Rc<RefCell<FlowRegistry>>,
    dns_server_ip: Option<Ipv4Addr>,
    mut upstream: Option<UpstreamDns>,
    idle_timeout: Duration,
    poll_interval: Duration,
) -> io::Result<()> {
    let mut conns: HashMap<FlowKey, Vconn> = HashMap::new();
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut consecutive_none: u32 = 0;
    let mut upstream_buf = [0u8; DNS_UPSTREAM_BUF];
    // Proxy-resolve por el overlay (M3-DNS #2): INTRÍNSECO al servidor DNS embebido (el oráculo lo
    // tiene siempre que el DNS corre — no hay flag), así que se construye junto a él. El manager
    // (estado) y su receiver de eventos van separados: el future de `recv` de la rama del select!
    // no debe retener un borrow del manager que las otras ramas mutan.
    let (mut proxy, mut proxy_events) = match dns_server_ip {
        Some(_) => {
            let (p, rx) = ProxyDns::new();
            (Some(p), Some(rx))
        }
        None => (None, None),
    };
    loop {
        tokio::select! {
            msg = udp.recv_from() => {
                // recv_from()->None is AMBIGUOUS (transient malformed-datagram None vs terminal close).
                // `classify_recv` encapsulates the bounded-continue logic (the slice's primary NEW safety
                // logic, no T3 analogue) so it is deterministically unit-testable.
                match classify_recv(msg, &mut consecutive_none) {
                    RecvStep::Route(payload, dst, src) => {
                        if is_dns_server_datagram(dst, dns_server_ip) {
                            if serve_dns_datagram(
                                client,
                                resolver,
                                &reply,
                                &mut upstream,
                                &mut proxy,
                                payload,
                                dst,
                                src,
                            )
                            .is_break()
                            {
                                break;
                            }
                        } else {
                            // Borrow síncrono del resolver SOLO durante la decisión de routing (el spawn
                            // del vconn dentro de `create_vconn` no corre aún; nada cruza un await). El
                            // `flows.borrow_mut()` de `create_vconn` anida bajo este borrow del resolver:
                            // celdas DISTINTAS, sin await en el scope → permitido.
                            route_datagram(&mut conns, client, &resolver.borrow(), &reply, flows, dst, src, payload);
                        }
                    }
                    RecvStep::Continue => {}
                    RecvStep::Stop => {
                        // Presunción de pila cerrada (heurístico acotado, ver
                        // [`MAX_CONSECUTIVE_RECV_NONE`]): retorna ERROR, nunca `Ok`. En el runner
                        // combinado este retorno derriba el tunneler ENTERO (select!), así que un
                        // teardown disparado por input del data-path — camino que el oráculo NO
                        // tiene (su uv-loop nunca muere por un paquete) — debe ser RUIDOSO: el
                        // subcomando termina con error/exit≠0, jamás con éxito silencioso que un
                        // supervisor por exit-code confundiría con un cierre limpio.
                        tracing::error!("intercept udp: stack yielded None repeatedly; presuming closed");
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "intercept udp: recv_from agotó el límite de None consecutivos (pila presuntamente cerrada o ráfaga de datagramas malformados)",
                        ));
                    }
                }
            }
            // Respuesta de un upstream DNS (M3-DNS #1): casa por ID contra un request en vuelo y hace
            // passthrough VERBATIM al cliente (`on_upstream_packet`). Inerte (Pending para siempre) sin
            // upstream configurado.
            res = recv_upstream(upstream.as_ref(), &mut upstream_buf), if upstream.is_some() => {
                if let Ok(n) = res {
                    // El borrow de `upstream` de la rama del select! ya murió (future dropeado antes
                    // del cuerpo); aquí re-borrow `&mut` para casar+consumir el pending.
                    let up = upstream.as_mut().expect("la guarda `if upstream.is_some()`");
                    if let Some((server_addr, client_addr)) = up.match_response(&upstream_buf[..n]) {
                        let bytes = upstream_buf[..n].to_vec();
                        if send_dns_reply(&reply, bytes, server_addr, client_addr).is_break() {
                            break;
                        }
                    }
                }
            }
            // Un evento de una conn proxy-resolve (M3-DNS #2): una respuesta JSON del resolver
            // hostante (parse + injerto + formateo, todo síncrono en el manager) o el fallo del
            // write de un request (→ SERVFAIL). Inerte sin servidor DNS (sin proxy).
            ev = recv_proxy_event(proxy_events.as_mut()), if proxy_events.is_some() => {
                let p = proxy.as_mut().expect("evento proxy ⇒ proxy cableado");
                if let Some((bytes, dst, src)) = p.on_event(ev, upstream.is_some())
                    && send_dns_reply(&reply, bytes, dst, src).is_break()
                {
                    break;
                }
            }
            _ = ticker.tick() => {
                drop_expired(&mut conns, idle_timeout, Instant::now());
                if let Some(up) = upstream.as_mut() {
                    up.evict_expired(Instant::now());
                }
                if let Some(p) = proxy.as_mut() {
                    p.evict_expired(Instant::now());
                }
            }
        }
    }
    Ok(())
}
