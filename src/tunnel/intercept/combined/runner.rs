//! Producción del runner combinado del intercept (F6 tramo 17 troceo): el runner TCP+UDP+DNS
//! (`run_combined_intercept` + su seam `_inner` con el `select!` de 3 ramas) y la rama svc-poll
//! (`svc_poll_loop`) que re-alimenta la tabla de intercept, conduce las rutas OS y el kill-active.

use std::cell::RefCell;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;

use crate::edge::client::EdgeClient;
use crate::edge::error::EdgeError;
use crate::edge::service_refresh::{
    PROD_SERVICE_INTERVALS, ServiceRefreshIntervals, backoff_delay, jittered_duration,
    rand_fraction,
};
use crate::edge::services::ServiceEvent;

use crate::tunnel::intercept::flows::FlowRegistry;
use crate::tunnel::intercept::resolve::{INTERCEPT_V1_CONFIG_TYPE, InterceptResolver};
use crate::tunnel::intercept::routes::RouteApplier;
use crate::tunnel::intercept::stack::InterceptStack;
use crate::tunnel::intercept::tcp::tcp_intercept_loop;
use crate::tunnel::intercept::udp::{
    UpstreamDns, VCONN_IDLE_TIMEOUT, VCONN_POLL_INTERVAL, udp_intercept_loop,
};

/// El nombre de servicio que porta un [`ServiceEvent`] — la clave del kill (espejo del `zi_ctx`
/// per-servicio contra el que filtran `tunneler_tcp_active`/`tunneler_udp_active`).
fn event_service_name(ev: &ServiceEvent) -> &str {
    match ev {
        ServiceEvent::Added(svc) | ServiceEvent::Changed(svc) | ServiceEvent::Removed(svc) => {
            &svc.name
        }
    }
}

/// Corre el intercept COMPLETO (TCP + UDP + servidor DNS embebido en `(dns_server_ip, 53)`) sobre una
/// pila con UDP habilitado ([`InterceptStack::new_with_udp`]) y un único resolver compartido — el
/// análogo del `run` del oráculo (ver el doc del módulo). `dns_server_ip` es la IP que `main.rs`
/// reserva como resolver embebido (`utun_addr+1`, espejo de `dns_ip = tun_ip+1`,
/// `ziti-edge-tunnel.c:1491-1492`). `upstream_servers` = los DNS upstream a los que reenviar las
/// queries que el resolver embebido no responde localmente (M3-DNS #1, `-u|--dns-upstream`); VACÍO =
/// sin forwarding (miss → REFUSE local, RA nunca — byte-idéntico al pre-upstream).
///
/// Igual que los runners por-protocolo, DEBE conducirse dentro de un [`tokio::task::LocalSet`] (los
/// dials del overlay son `!Send`, slice 10c).
///
/// # Errors
/// `InvalidInput` si la pila es TCP-only (sin surface UDP no hay ni manager UDP ni DNS montable).
/// Propaga el fallo de bind del socket upstream si `upstream_servers` no está vacío.
/// `UnexpectedEof` si el manager UDP agota su límite de `None` consecutivos (teardown ruidoso, ver
/// el doc del módulo). Retorna `Ok(())` cuando la pila se cierra limpia (`accept → None`).
pub async fn run_combined_intercept(
    client: Rc<EdgeClient>,
    stack: InterceptStack,
    resolver: InterceptResolver,
    dns_server_ip: Ipv4Addr,
    upstream_servers: Vec<SocketAddr>,
    routes: Option<Box<dyn RouteApplier>>,
) -> io::Result<()> {
    // El subcomando intercept pide SIEMPRE `intercept.v1` (idéntico al fetch inicial de `main.rs`, que
    // ya sembró el cache del `ServiceWatcher` vía `prime_service_cache`) y usa el timing de producción
    // del oráculo para la rama svc-poll (`runRefreshes` svc arm: 5 min ±10%). El seam `_inner` inyecta
    // ambos para que los tests puedan usar un intervalo diminuto + un controller wiremock. `routes` =
    // el ciclo de vida de rutas OS ([`RouteLifecycle`] sembrado por `main.rs`; `None` = sin efectos
    // de ruta, p.ej. tests sin root) que la rama svc-poll alimenta con los `RouteDelta` de cada evento.
    run_combined_intercept_inner(
        client,
        stack,
        resolver,
        dns_server_ip,
        upstream_servers,
        vec![INTERCEPT_V1_CONFIG_TYPE.to_string()],
        PROD_SERVICE_INTERVALS,
        routes,
        Rc::new(RefCell::new(FlowRegistry::new())),
    )
    .await
}

/// El cuerpo real de [`run_combined_intercept`], parametrizado por los `config_types` y el timing de la
/// rama svc-poll para que los tests inyecten un intervalo diminuto + un controller wiremock. Añade una
/// TERCERA rama al `select!` (junto a los loops TCP y UDP): [`svc_poll_loop`], que re-alimenta la tabla
/// de intercept con los cambios de servicio del controller y conduce el ciclo de rutas OS (`routes`).
/// Ver su doc para la disciplina de borrow y el ciclo completo por evento.
#[allow(clippy::too_many_arguments)] // seam de test del runner completo; el pub delega aquí
pub(super) async fn run_combined_intercept_inner(
    client: Rc<EdgeClient>,
    mut stack: InterceptStack,
    resolver: InterceptResolver,
    dns_server_ip: Ipv4Addr,
    upstream_servers: Vec<SocketAddr>,
    svc_config_types: Vec<String>,
    svc_intervals: ServiceRefreshIntervals,
    routes: Option<Box<dyn RouteApplier>>,
    flows: Rc<RefCell<FlowRegistry>>,
) -> io::Result<()> {
    // El reply-sender se deriva ANTES del split (toma `&self`; el emisor es owned/clonable).
    let reply = stack.udp_reply_sender().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "run_combined_intercept requiere una pila con UDP (InterceptStack::new_with_udp)",
        )
    })?;
    // El contexto DNS-over-TCP (#4b) captura la IP del resolver + los MISMOS upstreams ANTES de que
    // `UpstreamDns::bind` CONSUMA el `Vec`: el path TCP hace su forward con sockets TCP propios por
    // query (no comparte el socket UDP del manager, spec §5.1) pero al MISMO conjunto de servidores.
    let dns_tcp = crate::tunnel::intercept::dns_tcp::DnsTcpContext {
        server_ip: dns_server_ip,
        upstream_servers: upstream_servers.as_slice().into(),
    };
    // Bind del socket upstream ANTES del split (async, fuera del select!). VACÍO → sin forwarding.
    let upstream = if upstream_servers.is_empty() {
        None
    } else {
        Some(UpstreamDns::bind(upstream_servers).await?)
    };
    let (tcp, udp) = stack.split_mut();
    let udp = udp.expect("udp_reply_sender() dio Some ⇒ la surface UDP existe (mismo Option)");
    // EL resolver único compartido (ver el doc del módulo): el DNS del manager UDP asigna, el
    // dispatch de ambos loops ve la asignación — espejo del `ziti_dns` global único del oráculo. Es
    // un `Rc<RefCell<…>>` (no `RefCell<…>`) para que la task de servicio DNS-over-TCP del loop TCP
    // (`serve_dns_over_tcp`, #4) pueda retener un handle propio TODA la conexión (el loop UDP lo toma
    // como `&RefCell` vía deref-coercion, sin cambio). La interior-mutabilidad y la disciplina de
    // borrow síncrono son idénticas: el `Rc` solo añade conteo de referencias, no un 2º mutador.
    let resolver = Rc::new(RefCell::new(resolver));
    tokio::select! {
        r = tcp_intercept_loop(&client, tcp, &resolver, Some(dns_tcp), &flows) => r,
        r = udp_intercept_loop(
            &client,
            udp,
            reply,
            &resolver,
            &flows,
            Some(dns_server_ip),
            upstream,
            VCONN_IDLE_TIMEOUT,
            VCONN_POLL_INTERVAL,
        ) => r,
        // 3ª rama: re-alimenta la tabla de intercept con los cambios de servicio del controller (svc
        // re-feed, T5). Nunca retorna → no es un trigger de teardown (ver el doc de `svc_poll_loop`).
        // `Box::pin` la mueve al heap: contiene un fetch HTTP (`poll_services_if_changed`) que, inline en
        // el `select!`, empujaba el future del runner por encima del umbral `clippy::large_futures`
        // (16 KB); heap-allocada (una vez, al arrancar), el runner recupera su tamaño pre-slice.
        r = Box::pin(svc_poll_loop(&client, &resolver, &svc_config_types, svc_intervals, routes, &flows)) => r,
    }
}

/// La rama svc-poll del runner combinado: mantiene la tabla de intercept FRESCA re-alimentándola con
/// los cambios de servicio que el controller publica, cerrando el gap "resolver-snapshot sin
/// svc-poller" del arco. Espejo estructural de [`crate::edge::service_refresh::run_service_refreshes`]
/// (la rama svc de `runRefreshes`, `sdk-golang` v1.7.0 `ziti/ziti.go:1024-1078`): primer tick a un
/// intervalo jittereado (NUNCA poll inmediato — el snapshot inicial ya lo cargó `main.rs`), y en cada
/// tick el chequeo de update gated ([`EdgeClient::poll_services_if_changed`]: `GET /service-updates` y,
/// SÓLO si cambió, `GET /services` + diff → eventos + evict de dial-sessions de los `Removed`). La
/// diferencia PRINCIPAL con el timer SDK es el SUMIDERO: en vez de emitir a los listeners registrados, cada
/// evento se aplica a la tabla de intercept vía [`InterceptResolver::apply_event`] (Added/Changed →
/// reconcilia el intercept por nombre; Removed → lo retira; el primitivo entregado en la rebanada previa).
/// (Diferencia SECUNDARIA, safe-direction: nuestro fetch pasa por `poll_services_if_changed` →
/// `with_reauth_retry` — reauth reactiva ante un 401 —, mientras `run_service_refreshes` usa el
/// `do_list_services` LIBRE sin reauth (su desviación #2). Aquí somos MÁS fieles al oráculo Go, que
/// re-autentica ante un 401 en `refreshServices`, `ziti.go:892/:921`.)
///
/// # Disciplina de borrow (el crux de concurrencia del arco)
/// Corre en el MISMO hilo/`LocalSet` que los loops TCP/UDP (una rama más del `select!`), así que
/// comparte el `Rc<RefCell<InterceptResolver>>` sin `Send`. El `borrow_mut()` de `apply_event` es
/// SÍNCRONO y muere al final de la sentencia — JAMÁS se retiene a través de un `.await` (el único await
/// del cuerpo es el fetch de `poll_services_if_changed`, que NO toca el resolver). Como el `select!` es
/// cooperativo mono-hilo, nunca hay dos borrows solapados → sin panic de `RefCell` (misma disciplina ya
/// verificada en `b8d3a55`/`6ac6cb8`, extendida en un sitio más).
///
/// # NUNCA retorna (no es un trigger de teardown)
/// Igual que la rama svc del oráculo, log-and-continue en TODO error (retriable el próximo tick;
/// `ControllerUnavailable` → backoff más corto, `ziti.go:1072`): el `loop` no tiene salida, así que
/// esta rama del `select!` nunca gana y NO puede tumbar el runner. El contrato de teardown ("el primer
/// loop que cae derriba todo") lo siguen fijando SÓLO los loops TCP/UDP.
///
/// # Ciclo COMPLETO por evento (match + DNS + rutas OS)
/// Reconcilia la TABLA DE MATCH del resolver + su estado DNS + las RUTAS OS: `add_service` registra el
/// dominio/hostname del nuevo servicio en el `DnsMatcher` COMPARTIDO (→ un hostname/wildcard añadido en
/// vivo resuelve y despacha inmediatamente, porque su IP sintética cae dentro del CIDR del utun YA
/// ruteado), `remove_service` LIBERA el estado DNS del servicio retirado (`deregister_intercept`,
/// espejo de `ziti_dns_deregister_intercept` — #5 eviction: una query posterior bajo su
/// dominio/hostname → REFUSED, como el oráculo), y el [`crate::tunnel::intercept::resolve::RouteDelta`] de cada evento se aplica a
/// `routes` ([`crate::tunnel::intercept::routes::RouteLifecycle`] refcounted, espejo de `route.c` — rebanada RUTAS OS): un CIDR literal
/// añadido en vivo INSTALA su ruta (el kernel empieza a entregar ese destino al utun) y uno retirado
/// la QUITA cuando ningún servicio la referencia. Con `routes = None` (tests sin root) los deltas se
/// descartan y el comportamiento es el pre-rebanada (under-dispatch seguro de CIDRs vivos).
///
/// Desviación consciente (orden INTRA-batch): los eventos se aplican en el orden en que el
/// `ServiceWatcher` los emite (fiel al SDK Go), mientras el tunneler-ctrl del C procesa un batch
/// como removed → added → changed (`ziti_tunnel_ctrl.c:1065-1097`) — un CIDR que MIGRA de un
/// servicio a otro dentro del MISMO batch puede churnear delete→add donde el C (added primero,
/// refcount 2→1) no tocaría la ruta. Estado final idéntico; ventana de un batch; solo observable
/// desde esta rebanada.
#[allow(clippy::too_many_arguments)] // el seam completo de reconciliación (tabla + DNS + rutas + flujos)
async fn svc_poll_loop(
    client: &EdgeClient,
    resolver: &Rc<RefCell<InterceptResolver>>,
    config_types: &[String],
    intervals: ServiceRefreshIntervals,
    mut routes: Option<Box<dyn RouteApplier>>,
    flows: &Rc<RefCell<FlowRegistry>>,
) -> io::Result<()> {
    // El oráculo arma el timer ANTES del loop (`ziti.go:1024`) → el PRIMER tick sale a un intervalo
    // jittereado (sin poll inmediato).
    let mut next = jittered_duration(intervals.interval, intervals.jitter, rand_fraction());
    loop {
        tokio::time::sleep(next).await;
        match client.poll_services_if_changed(config_types).await {
            Ok(events) => {
                for ev in &events {
                    // Borrow SÍNCRONO: nace y muere en esta sentencia, sin `.await` dentro. El delta
                    // sale del borrow y se aplica DESPUÉS (syscalls de ruta síncronos, sin tocar el
                    // resolver) — orden del oráculo: stop/intercept mueve la tabla y sus rutas en el
                    // mismo on_service, antes del siguiente evento.
                    let applied = resolver.borrow_mut().apply_event(ev);
                    // KILL-ACTIVE: espejo del `tunneler_kill_active` que `stop_intercept` arrastra
                    // (`ziti_tunnel_cbs.c:600` → `ziti_tunnel.c:493`/`:510`). Va SÍNCRONO, entre la
                    // aplicación del evento y las rutas: el `cancel()` despierta a cada flujo, que
                    // ejecuta su propio camino de cierre. Celda DISJUNTA de la del resolver, cuyo
                    // borrow ya murió en la sentencia anterior; sin `await` entre medias, así que
                    // ninguna otra rama del `select!` puede despachar un flujo en el intervalo (DV-6:
                    // nuestro orden tabla+DNS → kill → rutas vs el DNS → kill → tabla → rutas del C es
                    // inobservable).
                    if applied.kill_active {
                        let service = event_service_name(ev);
                        let killed = flows.borrow_mut().kill_service(service);
                        if killed > 0 {
                            tracing::debug!(
                                service,
                                killed,
                                "intercept svc-poll: flujos activos cerrados al retirar/reemplazar el servicio"
                            );
                        }
                    }
                    if let Some(r) = routes.as_deref_mut() {
                        r.apply_delta(&applied.routes);
                    }
                }
                next = jittered_duration(intervals.interval, intervals.jitter, rand_fraction());
            }
            Err(EdgeError::ControllerUnavailable) => {
                // Oráculo: backoff más corto, sin re-armar el timer normal este tick (`ziti.go:1072`).
                next = backoff_delay(intervals.interval, rand_fraction());
            }
            Err(e) => {
                // Oráculo: `log.Error("failed to load service updates")` (`ziti.go:1076`) + re-arma
                // normal. Retriable el próximo tick, NUNCA fatal (no tumba el runner).
                tracing::error!(error = %e, "intercept svc-poll: failed to load service updates");
                next = jittered_duration(intervals.interval, intervals.jitter, rand_fraction());
            }
        }
    }
}
