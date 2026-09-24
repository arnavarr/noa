//! M2b-pre del arco intercept: el camino de FORWARDING TCP host→overlay — superface **(A)**, cara al
//! overlay, **fidelidad estricta** reusando T4b (`build_app_data` + `splice`, ya validados en vivo).
//!
//! Es el ESPEJO EMISOR de [`run_tcp_proxy`](crate::tunnel::proxy::run_tcp_proxy) (T1) con la fuente de
//! *accept* cambiada: en vez de un `TcpListener` del SO, los flujos vienen del [`InterceptStack`]
//! (utun → netstack, M1), que entrega `(stream, dst, src)` donde `dst` es el destino ORIGINAL que el
//! cliente local quería alcanzar. Por cada flujo: se emite el `AppData` (mapa `dst_*`) del destino, se
//! dial-ea el servicio overlay con ese AppData, y se splicea el [`InterceptTcpStream`] (half-close
//! ACOTADO de M2a) contra la conexión overlay.
//!
//! ## Oráculo (A) — la cadena del interceptor transparent-proxy
//! `openziti/ziti` v2.0.0 `tunnel/intercept/tproxy/tproxy_linux.go:325-331` (`acceptTCP`) →
//! `tunnel.GetAppInfo("tcp", dstHostname, dstIp, dstPort, sourceAddr)` (`tunnel/tunnel.go:72`) →
//! `tunnel.DialAndRun(..., appInfo, halfClose=true)` (`tunnel.go:41`) → `TunnelService`
//! (`provider.go:103`, `DialOptions{AppData}`) → `Run` (`tunnel.go:86`) = nuestro
//! [`splice`](crate::tunnel::proxy::splice). El modelo tproxy (intercepta el destino REAL del flujo)
//! es el análogo de nuestra captura utun/netstack — NO el modo `proxy` de listener fijo por servicio
//! (`proxy.go:267`, que emite el IP/puerto CONFIGURADO, no el del flujo).
//!
//! ## §4.2.2 GATE del AppData-emisor (el `fidelity_risk` de M2b)
//! El interceptor Go (tproxy) emite por flujo, vía `GetAppInfo` (que añade `dst_hostname`/`source_addr`
//! SOLO si son no-vacíos):
//!   - `dst_protocol = "tcp"` — literal para TCP;
//!   - `dst_ip` / `dst_port` = `GetIpAndPort(client.LocalAddr())` = el destino interceptado (en
//!     transparent-proxy el `LocalAddr` del socket aceptado ES el destino original) ↔ nuestro `dst`;
//!   - `dst_hostname` = `resolver.Lookup(dstIP)` = reverse-DNS del IP destino contra el mapa de IPs
//!     sintéticas del DNS embebido → cadena vacía SIN ese resolver (no se añade al mapa);
//!   - `source_addr` = `service.GetSourceAddr(client.RemoteAddr(), client.LocalAddr())`
//!     (`service.go:425`) = cadena vacía SIN un `SourceAddrProvider` (la plantilla `sourceIp` del
//!     config `intercept.v1`, `svcpoll.go:335`) → no se añade.
//!
//! **DELTA con el emisor del dialer T4b = CERO.** [`build_app_data`](crate::edge::dial::build_app_data)
//! (validado en T4b contra la forma de `GetAppInfo`, test `build_app_data_ip_path_is_oracle_get_app_info_shape`)
//! produce EXACTAMENTE el mismo mapa para el caso IP-puro (`dst_protocol`, `dst_ip`, `dst_port`, sin
//! `dst_hostname`, sin `source_addr`). Reusamos `build_app_data` — NO un emisor paralelo (evita
//! reintroducir la clase de divergencias que el arco T4b cazó por differential).
//!
//! ## Tres diferidos NOMBRADOS (no silenciosos)
//! Los dos primeros están en el VALOR de campos OPCIONALES del mapa `AppData`; ninguno cambia la forma
//! del mapa para el caso por defecto (intercept por-IP, servicio sin plantillas). El tercero NO es un
//! campo del mapa sino una opción de dial SEPARADA (la identidad de terminador direccionable), pero de
//! la MISMA clase config-template que `source_addr`, así que se nombra aquí para no dejarlo silencioso:
//!   1. ~~**`dst_hostname` ← DNS embebido (M3).**~~ CERRADO por el slice combinado: el accept-loop
//!      hace el reverse-lookup del destino contra el DNS embebido (el MISMO resolver que despachó) y
//!      lo emite, espejo del C `get_app_data` (`ziti_dns_reverse_lookup(dst_ip)`,
//!      `ziti_tunnel_cbs.c:255-259`) y del Go tproxy (`resolver.Lookup(dstIP)`). Un intercept
//!      por-IP puro sigue sin entrada DNS → se omite, fiel al `GetAppInfo` con `dstHostname==""`.
//!   2. **`source_addr` ← resolver `intercept.v1` (B).** Solo se emite si el servicio define una
//!      plantilla `sourceIp` (`SourceAddrProvider`). Con un servicio HARDCODED no hay plantilla →
//!      `GetSourceAddr` con provider `nil` devuelve `""` → se omite — fiel.
//!   3. **`DialOptions.Identity` (instanceId del terminador direccionable) ← resolver `intercept.v1`
//!      (B), NO es un campo del `AppData`.** El interceptor hila `identity := service.GetDialIdentity(
//!      remote, local)` en CADA flujo (`tproxy_linux.go:330` → `DialAndRun` → `TunnelService` →
//!      `DialOptions{Identity}`, `provider.go:107`). `GetDialIdentity` (`service.go:444`) es el HERMANO
//!      EXACTO de `GetSourceAddr`: provider `nil` → `""`, y el provider solo se fija desde la plantilla
//!      `dialOptions.identity` del config `intercept.v1` (`configureDialIdentityProvider`,
//!      `svcpoll.go:343`, hermano de `configureSourceAddrProvider`, `svcpoll.go:335`). Con un servicio
//!      HARDCODED no hay plantilla → `""` → NINGÚN selector de terminador hoy → bytes fieles. PERO
//!      [`connect_with_appdata`](crate::edge::client::EdgeClient::connect_with_appdata) NO tiene
//!      parámetro para emitir un instanceId de terminador → la superface (B) DEBE añadir esa fontanería;
//!      un implementador que solo viese `source_addr` podría OMITIRLO en silencio (un UNDER-emit para
//!      servicios con terminadores direccionables — la dirección menos vigilada en este arco). Nombrado
//!      aquí para cerrar el hueco.
//!
//! El mapeo `dst`→servicio sigue **HARDCODED** (el resolver `intercept.v1` real es la superface (B),
//! rebanada posterior). El round-trip e2e host→overlay (la aceptación de M2 — "un flujo TCP completo
//! atraviesa host→overlay y vuelve") es **M2b-e2e**: requiere root (utun) + overlay (controller+router
//! en OrbStack), la prueba en vivo con root, ejecutada a mano. Esta rebanada (M2b-pre) entrega el emisor + el cableado,
//! validados por differential + cobertura in-memory; el emisor en el cable ya es live vía el arco T4b.

use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::edge::client::EdgeClient;
use crate::edge::dial::build_app_data;
use crate::tunnel::proxy::splice;

use super::flows::FlowRegistry;
use super::resolve::{InterceptResolver, Protocol};
use super::splice_kill::splice_until_killed;
use super::stack::{InterceptStack, TcpHalf};
use super::stream::InterceptTcpStream;

/// Pin en tiempo de compilación del **spike de escala** (diseño §7.1, parte (d)): prueba que el
/// FUTURO del splice establecido es `Send + 'static`, así puede ejecutarse en el runtime multi-thread.
///
/// NO es un ciclo RED→GREEN: `Send` es una propiedad PREEXISTENTE de los halves del edge (el spike la
/// verificó empíricamente con el compilador — `EdgeReadHalf`/`EdgeWriteHalf`/`Arc<EdgeChannel>`/
/// `InterceptTcpStream` son todos `Send`, porque `connect` es `!Send` por el `Rc<EdgeClient>` del path
/// de dial (slice 10c), NO por los halves). Este `const` la PINEA: si un cambio futuro de M3 reintrodujese
/// un campo `!Send` (p.ej. un `Rc` en la cripto o en el `TcpStream` de netstack), el build ROMPE aquí en
/// vez de en producción. Afirma el FUTURO completo de [`splice`] (no solo los campos): un local `!Send`
/// sostenido a través de un `.await` rompería `Send` aunque los campos lo fuesen (el `MutexGuard` de
/// `tokio::sync::Mutex` de `EdgeWriteHalf::write` SÍ es `Send`, pero lo PROBAMOS, no lo inferimos).
const _: fn(crate::edge::data::EdgeReadHalf, crate::edge::data::EdgeWriteHalf, InterceptTcpStream) =
    |zr, zw, stream| {
        fn require_send<T: Send + 'static>(_: T) {}
        require_send(splice(zr, zw, stream));
    };

/// Construye el `AppData` (mapa `dst_*` JSON, header 1011) de un flujo TCP interceptado hacia `dst`,
/// espejo del `GetAppInfo("tcp", dstHostname, dstIp, dstPort, "")` del interceptor Go (tproxy) y del
/// `get_app_data` del tunneler C (`ziti_tunnel_cbs.c:247-260`).
///
/// `dst_hostname` = el reverse-lookup del destino contra el DNS embebido (M3-DNS): el llamante lo
/// resuelve con [`DnsMatcher::reverse_lookup`](super::dns::DnsMatcher::reverse_lookup) del MISMO
/// resolver que despachó el flujo, espejo de AMBOS oráculos — el C hace
/// `ziti_dns_reverse_lookup(dst_ip) → app_data->dst_hostname` para TODO dial interceptado
/// (`get_app_data`, `ziti_tunnel_cbs.c:255-259`), y el Go tproxy hace `resolver.Lookup(dstIP)`
/// (`tproxy_linux.go:327`). Un destino sin entrada DNS (intercept por-IP puro) va `None` → se omite
/// del mapa exactamente como `GetAppInfo` omite un `dstHostname` vacío. Un hostname VACÍO (la entrada
/// reservada calloc'd del oráculo, inalcanzable aquí porque una IP reservada nunca despacha) también
/// se omite — mismo criterio omit-empty. `source_addr` sigue DIFERIDO (plantilla `sourceIp`,
/// resolver B) → `None`. **Divergencia nombrada Go-vs-C (mantenida a favor del Go):** el C emite
/// además `src_protocol`/`src_ip`/`src_port` (`get_app_data`, `ziti_tunnel_cbs.c:262-265`);
/// pineamos el mapa del `GetAppInfo` Go (oráculo PRIMARIO del emisor, differential T4b) que no los
/// tiene — observable solo por un host con plantilla `$src_ip`-style, misma clase que `source_addr`.
///
/// Única divergencia teórica Go-vs-Rust del string del IP: un IPv6 v4-mapeado (`::ffff:a.b.c.d`) — Go
/// `net.IP.String()` lo renderiza en forma punteada v4, Rust `Ipv6Addr::to_string` lo conserva mapeado.
/// Es DATAPATH-INALCANZABLE (RFC 4291 §2.5.5.2: forma interna de la API de sockets, nunca en el cable;
/// `dst.ip()` preserva la familia del paquete que entrega smoltcp). Flag defensivo por si M3 admitiese
/// un paquete v6 manipulado.
#[must_use]
pub(crate) fn intercept_tcp_appdata(dst: SocketAddr, dst_hostname: Option<&str>) -> Vec<u8> {
    build_app_data(
        "tcp",
        &dst.ip().to_string(),
        &dst.port().to_string(),
        dst_hostname.filter(|h| !h.is_empty()),
        None,
    )
}

/// Corre el forwarding TCP de intercept: acepta flujos de `stack`, **resuelve el destino REAL de cada
/// flujo a un servicio ziti** vía `resolver` (slice (B): el `intercept.v1`, reemplaza el `service`
/// HARDCODED de M2b-pre), y splicea el flujo contra una conexión overlay recién dial-eada a ese
/// servicio, emitiendo el `AppData` del destino interceptado. Un flujo por accept, concurrente.
///
/// Espejo de [`run_tcp_proxy`](crate::tunnel::proxy::run_tcp_proxy) con la fuente de accept cambiada
/// (utun/netstack en vez de un `TcpListener` del SO) **y** un paso de resolución dst→servicio.
///
/// **Modelo de concurrencia (spike de escala, diseño §7.1 parte (d)):** el accept-loop y el
/// **dial** corren bajo [`tokio::task::spawn_local`] (debe conducirse dentro de un
/// [`tokio::task::LocalSet`]) porque el `connect` del overlay es `!Send` (desde slice 10c). Pero el
/// **splice establecido** (post-dial) usa halves `Send` (verificado por el compilador, ver el pin
/// `const` arriba), así que se mueve al runtime MULTI-THREAD vía [`tokio::task::JoinSet::spawn`]: la
/// cripto por-frame y las copias de N flujos paralelizan entre cores en vez de serializar en el único
/// hilo del `LocalSet` (el cuello que el §7(d) anticipaba, **MITIGADO** para el plano overlay — la
/// cripto y las copias paralelizan; la EMISIÓN de frames de flujos que comparten un canal pooleado aún
/// serializa en el `AsyncMutex` `state.write`, ver §7.1). Un dial fallido se loguea y el runner sigue
/// aceptando.
///
/// **Resolución dst→servicio (B):** [`InterceptResolver::lookup`] elige el servicio Y su timeout de
/// dial (5s default / 15s / N, según el `intercept.v1` del servicio — `svcpoll.go:184` +
/// `ziti.go:1449`). Si NINGÚN servicio intercepta el destino, el flujo se cierra limpio (se dropea el
/// stream): un destino no interceptado no se rutea (fiel; en producción la instalación de rutas de M3
/// hace que solo los CIDRs interceptados lleguen al device — un dst sin servicio sería una misconfig).
///
/// **Teardown (verificado en fuente, `netstack-smoltcp-0.2.3/src/tcp.rs`):** si `accept` devuelve
/// `None` (la pila se cerró) el runner retorna; al hacerlo, `stack` (tomado por valor) se dropea y
/// `InterceptStack::Drop` ABORTA el Runner de netstack. Un `TcpStream` de netstack cuyo Runner ha sido
/// abortado deja `poll_read` en `Pending` PARA SIEMPRE (`recv_state` nunca pasa a `Closed` sin el Runner,
/// `tcp.rs:485-519`) y `poll_write` en `Pending` al llenarse el buffer (`tcp.rs:522-554`) — así que un
/// `tokio::spawn` DETACHED filtraría todo splice en vuelo de cada stack derribado (benigno al salir el
/// proceso, pero un leak ACUMULATIVO en los escenarios multi-stack/restart de M3). Por eso los splices
/// se rastrean en un [`JoinSet`]: al retornar este loop el `JoinSet` se dropea → aborta los splices en
/// vuelo, PRESERVANDO la semántica de teardown del modelo previo (un cierre de stack aborta los flujos
/// en vuelo). El `LocalSet` que conduce el loop dropea en paralelo, abortando las tasks de dial `!Send`.
/// (El oráculo desacopla las goroutines `DialAndRun` del accept-loop; nuestra elección de abortar en
/// teardown es la desviación consciente ya documentada en `proxy.rs`, intacta aquí.)
///
/// # Errors
/// Retorna `Ok(())` cuando la pila se cierra (`accept` → `None`); los errores de flujo individuales no
/// se propagan (cada uno se loguea y la conexión se desmonta de todos modos).
pub async fn run_tcp_intercept(
    client: Rc<EdgeClient>,
    mut stack: InterceptStack,
    resolver: InterceptResolver,
) -> io::Result<()> {
    // Delegación en el loop compartido con el runner COMBINADO (`combined::run_combined_intercept`):
    // este subcomando standalone es el caso "resolver de un solo consumidor" — el `RefCell` local es
    // puro plumbing (nunca hay un segundo borrower), la semántica es byte-idéntica al loop previo.
    let (tcp, _udp) = stack.split_mut();
    // Standalone TCP-only: sin servidor DNS embebido (`None`) → un flujo a TCP:53 se dropea como
    // antes (el DNS-over-TCP lo monta solo el runner combinado, que sí tiene el `DnsTcpContext`).
    // Registro de flujos INERTE (DV-8): sin rama svc-poll no hay eventos `Removed`, así que nadie
    // llama `kill_service`; su tabla es estática por construcción. La poda amortizada lo mantiene
    // acotado. Firma uniforme con el runner combinado.
    tcp_intercept_loop(
        &client,
        tcp,
        &Rc::new(RefCell::new(resolver)),
        None,
        &Rc::new(RefCell::new(FlowRegistry::new())),
    )
    .await
}

/// El accept-loop TCP real, sobre la mitad TCP ([`TcpHalf`]) y un resolver COMPARTIBLE
/// (`&Rc<RefCell<…>>`): lo conducen tanto [`run_tcp_intercept`] (standalone, RefCell local de un solo
/// consumidor) como el runner combinado (`combined::run_combined_intercept`, donde el MISMO resolver
/// lo muta concurrentemente el servidor DNS del manager UDP — espejo del `ziti_dns` global único del
/// oráculo). Los borrows del `RefCell` son SIEMPRE síncronos y mueren antes de cualquier `await`
/// (ambos loops corren en el MISMO hilo del `LocalSet`, así que un borrow vivo a través de un `await`
/// paniquearía al otro loop — la disciplina es load-bearing, no estilo).
///
/// `dns` = el contexto del servidor DNS embebido ([`super::dns_tcp::DnsTcpContext`]: `(server_ip, 53)` + los upstreams
/// para el forward sobre TCP, la pasa el runner combinado; el standalone da `None`). Un flujo TCP a
/// `(server_ip, 53)` se sirve como **DNS-over-TCP** ([`super::dns_tcp::serve_dns_over_tcp`],
/// beyond-oracle #4/#4b) en vez de dial-earse al overlay. El resolver es `&Rc<RefCell<…>>` (no
/// `&RefCell<…>`) porque esa task de servicio DNS retiene un handle del resolver TODA la conexión —
/// necesita un `Rc` clonable con vida propia, no un préstamo.
///
/// `flows` = el [`FlowRegistry`] compartido (kill-active). Cada flujo se da de alta AL ACEPTARSE —
/// antes del dial, espejo del `tcp_arg(npcb, io)` que el oráculo instala en `tunnel_tcp.c:434` ANTES
/// del `zdial` de `:438`, lo que hace enumerable (y matable) un flujo con el dial en vuelo — y su
/// token viaja hasta el splice. Su `RefCell` es una celda DISJUNTA de la del resolver, y el borrow del
/// `register` va en sentencia propia, DESPUÉS de que el borrow del resolver haya muerto.
pub(crate) async fn tcp_intercept_loop(
    client: &Rc<EdgeClient>,
    mut tcp: TcpHalf<'_>,
    resolver: &Rc<RefCell<InterceptResolver>>,
    dns: Option<super::dns_tcp::DnsTcpContext>,
    flows: &Rc<RefCell<FlowRegistry>>,
) -> io::Result<()> {
    // Splices establecidos, en el runtime MULTI-THREAD. Compartido (`Rc<RefCell<…>>`) con las tasks de
    // dial `!Send` del `LocalSet` (que empujan aquí post-dial); el `JoinSet` mismo vive en ESTE hilo
    // (`!Send` por el `Rc`), solo los FUTUROS del splice (que son `Send`) cruzan al pool. Al retornar
    // el loop el `JoinSet` se dropea → aborta los splices en vuelo (ver el doc de teardown arriba).
    let splices: Rc<RefCell<JoinSet<()>>> = Rc::new(RefCell::new(JoinSet::new()));
    // La IP del resolver embebido para el gate de dispatch (el standalone da `None`).
    let dns_server_ip = dns.as_ref().map(|d| d.server_ip);
    while let Some((stream, dst, src)) = tcp.accept().await {
        // Cosecha oportunista de los splices ya terminados para que los flujos cerrados no se acumulen
        // en el set (replica el auto-reaping que una task `spawn_local` detached recibía del `LocalSet`).
        // `try_join_next` no bloquea; el borrow es síncrono (no cruza `await`), así que no choca con el
        // `borrow_mut` que una task de dial hace al empujar su splice (hilo único, borrows disjuntos).
        while splices.borrow_mut().try_join_next().is_some() {}

        // DNS-over-TCP (beyond-oracle #4/#4b): un flujo a `(server_ip, 53)` lo SIRVE el servidor DNS
        // embebido con el framing de RFC 7766, NO se dial-ea al overlay — espejo TCP del gate `dst ==
        // (dns_ip, 53)` del path UDP. La task retiene el `Rc<RefCell<resolver>>` + el `Rc<EdgeClient>`
        // (para el dial de proxy-resolve, #4b) + los upstreams toda la conexión → es `!Send`, así que
        // va DETACHED al `LocalSet` como la task EXTERIOR del dial (`handle_intercept_conn`): el
        // teardown del `LocalSet` la cancela, dropeando el stream y cerrando la conn de netstack.
        if is_dns_tcp(dst, dns_server_ip)
            && let Some(d) = dns.as_ref()
        {
            tokio::task::spawn_local(super::dns_tcp::serve_dns_over_tcp(
                stream,
                Rc::clone(resolver),
                Rc::clone(client),
                Rc::clone(&d.upstream_servers),
            ));
            continue;
        }

        // Resuelve el destino REAL a un servicio (síncrono, no cruza await). `service`/`timeout`/
        // `dst_hostname` se copian a owned DENTRO del scope del borrow → ni el borrow del `RefCell`
        // ni los `&str` prestados sobreviven al statement (no entran a la task ni cruzan el `accept`).
        // `dst_hostname` = reverse-lookup del destino en el MISMO instante del dispatch, espejo del
        // `get_app_data` del oráculo C (`ziti_dns_reverse_lookup(dst_ip)`, `ziti_tunnel_cbs.c:255`)
        // y del `resolver.Lookup(dstIP)` del tproxy Go — ver `intercept_tcp_appdata`.
        let target = {
            let r = resolver.borrow();
            r.lookup(dst.ip(), dst.port(), Protocol::Tcp, src.ip())
                .map(|m| {
                    let hostname = match dst.ip() {
                        std::net::IpAddr::V4(v4) => r.dns().reverse_lookup(v4).map(str::to_string),
                        std::net::IpAddr::V6(_) => None,
                    };
                    (m.service.to_string(), m.dial_timeout, hostname)
                })
        };
        let Some((service, timeout, dst_hostname)) = target else {
            // Ningún servicio intercepta este destino → cierra el flujo limpio. netstack ya respondió
            // el SYN (artefacto del all-capture, ver el doc de `resolve`); soltar el stream lo cierra.
            tracing::debug!(%dst, %src, "intercept: ningún servicio intercepta el destino; flujo descartado");
            drop(stream);
            continue;
        };
        // Alta en el registro de flujos ANTES del dial (espejo de `tcp_arg` antes del `zdial`): un
        // `Removed` que llegue con el dial en vuelo ya encuentra este flujo y lo mata. Sentencia
        // propia: el `borrow_mut` nace y muere aquí, con el borrow del resolver ya difunto y sin
        // cruzar ningún `await`. El `Arc` devuelto se MUEVE a la task del flujo (invariante de vida).
        let kill = flows
            .borrow_mut()
            .register(&service, Protocol::Tcp, src, dst);
        let client = Rc::clone(client);
        let splices = Rc::clone(&splices);
        // El dial es `!Send` → corre en el `LocalSet`. Una vez produce los halves (que SÍ son `Send`),
        // empuja el splice al `JoinSet` (runtime MT). Ver `handle_intercept_conn`.
        tokio::task::spawn_local(async move {
            handle_intercept_conn(
                &client,
                &service,
                timeout,
                dst_hostname,
                stream,
                dst,
                src,
                &splices,
                kill,
            )
            .await;
        });
    }
    Ok(())
}

/// Dial `service` con el `AppData` del destino `dst` (en el `LocalSet`, `connect` es `!Send`) y, una vez
/// establecido, **empuja el splice al runtime MULTI-THREAD** vía `splices` (el `JoinSet` compartido de
/// [`tcp_intercept_loop`], sea quien sea su conductor — el standalone [`run_tcp_intercept`] o el runner
/// combinado). El splice sostiene el `Arc` del canal COMPARTIDO en scope a través de la copia
/// (para que su rx-loop siga alimentando la read-half) y lo suelta al terminar. Espejo de `handle_conn`
/// de `run_tcp_proxy`, salvo que el splice corre en el pool en vez de inline en el `LocalSet` (spike §7).
///
/// `dst_hostname` viene YA resuelto por el accept-loop (reverse-lookup en el instante del dispatch,
/// owned para no arrastrar el borrow del resolver a esta task) → entra al `AppData` vía
/// [`intercept_tcp_appdata`]. `src` es informativo (logging/diagnóstico). El oráculo lo usa SOLO para
/// derivar `source_addr` vía `GetSourceAddr` (diferido: sin `SourceAddrProvider` devuelve `""`) — por
/// eso no entra al `AppData`.
/// `kill` = el token de este flujo, dado de alta por el accept-loop ANTES del dial. Se MUEVE al future
/// del splice y no se clona fuera de él (invariante de vida del [`FlowRegistry`]). Si el dial FALLA, el
/// `Arc` se dropea al salir de esta fn → su `Weak` muere → la poda amortizada lo retira del registro
/// (sin deregister explícito). Si el kill disparó CON el dial en vuelo, `splice_until_killed` observa el
/// token ya cancelado en su primer poll y cierra sin relevar ni un byte (GWT-8): el dial NO se cancela
/// (la cancel-safety de `connect_with_appdata` no está probada — DV-5).
#[allow(clippy::too_many_arguments)]
async fn handle_intercept_conn(
    client: &EdgeClient,
    service: &str,
    timeout: Duration,
    dst_hostname: Option<String>,
    stream: InterceptTcpStream,
    dst: SocketAddr,
    src: SocketAddr,
    splices: &Rc<RefCell<JoinSet<()>>>,
    kill: std::sync::Arc<CancellationToken>,
) {
    let appdata = intercept_tcp_appdata(dst, dst_hostname.as_deref());
    match client
        .connect_with_appdata(service, timeout, Some(&appdata))
        .await
    {
        Ok(svc) => {
            let (zr, zw, channel) = svc.into_parts();
            // Los halves del splice son `Send` (pin `const` del módulo) → córrelo en el runtime
            // MULTI-THREAD para que su cripto + copias no se serialicen en el hilo del `LocalSet`.
            // Rastreado en el `JoinSet` compartido para que el teardown del accept-loop lo aborte (un
            // stack derribado colgaría el `TcpStream` de netstack para siempre — ver el doc de teardown
            // de `run_tcp_intercept`). El `borrow_mut` para `spawn` es síncrono (no cruza `await`).
            splices.borrow_mut().spawn(async move {
                let res = splice_until_killed(zr, zw, stream, kill).await;
                // El full-close de la conexión (StateClosed + deregister de este conn-id) ya ocurrió
                // dentro de `splice` (`zw.close()`). NO cerramos el CANAL: es un `Arc<EdgeChannel>`
                // COMPARTIDO que el pool posee y conserva para reuse — nuestra clone solo dropea aquí (el
                // rx-loop se aborta solo cuando dropea el ÚLTIMO `Arc`, el del pool incluido). Espejo de
                // `handle_conn` (T1).
                drop(channel);
                if let Err(e) = res {
                    tracing::warn!(error = %e, %dst, %src, "intercept: conexión TCP terminó con error");
                }
            });
        }
        Err(e) => {
            // `stream` se cierra implícitamente al dropear al final de este arm — espejo fiel del
            // `clientConn.Close()` EXPLÍCITO de `DialAndRun` cuando el dial al overlay falla
            // (`tunnel.go:52`). (El otro close del oráculo, ante un marshal-error del appInfo
            // `tunnel.go:46`, es N/A: `build_app_data` es infalible.)
            tracing::warn!(error = %e, %dst, %src, service = %service, "intercept: connect al overlay falló");
        }
    }
}

/// ¿Este destino es el servidor DNS embebido sobre TCP? `(dns_ip, 53)` con DNS configurado (el runner
/// combinado pasa `Some(dns_ip)`; el standalone TCP-only pasa `None` → nunca casa, TCP:53 se dropea
/// como antes). Espejo TCP del gate `dst == (dns_ip, 53)` que el manager UDP aplica antes de dial-ear.
fn is_dns_tcp(dst: SocketAddr, dns_server_ip: Option<Ipv4Addr>) -> bool {
    matches!(dns_server_ip, Some(ip) if dst.ip() == IpAddr::V4(ip) && dst.port() == 53)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    use crate::channel::connect::read_message;
    use crate::channel::message::Message;
    use crate::edge::data::{ChannelState, EdgeConn};
    use crate::edge::dial::{CT_DATA, CT_STATE_CLOSED, FLAG_FIN, HDR_FLAGS, build_data};

    /// Parsea el `AppData` emitido a un mapa `String→String` (como hace `json.Unmarshal` del host) para
    /// asertar la forma EXACTA del mapa, no solo bytes.
    fn parse(appdata: &[u8]) -> BTreeMap<String, String> {
        serde_json::from_slice(appdata).expect("el AppData es un objeto JSON string→string")
    }

    /// GATE §4.2.2 (IP-path v4): el emisor de intercept produce EXACTAMENTE el mapa del
    /// `GetAppInfo("tcp", "", dstIp, dstPort, "")` del interceptor Go — `dst_protocol`/`dst_ip`/
    /// `dst_port` presentes con los valores del destino, y NINGÚN otro campo. Las dos aserciones
    /// negativas son load-bearing: un destino SIN entrada DNS (intercept por-IP) NO emite
    /// `dst_hostname` (omit-empty de ambos oráculos), y `source_addr` sigue DIFERIDO — una mutación
    /// que emitiese cualquiera (o cambiase el protocolo) va RED.
    #[test]
    fn intercept_tcp_appdata_matches_oracle_get_app_info_ip_path_v4() {
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)), 19009);
        let map = parse(&intercept_tcp_appdata(dst, None));

        let mut expected = BTreeMap::new();
        expected.insert("dst_protocol".to_string(), "tcp".to_string());
        expected.insert("dst_ip".to_string(), "100.64.0.7".to_string());
        expected.insert("dst_port".to_string(), "19009".to_string());
        assert_eq!(map, expected, "mapa AppData == GetAppInfo IP-path");

        assert!(
            !map.contains_key("dst_hostname"),
            "sin entrada DNS no hay dst_hostname: omitido como GetAppInfo con dstHostname vacío"
        );
        assert!(
            !map.contains_key("source_addr"),
            "source_addr DIFERIDO (SourceAddrProvider/resolver-B): omitido como GetSourceAddr nil"
        );
    }

    /// GATE del hostname-path (cierre del diferido #1 de M2b-pre): con el reverse-lookup resuelto, el
    /// emisor añade `dst_hostname` — espejo EXACTO del `get_app_data` del C
    /// (`ziti_dns_reverse_lookup(dst_ip) → app_data->dst_hostname`, `ziti_tunnel_cbs.c:255-259`) y
    /// del `GetAppInfo("tcp", dstHostname, ...)` del Go tproxy. Y el caso degenerado: un hostname
    /// VACÍO (la entrada reservada calloc'd del oráculo, hoy inalcanzable porque una IP reservada no
    /// despacha) se OMITE — mismo criterio omit-empty que `GetAppInfo`.
    #[test]
    fn intercept_tcp_appdata_emits_dst_hostname_when_reverse_lookup_knows_it() {
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)), 19009);
        let map = parse(&intercept_tcp_appdata(dst, Some("app.wild.ziti.test")));

        let mut expected = BTreeMap::new();
        expected.insert("dst_protocol".to_string(), "tcp".to_string());
        expected.insert("dst_ip".to_string(), "100.64.0.3".to_string());
        expected.insert("dst_port".to_string(), "19009".to_string());
        expected.insert("dst_hostname".to_string(), "app.wild.ziti.test".to_string());
        assert_eq!(map, expected, "mapa == get_app_data con reverse-lookup hit");

        // Hostname vacío (entrada reservada) → omitido (omit-empty, como GetAppInfo).
        let empty = parse(&intercept_tcp_appdata(dst, Some("")));
        assert!(
            !empty.contains_key("dst_hostname"),
            "un hostname vacío se omite del mapa"
        );
        assert_eq!(empty.len(), 3);
    }

    /// GATE §4.2.2 (IP-path v6): la forma del IPv6 destino en `dst_ip` es la canónica comprimida
    /// (espejo de `net.IP.String()` del oráculo) y el resto del mapa es idéntico al caso v4. Pinea que
    /// `dst.ip().to_string()` no introduce un formato divergente para v6.
    #[test]
    fn intercept_tcp_appdata_ipv6_canonical_form() {
        let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), 443);
        let map = parse(&intercept_tcp_appdata(dst, None));

        assert_eq!(map.get("dst_protocol").map(String::as_str), Some("tcp"));
        assert_eq!(map.get("dst_ip").map(String::as_str), Some("fd00::1"));
        assert_eq!(map.get("dst_port").map(String::as_str), Some("443"));
        assert_eq!(map.len(), 3, "solo los 3 campos del caso IP-puro");
    }

    // === Spike de escala §7(d): el splice establecido corre en el runtime MULTI-THREAD ===

    const TEST_CONN_ID: u32 = 7;

    fn flags_of(msg: &Message) -> u32 {
        msg.headers
            .get(&HDR_FLAGS)
            .map_or(0, |v| u32::from_le_bytes(v[..4].try_into().unwrap()))
    }

    fn fin_frame() -> Message {
        let mut fin = build_data(TEST_CONN_ID, b"", false);
        fin.headers
            .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
        fin
    }

    /// Una conexión ziti falsa partida en halves (espejo del `fake_conn` de `proxy.rs`): `state` para
    /// asertar el deregister; `data_tx` para INYECTAR frames inbound (ziti→socket); y el extremo del
    /// router (duplex) que transporta lo que el splice ESCRIBE a ziti (socket→ziti + FIN + StateClosed).
    fn fake_conn() -> (
        crate::edge::data::EdgeReadHalf,
        crate::edge::data::EdgeWriteHalf,
        Arc<ChannelState>,
        mpsc::Sender<Message>,
        tokio::io::DuplexStream,
    ) {
        let (cw, router) = tokio::io::duplex(64 * 1024);
        let state = Arc::new(ChannelState::new(Box::new(cw)));
        let (data_tx, data_rx) = mpsc::channel(64);
        state.register_conn(TEST_CONN_ID, data_tx.clone());
        let conn = EdgeConn::new_for_test(TEST_CONN_ID, data_rx, state.clone());
        let (zr, zw) = conn.into_split();
        (zr, zw, state, data_tx, router)
    }

    /// Prueba EN RUNTIME del hallazgo del spike (complementa el pin `const` del módulo): un splice
    /// establecido se mueve a [`tokio::spawn`] en un runtime **multi-thread** y completa allí su
    /// round-trip + half-close + full-close. `tokio::spawn` exige `Send + 'static`; si cualquier half
    /// establecido fuese `!Send` (p.ej. un `Rc` en la cripto o en el `TcpStream` de netstack) esta línea
    /// NO compilaría. Que además el round-trip funcione prueba que el splice no solo es spawnable sino
    /// que ejecuta correctamente fuera del `LocalSet` — el refactor de `handle_intercept_conn`. Espejo
    /// del happy-path de `proxy::splice` (`splice_round_trips_bytes_propagates_half_close...`) pero
    /// spawneado en el pool en vez de bajo un `join!` inline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn established_splice_runs_spawned_on_a_multi_thread_runtime() {
        let (zr, zw, state, data_tx, mut router) = fake_conn();
        let (sock_for_splice, mut local) = tokio::io::duplex(64 * 1024);

        // Peer ziti falso: hace echo de los Data; ante el FIN del splice responde un FIN (half-close del
        // peer) y deja de hacer echo; registra si vio el StateClosed final.
        let echo = tokio::spawn(async move {
            let mut saw_state_closed = false;
            loop {
                let Ok(msg) = read_message(&mut router).await else {
                    break;
                };
                match msg.content_type {
                    CT_DATA if flags_of(&msg) & FLAG_FIN != 0 => {
                        let _ = data_tx.send(fin_frame()).await; // el peer half-cierra de vuelta
                    }
                    CT_DATA => {
                        let echoed = build_data(TEST_CONN_ID, &msg.body, false);
                        if data_tx.send(echoed).await.is_err() {
                            break;
                        }
                    }
                    CT_STATE_CLOSED => {
                        saw_state_closed = true;
                        break;
                    }
                    _ => {}
                }
            }
            saw_state_closed
        });

        // LA LÍNEA LOAD-BEARING: `tokio::spawn` (runtime MT, no el `LocalSet`) exige `Send + 'static`.
        let splice_task = tokio::spawn(splice(zr, zw, sock_for_splice));

        local.write_all(b"hello-intercept").await.unwrap();
        let mut buf = [0u8; 15];
        local.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            &buf, b"hello-intercept",
            "los bytes hacen round-trip por el splice spawneado en el pool"
        );
        local.shutdown().await.unwrap(); // half-close local → FIN a ziti → FIN del peer → EOF ziti
        let mut rest = Vec::new();
        local.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "sin bytes extra tras el echo");

        splice_task
            .await
            .expect("la task del splice spawneada hace join")
            .expect("el splice completa limpio en el runtime MT");
        assert!(
            echo.await.unwrap(),
            "el splice envió StateClosed (full-close) tras terminar ambas direcciones"
        );
        assert_eq!(
            state.conn_count(),
            0,
            "el conn se deregistró del mux exactamente una vez"
        );
    }

    // ───── DNS-over-TCP dispatch gate (el servicio y sus tests viven en `dns_tcp/`) ─────

    /// Dispatch pin: `(dns_ip, 53)` sobre TCP → DNS-over-TCP; cualquier otra cosa (otro puerto, otra
    /// IP, sin DNS configurado, o v6) → NO (se dial-ea/dropea como antes).
    #[test]
    fn dns_tcp_dispatch_gate() {
        let dns_ip = Ipv4Addr::new(100, 64, 0, 1);
        let at = |ip: [u8; 4], port: u16| SocketAddr::from((ip, port));
        assert!(
            is_dns_tcp(at([100, 64, 0, 1], 53), Some(dns_ip)),
            "(dns_ip,53)"
        );
        assert!(!is_dns_tcp(at([100, 64, 0, 1], 53), None), "sin DNS → no");
        assert!(
            !is_dns_tcp(at([100, 64, 0, 1], 443), Some(dns_ip)),
            "otro puerto → no"
        );
        assert!(
            !is_dns_tcp(at([100, 64, 0, 2], 53), Some(dns_ip)),
            "otra IP → no"
        );
        assert!(
            !is_dns_tcp(SocketAddr::from((Ipv6Addr::LOCALHOST, 53)), Some(dns_ip)),
            "v6 → no (dns_ip es v4)"
        );
    }
}
