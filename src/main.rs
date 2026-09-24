//! `noa` binary (crate `noa-sdk`).
//! Subcommands:
//! - `enroll <token.jwt> [--out <path>] [--keyAlg RSA|EC] [--ca <ca-bundle.pem>]`
//! - `proxy <listen_addr> <service> <identity.json>` — TCP proxy onto a ziti service (tunneler T1).
//! - `proxy-udp <listen_addr> <service> <identity.json>` — UDP proxy onto a ziti service (tunneler
//!   T3): demultiplexes datagrams by source address into per-source ziti connections.
//! - `host <service> <target_addr> <identity.json>` — host a ziti service, forward to a local TCP
//!   target (tunneler T2).
//! - `host-forward <service> <identity.json>` — host a ziti service, forward to a DYNAMIC local TCP
//!   target resolved from each inbound dial's appData against the service's `host.v1` config
//!   (tunneler T4b-1).
//! - `intercept <utun-cidr> <identity.json>` — (feature `intercept`, REQUIERE root) capturar el
//!   tráfico TCP **y UDP** local destinado a la subred del utun (o a una ruta instalada, M3-rutas) y
//!   rutarlo al servicio overlay que su `intercept.v1` intercepta (resolver dst→servicio, slice (B)),
//!   emitiendo el `AppData` del destino; monta además el servidor DNS embebido en `(utun_addr+1, 53)`
//!   (M3-DNS) — el análogo de `ziti-edge-tunnel run`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::rc::Rc;

use noa_sdk::edge::client::EdgeClient;
use noa_sdk::edge::model::HOST_V1_CONFIG_TYPE;
use noa_sdk::enroll::csr::KeyAlg;
use noa_sdk::enroll::error::EnrollError;
use noa_sdk::enroll::identity::Config;
use noa_sdk::enroll::{self, ott::EnrollOptions};
use noa_sdk::tunnel::{run_tcp_host, run_tcp_host_forwarding, run_tcp_proxy, run_udp_proxy};
use tokio::net::{TcpListener, UdpSocket};

#[cfg(feature = "intercept")]
use noa_sdk::tunnel::intercept::{
    DnsMatcher, INTERCEPT_V1_CONFIG_TYPE, InterceptResolver, InterceptStack, IpPacketDevice,
    OsRouteOps, RouteApplier, RouteLifecycle, UtunDevice, control_plane_addrs,
    run_combined_intercept,
};
#[cfg(feature = "intercept")]
use std::net::Ipv4Addr;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map_or("noa", String::as_str);
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::WARN.into())
        .from_env_lossy();
    if let Err(e) = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
    {
        eprintln!("warning: no se pudo instalar el subscriber de tracing: {e}");
    }
    tracing::debug!(prog = %prog, "noa iniciando (RUST_LOG activo)");
    match args.get(1).map(String::as_str) {
        Some("enroll") => match run_enroll(&args).await {
            Ok(out) => {
                println!("enrolled; identity written to {}", out.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Some("proxy") => match run_proxy(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Some("proxy-udp") => match run_proxy_udp(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Some("host") => match run_host(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Some("host-forward") => match run_host_forward(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        #[cfg(feature = "intercept")]
        Some("intercept") => match run_intercept(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        #[cfg(not(feature = "intercept"))]
        Some("intercept") => {
            eprintln!(
                "error: el subcomando `intercept` requiere compilar con `--features intercept`"
            );
            ExitCode::FAILURE
        }
        _ => {
            eprintln!(
                "usage:\n  {prog} enroll <token.jwt> [--out <path>] [--keyAlg RSA|EC] [--ca <ca-bundle.pem>]\n  {prog} proxy <listen_addr> <service> <identity.json>\n  {prog} proxy-udp <listen_addr> <service> <identity.json>\n  {prog} host <service> <target_addr> <identity.json>\n  {prog} host-forward <service> <identity.json>\n  {prog} intercept <utun-cidr> <identity.json>   (feature `intercept`, root)"
            );
            ExitCode::FAILURE
        }
    }
}

/// `noa intercept <utun-cidr> <identity.json>` (feature `intercept`, **REQUIERE root**): abre un
/// dispositivo utun con la dirección/prefijo dados, monta la pila netstack de intercept CON UDP
/// (M1 + M3-UDP-stack), y corre el runner COMBINADO ([`run_combined_intercept`], el análogo de
/// `ziti-edge-tunnel run`): cada flujo TCP y cada datagrama UDP que el SO rutee a esa subred (o a una
/// ruta instalada, M3-rutas) va al servicio overlay que su `intercept.v1` intercepta (resolver (B):
/// el DESTINO elige el servicio), emitiendo el `AppData` del destino interceptado; y el servidor DNS
/// embebido queda montado en `(utun_addr+1, 53)` (M3-DNS): una query **A** por un hostname/dominio
/// interceptado devuelve su IP sintética (una AAAA asigna igualmente pero responde NOERROR SIN
/// registros — las IPs sintéticas son v4, espejo del oráculo), que despacha en el paquete siguiente
/// (el resolver es UNO, compartido entre el DNS y el dispatch de ambos protocolos). Con
/// `--dns-upstream <ip[:puerto]>` (repetible, M3-DNS #1), una query recursiva que el resolver no
/// resuelve localmente se REENVÍA a esos servidores (passthrough de la respuesta al cliente); sin el
/// flag, un miss = REFUSED.
///
/// Uso: `sudo noa intercept 100.64.0.1/10 id.json`; luego un cliente real resuelve y conecta:
/// `dig @100.64.0.2 app.example.com` → IP sintética; `nc <esa-ip> 80` → el flujo atraviesa
/// host→overlay. (Un `intercept.v1` por IP/CIDR sigue funcionando sin el paso DNS, p. ej.
/// `nc 100.64.0.9 80` si algún servicio intercepta esa dirección.)
///
/// Corre `run_combined_intercept` bajo un `LocalSet` (el `connect` del overlay es `!Send`, slice
/// 10c). El timeout del dial overlay lo aporta el resolver por-servicio (`intercept.v1`
/// `dialOptions`, default 5s = `svcpoll.go:184`), NO un default fijo.
#[cfg(feature = "intercept")]
async fn run_intercept(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let prog = args.first().map_or("noa", String::as_str);
    let (Some(utun_cidr), Some(identity_path)) = (args.get(2), args.get(3)) else {
        return Err(format!("usage: {prog} intercept <utun-cidr> <identity.json>").into());
    };
    let (utun_addr, prefix) = parse_utun_cidr(utun_cidr)?;

    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(identity_path)?)?;
    let mut client = EdgeClient::from_identity(&cfg)?;
    client.authenticate().await?;

    // M3-DNS: siembra el pool de IP sintética desde el MISMO CIDR del utun (reusa `utun_addr`/`prefix`
    // ya parseados; ver `seed_and_reserve_dns_pool`) + reserva la IP del utun y la del DNS resolver
    // embebido (`utun_addr+1`, donde el runner combinado monta el servidor) antes de registrar ningún
    // hostname.
    let (dns, dns_server_ip) = seed_and_reserve_dns_pool(utun_addr, prefix)?;

    // El snapshot de servicios (`intercept.v1`, el MISMO wire ya live por T4b-0). El resolver se
    // construye MÁS ABAJO, foldeando este snapshot con los deltas de ruta hacia el `RouteLifecycle`
    // (necesita el `if_index` del utun, aún no abierto).
    let services = client
        .list_services_with_config_types(&[INTERCEPT_V1_CONFIG_TYPE.to_string()])
        .await?;
    // Siembra el cache del `ServiceWatcher` con el MISMO snapshot que construirá el resolver, así el
    // primer tick de la rama svc-poll del runner combinado (T5 re-feed) diffea contra el conjunto ACTUAL
    // — sólo los cambios reales disparan eventos — en vez de re-emitir todo como `Added`. Espejo del
    // `context.services` que el oráculo deja caliente tras `Authenticate` antes de `runRefreshes`.
    client.prime_service_cache(&services);

    // Abre el utun (requiere root). El SO ruteará la subred on-link del utun hacia el device.
    let dev = UtunDevice::open(utun_addr, prefix, UtunDevice::DEFAULT_MTU)?;
    let iface = dev.name().unwrap_or_else(|_| "utun?".to_string());

    // RUTAS OS (refcounted, espejo de `route.c`): el ciclo de vida vive en un `RouteLifecycle` que
    // (a) se SIEMBRA aquí por-SERVICIO foldeando el snapshot (mismo conjunto instalado que el plan
    // en bloque previo para todo config válido según el esquema del controller — la excepción
    // teórica, un `intercept.v1` con `addresses` pero `protocols`/`portRanges` VACÍOS, ahora SÍ se
    // rutea, que es lo que hace el C (`add_route` recorre `addresses` incondicionalmente) e
    // inalcanzable con un controller real (su esquema exige ambos no-vacíos): cambio oracle-ward —
    // y con counts: un CIDR compartido por N servicios sobrevive a la retirada en vivo de N−1), y
    // (b) lo CONDUCE en vivo la rama svc-poll del runner combinado (un servicio añadido/retirado
    // instala/quita sus rutas mid-run, `ziti_tunneler_intercept`/`stop_intercepting`). `if_index`
    // se lee ANTES de mover `dev` a la pila. Su `Drop` quita lo que quede instalado al salir (en un
    // crash sin Drop, el kernel purga al morir el utun, igual que el oráculo).
    let if_index = dev.if_index()?;
    // Carve-out del plano de control: resuelve las IPs del controller (`ztAPI`/`ztAPIs`) para que
    // NINGUNA ruta de intercept amplia capture los dials del propio SDK (renovación/reauth/poll →
    // self-DoS). Las direcciones de edge router no se conocen aún en este snapshot (dial lazy) → el
    // exclude es PARCIAL (solo controller, por rehúso); ver el diferido nombrado en `routes/mod.rs`. El
    // guard vive DENTRO del lifecycle → protege igual las rutas de servicios añadidos EN VIVO.
    let mut controller_urls = vec![cfg.zt_api.clone()];
    if let Some(apis) = &cfg.zt_apis {
        controller_urls.extend(apis.iter().cloned());
    }
    let control_plane = control_plane_addrs(&controller_urls);
    let mut routes =
        RouteLifecycle::new(OsRouteOps::new(if_index)?, utun_addr, prefix, control_plane)?;

    // Resolver (B): la tabla dst→servicio, construida foldeando el snapshot servicio a servicio
    // (idéntico a `from_services_with_dns` — ES el mismo fold) y aplicando el `RouteDelta` de cada
    // alta al lifecycle (espejo del arranque del oráculo: cada servicio del snapshot pasa por
    // `on_service` → `ziti_tunneler_intercept` → `add_route`). Los hostnames exactos reciben una IP
    // sintética eager del pool `dns` (dentro de la subred on-link → sin ruta explícita); los dominios
    // wildcard construyen entradas de dispatch por-dominio (#6).
    let mut resolver = InterceptResolver::from_services_with_dns(&[], dns);
    for svc in &services {
        // El fold del snapshot ignora `kill_active` (siempre `false`: ningún nombre está instalado
        // todavía) — y aunque fuese `true` no habría flujo alguno que matar: el runner no ha arrancado.
        let applied = resolver.add_service(svc);
        routes.apply_delta(&applied.routes);
    }
    if resolver.is_empty() {
        eprintln!(
            "intercept: aviso — ningún servicio Dial-permitido con un `intercept.v1` visible (IP/CIDR, hostname o dominio wildcard); no se interceptará nada"
        );
    }

    // Monta la pila intercept CON UDP (4 tasks de fondo: runner + ingress + egress + reply-egress).
    // CADA flujo TCP a un destino ruteado (la subred on-link O una ruta instalada) entra a la pila
    // como un `InterceptTcpStream`, cada datagrama UDP como `(payload, dst, src)`, y el resolver
    // elige su servicio por el DESTINO; el servidor DNS embebido atiende `(utun_addr+1, 53)`.
    let stack = InterceptStack::new_with_udp(dev)?;
    println!(
        "intercept: {iface} {utun_addr}/{prefix} -> resolver intercept.v1 ({} servicios, {} rutas OS-level, DNS embebido en {dns_server_ip}:53; el destino elige el servicio)",
        services.len(),
        routes.installed()
    );

    // Upstream DNS (`--dns-upstream <ip[:puerto]>`, M3-DNS #1): las queries que el resolver embebido
    // no responde localmente (y piden recursión, RD=1) se reenvían a estos servidores. Sin el flag,
    // un miss = REFUSED local (comportamiento pre-upstream). Espejo de `-u|--dns-upstream` del oráculo.
    let upstream_servers = parse_dns_upstream_flags(args)?;
    if !upstream_servers.is_empty() {
        println!("intercept: DNS upstream configurado: {upstream_servers:?}");
    }

    // EdgeClient::connect es !Send -> conduce ambos loops (accept TCP + manager UDP/DNS) y el trabajo
    // por-flujo en un LocalSet. El lifecycle de rutas se MUEVE al runner (la rama svc-poll lo
    // alimenta con los deltas de los eventos vivos); su `Drop` — al terminar el runner — quita las
    // rutas que sigan instaladas.
    let client = Rc::new(client);
    tokio::task::LocalSet::new()
        .run_until(run_combined_intercept(
            client,
            stack,
            resolver,
            dns_server_ip,
            upstream_servers,
            Some(Box::new(routes)),
        ))
        .await?;
    Ok(())
}

/// `--dns-upstream <ip[:puerto]>` (repetible; también `--dns-upstream=<...>`): servidores DNS upstream
/// a los que el resolver embebido reenvía las queries que no resuelve localmente (M3-DNS #1). Espeja
/// la FUNCIÓN `ziti_dns_set_upstream` (que sí acepta un ARRAY de upstreams con puerto,
/// `ziti_dns.c:210-275`), NO el flag `-u|--dns-upstream` del oráculo, que es ESCALAR last-wins e
/// IP-only sin `:puerto` (`ziti-edge-tunnel.c:1225,1326,941-946`). Ser repetible y aceptar `:puerto`
/// son mejoras conscientes sobre esa CLI (alcanzables en el oráculo solo por su path IPC/JSON).
/// **Dos desviaciones nombradas:** (1) un valor sin `:puerto` usa 53, con `:` explícito lo respeta
/// (`1.1.1.1:5353`); (2) el upstream debe ser una IP — un HOSTNAME (que el oráculo resolvería vía
/// `uv_getaddrinfo`, `ziti_dns.c:262-267`) se RECHAZA fail-loud (contrato `<ip[:puerto]>`,
/// under-capability consciente, consistente con el resto de flags del bin, que también fallan-loud
/// ante un valor mal formado en vez del warn-y-sigue del oráculo).
#[cfg(feature = "intercept")]
fn parse_dns_upstream_flags(
    args: &[String],
) -> Result<Vec<std::net::SocketAddr>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let value = if let Some(v) = args[i].strip_prefix("--dns-upstream=") {
            Some(v.to_string())
        } else if args[i] == "--dns-upstream" {
            let v = args
                .get(i + 1)
                .ok_or("--dns-upstream requiere un valor <ip[:puerto]>")?;
            i += 1;
            Some(v.clone())
        } else {
            None
        };
        if let Some(v) = value {
            // Con `:puerto` explícito → parsea como SocketAddr; sin él → IP + puerto 53.
            let addr: std::net::SocketAddr = if let Ok(sa) = v.parse() {
                sa
            } else {
                let ip: std::net::IpAddr = v
                    .parse()
                    .map_err(|e| format!("--dns-upstream '{v}' inválido (ip o ip:puerto): {e}"))?;
                std::net::SocketAddr::new(ip, 53)
            };
            out.push(addr);
        }
        i += 1;
    }
    Ok(out)
}

/// Parsea `<addr>/<prefix>` (p. ej. `10.99.0.1/24`) a `(Ipv4Addr, u8)` para configurar el utun. La
/// subred on-link resultante es la que el SO rutea al device (el destino interceptado debe caer en
/// ella). Sin barra o con prefijo > 32 → error claro.
#[cfg(feature = "intercept")]
fn parse_utun_cidr(s: &str) -> Result<(Ipv4Addr, u8), Box<dyn std::error::Error>> {
    let (addr, prefix) = s.split_once('/').ok_or_else(|| {
        format!("utun-cidr inválido '{s}': se espera <addr>/<prefix>, p. ej. 10.99.0.1/24")
    })?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|e| format!("IPv4 inválida '{addr}': {e}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|e| format!("prefijo inválido '{prefix}': {e}"))?;
    if prefix > 32 {
        return Err(format!("prefijo fuera de rango '{prefix}': debe ser 0..=32").into());
    }
    Ok((addr, prefix))
}

/// Siembra un [`DnsMatcher`] para M3-DNS desde el MISMO CIDR configurado para el utun, y reserva la
/// dirección del utun + la del DNS resolver embebido (`utun_addr+1`, devuelta como 2º elemento: es
/// donde el runner combinado monta el servidor UDP:53) — espejo de `ziti_dns_setup`
/// (`ziti_dns.c:181-202`): el tunneler C siembra el pool desde el MISMO `dns_cidr` que usa para la
/// dirección del propio tun (`ziti-edge-tunnel.c`: `tun_ip` y `dns_cidr` derivan del MISMO valor
/// `--dns-ip-range`, default `100.64.0.1/10`, y `dns_ip = tun_ip+1`, `:1491-1492`), y reserva AMBAS
/// direcciones (`tun_ip`, `dns_ip`) antes de registrar ningún hostname de servicio. Reusar
/// `utun_addr`/`prefix` en vez de introducir un flag CLI nuevo es la elección fiel: nuestro CLI ya le
/// pide al operador exactamente ese CIDR (`noa intercept <utun-cidr> ...`), y una IP sintética así
/// asignada cae SIEMPRE on-link (el SO ya rutea toda la subred del utun al device, sin necesitar una
/// ruta OS-level adicional de M3-rutas).
///
/// **Restricción NUEVA** (antes de esta rebanada, cualquier prefijo 0..=32 era válido para el utun):
/// [`DnsMatcher::seed_pool`] rechaza `/0` y `/32` (degenerados para el pool de IP sintética, ver el
/// doc de `dns/`) — fail-loud con el porqué, espejo de `exit(EXIT_FAILURE)` del oráculo ante un
/// `dns_cidr` inválido, en vez de degradar silenciosamente a "sin M3-DNS" para esos prefijos.
#[cfg(feature = "intercept")]
fn seed_and_reserve_dns_pool(
    utun_addr: Ipv4Addr,
    prefix: u8,
) -> Result<(DnsMatcher, Ipv4Addr), Box<dyn std::error::Error>> {
    let mut dns = DnsMatcher::new();
    if !dns.seed_pool(&format!("{utun_addr}/{prefix}")) {
        return Err(format!(
            "utun-cidr '{utun_addr}/{prefix}' inválido para el pool de IP sintética de M3-DNS: el \
             mismo CIDR del utun ahora sirve también de rango DNS, y /0 y /32 se rechazan \
             (degenerados, ver IpPool::seed en dns/)"
        )
        .into());
    }
    dns.reserve(utun_addr);
    let dns_resolver_addr = Ipv4Addr::from(u32::from(utun_addr).wrapping_add(1));
    dns.reserve(dns_resolver_addr);
    Ok((dns, dns_resolver_addr))
}

/// `noa proxy <listen_addr> <service> <identity.json>`: bind a local TCP listener and splice each
/// accepted connection onto a dialed ziti `service` (tunneler T1). Runs until the listener errors
/// (e.g. interrupted). Per-connection work runs under a `LocalSet` (`EdgeClient::connect` is
/// `!Send`, see [`run_tcp_proxy`]).
async fn run_proxy(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let prog = args.first().map_or("noa", String::as_str);
    let (Some(listen_addr), Some(service), Some(identity_path)) =
        (args.get(2), args.get(3), args.get(4))
    else {
        return Err(format!("usage: {prog} proxy <listen_addr> <service> <identity.json>").into());
    };
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(identity_path)?)?;
    let mut client = EdgeClient::from_identity(&cfg)?;
    client.authenticate().await?;
    let listener = TcpListener::bind(listen_addr).await?;
    println!(
        "proxy: listening on {} -> ziti service '{service}'",
        listener.local_addr()?
    );
    // EdgeClient::connect is !Send -> drive the accept loop + per-conn splices on a LocalSet.
    let client = Rc::new(client);
    let service = service.clone();
    tokio::task::LocalSet::new()
        .run_until(run_tcp_proxy(client, listener, service))
        .await?;
    Ok(())
}

/// `noa proxy-udp <listen_addr> <service> <identity.json>`: bind a local UDP socket and demultiplex
/// its datagrams by source address onto per-source dialed ziti `service` connections (tunneler T3).
/// Runs until the socket errors. The manager + per-source vconns run under a `LocalSet`
/// (`EdgeClient::connect` is `!Send`, see [`run_udp_proxy`]).
async fn run_proxy_udp(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let prog = args.first().map_or("noa", String::as_str);
    let (Some(listen_addr), Some(service), Some(identity_path)) =
        (args.get(2), args.get(3), args.get(4))
    else {
        return Err(
            format!("usage: {prog} proxy-udp <listen_addr> <service> <identity.json>").into(),
        );
    };
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(identity_path)?)?;
    let mut client = EdgeClient::from_identity(&cfg)?;
    client.authenticate().await?;
    let socket = UdpSocket::bind(listen_addr).await?;
    println!(
        "proxy-udp: listening on {} -> ziti service '{service}'",
        socket.local_addr()?
    );
    // EdgeClient::connect is !Send -> drive the manager + per-source vconns on a LocalSet.
    let client = Rc::new(client);
    let service = service.clone();
    tokio::task::LocalSet::new()
        .run_until(run_udp_proxy(client, socket, service))
        .await?;
    Ok(())
}

/// `noa host <service> <target_addr> <identity.json>`: register this identity as a host of the ziti
/// `service` and forward each inbound dial to a local TCP `target_addr` (tunneler T2). Runs until
/// the listener (bind) is torn down. Per-connection work runs under a `LocalSet` (see
/// [`run_tcp_host`]); `bind` is `!Send` (slice 10c) but is awaited directly here, before the loop.
async fn run_host(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let prog = args.first().map_or("noa", String::as_str);
    let (Some(service), Some(target_addr), Some(identity_path)) =
        (args.get(2), args.get(3), args.get(4))
    else {
        return Err(format!("usage: {prog} host <service> <target_addr> <identity.json>").into());
    };
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(identity_path)?)?;
    let mut client = EdgeClient::from_identity(&cfg)?;
    client.authenticate().await?;
    let binding = client.bind(service).await?;
    println!("host: serving ziti service '{service}' -> local TCP {target_addr}");
    let target = target_addr.clone();
    tokio::task::LocalSet::new()
        .run_until(run_tcp_host(binding, target))
        .await?;
    Ok(())
}

/// `noa host-forward <service> <identity.json>`: register this identity as a host of the ziti `service`
/// and forward each inbound dial to a DYNAMIC local TCP target resolved from the dial's appData
/// (`dst_*`, header 1011) against the service's `host.v1` config (tunneler T4b-1). Reads the service's
/// `host.v1` once at startup (a missing/malformed host.v1 is a clean startup error — the
/// `host_v1_config()` log-and-skip is for the multi-service poller, T5; one subcommand surfaces it).
async fn run_host_forward(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let prog = args.first().map_or("noa", String::as_str);
    let (Some(service), Some(identity_path)) = (args.get(2), args.get(3)) else {
        return Err(format!("usage: {prog} host-forward <service> <identity.json>").into());
    };
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string(identity_path)?)?;
    let mut client = EdgeClient::from_identity(&cfg)?;
    client.authenticate().await?;

    // Fetch the service WITH its host.v1 config (the configTypes wire from T4b-0), resolve by name, and
    // parse host.v1. Oracle: the tunneler reads `host.v1` from the polled service (svcpoll.go) — here a
    // single-service subcommand reads it once at startup.
    let services = client
        .list_services_with_config_types(&[HOST_V1_CONFIG_TYPE.to_string()])
        .await?;
    let svc = services
        .iter()
        .find(|s| s.name == *service)
        .ok_or_else(|| format!("service '{service}' not found"))?;
    let host_v1 = svc.host_v1_config()?.ok_or_else(|| {
        format!("service '{service}' has no host.v1 config (forwarding requires it)")
    })?;

    let binding = client.bind(service).await?;
    println!("host-forward: serving ziti service '{service}' -> dynamic host.v1 target");
    tokio::task::LocalSet::new()
        .run_until(run_tcp_host_forwarding(binding, host_v1))
        .await?;
    Ok(())
}

async fn run_enroll(args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if args.len() < 3 || args[1] != "enroll" {
        return Err(format!(
            "usage: {} enroll <token.jwt> [--out <path>] [--keyAlg RSA|EC] [--ca <ca-bundle.pem>]",
            args.first().map_or("noa", String::as_str)
        )
        .into());
    }
    let jwt_path = PathBuf::from(&args[2]);
    let out_path = parse_out_flag(args).unwrap_or_else(|| default_out(&jwt_path));
    let key_alg = parse_keyalg_flag(args)?;
    // Read the --ca bundle eagerly: unlike the oracle (which silently ignores os.ReadFile errors,
    // enroll.go:76), surface an unreadable --ca path as an error (fail fast on a bad flag).
    let additional_cas = parse_ca_flag(args)
        .map(std::fs::read_to_string)
        .transpose()?;

    let jwt = std::fs::read_to_string(&jwt_path)?;
    let opts = EnrollOptions {
        key_alg,
        additional_cas,
        ..Default::default()
    };
    let config = enroll::ott::enroll(jwt.trim(), opts).await?;
    let json = config.to_json()?;
    std::fs::write(&out_path, json)?;
    // Match the Go client: remove the consumed JWT.
    let _ = std::fs::remove_file(&jwt_path);
    Ok(out_path)
}

fn parse_out_flag(args: &[String]) -> Option<PathBuf> {
    let i = args.iter().position(|a| a == "--out")?;
    args.get(i + 1).map(PathBuf::from)
}

/// `--ca <path>` (also `--ca=<path>`): a PEM bundle of extra trusted CAs to add to the enrolment
/// trust pool + identity CA bundle (oracle `EnrollmentFlags.AdditionalCAs` / `ziti edge enroll --ca`).
/// Returns the path; `run` reads it (a missing/unreadable path errors, unlike the oracle's silent
/// ignore). Both forms are handled so `--ca=foo.pem` is NOT silently dropped (consistent with `--keyAlg`).
fn parse_ca_flag(args: &[String]) -> Option<PathBuf> {
    for (i, arg) in args.iter().enumerate() {
        if let Some(p) = arg.strip_prefix("--ca=") {
            return Some(PathBuf::from(p));
        }
        if arg == "--ca" {
            return args.get(i + 1).map(PathBuf::from);
        }
    }
    None
}

/// `--keyAlg`/`-a <RSA|EC>` (also the `=` form `--keyAlg=RSA`): select the client key algorithm
/// (oracle CLI `-a, --keyAlg RSA|EC`). Absent → EC P-384 (our SDK default; the upstream CLI's flag
/// example defaults to RSA — a conscious deviation to keep the bin consistent with the library
/// `EnrollOptions::default()`). Value parsed by `KeyAlg::parse` (mirror of `KeyAlgVar.Set`). Both
/// the space and `=` forms are handled so `--keyAlg=RSA` is NOT silently ignored (→ default EC).
fn parse_keyalg_flag(args: &[String]) -> Result<KeyAlg, EnrollError> {
    for (i, arg) in args.iter().enumerate() {
        if let Some(v) = arg
            .strip_prefix("--keyAlg=")
            .or_else(|| arg.strip_prefix("-a="))
        {
            return KeyAlg::parse(v);
        }
        if arg == "--keyAlg" || arg == "-a" {
            let value = args.get(i + 1).ok_or(EnrollError::InvalidKeyAlg)?;
            return KeyAlg::parse(value);
        }
    }
    Ok(KeyAlg::default())
}

fn default_out(jwt_path: &Path) -> PathBuf {
    jwt_path.with_extension("json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(extra: &[&str]) -> Vec<String> {
        let mut v = vec!["noa".to_string(), "enroll".to_string(), "t.jwt".to_string()];
        v.extend(extra.iter().map(ToString::to_string));
        v
    }

    #[test]
    fn keyalg_flag_defaults_to_ec_when_absent() {
        assert_eq!(parse_keyalg_flag(&argv(&[])).unwrap(), KeyAlg::EcP384);
    }

    #[test]
    fn keyalg_flag_parses_rsa_and_ec_both_spellings() {
        assert_eq!(
            parse_keyalg_flag(&argv(&["--keyAlg", "RSA"])).unwrap(),
            KeyAlg::Rsa4096
        );
        assert_eq!(
            parse_keyalg_flag(&argv(&["-a", "ec"])).unwrap(),
            KeyAlg::EcP384
        );
    }

    #[test]
    fn keyalg_flag_handles_equals_form() {
        // `--keyAlg=RSA` must NOT silently fall back to EC.
        assert_eq!(
            parse_keyalg_flag(&argv(&["--keyAlg=RSA"])).unwrap(),
            KeyAlg::Rsa4096
        );
        assert_eq!(
            parse_keyalg_flag(&argv(&["-a=ec"])).unwrap(),
            KeyAlg::EcP384
        );
        assert!(matches!(
            parse_keyalg_flag(&argv(&["--keyAlg=p384"])),
            Err(EnrollError::InvalidKeyAlg)
        ));
    }

    #[test]
    fn keyalg_flag_rejects_bad_value_and_missing_value() {
        assert!(matches!(
            parse_keyalg_flag(&argv(&["--keyAlg", "p384"])),
            Err(EnrollError::InvalidKeyAlg)
        ));
        // Flag present with no following value.
        assert!(matches!(
            parse_keyalg_flag(&argv(&["--keyAlg"])),
            Err(EnrollError::InvalidKeyAlg)
        ));
    }

    #[test]
    fn out_flag_parses_path_or_defaults() {
        assert_eq!(
            parse_out_flag(&argv(&["--out", "/tmp/id.json"])),
            Some(PathBuf::from("/tmp/id.json"))
        );
        assert_eq!(parse_out_flag(&argv(&[])), None);
        assert_eq!(
            default_out(Path::new("/tmp/t.jwt")),
            PathBuf::from("/tmp/t.json")
        );
    }

    #[test]
    fn ca_flag_parses_path_or_none() {
        assert_eq!(
            parse_ca_flag(&argv(&["--ca", "/tmp/extra-ca.pem"])),
            Some(PathBuf::from("/tmp/extra-ca.pem"))
        );
        // The `=` form must NOT be silently dropped (would enrol without the extra CAs).
        assert_eq!(
            parse_ca_flag(&argv(&["--ca=/tmp/e.pem"])),
            Some(PathBuf::from("/tmp/e.pem"))
        );
        assert_eq!(parse_ca_flag(&argv(&[])), None);
    }

    // The conscious deviation (c): unlike the oracle's silent os.ReadFile ignore, an unreadable
    // --ca path fails fast. Testable without network — the --ca read precedes the JWT read + enroll().
    #[tokio::test]
    async fn ca_flag_unreadable_path_errors() {
        let args = argv(&["--ca", "/no/such/missing-ca-bundle.pem"]);
        assert!(run_enroll(&args).await.is_err());
    }

    #[cfg(feature = "intercept")]
    #[test]
    fn parse_utun_cidr_parses_and_rejects() {
        assert_eq!(
            parse_utun_cidr("10.99.0.1/24").unwrap(),
            (Ipv4Addr::new(10, 99, 0, 1), 24)
        );
        assert!(parse_utun_cidr("10.99.0.1").is_err(), "sin barra"); // falta el prefijo
        assert!(parse_utun_cidr("notanip/24").is_err(), "IPv4 inválida");
        assert!(parse_utun_cidr("10.0.0.1/33").is_err(), "prefijo > 32");
    }

    /// [`seed_and_reserve_dns_pool`]: reserva AMBAS direcciones (la del utun Y `utun_addr+1`, espejo
    /// `ziti_dns_setup` reservando `tun_ip` Y `dns_ip=tun_ip+1`) — un hostname exacto registrado
    /// contra el pool devuelto debe saltarse las DOS, no solo la primera — y devuelve `utun_addr+1`
    /// como la dirección del DNS embebido (donde `run_intercept` monta el servidor UDP:53).
    #[cfg(feature = "intercept")]
    #[test]
    fn seed_and_reserve_dns_pool_reserves_utun_addr_and_utun_addr_plus_one() {
        let (mut dns, dns_ip) = seed_and_reserve_dns_pool(Ipv4Addr::new(10, 99, 0, 1), 24).unwrap();
        assert_eq!(
            dns_ip,
            Ipv4Addr::new(10, 99, 0, 2),
            "la IP del DNS embebido devuelta = utun_addr+1 (espejo dns_ip = tun_ip+1)"
        );
        let ip = match dns.register("app.example.com", "i") {
            noa_sdk::tunnel::intercept::RegisterOutcome::Hostname(ip) => ip,
            other => panic!("debe asignar IP: {other:?}"),
        };
        assert_eq!(
            ip,
            Ipv4Addr::new(10, 99, 0, 3),
            "10.99.0.1 (utun) y 10.99.0.2 (DNS resolver) reservadas: el primer hostname recibe la \
             3ª dirección"
        );
    }

    /// `--dns-upstream`: puerto default 53, `:puerto` explícito respetado, ambas grafías
    /// (`--dns-upstream X` y `--dns-upstream=X`), repetible, y fail-loud ante un valor inválido.
    #[cfg(feature = "intercept")]
    #[test]
    fn parse_dns_upstream_flags_parses_all_forms() {
        use std::net::SocketAddr;
        let a = |v: &[&str]| {
            let argv: Vec<String> = v.iter().map(ToString::to_string).collect();
            parse_dns_upstream_flags(&argv)
        };
        assert_eq!(a(&["noa", "intercept"]).unwrap(), Vec::<SocketAddr>::new());
        assert_eq!(
            a(&["--dns-upstream", "1.1.1.1"]).unwrap(),
            vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()],
            "sin :puerto → 53"
        );
        assert_eq!(
            a(&["--dns-upstream=9.9.9.9:5353", "--dns-upstream", "8.8.8.8"]).unwrap(),
            vec![
                "9.9.9.9:5353".parse::<SocketAddr>().unwrap(),
                "8.8.8.8:53".parse::<SocketAddr>().unwrap()
            ],
            "= form + repetible, :puerto explícito respetado"
        );
        assert!(
            a(&["--dns-upstream", "no-una-ip"]).is_err(),
            "valor inválido fail-loud"
        );
        assert!(a(&["--dns-upstream"]).is_err(), "flag sin valor fail-loud");
    }

    /// `/0` y `/32` (válidos hoy para el utun en sí) se rechazan fail-loud para el pool DNS, con un
    /// mensaje que explica la NUEVA restricción (no un error opaco de `IpPool::seed`).
    #[cfg(feature = "intercept")]
    #[test]
    fn seed_and_reserve_dns_pool_rejects_degenerate_prefixes_with_a_clear_message() {
        let err = seed_and_reserve_dns_pool(Ipv4Addr::new(10, 99, 0, 1), 32)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("DNS") && err.contains("/32"),
            "el error debe explicar la restricción NUEVA (utun-cidr también sirve de rango DNS): {err}"
        );
        assert!(seed_and_reserve_dns_pool(Ipv4Addr::new(10, 99, 0, 1), 0).is_err());
    }
}
