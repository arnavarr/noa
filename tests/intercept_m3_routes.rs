//! M3-rutas-e2e del arco intercept: aceptación LIVE del mecanismo de M3-rutas (`plan_routes` +
//! [`InstalledRoutes`]) — un flujo TCP REAL del SO llega al utun **SOLO porque instalamos una ruta
//! OS-level** para un CIDR que el `intercept.v1` anuncia FUERA de la subred on-link, y round-trippea
//! utun→netstack→overlay→echo. Es la contraparte LIVE de M3-rutas (mergeado `282c9ba`, categoría-C,
//! sin oráculo darwin exacto): M3-rutas entregó `plan_routes`/[`InstalledRoutes`] driver-validables
//! (unit tests puros, sin root); esta prueba ejercita el `route add -interface utunN` REAL contra el
//! kernel.
//!
//! **Discriminador vs (B-e2e)/M2b-e2e:** en M2b el cliente conecta a una IP ON-LINK (dentro de la
//! subred con la que se abrió el utun) — el SO ya la rutea al device SIN ninguna ruta explícita, así
//! que M2b NO prueba nada sobre `plan_routes`/`InstalledRoutes`. Aquí el cliente conecta a un destino
//! FUERA del on-link; si la instalación de la ruta fallara en silencio (el `add` de
//! `InstalledRoutes::install` hace log-y-continúa, nunca propaga el error por-ruta) el `connect`
//! iría al gateway por defecto y el test colgaría hasta el timeout — nunca daría un pase espurio. Tres
//! asserts hacen el mecanismo verificable en vez de asumido: (1) `plan_routes` planifica EXACTAMENTE
//! el CIDR ruteado (la tubería snapshot→plan es la MISMA de `main.rs::run_intercept`, alimentada con
//! el resolver construido en el test); (2) `InstalledRoutes::install` instala esa ruta (¬ instalación
//! silenciosamente fallida); (3) el destino está PROBADAMENTE fuera del on-link (si no, el kernel lo
//! rutearía igual sin la ruta, y el test no probaría nada).
//!
//! **Elección del CIDR ruteado: RFC 5737 TEST-NET (`203.0.113.0/24`/`198.51.100.0/24`), NUNCA
//! `10.x`/`172.x`.** El BLOCKER de self-DoS que la reinforced review 17-ag cazó en `plan_routes`
//! (una CIDR amplia capturando el underlay del propio plano de control del SDK) es exactamente el
//! riesgo de elegir aquí una CIDR que solape con el underlay de OrbStack/Docker (típicamente
//! `10.x`/`172.x`). Las TEST-NET de RFC 5737 están reservadas para documentación — nunca asignables a
//! infraestructura real — así que son disjuntas por construcción del controller/router/bridge de la
//! rig, sin depender de conocer su IP exacta. **Belt-and-suspenders:** el test alimenta `plan_routes`
//! con el `control_plane` REAL (`control_plane_addrs` de `cfg.zt_api`/`zt_apis`, la MISMA tubería de
//! `main.rs:159`) — si algún día una TEST-NET llegara a solapar con el controller, el guard de
//! `plan_routes` la rehusaría y el assert (1) fallaría RUIDOSAMENTE en el paso de planificación, en vez
//! de colgar el round-trip en la ejecución manual con root.
//!
//! **Rig: la MISMA de (B-e2e)/M2b-e2e, SIN CAMBIOS.** Reusa `testsvc-noenc`/`testsvc` (host.v1
//! router-hosteados, echo externo `ncat :19009`, 1 identidad) — a diferencia de M3-UDP-e2e (que
//! necesitó una rig nueva con eco in-process), M3-rutas-e2e no necesita nada nuevo del controller: el
//! `intercept.v1` se construye EN EL TEST (igual que M2b), mapeando el CIDR RUTEADO (no el on-link)
//! hacia el servicio.
//!
//! REQUIERE **root** (abre un utun real + instala/borra una ruta OS-level real) **Y** la rig OrbStack
//! viva: controller + router online + `testsvc-noenc`/`testsvc` hosteados con un echo backend (ver
//! `docs/edge-integration.md`) + un OTT JWT **FRESCO** en `ZITI_EDGE_JWT`. Gated con `#[ignore]`
//! (compila siempre, solo se ejecuta a mano):
//!
//! ```sh
//! sudo env ZITI_EDGE_JWT=/ruta/a/fresh.jwt \
//!   cargo test --features intercept --test intercept_m3_routes -- --ignored --nocapture
//! ```
//!
//! Detalle del rig + pasos exactos en `docs/M3-rutas-e2e-runbook.md`.
#![cfg(feature = "intercept")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use noa_sdk::edge::client::EdgeClient;
use noa_sdk::edge::model::Service;
use noa_sdk::enroll::{self, ott::EnrollOptions};
use noa_sdk::tunnel::intercept::{
    InstalledRoutes, InterceptResolver, InterceptStack, IpPacketDevice, UtunDevice,
    control_plane_addrs, plan_routes, run_tcp_intercept,
};

/// Timeout generoso por paso (la rig OrbStack + la apertura del utun/instalación de la ruta pueden
/// tardar).
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

fn jwt_path() -> String {
    std::env::var("ZITI_EDGE_JWT")
        .expect("set ZITI_EDGE_JWT a la ruta de un OTT JWT FRESCO (de un solo uso)")
}

/// Construye un `Service` con un `intercept.v1` que intercepta `routed_cidr` (tcp, puerto 80) hacia
/// `service`, con permiso `Dial`. A diferencia de `intercept_service` de M2b (que mapea la subred
/// ON-LINK del utun), aquí `routed_cidr` es el CIDR que `plan_routes`/[`InstalledRoutes`] deben rutear
/// explícitamente al utun — el resolver (B) lo elige por el destino REAL una vez que la ruta OS-level
/// lo entrega al device.
fn intercept_routed_service(routed_cidr: &str, service: &str) -> Service {
    let config_json = format!(
        r#"{{"intercept.v1":{{"protocols":["tcp"],"addresses":["{routed_cidr}"],"portRanges":[{{"low":80,"high":80}}]}}}}"#
    );
    let config: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&config_json).expect("intercept.v1 JSON");
    Service {
        id: format!("id-{service}"),
        name: service.to_string(),
        encryption_required: false,
        permissions: vec!["Dial".to_string()],
        config,
        configs: vec![],
    }
}

/// Una vuelta completa host→overlay→host por el intercept para `service`, a través de una ruta
/// OS-level REAL hacia `routed_cidr` (fuera del on-link del utun). Usa una subred de utun propia
/// (`10.99.<idx>.0/24`) para no colisionar entre iteraciones; `routed_cidr` es también DISTINTO por
/// iteración (dos TEST-NET de RFC 5737 diferentes) — defensivo contra cualquier solape residual entre
/// el `Drop` (borrado) de la ruta de una iteración y la instalación de la siguiente.
async fn intercept_route_round_trip(
    client: &Rc<EdgeClient>,
    control_plane: &[IpAddr],
    idx: u8,
    routed_cidr: &str,
    dst: &str,
    service: &str,
) {
    let utun_addr = Ipv4Addr::new(10, 99, idx, 1);
    let utun_prefix = 24u8;

    let dev = UtunDevice::open(utun_addr, utun_prefix, UtunDevice::DEFAULT_MTU)
        .expect("abrir utun (¿se ejecuta como root?)");
    let iface = dev.name().unwrap_or_else(|_| "utun?".into());
    // if_index se lee ANTES de mover `dev` a la pila (`InterceptStack::new` toma ownership), espejo de
    // `main.rs::run_intercept`.
    let if_index = dev.if_index().expect("if_index del utun");

    // Resolver (B): el intercept.v1 mapea el CIDR RUTEADO (no el on-link) -> service. El destino del
    // flujo solo puede llegar al device por la ruta OS-level que instalamos abajo.
    let resolver =
        InterceptResolver::from_services(&[intercept_routed_service(routed_cidr, service)]);

    // MISMA tubería que `main.rs::run_intercept` (snapshot -> plan -> install), alimentada con el
    // control-plane REAL: prueba también que el guard self-DoS de `plan_routes` no rehúsa este CIDR.
    let planned = plan_routes(
        &resolver.intercept_cidrs(),
        utun_addr,
        utun_prefix,
        control_plane,
    );
    let expected_cidr: IpNet = routed_cidr.parse().expect("CIDR de test válido");
    assert_eq!(
        planned,
        vec![expected_cidr],
        "el CIDR ruteado debe planificarse (fuera del on-link, fuera del plano de control real)"
    );
    let routes = InstalledRoutes::install(&planned, if_index, &iface)
        .expect("instalar la ruta OS-level (¿root?)");
    assert_eq!(
        routes.len(),
        1,
        "la ruta OS-level debe instalarse de verdad (un `add` fallido se log-y-continúa en \
         silencio; sin este assert un install roto igual podría dar un pase espurio si el tráfico \
         llegara por otra vía)"
    );

    // Discriminador: `dst` debe caer FUERA del on-link del utun, o el kernel lo rutearía igual SIN la
    // ruta instalada y el test no probaría nada sobre el mecanismo de M3-rutas.
    let on_link = Ipv4Net::new(utun_addr, utun_prefix)
        .expect("on-link válido")
        .trunc();
    let dst_addr: SocketAddr = dst.parse().expect("dst es un SocketAddr válido");
    let SocketAddr::V4(dst_v4) = dst_addr else {
        panic!("dst de test debe ser v4")
    };
    assert!(
        !on_link.contains(dst_v4.ip()),
        "dst debe estar FUERA del on-link del utun (si no, el kernel lo entregaría sin necesitar \
         la ruta instalada)"
    );

    let stack = InterceptStack::new(dev).expect("montar la pila intercept");
    println!(
        "intercept-rutas: {iface} {utun_addr}/{utun_prefix} + ruta OS-level -> {routed_cidr} -> \
         resolver(intercept.v1) -> '{service}', cliente -> {dst}"
    );

    let c = Rc::clone(client);
    let payload = format!("hello-intercept-rutas-{service}\n");

    tokio::task::LocalSet::new()
        .run_until(async move {
            // El accept-loop del intercept corre en el fondo del LocalSet (spawn_local: el connect del
            // overlay es !Send, slice 10c).
            let intercept = tokio::task::spawn_local(run_tcp_intercept(c, stack, resolver));

            // Cliente REAL del SO: conecta a un destino que SOLO la ruta OS-level instalada entrega al
            // utun (fuera del on-link).
            let mut tcp = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(dst))
                .await
                .expect("timeout conectando a través de la ruta instalada")
                .expect("connect a través de la ruta instalada");

            tcp.write_all(payload.as_bytes())
                .await
                .expect("escribir la petición");
            let mut buf = vec![0u8; payload.len()];
            tokio::time::timeout(STEP_TIMEOUT, tcp.read_exact(&mut buf))
                .await
                .expect("timeout leyendo el eco")
                .expect("leer el eco por intercept->overlay->intercept");
            assert_eq!(
                buf,
                payload.as_bytes(),
                "el eco vuelve EXACTO por la ruta OS-level instalada"
            );

            // Half-close del cliente -> intercept manda un FIN a ziti -> el echo cierra -> intercept
            // medio-cierra el socket -> nuestra lectura ve EOF (el camino de half-close M2a/splice).
            tcp.shutdown().await.expect("half-close del cliente");
            let mut rest = Vec::new();
            tokio::time::timeout(STEP_TIMEOUT, tcp.read_to_end(&mut rest))
                .await
                .expect("timeout drenando el socket a EOF")
                .expect("drenar el socket a EOF");

            intercept.abort();
        })
        .await;
    // `routes` sigue viva hasta AQUÍ (todo el round-trip): su `Drop` borra la ruta al final del scope,
    // espejo del RAII de `main.rs::run_intercept`.
    drop(routes);
    println!("intercept M3-rutas-e2e round-trip OK para '{service}' vía {routed_cidr}");
}

/// El round-trip e2e por el servicio plano (`testsvc-noenc`) Y el cifrado (`testsvc`), reusando la
/// MISMA rig e identidad que `enrol_then_proxy_tcp_round_trip`/M2b-e2e. Dos CIDRs RFC 5737 TEST-NET
/// DISTINTOS (`203.0.113.0/24`/`198.51.100.0/24`): reservados para documentación, nunca asignables a
/// infraestructura real, así que la ruta OS-level instalada no puede solapar con el underlay de la rig
/// OrbStack (evita la clase de BLOCKER de self-DoS que la reinforced review 17-ag cazó en
/// `plan_routes`). `multi_thread` para que las 3 tasks de fondo del device corran en workers mientras
/// el `LocalSet` conduce el accept-loop + el dial del overlay (espejo del runtime de M2b-e2e).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requiere root + utun + ruta OS-level real + rig OrbStack (controller+router+testsvc/testsvc-noenc) + OTT JWT fresco; M3-rutas-e2e"]
async fn m3_intercept_routes_round_trip_host_to_overlay() {
    let jwt = std::fs::read_to_string(jwt_path()).expect("leer el JWT");
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment OTT");
    let mut client = EdgeClient::from_identity(&cfg).expect("cliente mTLS");
    client.authenticate().await.expect("authenticate");

    // Carve-out del plano de control: MISMA tubería que `main.rs::run_intercept` (`control_plane_addrs`
    // de `ztAPI`/`ztAPIs`) — alimenta el guard self-DoS de `plan_routes` con las IPs REALES del
    // controller de esta rig, no un placeholder.
    let mut controller_urls = vec![cfg.zt_api.clone()];
    if let Some(apis) = &cfg.zt_apis {
        controller_urls.extend(apis.iter().cloned());
    }
    let control_plane = control_plane_addrs(&controller_urls);

    let client = Rc::new(client);

    // Plano primero (la mitad load-bearing del mecanismo de rutas), luego cifrado (la partición cripto
    // del splice, ya validada en M2b — aquí solo confirma que la ruta no interfiere con ella).
    intercept_route_round_trip(
        &client,
        &control_plane,
        0,
        "203.0.113.0/24",
        "203.0.113.2:80",
        "testsvc-noenc",
    )
    .await;
    intercept_route_round_trip(
        &client,
        &control_plane,
        1,
        "198.51.100.0/24",
        "198.51.100.2:80",
        "testsvc",
    )
    .await;
}
