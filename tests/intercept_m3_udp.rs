//! M3-UDP-e2e del arco intercept: un DATAGRAMA UDP REAL del SO atraviesa el utun, la surface UDP de la
//! pila netstack-smoltcp ([`InterceptStack::new_with_udp`]/[`recv_from`]) Y el OVERLAY ziti, ida y
//! vuelta, con el resolver `intercept.v1` (slice (B)) eligiendo el servicio por el DESTINO real del
//! flujo y el relay UDP de M3-UDP-handler ([`run_udp_intercept`]) reenviando cada datagrama como una
//! `Data` frame. Es la aceptación de **M3-UDP**: cierra la mitad LIVE del handler (M3-UDP-stack +
//! M3-UDP-handler, ya mergeados, entregaron la surface + el relay driver-validables; esta prueba
//! ejercita el round-trip UDP contra un overlay real).
//!
//! Flujo: un cliente del SO (un `UdpSocket` del kernel) hace `send_to` a una IP on-link ruteada al utun
//! → el kernel manda el datagrama al device → [`InterceptStack::recv_from`] lo entrega como
//! `(payload, dst, src)` → [`run_udp_intercept`] **resuelve `(dst_ip,dst_port,udp,src_ip)` → servicio**
//! vía el [`InterceptResolver`] construido de un `intercept.v1`, emite el `AppData` UDP del destino
//! (`intercept_udp_appdata` = `build_app_data("udp", …)`) y dial-ea `connect_with_appdata` → el router lo
//! enruta al HOST del servicio → el host echoea el datagrama como una `Data` de vuelta → el relay lo
//! devuelve por [`UdpReplySender::send_to`] (swap `(dst,src)`) → netstack lo emite al utun → el cliente
//! lo lee con `recv_from`. La variante cifrada (`bindsvc-enc`) ejercita además la partición cripto por el
//! relay UDP del lado intercept.
//!
//! **Rig ESPEJO de T3 (`enrol_then_proxy_udp_round_trip`), NO de M2b/(B-e2e).** A diferencia del TCP
//! intercept (M2b/(B-e2e), que dial-ea `testsvc`/`testsvc-noenc` hosteados por el router `er1` con un echo
//! externo `ncat` en `:19009`), aquí el echo es **IN-PROCESS**: una identidad HOST (`ZITI_EDGE_JWT`)
//! hace `bind` de `bindsvc`/`bindsvc-enc` y devuelve cada chunk aceptado (el mismo paradigma de eco
//! in-process que T3), y una identidad INTERCEPT (`ZITI_EDGE_JWT_DIALER`) dial-ea a través del relay UDP.
//! NO hace falta un backend `ncat -u` (`ncat` UDP con `--keep-open --exec` es notoriamente frágil: UDP no
//! tiene conexiones que forkear por origen) ni un `host.v1` UDP nuevo — reusa `bindsvc`/`bindsvc-enc`
//! (Bind+Dial `#all`), que YA existen en la rig y que T3 prueba que round-trippean UDP cifrado.
//!
//! **El `intercept.v1` se construye EN EL TEST** (un `Service` con su config JSON `protocols:["udp"]` →
//! `from_services`), mapeando la subred del utun (`10.99.<idx>.0/24`, udp, puerto 53) → el nombre del
//! servicio. Así NO hace falta cambiar la rig (el controller no necesita un `intercept.v1`): la prueba
//! ejercita el PARSE de `intercept.v1` + el match-por-dst REAL + el round-trip UDP. El fetch de
//! `intercept.v1` del controller es el MISMO wire (`list_services_with_config_types`) ya live por T4b-0,
//! así que no necesita validarse aquí (regla de validación en vivo: solo el wire nuevo exige prueba en vivo).
//!
//! REQUIERE **root** (abre un utun real) **Y** la rig OrbStack viva: controller + router online +
//! `bindsvc`/`bindsvc-enc` con sus Bind+Dial `#all` (ver `docs/edge-integration.md`) + **DOS** OTT JWTs
//! **FRESCOS** (OTT es de un solo uso): `ZITI_EDGE_JWT` (host que hace bind+echo) y `ZITI_EDGE_JWT_DIALER`
//! (identidad que intercepta+dial-ea). Gated con `#[ignore]` (compila siempre, solo se ejecuta a mano):
//!
//! ```sh
//! sudo env ZITI_EDGE_JWT=/ruta/host.jwt ZITI_EDGE_JWT_DIALER=/ruta/dialer.jwt \
//!   cargo test --features intercept --test intercept_m3_udp -- --ignored --nocapture
//! # graviola (firma el client-auth mTLS con el provider graviola; usa 2 JWTs frescos MÁS):
//! sudo env ZITI_EDGE_JWT=/ruta/host-grav.jwt ZITI_EDGE_JWT_DIALER=/ruta/dialer-grav.jwt \
//!   cargo test --features intercept,graviola --test intercept_m3_udp -- --ignored --nocapture
//! ```
//!
//! Detalle del rig + pasos exactos en `docs/M3-UDP-e2e-runbook.md`.
#![cfg(feature = "intercept")]

use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use tokio::net::UdpSocket;

use noa_sdk::edge::client::EdgeClient;
use noa_sdk::edge::model::Service;
use noa_sdk::enroll::{self, ott::EnrollOptions};
use noa_sdk::tunnel::intercept::{
    InterceptResolver, InterceptStack, IpPacketDevice, UtunDevice, run_udp_intercept,
};

/// Timeout generoso por paso (la rig OrbStack + la apertura del utun pueden tardar).
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// El puerto UDP interceptado (arbitrario; solo tiene que casar entre el `portRanges` del `intercept.v1`
/// y el `send_to` del cliente). 53 es un puerto UDP canónico; el servicio no mira el puerto (es solo el
/// nombre que el resolver mapea).
const UDP_PORT: u16 = 53;

fn env_path(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("set {name} a la ruta de un OTT JWT FRESCO (de un solo uso)"))
}

/// Construye un `Service` con un `intercept.v1` que intercepta la subred `10.99.<idx>.0/24` (**udp**,
/// puerto [`UDP_PORT`]) hacia `service`, con permiso `Dial`. El resolver (B) lo elige por el DESTINO del
/// datagrama. `encryption_required` aquí es un don't-care: el resolver NO lo consulta (casa por
/// addresses/ports/protocols/permissions) y la cripto real la negocia `connect_with_appdata` contra la
/// definición VIVA del servicio en el controller (por eso `bindsvc-enc` cifra aunque este campo sea
/// `false`, igual que `testsvc` en M2b-e2e).
fn intercept_udp_service(idx: u8, service: &str) -> Service {
    let config_json = format!(
        r#"{{"intercept.v1":{{"protocols":["udp"],"addresses":["10.99.{idx}.0/24"],"portRanges":[{{"low":{UDP_PORT},"high":{UDP_PORT}}}]}}}}"#
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

/// Una vuelta completa host→overlay→host por el intercept UDP para `service`, usando una subred de utun
/// propia (`10.99.<idx>.0/24`) para no colisionar entre iteraciones. El HOST (`host`) hace `bind`
/// del servicio y echoea in-process; la identidad INTERCEPT (`intercept`) corre el relay UDP. El cliente
/// del SO hace `send_to` a `10.99.<idx>.2:<UDP_PORT>` (on-link, distinta del addr de interfaz `.1`) → el
/// datagrama entra a la surface UDP de la pila. El resolver (B) mapea ese destino → `service`. La
/// `InterceptStack` (+ su utun) se abre y se cierra DENTRO de esta función (su `Drop` aborta las 4 tasks
/// del device al terminar el `run_until`), así que las iteraciones no comparten device.
async fn intercept_udp_round_trip(
    host: &Rc<EdgeClient>,
    intercept: &Rc<EdgeClient>,
    idx: u8,
    service: &str,
) {
    let utun_addr = Ipv4Addr::new(10, 99, idx, 1);
    let dst = format!("10.99.{idx}.2:{UDP_PORT}");

    // El HOST hace bind del servicio (eco ziti in-process). `bind` es `&self` → funciona sobre el `Rc`.
    let mut binding = host.bind(service).await.expect("bind(service)");

    let dev = UtunDevice::open(utun_addr, 24, UtunDevice::DEFAULT_MTU)
        .expect("abrir utun (¿se ejecuta como root?)");
    let iface = dev.name().unwrap_or_else(|_| "utun?".into());
    // new_with_udp: habilita la surface UDP (4ª task de reply-egress) → recv_from drena los datagramas y
    // udp_reply_sender da el emisor de respuestas. run_udp_intercept los deriva del stack internamente.
    let stack = InterceptStack::new_with_udp(dev).expect("montar la pila intercept UDP");
    // Resolver (B): el destino REAL del datagrama (10.99.<idx>.2:UDP_PORT) elige el servicio.
    let resolver = InterceptResolver::from_services(&[intercept_udp_service(idx, service)]);
    println!(
        "intercept-udp: {iface} {utun_addr}/24 -> resolver(intercept.v1 udp) -> '{service}', cliente -> {dst}"
    );

    let ic = Rc::clone(intercept);
    let payload = format!("hello-intercept-udp-{service}");

    tokio::task::LocalSet::new()
        .run_until(async move {
            // Eco ziti IN-PROCESS (paradigma de T3): acepta cada dial entrante y devuelve sus chunks. El
            // host ignora el `AppData` UDP (consistente con todo el arco: el appData solo se consulta bajo
            // `forwardAddress`), así que valida el data-plane datagrama↔Data-frame del relay de intercept.
            let host_loop = tokio::task::spawn_local(async move {
                while let Ok(mut child) = binding.accept().await {
                    tokio::task::spawn_local(async move {
                        while let Ok(Some(chunk)) = child.read().await {
                            if child.write(&chunk).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            // El relay UDP de intercept REAL (drena recv_from, resuelve dst→servicio, dial-ea con el
            // AppData UDP, reenvía el datagrama como Data). Es `!Send` (el `Rc<EdgeClient>` del dial, slice
            // 10c) → spawn_local dentro del LocalSet.
            let intercept_loop = tokio::task::spawn_local(run_udp_intercept(ic, stack, resolver));

            // Cliente REAL del SO: hace send_to a la IP on-link ruteada al utun. bind 0.0.0.0:0 deja que
            // el kernel elija el source IP del route (el addr del utun `.1`); el socket sin conectar recibe
            // el eco (que llega swappeado desde `10.99.<idx>.2:UDP_PORT`) con recv_from.
            let client = UdpSocket::bind("0.0.0.0:0")
                .await
                .expect("bind del socket UDP cliente");
            client
                .send_to(payload.as_bytes(), &dst)
                .await
                .expect("send_to del datagrama a través del utun");

            let mut buf = vec![0u8; 65507];
            let (n, from) = tokio::time::timeout(STEP_TIMEOUT, client.recv_from(&mut buf))
                .await
                .expect("timeout recibiendo el eco del datagrama")
                .expect("recv_from del eco por intercept-udp->overlay->intercept");
            assert_eq!(
                &buf[..n],
                payload.as_bytes(),
                "el datagrama vuelve EXACTO por intercept-udp->overlay->echo"
            );
            // El eco DEBE parecer venir del destino interceptado: la surface UDP swapea `(dst, src)` en
            // `send_to`, así que netstack emite el IP con src = destino interceptado. Este es el ÚNICO test
            // que valida ese source-swap del ENCODER de netstack contra un kernel REAL e2e (T3 responde por
            // un `UdpSocket` del kernel, no por el encoder). Sin este assert, un swap incorrecto (p. ej. src
            // = utun `.1:53`) igual entregaría el datagrama al socket sin conectar y el assert de payload
            // pasaría, OCULTANDO el bug. Pineado también unit en `stack/`, aquí es el cierre e2e.
            let expected_from: SocketAddr = dst.parse().expect("dst es un SocketAddr válido");
            assert_eq!(
                from, expected_from,
                "el eco parece venir del destino interceptado (swap (dst,src) de la surface UDP)"
            );

            intercept_loop.abort();
            host_loop.abort();
        })
        .await;
    println!("intercept M3-UDP-e2e round-trip OK para '{service}'");
}

/// El round-trip e2e UDP por el servicio plano (`bindsvc`) Y el cifrado (`bindsvc-enc`), con el eco ziti
/// IN-PROCESS (espejo de T3): UNA identidad host (`ZITI_EDGE_JWT`) hace bind+echo de ambos servicios y
/// UNA identidad intercept (`ZITI_EDGE_JWT_DIALER`) dial-ea ambos a través del relay UDP. Un utun por
/// servicio (subred distinta), abierto/cerrado secuencialmente. `multi_thread` para que las 4 tasks de
/// fondo del device (runner + ingress + egress + reply-egress UDP) corran en workers mientras el
/// `LocalSet` (en el hilo del test) conduce el eco in-process + el relay + el dial del overlay (espejo del
/// runtime de `intercept_m1`/M2b-e2e, con la 4ª task de UDP añadida por `new_with_udp`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requiere root + utun + rig OrbStack (controller+router+bindsvc/bindsvc-enc) + 2 OTT JWTs frescos (host=ZITI_EDGE_JWT, intercept=ZITI_EDGE_JWT_DIALER); pre-flight: scripts/rig-fixtures.sh; M3-UDP-e2e"]
async fn m3_intercept_udp_round_trips_host_to_overlay() {
    // Identidad HOST (ZITI_EDGE_JWT): hace bind de bindsvc/bindsvc-enc + eco in-process.
    let host_jwt =
        std::fs::read_to_string(env_path("ZITI_EDGE_JWT")).expect("leer el JWT del host");
    let host_cfg = enroll::ott::enroll(host_jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment OTT del host");
    let mut host = EdgeClient::from_identity(&host_cfg).expect("cliente host mTLS");
    host.authenticate().await.expect("host authenticate");
    let host = Rc::new(host);

    // Identidad INTERCEPT (ZITI_EDGE_JWT_DIALER): dial-ea a través del relay UDP de intercept.
    let dialer_jwt =
        std::fs::read_to_string(env_path("ZITI_EDGE_JWT_DIALER")).expect("leer el JWT del dialer");
    let dialer_cfg = enroll::ott::enroll(dialer_jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment OTT del dialer");
    let mut intercept = EdgeClient::from_identity(&dialer_cfg).expect("cliente intercept mTLS");
    intercept
        .authenticate()
        .await
        .expect("intercept authenticate");
    let intercept = Rc::new(intercept);

    // Plano primero (la mitad load-bearing del cableado), luego cifrado (la partición cripto del relay).
    intercept_udp_round_trip(&host, &intercept, 0, "bindsvc").await;
    intercept_udp_round_trip(&host, &intercept, 1, "bindsvc-enc").await;
}
