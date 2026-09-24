//! (B-e2e) del arco intercept (evolucionado desde M2b-e2e): un flujo TCP REAL atraviesa el utun, la
//! pila netstack-smoltcp Y el OVERLAY ziti, ida y vuelta, **con el resolver `intercept.v1` (slice (B))
//! eligiendo el servicio por el DESTINO real del flujo** (ya no un `service` HARDCODED). Es la
//! aceptación de (B): cierra la mitad LIVE del resolver. (B-pre, mergeado, entregó el resolver +
//! cableado + differential driver-validables; esta prueba ejercita la elección-por-dst contra un
//! overlay real.)
//!
//! Flujo: un cliente del SO (la pila TCP del kernel) conecta a una IP on-link ruteada al utun → el
//! kernel manda el SYN al device → [`InterceptStack`] lo acepta como `InterceptTcpStream` con
//! `(dst, src)` → [`run_tcp_intercept`] **resuelve `(dst_ip,dst_port,tcp,src_ip)` → servicio** vía el
//! [`InterceptResolver`] construido de un `intercept.v1`, emite el `AppData` del destino (mapa `dst_*`)
//! y dial-ea `connect_with_appdata(servicio_resuelto)` → el router lo enruta al HOST del servicio (el
//! echo backend de la rig OrbStack, hosteando `testsvc-noenc`/`testsvc`) → `splice` copia en ambos
//! sentidos → el cliente lee el eco de vuelta a través del utun. La variante cifrada (`testsvc`)
//! ejercita además la partición cripto a través del `splice` del lado intercept.
//!
//! **El `intercept.v1` se construye EN EL TEST** (un `Service` con su config JSON → `from_services`),
//! mapeando la subred del utun (`10.99.<idx>.0/24`, tcp, puerto 80) → el nombre del servicio. Así NO
//! hace falta cambiar la rig (el controller no necesita un `intercept.v1`): la prueba ejercita el
//! PARSE de `intercept.v1` + el match-por-dst REAL + el round-trip. El fetch de `intercept.v1` del
//! controller es el MISMO wire (`list_services_with_config_types`) ya live por T4b-0, así que no
//! necesita validarse aquí (regla de validación en vivo: solo el wire nuevo exige prueba en vivo).
//!
//! REQUIERE **root** (abre un utun real) **Y** la rig OrbStack viva: controller + router online +
//! `testsvc-noenc`/`testsvc` hosteados con un echo backend (`ncat --exec /bin/cat`, ver
//! `docs/edge-integration.md`) + un OTT JWT **FRESCO** (OTT es de un solo uso) en `ZITI_EDGE_JWT`.
//! Gated con `#[ignore]` (compila siempre, solo se ejecuta a mano):
//!
//! ```sh
//! sudo env ZITI_EDGE_JWT=/ruta/a/fresh.jwt \
//!   cargo test --features intercept --test intercept_m2b -- --ignored --nocapture
//! # graviola (firma el client-auth mTLS con el provider graviola):
//! sudo env ZITI_EDGE_JWT=/ruta/a/fresh.jwt \
//!   cargo test --features intercept,graviola --test intercept_m2b -- --ignored --nocapture
//! ```
//!
//! Detalle del rig + pasos exactos en `docs/M2b-e2e-runbook.md`.
#![cfg(feature = "intercept")]

use std::net::Ipv4Addr;
use std::rc::Rc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use noa_sdk::edge::client::EdgeClient;
use noa_sdk::edge::model::Service;
use noa_sdk::enroll::{self, ott::EnrollOptions};
use noa_sdk::tunnel::intercept::{
    InterceptResolver, InterceptStack, IpPacketDevice, UtunDevice, run_tcp_intercept,
};

/// Timeout generoso por paso (la rig OrbStack + la apertura del utun pueden tardar).
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

fn jwt_path() -> String {
    std::env::var("ZITI_EDGE_JWT")
        .expect("set ZITI_EDGE_JWT a la ruta de un OTT JWT FRESCO (de un solo uso)")
}

/// Construye un `Service` con un `intercept.v1` que intercepta la subred `10.99.<idx>.0/24` (tcp,
/// puerto 80) hacia `service`, con permiso `Dial`. El resolver (B) lo elige por el DESTINO del flujo.
fn intercept_service(idx: u8, service: &str) -> Service {
    let config_json = format!(
        r#"{{"intercept.v1":{{"protocols":["tcp"],"addresses":["10.99.{idx}.0/24"],"portRanges":[{{"low":80,"high":80}}]}}}}"#
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

/// Una vuelta completa host→overlay→host por el intercept para `service`, usando una subred de utun
/// propia (`10.99.<idx>.0/24`) para no colisionar entre iteraciones. El cliente del SO conecta a
/// `10.99.<idx>.2:80` (on-link, distinta del addr de interfaz `.1`) → el SYN entra a la pila. El
/// resolver (B) mapea ese destino → `service`. La `InterceptStack` (+ su utun) se abre y se cierra
/// DENTRO de esta función (su `Drop` aborta las tasks del device al terminar el `run_until`), así que
/// las iteraciones no comparten device.
async fn intercept_round_trip(client: &Rc<EdgeClient>, idx: u8, service: &str) {
    let utun_addr = Ipv4Addr::new(10, 99, idx, 1);
    let dst = format!("10.99.{idx}.2:80");

    let dev = UtunDevice::open(utun_addr, 24, UtunDevice::DEFAULT_MTU)
        .expect("abrir utun (¿se ejecuta como root?)");
    let iface = dev.name().unwrap_or_else(|_| "utun?".into());
    let stack = InterceptStack::new(dev).expect("montar la pila intercept");
    // Resolver (B): el destino REAL del flujo (10.99.<idx>.2:80) elige el servicio.
    let resolver = InterceptResolver::from_services(&[intercept_service(idx, service)]);
    println!(
        "intercept: {iface} {utun_addr}/24 -> resolver(intercept.v1) -> '{service}', cliente -> {dst}"
    );

    let c = Rc::clone(client);
    let payload = format!("hello-intercept-{service}\n");

    tokio::task::LocalSet::new()
        .run_until(async move {
            // El accept-loop del intercept corre en el fondo del LocalSet (spawn_local: el connect del
            // overlay es !Send, slice 10c). Al abortarlo + soltar el LocalSet, `stack` se dropea y sus
            // tasks de device se abortan.
            let intercept = tokio::task::spawn_local(run_tcp_intercept(c, stack, resolver));

            // Cliente REAL del SO: conecta a la IP on-link ruteada al utun.
            let mut tcp = tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect(&dst))
                .await
                .expect("timeout conectando a través del utun")
                .expect("connect a través del utun");

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
                "el eco vuelve EXACTO por intercept->overlay->intercept"
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
    println!("intercept M2b-e2e round-trip OK para '{service}'");
}

/// El round-trip e2e por el servicio plano (`testsvc-noenc`) Y el cifrado (`testsvc`), reusando la
/// MISMA rig que `enrol_then_proxy_tcp_round_trip` (una sola identidad dial-ea ambos). Un utun por
/// servicio (subred distinta), abierto/cerrado secuencialmente. `multi_thread` para que las 3 tasks de
/// fondo del device (runner + ingress + egress) corran en workers mientras el `LocalSet` (en el hilo
/// del test) conduce el accept-loop + el dial del overlay (espejo del runtime de `intercept_m1`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requiere root + utun + rig OrbStack (controller+router+testsvc/testsvc-noenc) + OTT JWT fresco; M2b-e2e"]
async fn m2b_intercept_tcp_round_trips_host_to_overlay() {
    let jwt = std::fs::read_to_string(jwt_path()).expect("leer el JWT");
    let cfg = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("enrolment OTT");
    let mut client = EdgeClient::from_identity(&cfg).expect("cliente mTLS");
    client.authenticate().await.expect("authenticate");
    let client = Rc::new(client);

    // Plano primero (la mitad load-bearing del cableado), luego cifrado (la partición cripto del splice).
    intercept_round_trip(&client, 0, "testsvc-noenc").await;
    intercept_round_trip(&client, 1, "testsvc").await;
}
