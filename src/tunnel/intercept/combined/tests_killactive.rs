//! Tests 13-16: la rama svc-poll cierra los flujos VIVOS del servicio retirado/reemplazado
//! (kill-active) + register-on-create — F6 tramo 17 troceo.

use super::runner::run_combined_intercept_inner;
use super::testsupport::*;

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::rc::Rc;
use std::sync::Arc;

use netstack_smoltcp::smoltcp::wire::TcpControl;

use crate::edge::client::EdgeClient;
use crate::edge::model::Service;
use crate::edge::service_refresh::ServiceRefreshIntervals;
use crate::tunnel::intercept::dns::DnsMatcher;
use crate::tunnel::intercept::flows::FlowRegistry;
use crate::tunnel::intercept::resolve::{INTERCEPT_V1_CONFIG_TYPE, InterceptResolver, Protocol};
use crate::tunnel::intercept::stack::InterceptStack;

// ───── kill-active: la rama svc-poll cierra los flujos VIVOS del servicio retirado ─────

use tokio_util::sync::CancellationToken;

/// Un segundo servicio (CIDR, tcp) para el rol de "otro servicio" en los tests de aislamiento.
fn other_service() -> Service {
    cidr_service("other-svc", "10.99.0.0/24")
}

/// El `intercept.v1` de `wildcard-svc` PERO con otro dominio (config DISTINTO ⇒ REPLACE).
fn wildcard_service_replaced() -> Service {
    let config: serde_json::Map<String, serde_json::Value> = serde_json::from_str(
        r#"{"intercept.v1":{"protocols":["tcp","udp"],"addresses":["*.replaced.com"],
                "portRanges":[{"low":80,"high":80}]}}"#,
    )
    .unwrap();
    Service {
        config,
        ..wildcard_service()
    }
}

/// `wildcard-svc` con el MISMO `intercept.v1` pero otras `permissions` ⇒ el watcher emite `Changed`
/// (`service_details_equal` compara el servicio entero) y `add_service` cae en keep-unchanged.
fn wildcard_service_same_config_other_perms() -> Service {
    Service {
        permissions: vec!["Dial".into(), "Bind".into()],
        ..wildcard_service()
    }
}

fn services_body(svcs: &[Service]) -> String {
    let data: Vec<serde_json::Value> = svcs
        .iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id, "name": s.name, "encryptionRequired": s.encryption_required,
                "permissions": s.permissions, "config": s.config, "configs": s.configs,
            })
        })
        .collect();
    serde_json::json!({
        "data": data,
        "meta": {"pagination": {"limit": 500, "offset": 0, "totalCount": data.len()}},
    })
    .to_string()
}

/// Monta el wiremock del svc-poll: `service-updates` siempre "cambió", `/services` devuelve `body`.
async fn svc_poll_server(body: String) -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session/service-updates"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"lastChangeAt":"2026-06-26T12:00:00.000Z"},"meta":{}}"#,
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    server
}

/// Siembra el registro INYECTADO con un token DUMMY por servicio. Offline los dials NUNCA
/// establecen (token ausente ⇒ `NotAuthenticated` corto-circuita sin socket), así que un flujo REAL
/// es imposible aquí: el dummy ocupa su hueco en el bucket y el TEST retiene su `Arc` (por eso su
/// `Weak` sigue upgradeable y `kill_service` lo alcanza). El wiring bajo prueba es
/// `svc_poll_loop → kill_service`, no la creación del flujo (eso lo pinea el test 13).
fn seeded_flows(services: &[&str]) -> (Rc<RefCell<FlowRegistry>>, Vec<Arc<CancellationToken>>) {
    let flows = Rc::new(RefCell::new(FlowRegistry::new()));
    let tokens = services
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let src = SocketAddr::from(([10, 0, 0, u8::try_from(i).unwrap() + 1], 40_000));
            let dst = SocketAddr::from(([100, 64, 0, 7], 80));
            flows.borrow_mut().register(name, Protocol::Tcp, src, dst)
        })
        .collect();
    (flows, tokens)
}

const FAST_TICK: ServiceRefreshIntervals = ServiceRefreshIntervals {
    interval: std::time::Duration::from_millis(10),
    jitter: 0.0,
};

/// Bound GENEROSO para los tests de wiring del kill. Son esperas "hasta que ocurra X" sobre un
/// poll de 10 ms + un wiremock: un bound holgado NO ralentiza el camino feliz (se sale en cuanto
/// el token se cancela) y evita que un pico de carga de la máquina lo convierta en un falso rojo.
/// El `TEST_TIMEOUT` de 3 s del resto del módulo era demasiado justo bajo carga.
const KILL_WIRING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// **Test 11 (§7) — EL pin del wiring `svc_poll_loop → FlowRegistry::kill_service`.** El controller
/// retira `wildcard-svc`; la 3ª rama del `select!` del runner REAL aplica el `Removed`, ve
/// `kill_active == true` y cancela el token de ESE servicio — y solo el de ése.
///
/// **MUTACIÓN-RED (verificada):** borrar el `if applied.kill_active { … kill_service … }` de
/// `svc_poll_loop` ⇒ el token de `wildcard-svc` jamás se cancela ⇒ el `timeout` expira ⇒ ROJO.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn svc_poll_removed_kills_preregistered_flow_of_that_service_only() {
    // `/services` vacío + cache sembrado ⇒ `Removed(wildcard-svc)`.
    let server = svc_poll_server(services_body(&[])).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = Rc::new(EdgeClient::for_test_with(&base, "T0"));
    client.prime_service_cache(&[wildcard_service()]);

    let (dev, _host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let (flows, tokens) = seeded_flows(&["wildcard-svc", "other-svc"]);
    let (killed, survivor) = (tokens[0].clone(), tokens[1].clone());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let _runner = tokio::task::spawn_local(run_combined_intercept_inner(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                Vec::new(),
                vec![INTERCEPT_V1_CONFIG_TYPE.to_string()],
                FAST_TICK,
                None,
                Rc::clone(&flows),
            ));

            tokio::time::timeout(KILL_WIRING_TIMEOUT, killed.cancelled())
                .await
                .expect("el svc-poll debe matar los flujos de wildcard-svc al aplicar Removed");

            assert!(
                !survivor.is_cancelled(),
                "el flujo de OTRO servicio no se toca: el kill es keyed por servicio \
                     (espejo del filtro io->ziti_ctx == zi_ctx)"
            );
            assert_eq!(
                flows.borrow().live_flows("wildcard-svc"),
                0,
                "bucket drenado"
            );
            assert_eq!(flows.borrow().live_flows("other-svc"), 1, "bucket intacto");
        })
        .await;
}

/// **Test 11b (§7):** REPLACE a nivel RUNNER — un `Changed` con `intercept.v1` DISTINTO mata los
/// flujos del config VIEJO (espejo de `stop_intercept(curr_i)` antes del `model_map_set`,
/// `ziti_tunnel_cbs.c:632-637`). Complementa la truth-table de `intercept/resolve/tests_reconcile.rs` cubriendo el cableado.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn svc_poll_replace_kills_old_config_flow_through_the_runner() {
    let server = svc_poll_server(services_body(&[wildcard_service_replaced()])).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = Rc::new(EdgeClient::for_test_with(&base, "T0"));
    client.prime_service_cache(&[wildcard_service()]); // el config VIEJO ⇒ diff = Changed

    let (dev, _host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let (flows, tokens) = seeded_flows(&["wildcard-svc"]);
    let old_flow = tokens[0].clone();

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let _runner = tokio::task::spawn_local(run_combined_intercept_inner(
                client,
                stack,
                rig_resolver(), // `wildcard-svc` INSTALADO ⇒ curr_i != NULL ⇒ REPLACE mata
                DNS_IP,
                Vec::new(),
                vec![INTERCEPT_V1_CONFIG_TYPE.to_string()],
                FAST_TICK,
                None,
                Rc::clone(&flows),
            ));

            tokio::time::timeout(KILL_WIRING_TIMEOUT, old_flow.cancelled())
                .await
                .expect("un REPLACE mata los flujos establecidos bajo el config saliente");
        })
        .await;
}

/// **Test 12 (§7):** keep-unchanged NO mata. Un `Changed(wildcard-svc)` cuyo `intercept.v1` es
/// IDÉNTICO al instalado (solo cambian `permissions`) deja sus flujos intactos — espejo del
/// `new_ziti_intercept → NULL` (`compare()==0`) que NO llama `stop_intercept`.
///
/// **No es vacuo:** el MISMO batch retira `other-svc`, cuyo token SÍ debe morir. Esperar a esa
/// muerte prueba que el tick corrió y que el `for ev in &events` completó (no hay `await` dentro,
/// así que el batch es atómico frente a esta task) — solo ENTONCES se comprueba que el token de
/// `wildcard-svc` sigue vivo. Sin ese canario, el test pasaría aunque el poll nunca se ejecutase.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_unchanged_config_kills_nothing_through_the_runner() {
    // El controller sirve wildcard-svc con el MISMO intercept.v1 (perms distintas) y ya NO sirve
    // other-svc ⇒ diff = { Changed(wildcard-svc), Removed(other-svc) }.
    let server =
        svc_poll_server(services_body(&[wildcard_service_same_config_other_perms()])).await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = Rc::new(EdgeClient::for_test_with(&base, "T0"));
    client.prime_service_cache(&[wildcard_service(), other_service()]);

    let (dev, _host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let (flows, tokens) = seeded_flows(&["wildcard-svc", "other-svc"]);
    let (unchanged, canary) = (tokens[0].clone(), tokens[1].clone());

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let _runner = tokio::task::spawn_local(run_combined_intercept_inner(
                client,
                stack,
                rig_resolver(),
                DNS_IP,
                Vec::new(),
                vec![INTERCEPT_V1_CONFIG_TYPE.to_string()],
                FAST_TICK,
                None,
                Rc::clone(&flows),
            ));

            // Canario: el `Removed(other-svc)` del MISMO batch mata su token ⇒ el tick corrió.
            tokio::time::timeout(KILL_WIRING_TIMEOUT, canary.cancelled())
                .await
                .expect("el canario Removed prueba que el svc-poll aplicó el batch");

            assert!(
                !unchanged.is_cancelled(),
                "keep-unchanged (compare()==0): el oráculo conserva el intercept Y sus flujos vivos"
            );
            assert_eq!(flows.borrow().live_flows("wildcard-svc"), 1);
        })
        .await;
}

/// Servicio CIDR que intercepta TCP **y** UDP (el `cidr_service` de la rig es tcp-only).
fn tcp_udp_cidr_service(name: &str, cidr: &str) -> Service {
    let config: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&format!(
            r#"{{"intercept.v1":{{"protocols":["tcp","udp"],"addresses":["{cidr}"],"portRanges":[{{"low":80,"high":80}}]}}}}"#
        ))
        .unwrap();
    Service {
        id: format!("id-{name}"),
        name: name.into(),
        encryption_required: false,
        permissions: vec!["Dial".into()],
        config,
        configs: vec![],
    }
}

/// **Test 13 (§7) — register-on-create + no-leak (GWT-5).** Un flujo TCP y uno UDP hacia un destino
/// interceptado se dan de alta en el registro **en su creación**, ANTES del dial (espejo del
/// `tcp_arg`/`udp_recv` que el oráculo instala antes del `zdial`) — offline esos dials FALLAN
/// (`NotAuthenticated`, sin socket), y aun así `registered_total()` llega a 2.
///
/// Luego, al morir ambos flujos, sus `Arc` caen y el registro deja de contarlos como vivos: se
/// asserta por `live_flows()` (semántica de `Weak`), NO por el timing de la poda amortizada — un
/// flujo muerto NUNCA debe seguir figurando como vivo, aunque su entrada aún no se haya barrido.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flows_register_at_creation_even_when_dial_fails() {
    let svc = tcp_udp_cidr_service("flowsvc", "10.77.0.0/24");
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("100.64.0.0/24"));
    dns.reserve(UTUN_IP);
    dns.reserve(DNS_IP);
    let resolver = InterceptResolver::from_services_with_dns(&[svc], dns);

    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    let client = Rc::new(EdgeClient::from_identity_for_test()); // sus dials fallan sin socket
    let flows = Rc::new(RefCell::new(FlowRegistry::new()));

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let _runner = tokio::task::spawn_local(run_combined_intercept_inner(
                client,
                stack,
                resolver,
                DNS_IP,
                Vec::new(),
                vec![INTERCEPT_V1_CONFIG_TYPE.to_string()],
                // Intervalo enorme: el svc-poll no debe interferir (no hay controller detrás).
                ServiceRefreshIntervals {
                    interval: std::time::Duration::from_secs(3600),
                    jitter: 0.0,
                },
                None,
                Rc::clone(&flows),
            ));

            let cli = SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 200), 40_000);
            let target = SocketAddrV4::new(Ipv4Addr::new(10, 77, 0, 5), 80);

            // (a) Flujo TCP: handshake completo → el accept-loop resuelve y REGISTRA antes del dial.
            let isn = 5000;
            host.ingress_tx
                .send(build_tcp_pkt(cli, target, TcpControl::Syn, isn, None, &[]))
                .expect("SYN");
            let synack = host.recv_tcp_egress_matching(|p| p.syn && p.ack).await;
            host.ingress_tx
                .send(build_tcp_pkt(
                    cli,
                    target,
                    TcpControl::None,
                    isn + 1,
                    Some(synack.seq + 1),
                    &[],
                ))
                .expect("ACK");

            // (b) Flujo UDP: un datagrama basta (`create_vconn` registra insert-first).
            host.ingress_tx
                .send(build_udp_pkt(cli, target, b"hola"))
                .expect("datagrama UDP");

            // Alta AL CREAR: 2 flujos registrados aunque ningún dial establezca.
            let mut total = 0;
            for _ in 0..1500u16 {
                total = flows.borrow().registered_total();
                if total >= 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert_eq!(
                total, 2,
                "TCP y UDP se registran EN LA CREACIÓN, antes del dial (que aquí falla)"
            );

            // No-leak: al fallar los dials, los `Arc` caen ⇒ ningún flujo cuenta como vivo.
            let mut live = usize::MAX;
            for _ in 0..1500u16 {
                live = flows.borrow().live_flows("flowsvc");
                if live == 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert_eq!(
                live, 0,
                "un dial fallido dropea el Arc ⇒ su Weak muere ⇒ el flujo no figura como vivo"
            );
        })
        .await;
}
