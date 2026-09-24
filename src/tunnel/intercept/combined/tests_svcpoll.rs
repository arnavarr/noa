//! Tests 8-11: la rama svc-poll re-alimenta la tabla de intercept en vivo (Added/Removed/
//! route-lifecycle/error-no-teardown) por el runner REAL — F6 tramo 17 troceo.

use super::runner::run_combined_intercept_inner;
use super::testsupport::*;

use std::cell::RefCell;
use std::io;
use std::net::Ipv4Addr;
use std::rc::Rc;

use crate::edge::client::EdgeClient;
use crate::edge::service_refresh::ServiceRefreshIntervals;
use crate::tunnel::intercept::dns::DnsMatcher;
use crate::tunnel::intercept::flows::FlowRegistry;
use crate::tunnel::intercept::resolve::{INTERCEPT_V1_CONFIG_TYPE, InterceptResolver};
use crate::tunnel::intercept::stack::InterceptStack;

// ───── T5 svc re-feed: la rama svc-poll re-alimenta la tabla de intercept en vivo ─────

/// El RCODE (4 bits bajos del byte 3 de flags) de una respuesta DNS: 0 = NOERROR, 5 = REFUSED.
fn rcode(resp: &[u8]) -> u8 {
    resp[3] & 0x0F
}

/// Un `/services` que sirve UN servicio hostname NUEVO (`newhost.ziti.test`, intercept.v1 tcp:80),
/// ausente del resolver inicial de la rig (que sólo tiene `*.example.com`). Misma forma de wire que
/// los `/services` de los tests de `edge/client` (envelope `data`/`meta`, `config` keyado por tipo).
const NEWHOST_SERVICES_BODY: &str = r#"{"data":[{"id":"id-newhost","name":"newhost-svc","encryptionRequired":false,"permissions":["Dial"],"config":{"intercept.v1":{"protocols":["tcp"],"addresses":["newhost.ziti.test"],"portRanges":[{"low":80,"high":80}]}},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#;

/// **El pin del WIRING (no de `apply_event`, ya cubierto en `intercept/resolve/resolver.rs`/`intercept/resolve/tests_reconcile.rs`).** Un servicio hostname
/// que el controller publica DESPUÉS del arranque entra en el resolver COMPARTIDO por la rama
/// svc-poll del runner combinado (fetch→`apply_event(Added)`→`dns.register`) → una query DNS por su
/// hostname pasa de REFUSED a NOERROR con una IP sintética, EN VIVO, sin reiniciar. Prueba de que la
/// 3ª rama del `select!` está cableada y comparte el mismo `RefCell` que el servidor DNS.
///
/// Mutación-RED (verificada): borrar la rama svc-poll del `select!` (o el `apply_event` de su
/// cuerpo) → `newhost.ziti.test` nunca entra en el resolver → la query queda SIEMPRE en REFUSED → el
/// retry-loop agota sus intentos y el `assert!(resolved)` falla. El retry-loop espera al primer tick
/// asíncrono del poll (no es una carrera flaky: una vez aplicado, resuelve determinista para siempre).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_svc_poll_applies_a_live_added_service() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    // Con `last_service_update = None` el primer chequeo fetchea igual (stored ≠ new_ts); el
    // timestamp concreto da lo mismo. El fetch devuelve el servicio hostname nuevo.
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
        .respond_with(ResponseTemplate::new(200).set_body_string(NEWHOST_SERVICES_BODY))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = Rc::new(EdgeClient::for_test_with(&base, "T0"));

    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");

    let local = tokio::task::LocalSet::new();
    local
            .run_until(async move {
                let _runner = tokio::task::spawn_local(run_combined_intercept_inner(
                    client,
                    stack,
                    rig_resolver(), // sólo `*.example.com`; NO `newhost.ziti.test`
                    DNS_IP,
                    Vec::new(),
                    vec![INTERCEPT_V1_CONFIG_TYPE.to_string()],
                    // Intervalo diminuto + jitter 0 → primer tick determinista a ~10 ms.
                    ServiceRefreshIntervals {
                        interval: std::time::Duration::from_millis(10),
                        jitter: 0.0,
                    },
                    None,
                    Rc::new(RefCell::new(FlowRegistry::new())),
                ));

                // Retry-loop acotado: consulta `newhost.ziti.test` hasta NOERROR (tras el 1er tick del
                // poll). El bound convierte el caso mutante (nunca aplica → siempre REFUSED) en FALLO,
                // no en cuelgue.
                let mut resolved: Option<Ipv4Addr> = None;
                for attempt in 0..100u16 {
                    host.ingress_tx
                        .send(build_udp_pkt(
                            client_addr(),
                            dns_server_addr(),
                            &dns_a_query(0x2000 + attempt, "newhost.ziti.test"),
                        ))
                        .expect("inyectar la query DNS");
                    let (esrc, _edst, payload) = host.recv_udp_egress().await;
                    assert_eq!(esrc, dns_server_addr(), "la respuesta sale de (dns_ip, 53)");
                    if rcode(&payload) == 0 {
                        resolved = Some(answered_ip(&payload));
                        break;
                    }
                    assert_eq!(rcode(&payload), 5, "antes de aplicar, un miss es REFUSED (RA=0)");
                    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                }

                let ip = resolved.expect(
                    "el servicio hostname añadido en vivo debe resolver NOERROR tras el svc-poll (la 3ª rama del select! aplicó el Added)",
                );
                assert_eq!(
                    &ip.octets()[..3],
                    &[100, 64, 0],
                    "la IP sintética sale del pool del utun ({ip})"
                );
                assert!(
                    ip != UTUN_IP && ip != DNS_IP,
                    "la IP sintética no pisa las reservas utun/dns ({ip})"
                );
            })
            .await;
}

/// **El pin del RELEASE en vivo (#5 eviction vía el wiring, no de `deregister_intercept`, ya
/// cubierto en `dns/`/`intercept/resolve/tests_reconcile.rs`).** El REVERSO del test de arriba: un servicio wildcard que
/// el controller RETIRA después del arranque sale del resolver COMPARTIDO por la rama svc-poll
/// (fetch→`apply_event(Removed)`→`remove_service`→`dns.deregister_intercept`) → una query DNS bajo
/// su dominio pasa de NOERROR a REFUSED, EN VIVO, sin reiniciar — byte-igual al oráculo tras
/// `ziti_dns_deregister_intercept`. El cache del watcher se siembra con `prime_service_cache`
/// (como `main.rs`), así el primer poll (lista vacía) diffea contra el conjunto ACTUAL y emite el
/// `Removed` real.
///
/// Mutación-RED (verificada): revertir `remove_service` a la Opción B (sin
/// `dns.deregister_intercept`) → el dominio sigue registrado → la query resuelve NOERROR para
/// siempre → el retry-loop agota sus intentos y el `expect` falla.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_svc_poll_releases_dns_of_a_live_removed_service() {
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
    // El controller ya NO publica el servicio wildcard: lista vacía → diff vs el cache sembrado
    // → `Removed(wildcard-svc)`.
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":0}}}"#,
        ))
        .mount(&server)
        .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = Rc::new(EdgeClient::for_test_with(&base, "T0"));
    // Sembrar el watcher con el snapshot del arranque (espejo de `main.rs`): el resolver de la
    // rig se construyó de [wildcard_service()], el cache debe diffear contra ESO.
    client.prime_service_cache(&[wildcard_service()]);

    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");

    let local = tokio::task::LocalSet::new();
    local
            .run_until(async move {
                let _runner = tokio::task::spawn_local(run_combined_intercept_inner(
                    client,
                    stack,
                    rig_resolver(), // `*.example.com` VIVO al arranque
                    DNS_IP,
                    Vec::new(),
                    vec![INTERCEPT_V1_CONFIG_TYPE.to_string()],
                    ServiceRefreshIntervals {
                        interval: std::time::Duration::from_millis(10),
                        jitter: 0.0,
                    },
                    None,
                    Rc::new(RefCell::new(FlowRegistry::new())),
                ));

                // Retry-loop acotado espejo del test Added, invertido: la query bajo el dominio
                // resuelve NOERROR hasta que el poll aplica el Removed → REFUSED. El bound convierte
                // el caso mutante (nunca libera → siempre NOERROR) en FALLO, no en cuelgue.
                let mut refused = false;
                for attempt in 0..100u16 {
                    host.ingress_tx
                        .send(build_udp_pkt(
                            client_addr(),
                            dns_server_addr(),
                            &dns_a_query(0x3000 + attempt, "app.example.com"),
                        ))
                        .expect("inyectar la query DNS");
                    let (esrc, _edst, payload) = host.recv_udp_egress().await;
                    assert_eq!(esrc, dns_server_addr(), "la respuesta sale de (dns_ip, 53)");
                    if rcode(&payload) == 5 {
                        refused = true;
                        break;
                    }
                    assert_eq!(
                        rcode(&payload),
                        0,
                        "antes de aplicar el Removed, el dominio vivo resuelve NOERROR"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                }
                assert!(
                    refused,
                    "el dominio del servicio retirado en vivo debe pasar a REFUSED tras el svc-poll \
                     (apply_event(Removed) → remove_service → dns.deregister_intercept, #5 eviction)"
                );
            })
            .await;
}

/// [`RouteOps`] recorder (espejo del de `routes/tests_lifecycle.rs`, redefinido aquí: los tipos de
/// test no cruzan
/// módulos): registra los syscalls de ruta que el lifecycle emitiría.
struct RecOps(Rc<RefCell<Vec<String>>>);
impl crate::tunnel::intercept::routes::RouteOps for RecOps {
    fn add(&mut self, cidr: ipnet::IpNet) -> io::Result<()> {
        self.0.borrow_mut().push(format!("+{cidr}"));
        Ok(())
    }
    fn delete(&mut self, cidr: ipnet::IpNet) -> io::Result<()> {
        self.0.borrow_mut().push(format!("-{cidr}"));
        Ok(())
    }
}

/// **El pin del WIRING de RUTAS OS (no del refcount, ya cubierto en `routes/lifecycle.rs`).** El
/// runner REAL
/// conduce el ciclo de rutas: arranca con el servicio CIDR `cidr-a` instalado (lifecycle sembrado
/// con su delta, como `main.rs`) y el controller pasa a publicar SOLO `cidr-b` → el primer poll
/// emite `Removed(cidr-a)` + `Added(cidr-b)` y la rama svc-poll aplica ambos deltas al lifecycle:
/// el recorder registra `-10.77.0.0/24` (la ruta del retirado se desinstala) y `+10.88.0.0/24`
/// (la del añadido se instala) — `route add`/`delete` mid-run, espejo de
/// `stop_intercept`→`delete_route` / `ziti_tunneler_intercept`→`add_route`.
///
/// Mutación-RED: sin el `routes.apply_delta` de la rama svc-poll (o pasando `None`), el recorder
/// se queda en el seed `+10.77.0.0/24` para siempre → el retry-loop agota y el assert falla.
///
/// Nota de composición: este rig usa `control_plane = []`; el guard anti-self-DoS sobre un CIDR
/// añadido en vivo está pineado a nivel unit en `routes/tests_lifecycle.rs`
/// (`lifecycle_policy_filters_symmetrically_in_add_and_delete`) — y la composición es
/// transitiva: la rama svc-poll aplica los deltas sobre el MISMO objeto `RouteLifecycle` cuyo
/// `add` ejecuta la política (aquí pineado que la rama lo conduce; allí, que la política filtra).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_svc_poll_drives_the_route_lifecycle() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::tunnel::intercept::routes::{RouteApplier, RouteLifecycle};

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
    // El controller publica SOLO cidr-b → diff vs el cache sembrado ([cidr-a]) = Removed(a)+Added(b).
    Mock::given(method("GET"))
            .and(path("/edge/client/v1/services"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":[{"id":"id-cidr-b","name":"cidr-b","encryptionRequired":false,"permissions":["Dial"],"config":{"intercept.v1":{"protocols":["tcp"],"addresses":["10.88.0.0/24"],"portRanges":[{"low":80,"high":80}]}},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
            ))
            .mount(&server)
            .await;
    let base = format!("{}/edge/client/v1", server.uri());
    let client = Rc::new(EdgeClient::for_test_with(&base, "T0"));
    client.prime_service_cache(&[cidr_service("cidr-a", "10.77.0.0/24")]);

    // Rig como `main.rs`: resolver foldeado del snapshot + lifecycle sembrado con sus deltas.
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut lifecycle = RouteLifecycle::new(RecOps(Rc::clone(&calls)), UTUN_IP, 24, Vec::new())
        .expect("prefijo válido");
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("100.64.0.0/24"));
    dns.reserve(UTUN_IP);
    dns.reserve(DNS_IP);
    let mut resolver = InterceptResolver::from_services_with_dns(&[], dns);
    let applied = resolver.add_service(&cidr_service("cidr-a", "10.77.0.0/24"));
    lifecycle.apply_delta(&applied.routes);
    assert_eq!(
        *calls.borrow(),
        vec!["+10.77.0.0/24"],
        "seed del arranque: la ruta del snapshot instalada"
    );

    let (dev, _host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");

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
                    ServiceRefreshIntervals {
                        interval: std::time::Duration::from_millis(10),
                        jitter: 0.0,
                    },
                    Some(Box::new(lifecycle)),
                    Rc::new(RefCell::new(FlowRegistry::new())),
                ));

                // Retry-loop acotado: espera a que el poll aplique ambos deltas al lifecycle.
                for _ in 0..100u16 {
                    {
                        let recorded = calls.borrow();
                        if recorded.contains(&"-10.77.0.0/24".to_string())
                            && recorded.contains(&"+10.88.0.0/24".to_string())
                        {
                            return;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                }
                panic!(
                    "la rama svc-poll debe conducir el ciclo de rutas (Removed→delete_route, Added→add_route); recorder: {:?}",
                    calls.borrow()
                );
            })
            .await;
}

/// **Sharpening del contrato de teardown.** La rama svc-poll hace log-and-continue en TODO error
/// (nunca `?`-propaga) → un fallo del poll NO tumba el runner (el contrato "el 1er loop que cae
/// derriba todo" lo fijan sólo TCP/UDP). Cliente sin token (`from_identity_for_test` → `token=None`)
/// + intervalo diminuto → cada tick corto-circuita con `NotAuthenticated` (Err genérico, ANTES de
/// abrir socket → determinista, sin depender de la red) y falla varias veces; el runner sigue
/// sirviendo DNS del servicio ESTÁTICO. Mutación-RED: si el cuerpo hiciese
/// `poll_services_if_changed(...).await?`, la rama resolvería con `Err` → el runner terminaría → la
/// query estática no recibiría respuesta → `recv_udp_egress` haría timeout y el test fallaría.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn combined_runner_svc_poll_error_does_not_tear_down_the_runner() {
    let (dev, mut host) = MockDevice::new();
    let stack = InterceptStack::new_with_udp(dev).expect("montar pila con UDP");
    // Sin token → cada tick corto-circuita con `NotAuthenticated` ANTES de abrir socket (Err
    // genérico ≠ ControllerUnavailable → log+re-arma). No depende de la red: determinista.
    let client = Rc::new(EdgeClient::from_identity_for_test());

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
                    ServiceRefreshIntervals {
                        interval: std::time::Duration::from_millis(10),
                        jitter: 0.0,
                    },
                    None,
                    Rc::new(RefCell::new(FlowRegistry::new())),
                ));

                // Deja que la rama poll-ee y falle unas cuantas veces (≥10 ticks) ANTES de la query, así
                // el test no es vacuo respecto a "el error no tumba el runner".
                tokio::time::sleep(std::time::Duration::from_millis(120)).await;

                // El servicio ESTÁTICO wildcard sigue resolviendo → el runner está VIVO pese a los
                // errores del poll.
                host.ingress_tx
                    .send(build_udp_pkt(
                        client_addr(),
                        dns_server_addr(),
                        &dns_a_query(0x3001, "app.example.com"),
                    ))
                    .expect("inyectar la query DNS estática");
                let (esrc, _edst, payload) = host.recv_udp_egress().await;
                assert_eq!(esrc, dns_server_addr(), "el runner sigue sirviendo desde (dns_ip, 53)");
                assert_eq!(
                    rcode(&payload),
                    0,
                    "el servicio estático resuelve NOERROR: el runner NO se tumbó por los errores del poll"
                );
            })
            .await;
}
