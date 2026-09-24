//! `FlowRegistry`: el registro de flujos VIVOS por servicio — el seam que permite matar los flujos
//! ACTIVOS de un servicio retirado (rebanada `kill-active`, cierre del último deferral del arco
//! intercept).
//!
//! ## Oráculo (`ziti-tunnel-sdk-c` v1.15.1, `2addfbb`)
//! `tunneler_kill_active(zi_ctx)` (`lib/ziti-tunnel/ziti_tunnel.c:437-465`) recolecta los flujos
//! TCP **y** UDP del servicio y, por cada uno, cierra su conexión ziti:
//! `zclose = n->io->close_fn; if (zclose) zclose(n->io->ziti_io);` — *"close the ziti connection,
//! which also closes the underlay"* (`:445-447` TCP, `:458-460` UDP) — con un `TNL_LOG(DEBUG, …
//! "killing active connection")` por flujo (`:444`, `:457`). Lo invoca
//! `ziti_tunneler_stop_intercepting` en `:493` (dentro del bloque `intercept != NULL`) y OTRA VEZ,
//! incondicional, en `:510`.
//!
//! Los enumeradores son la contrapartida de este registro:
//!  - `tunneler_tcp_active` (`lib/ziti-tunnel/tunnel_tcp.c:452-471`): recorre `tcp_active_pcbs` y
//!    selecciona los pcbs cuyo `io->ziti_ctx == zi_ctx` (`:461`);
//!  - `tunneler_udp_active` (`lib/ziti-tunnel/tunnel_udp.c:202-223`): ídem sobre `udp_pcbs`, con el
//!    guard `pcb->recv == on_udp_client_data` (`:207`) y el mismo filtro (`:212`).
//!
//! **El kill es keyed por SERVICIO, nunca por dirección/CIDR/dominio:** `io->ziti_ctx` se asigna al
//! `app_intercept_ctx` del intercept (uno por servicio) en la CREACIÓN del flujo
//! (`tunnel_tcp.c:428`, `tunnel_udp.c:161`). Y se asigna **antes** del `zdial` en AMBOS protocolos
//! (`tcp_arg(npcb, io)` en `tunnel_tcp.c:434` vs dial `:438`; `udp_recv(npcb, on_udp_client_data,
//! io)` en `tunnel_udp.c:169` vs dial `:171`) ⇒ el pcb es enumerable —y por tanto matable— desde el
//! instante de la creación, incluso con el dial EN VUELO. (El comentario de `tunnel_udp.c:207`,
//! *"recv_arg contains io_context after dial completes"*, contradice a su propio código de `:169`;
//! manda el código.) De ahí que aquí se registre **al crear el flujo**, no al establecerlo.
//!
//! ## Mecánica
//! El token de kill es un [`CancellationToken`] **nivel-disparado**: un `cancelled().await` sobre un
//! token YA cancelado resuelve en el primer poll (sin la trampa de versiones de `watch::Receiver`),
//! lo que hace que un kill disparado con el dial en vuelo se observe en el primer poll de la fase
//! establecida — sin cancelar el dial. Se envuelve en un [`Arc`] cuyo **único dueño es la task del
//! flujo**; el registro guarda un [`Weak`]. Así:
//!  - la muerte NATURAL del flujo (EOF, error, dial fallido) dropea el `Arc` → el `Weak` queda
//!    muerto → la poda amortizada de [`FlowRegistry::register`] lo elimina. No hace falta ningún
//!    deregister explícito cross-thread;
//!  - [`FlowRegistry::kill_service`] hace `upgrade()` + `cancel()` de los que sigan vivos.
//!
//! ## Invariante de vida (load-bearing, se vigila en revisión)
//! El `Arc<CancellationToken>` que devuelve [`FlowRegistry::register`] se **MUEVE** a la task del
//! flujo y **NUNCA se clona fuera de ella** (dentro del future puede clonarse si dos ramas necesitan
//! `cancelled()`). Un clone retenido en cualquier otro sitio mantendría el `Weak` upgradeable tras el
//! fin del flujo: la poda no podaría nunca y `live_flows`/`kill_service` mentirían sobre un flujo ya
//! muerto (fuga silenciosa del bucket). Las dos ÚNICAS altas son el accept-loop TCP
//! (`super::tcp::tcp_intercept_loop`) y la creación de vconn UDP (`super::udp::create_vconn`).
//!
//! ## Disciplina de borrow
//! El registro vive en un `Rc<RefCell<FlowRegistry>>` compartido por las tres ramas del runner
//! combinado, en el hilo único del `LocalSet`. Todos los borrows son SÍNCRONOS y mueren antes de
//! cualquier `await`; es una celda DISJUNTA de la del resolver. Lo único que cruza hilos son los
//! `Arc`/`Weak<CancellationToken>` (`Send + Sync`) y el `cancel()` (síncrono, despierta al splice que
//! corre en el pool multi-thread).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use tokio_util::sync::CancellationToken;

use super::resolve::Protocol;

/// Un flujo vivo registrado a nombre de un servicio. Los metadatos son los del `TNL_LOG` del oráculo
/// (`ziti_tunnel.c:444`/`:457`: el `client` del flujo); `kill` es el handle débil a su token.
struct RegisteredFlow {
    proto: Protocol,
    src: SocketAddr,
    dst: SocketAddr,
    kill: Weak<CancellationToken>,
}

impl RegisteredFlow {
    /// ¿Sigue viva la task del flujo? (Su `Arc` es el único fuerte; ver el invariante de vida.)
    fn is_live(&self) -> bool {
        self.kill.strong_count() > 0
    }
}

/// Flujos vivos indexados por NOMBRE de servicio — el análogo del filtro `io->ziti_ctx == zi_ctx` que
/// los enumeradores del oráculo aplican sobre las listas de pcbs de lwIP.
pub(crate) struct FlowRegistry {
    flows: HashMap<String, Vec<RegisteredFlow>>,
    registered_total: u64,
}

impl FlowRegistry {
    pub(crate) fn new() -> Self {
        Self {
            flows: HashMap::new(),
            registered_total: 0,
        }
    }

    /// Da de alta un flujo de `service` **en su creación** (antes del dial, como el oráculo) y
    /// devuelve el `Arc<CancellationToken>` que la task del flujo debe MOVER a su future y retener
    /// toda su vida (ver el invariante de vida del módulo).
    ///
    /// Poda amortizada: antes de insertar, purga del bucket los `Weak` cuyo flujo ya murió. Es la
    /// única recolección — no hay deregister explícito (la task del flujo puede terminar en otro
    /// hilo). Un servicio con alta rotación de flujos poda en cada alta; uno sin altas nuevas
    /// conserva entradas muertas hasta su próxima alta o su `kill_service` (ambos las tiran).
    pub(crate) fn register(
        &mut self,
        service: &str,
        proto: Protocol,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Arc<CancellationToken> {
        let token = Arc::new(CancellationToken::new());
        let bucket = self.flows.entry(service.to_string()).or_default();
        bucket.retain(RegisteredFlow::is_live);
        bucket.push(RegisteredFlow {
            proto,
            src,
            dst,
            kill: Arc::downgrade(&token),
        });
        self.registered_total += 1;
        // Espejo del DEBUG de creación del oráculo (`tunnel_tcp.c:436-437`, `tunnel_udp.c:166-167`:
        // "intercepted address[%s] client[%s] service[%s]").
        tracing::debug!(
            service,
            proto = proto.as_str(),
            client = %src,
            intercepted = %dst,
            total = self.registered_total,
            "intercept: flujo registrado"
        );
        token
    }

    /// Mata TODOS los flujos vivos de `service` (ambos protocolos, como el oráculo — su
    /// `// todo be selective about protocols` de `ziti_tunnel.c:453` nunca se implementó) y drena su
    /// bucket. Devuelve cuántos mató. Un servicio ausente o con el bucket vacío devuelve `0` sin
    /// pánico: ése es el pliegue que hace que nuestro kill INCONDICIONAL en `Removed` sea observable-
    /// equivalente al gate `model_map_remove != NULL` del oráculo (`ziti_tunnel_cbs.c:679-681`), y que
    /// la doble llamada defensiva del C (`:493` + `:510`) colapse a una sola aquí (DV-1).
    ///
    /// `cancel()` es idempotente y síncrono: despierta al flujo, que ejecuta SU PROPIO camino de
    /// cierre existente (`zw.close()` = StateClosed + deregister del mux). Aquí NO se cierra nada
    /// directamente — matar es señalizar, no tocar la conexión desde fuera de su task.
    pub(crate) fn kill_service(&mut self, service: &str) -> usize {
        let Some(bucket) = self.flows.remove(service) else {
            return 0;
        };
        let mut killed = 0;
        for flow in bucket {
            let Some(token) = flow.kill.upgrade() else {
                continue; // murió de forma natural entre la última poda y ahora
            };
            // Espejo del `TNL_LOG(DEBUG, "… client[%s] killing active connection")` por flujo.
            tracing::debug!(
                service,
                proto = flow.proto.as_str(),
                client = %flow.src,
                intercepted = %flow.dst,
                "intercept: killing active connection"
            );
            token.cancel();
            killed += 1;
        }
        killed
    }

    /// Flujos de `service` cuya task sigue viva (0 si el servicio no tiene bucket). Observabilidad de
    /// tests: mide el efecto de la poda y del kill sin depender del timing del reaper.
    #[cfg(test)]
    pub(crate) fn live_flows(&self, service: &str) -> usize {
        self.flows
            .get(service)
            .map_or(0, |b| b.iter().filter(|f| f.is_live()).count())
    }

    /// Altas acumuladas desde el arranque (nunca decrece). Observabilidad de tests: pinea que el alta
    /// ocurre AL CREAR el flujo, incluso si su dial falla después.
    #[cfg(test)]
    pub(crate) fn registered_total(&self) -> u64 {
        self.registered_total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last], port))
    }

    /// **Test 1 (§7):** el kill es keyed por SERVICIO — espejo del filtro `io->ziti_ctx == zi_ctx` de
    /// `tunneler_tcp_active`/`tunneler_udp_active`. Dos flujos de `a` (uno TCP, uno UDP: el C mata
    /// AMBOS protocolos, `ziti_tunnel.c:453`) y uno de `b`; `kill_service("a")` cancela los dos de `a`,
    /// deja intacto el de `b`, devuelve 2 y drena el bucket de `a`.
    #[test]
    fn kill_service_cancels_only_that_services_flows() {
        let mut reg = FlowRegistry::new();
        let a1 = reg.register("a", Protocol::Tcp, addr(1, 1000), addr(9, 80));
        let a2 = reg.register("a", Protocol::Udp, addr(2, 1001), addr(9, 53));
        let b1 = reg.register("b", Protocol::Tcp, addr(3, 1002), addr(8, 443));
        assert_eq!(reg.registered_total(), 3);
        assert_eq!(reg.live_flows("a"), 2);

        assert_eq!(reg.kill_service("a"), 2, "mató los dos flujos de `a`");

        assert!(a1.is_cancelled(), "flujo TCP de `a` cancelado");
        assert!(
            a2.is_cancelled(),
            "flujo UDP de `a` cancelado (ambos protocolos)"
        );
        assert!(
            !b1.is_cancelled(),
            "el flujo de OTRO servicio no se toca (keyed por servicio, no por dirección)"
        );
        assert_eq!(reg.live_flows("a"), 0, "bucket de `a` drenado");
        assert_eq!(reg.live_flows("b"), 1, "bucket de `b` intacto");
        assert_eq!(
            reg.registered_total(),
            3,
            "el contador de altas no decrece con el kill"
        );
    }

    /// **Test 2 (§7):** un flujo que cierra de forma NATURAL suelta su `Arc` → su `Weak` muere → la
    /// poda amortizada del siguiente `register` lo elimina, y un `kill_service` posterior es un no-op
    /// que devuelve 0 sin pánico (GWT-5, sin fuga de handles).
    #[test]
    fn natural_close_prunes_handle_and_kill_is_noop() {
        let mut reg = FlowRegistry::new();
        let dying = reg.register("a", Protocol::Tcp, addr(1, 1000), addr(9, 80));
        assert_eq!(reg.live_flows("a"), 1);

        drop(dying); // cierre natural: la task del flujo terminó y soltó su Arc
        assert_eq!(
            reg.live_flows("a"),
            0,
            "el Weak muerto ya no cuenta como vivo"
        );

        // La poda ocurre en el siguiente `register` del MISMO servicio.
        let fresh = reg.register("a", Protocol::Tcp, addr(4, 1003), addr(9, 80));
        assert_eq!(reg.live_flows("a"), 1, "solo el nuevo");
        assert_eq!(reg.registered_total(), 2);

        drop(fresh);
        assert_eq!(
            reg.kill_service("a"),
            0,
            "kill sobre flujos ya muertos: 0, sin pánico (Weak::upgrade → None)"
        );
        assert_eq!(
            reg.kill_service("jamas-registrado"),
            0,
            "kill sobre un servicio desconocido: no-op (el pliegue de DV-1)"
        );
    }

    /// **Test 3 (§7):** el token es NIVEL-disparado — `cancel()` ANTES del primer `cancelled().await`
    /// resuelve inmediato. Es el contrato que hace correcto el kill mid-dial (GWT-8): el flujo observa
    /// la cancelación en el primer poll de su fase establecida, sin que nadie cancele el dial. Un
    /// `watch::Receiver` (flanco-disparado, con su trampa de versiones) fallaría este test.
    #[tokio::test]
    async fn cancelled_before_first_poll_still_fires() {
        let mut reg = FlowRegistry::new();
        let token = reg.register("a", Protocol::Tcp, addr(1, 1000), addr(9, 80));

        assert_eq!(reg.kill_service("a"), 1);

        // Sin timeout: si el token fuese flanco-disparado, este await colgaría para siempre.
        tokio::time::timeout(std::time::Duration::from_secs(5), token.cancelled())
            .await
            .expect("un token YA cancelado resuelve en el primer poll (nivel-disparado)");
        assert!(token.is_cancelled());
    }
}
