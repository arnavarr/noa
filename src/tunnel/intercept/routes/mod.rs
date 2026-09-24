//! Rutas OS-level del intercept: por cada CIDR `intercept.v1` que el utun NO cubre ya on-link, una
//! ruta interface-scoped hacia el device hace que el SO le entregue el tráfico a ese destino — el
//! intercept captura así los destinos REALES que anuncian los servicios, estén donde estén (sin
//! ruta, solo capturaría la subred on-link del utun). Dos superficies: el plan EN BLOQUE de un
//! snapshot ([`plan_routes`] + [`InstalledRoutes`], M3-rutas, hoy el e2e root standalone) y el
//! CICLO DE VIDA refcounted conducido en vivo por el poller ([`RouteLifecycle`], rebanada RUTAS OS
//! — el path de producción de `noa intercept`).
//!
//! **Oráculo (`ziti-tunnel-sdk-c`, categoría-C — semántica, no los bytes darwin exactos):** el
//! tunneler macOS instala rutas con `route -n add <ip/bits> -interface utunN`
//! (`programs/ziti-edge-tunnel/netif_driver/darwin/utun.c:103-108`): interface-scoped (por NOMBRE, sin
//! gateway), destino `ip/bits` (`ziti_address_print` fuerza `/32` para host,
//! `library/internal_model.c:302`), host-route para /32. `route_manager` con `gateway=None` +
//! `if_index` emite EXACTAMENTE esa ruta interface-scoped (en macOS el `sockaddr_dl` del enlace viaja
//! en el slot RTA_GATEWAY con RTF_GATEWAY LIMPIO — no un gateway IP; `RTF_HOST` para /32;
//! `unix_bsd/mod.rs:206-274`) — mismo shape, sin subproceso. El oráculo IGNORA el retorno de
//! `route add` (`lib/ziti-tunnel/route.c:50`) → aquí un `add` fallido se log-y-continúa, nunca aborta
//! el intercept.
//!
//! **Desviaciones conscientes vs el oráculo (documentadas, faithful-or-more-correct):**
//!   - **Dedup contra la subred on-link.** El oráculo NO deduplica por cobertura (`route.c:40` solo
//!     refcuenta por-string), pero su utun es un /32 punto-a-punto (`utun.c:281`) SIN subred on-link
//!     real, así que TODO destino es una ruta explícita. NUESTRO utun tiene subred on-link real (p.ej.
//!     /24): una CIDR ya cubierta on-link ya la rutea el SO al device, así que instalarla es redundante
//!     → se OMITE (redundancia + limpieza del teardown). [`Drop`] no podría borrar la ruta on-link en
//!     ningún caso (una sub-CIDR es un destino distinto; una /24 exacta daría EEXIST en `add` → jamás
//!     entra en `installed`); la omisión evita esa redundancia, no un clobber. (Con un utun /32,
//!     `plan_routes` rutea TODO, igual que el oráculo.)
//!   - **Exclude del plano de control (PARCIAL aquí; el subsistema completo DIFERIDO).** El oráculo
//!     instala SIEMPRE una ruta de EXCLUDE apuntada al gateway real para el controller
//!     (`ziti_tunnel_ctrl.c:1044`) y para CADA edge router (`:1113`), para que el tráfico del PROPIO
//!     SDK (renovación de sesión, reauth-401, svc-poll, reconexión de ER — todo sobre la pila del SO,
//!     sin source-bind) NUNCA caiga en el utun. Aquí se protege el controller por REHÚSO —no por bypass
//!     al gateway— **SI su dirección se resolvió** ([`plan_routes`] recibe `control_plane` = las IPs del
//!     controller de `ztAPI`/`ztAPIs` vía [`control_plane_addrs`]; un host irresoluble se log-y-omite y
//!     esa dirección NO queda protegida). **Residuales alcanzables, NO silenciosos** (cada uno con su
//!     `warn!`): (1) las direcciones de EDGE ROUTER no se conocen en el snapshot de arranque (dial
//!     lazy) → NO se excluyen aún; una CIDR que cubra el underlay de un ER, o la mitad no-controller de
//!     un split-default (`0.0.0.0/1`+`128.0.0.0/1`), causaría self-DoS de ESE ER. (2) un `HTTPS_PROXY`/
//!     `ALL_PROXY` que desvíe el dial del underlay a un proxy: su IP no está en el guard (host-only,
//!     igual que el exclude del oráculo). (3) si la PROPIA subred on-link del utun contiene el
//!     controller (misconfig del operador del `<utun-cidr>`), el chequeo on-link precede al del
//!     control-plane y el guard no dispara. Un `0.0.0.0/0` con controller resuelto lo REHÚSA el guard
//!     (lo cubre) antes de instalar; sin controller resuelto, `add` da EEXIST contra la default
//!     preexistente → inerte. El subsistema de exclude COMPLETO (event-driven, per-ER, refcounted,
//!     bypass al gateway) queda DIFERIDO a su propia rebanada.
//!   - ~~**Snapshot vs poller.**~~ — CERRADO (rebanada RUTAS OS): [`RouteLifecycle`] es la tabla de
//!     refcounts por-CIDR del oráculo (`route.c:20-80` — instala en la 1ª referencia, desinstala en
//!     la última, no-op sobre una ruta desconocida), sembrada por-SERVICIO en el arranque (fold de
//!     los [`RouteDelta`](super::resolve::RouteDelta)s del snapshot) y conducida EN VIVO por la rama
//!     svc-poll del runner combinado (un `Added`/`Changed`/`Removed` instala/retira las rutas de sus
//!     CIDRs literales; un CIDR compartido por N servicios sobrevive hasta el último). La política
//!     por-CIDR ([`route_allowed`](crate::tunnel::intercept::routes::policy::route_allowed): v4,
//!     off-on-link, carve-out del control-plane) se aplica
//!     SIMÉTRICAMENTE en add y delete — crítico en vivo: un servicio AÑADIDO por el poller cuyo CIDR
//!     cubra el controller se REHÚSA igual que en el snapshot (sin el guard, un svc re-feed podría
//!     self-DoSear). [`InstalledRoutes`] (bulk RAII) queda para el e2e root standalone.
//!   - **v6 diferido.** El utun se direcciona v4; un CIDR v6 no es ruteable sin dirección v6 en el
//!     device → se omite (diferido al slice que dé v6 al utun).
//!
//! **Teardown / orphan:** [`InstalledRoutes`] es RAII — su [`Drop`] intenta borrar las rutas que
//! instaló (espejo del `delete_route` grácil del oráculo). En la práctica, en la salida limpia el utun
//! (que poseen las tasks de fondo desprendidas de la pila) suele morir ANTES, y entonces el kernel ya
//! ha purgado sus rutas interface-scoped → el `delete` del `Drop` no-opea (ESRCH) y el purge del kernel
//! es el cleanup real (comportamiento oracle-fiel; en un crash sin `Drop` ocurre lo mismo). NO hacemos
//! delete-before-add (borraría una ruta AJENA al mismo destino; el oráculo nunca lo hace).

mod control_plane;
mod lifecycle;
mod ops;
mod policy;
mod snapshot;

#[cfg(test)]
mod tests_control_plane;
#[cfg(test)]
mod tests_lifecycle;
#[cfg(test)]
mod tests_snapshot;
#[cfg(test)]
mod testsupport;

pub use control_plane::control_plane_addrs;
pub use lifecycle::{RouteApplier, RouteLifecycle};
pub use ops::{OsRouteOps, RouteOps};
pub use snapshot::{InstalledRoutes, plan_routes};
