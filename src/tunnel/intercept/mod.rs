//! Capa de intercept de host: captura tráfico TCP/UDP local desde un dispositivo utun (macOS)
//! y lo convierte en flujos lógicos que se entregan al overlay ya construido (`connect()` +
//! `splice`). NO reconstruye el overlay; lo consume.
//!
//! Gated tras la feature `intercept` (opcional, off por defecto) → las deps de plataforma
//! (`tun-rs`, y más adelante `smoltcp`/`netstack-smoltcp`) NO entran en el build default y
//! noa-sdk sigue siendo platform-agnostic.
//!
//! **Tres oráculos, uno por superficie** (ver
//! `docs/superpowers/specs/2026-06-27-tunnel-intercept-design.md`, §1–2):
//!   - **(A) cara al overlay** (AppData + connect + splice): reusa T4b (`edge::dial::build_app_data`)
//!     + [`crate::tunnel::proxy::splice`] — fidelidad estricta, código ya validado en vivo.
//!   - **(B) resolver `intercept.v1`** (mapa `(dst_ip,dst_port,proto)` → servicio): `openziti/ziti`
//!     v2.0.0 `tunnel/intercept/*` + `tunnel/entities/service.go` (lógica de config plataforma-
//!     independiente; el MISMO árbol del matcher host de T4b). Frontera de seguridad → differential.
//!   - **(C) pila TCP/IP userspace + device + rutas/DNS**: `ziti-tunnel-sdk-c` (lwIP) = semántica;
//!     onetun / tun2proxy / netstack-smoltcp = mecanismo Rust. SIN oráculo darwin → design-correct +
//!     RFC 9293 + paridad.
//!
//! **M0:** el dispositivo utun vivo + el seam de fuente de paquetes ([`device`]).
//!
//! **M1:** la pila TCP/IP userspace ([`stack`]) sobre netstack-smoltcp — convierte el firehose de
//! paquetes IP del device en flujos lógicos `TcpStream`. Incluye la verificación del GATE del
//! half-close (§4.2.1 del diseño): `poll_shutdown` emite un FIN real, así que el `splice` de T1 reusa
//! el `TcpStream` de netstack sin adaptarlo.
//!
//! **M2a:** [`stream`] — [`InterceptTcpStream`], el adaptador de half-close ACOTADO sobre el
//! `TcpStream` de netstack. Resuelve el REQUISITO load-bearing que la review de M1 dejó para M2: el
//! `poll_shutdown` de netstack solo retorna `Ready` en cierre COMPLETO (`State::Closed`), así que un
//! `splice` directo se colgaría en el half-close (~10 s en el caso común, INDEFINIDO con un peer
//! half-open en FinWait2). El adaptador retorna en cuanto el FIN queda disparado (como un socket del
//! SO), dejando el `splice` de T1 INTACTO.
//!
//! **M2b-pre:** [`tcp`] — el camino de forwarding TCP host→overlay, superface (A): cablea
//! [`InterceptStack::accept`] → emisor de `AppData` (espejo de `GetAppInfo` del interceptor Go, delta
//! CERO con `build_app_data` de T4b) → `connect_with_appdata` → [`crate::tunnel::proxy::splice`] contra
//! el [`InterceptTcpStream`].
//!
//! **(B-pre) (esta rebanada):** [`resolve`] — el resolver `intercept.v1`, superface (B) (frontera de
//! seguridad): mapea el destino REAL de un flujo `(dst_ip, dst_port, proto, src_ip)` al servicio ziti
//! que debe recibirlo, REEMPLAZANDO el `service` HARDCODED de M2b-pre. REUSA la primitiva endurecida
//! [`crate::tunnel::resolve::parse_ip_or_cidr`] (el mismo `GetCidr` del interceptor Go) → la clase de
//! over-permits cazada 3× en T4b queda cerrada; differential-testeado contra `GetCidr`+`Contains`. El
//! round-trip e2e con el resolver eligiendo por dst REAL (aceptación de (B)) es **(B-e2e)**: requiere
//! root (utun) + overlay (controller+router) — la prueba en vivo con root, ejecutada a mano.

pub mod combined;
pub mod device;
pub mod dns;
pub mod dns_server;
pub mod dns_tcp;
pub mod error;
pub mod flows;
pub mod proxy_resolve;
pub mod resolve;
pub mod routes;
pub mod splice_kill;
pub mod stack;
pub mod stream;
pub mod tcp;
pub mod udp;

pub use combined::run_combined_intercept;
pub use device::{IpPacketDevice, UtunDevice};
pub use dns::{DnsMatch, DnsMatchKind, DnsMatcher, RegisterOutcome};
pub use dns_server::{DnsAction, handle_query};
pub use error::InterceptError;
pub use resolve::{
    AppliedEvent, INTERCEPT_V1_CONFIG_TYPE, InterceptResolver, InterceptV1Config, Protocol,
    RouteDelta, intercept_v1_config,
};
pub use routes::{
    InstalledRoutes, OsRouteOps, RouteApplier, RouteLifecycle, RouteOps, control_plane_addrs,
    plan_routes,
};
pub use stack::{InterceptStack, TcpHalf, UdpHalf, UdpReplySender};
pub use stream::InterceptTcpStream;
pub use tcp::run_tcp_intercept;
pub use udp::{run_udp_intercept, run_udp_intercept_with_dns};
