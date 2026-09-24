//! (B) — el resolver `intercept.v1`: mapea el destino REAL de un flujo interceptado
//! `(dst_ip, dst_port, protocolo, src_ip)` al **nombre del servicio** ziti que debe recibirlo.
//! Reemplaza el `service` HARDCODED de M2b-pre por una elección dirigida por la config del servicio.
//!
//! ## Oráculo (B) — `openziti/ziti` v2.0.0 (FRONTERA DE SEGURIDAD, fidelidad estricta + differential)
//! - `tunnel/entities/service.go:360-371` `InterceptV1Config` (`addresses`/`portRanges`/`protocols`/
//!   `dialOptions`/`sourceIp`/`allowedSourceAddresses`) + el esquema del controller
//!   `controller/db/migration_initialize.go:529-590` (claves camelCase, `portRange{low,high}`,
//!   `dialOptions{connectTimeoutSeconds,identity}`).
//! - `tunnel/intercept/interceptor.go:76` `InterceptAddress.Contains(ip,port)` =
//!   `cidr.Contains(ip) && port∈[low,high]`, expandido por `GetInterceptAddresses` (`:89-108`) sobre el
//!   producto `addresses × protocols × portRanges`.
//! - `tunnel/intercept/iputils.go:114` `getInterceptIP` → `utils.GetCidr` (`utils/ipcalc.go:25`) para
//!   las direcciones IP/CIDR; **el MISMO `GetCidr` que [`crate::tunnel::resolve::parse_ip_or_cidr`]
//!   porta y endurece** — por eso lo REUSAMOS (no un matcher paralelo): la clase de over-permits
//!   (leading-zero / v4-mapped / NAT64) cazada 3× en T4b queda cerrada por esa única primitiva.
//! - `tunnel/intercept/svcpoll.go:181-232` `addService`: registra el intercept SOLO si el servicio
//!   tiene permiso `Dial` (`:191`), y fija `svc.DialTimeout = 5s` (`:184`), sobreescrito SOLO por
//!   `dialOptions.connectTimeoutSeconds` (`:196-198`).
//! - `tproxy_linux.go:567-568,763-764`: `allowedSourceAddresses` se aplica como whitelist de IPs de
//!   ORIGEN que pueden interceptarse (iptables `-s`); ignorarla sería un OVER-PERMIT (rutar a un
//!   servicio un flujo de un origen no autorizado) → se aplica aquí (ver [`InterceptEntry::source_allowed`]).
//!
//! ## Semántica de match (espejo de `InterceptAddress.Contains` + el bucle de protocolos)
//! Un flujo `(dst_ip, dst_port, proto, src_ip)` casa una entrada si: el protocolo coincide
//! (case-SENSITIVE, espejo de `stringz.Contains`, igual que `get_protocol` host-side) **Y**
//! `cidr.contains(dst_ip)` **Y** `dst_port ∈ [low,high]` **Y** el origen está permitido (whitelist
//! `allowedSourceAddresses`, o sin restricción si está vacía). [`InterceptResolver::lookup`] devuelve
//! el PRIMER match en orden de la lista de servicios.
//!
//! ### Precedencia en solapamiento (decisión consciente, NO longest-prefix)
//! El oráculo NO define un orden de precedencia portable cuando dos servicios interceptan el mismo
//! destino: tproxy lo delega al kernel (reglas iptables ORDENADAS por orden de intercept, no
//! determinista; el userspace `proxy` es listener-fijo-por-servicio). Por eso elegimos **first-match
//! determinista en el orden de la lista de servicios** — UN resultado válido del oráculo, explícitamente
//! NO "longest-prefix" (eso sería beyond-oracle, no portado). NO es frontera de seguridad: la identidad
//! está autorizada para TODOS los servicios que ve (cualquiera de ellos es un dial legítimo), así que
//! elegir A vs B en un solapamiento no es una escalada de autorización.
//!
//! ## Diferidos NOMBRADOS (no silenciosos — cada uno cierra en una rebanada posterior)
//!  1. ~~**Direcciones por HOSTNAME / wildcard (`*.dominio`) → DNS embebido (M3).**~~ CERRADO por
//!     M3-DNS: un hostname EXACTO obtiene una IP sintética `/32` que despacha como una dirección
//!     literal, y un `*.dominio` construye una [`WildcardEntry`] que [`InterceptResolver::lookup`]
//!     despacha por el fallback per-paquete (`intercept_match_addr`, reverse-lookup IP→dominio). El
//!     wiring vive en el tunneler C (`ziti_tunnel_cbs.c`), NO en el Go de arriba (ver el doc de
//!     [`InterceptResolver`]). El server queda MONTADO en producción por el subcomando combinado
//!     (`combined::run_combined_intercept`, cerrado el diferido de M3-UDP-handler).
//!  2. **`sourceIp` template → `source_addr` del `AppData`** (motor de plantillas, `svcpoll.go:335`).
//!     Sin la plantilla no se emite `source_addr` (M2b-pre diferido #2). Aquí NO se plumbing-ea.
//!  3. **`dialOptions.identity` → instanceId del terminador direccionable** (`svcpoll.go:343` →
//!     `DialOptions{Identity}`, `provider.go:107`). Es un PARÁMETRO DE DIAL nuevo (no un campo del
//!     `AppData`), y [`crate::edge::client::EdgeClient::connect_with_appdata`] no tiene parámetro para
//!     emitirlo → emitirlo es un **header de Connect NUEVO = wire nuevo = su propia rebanada live**. Con
//!     un servicio sin plantilla `GetDialIdentity` devuelve `""` → ningún selector → bytes fieles HOY.
//!     M2b-pre diferido #3; queda NOMBRADO para no ser un UNDER-emit silencioso.
//!  4. **Fallback `client.v1` (`ziti-tunneler-client.v1`) → `ToInterceptV1Config`** (`svcpoll.go:208-211`):
//!     un servicio sin `intercept.v1` cae a `client.v1` cuya `Addresses=[Hostname]` (DNS) → diferido con
//!     #1. Además NO pedimos ese config-type al controller (solo `intercept.v1`), así que ni aparece.
//!  5. ~~**Refresco en vivo vía `ServiceWatcher` (T5).**~~ — CERRADO en dos rebanadas: el PRIMITIVO
//!     `add_service`/`remove_service`/`apply_event` (svc-reconcile, `dfb3b07`) + el WIRING vivo
//!     (`svc_poll_loop`, 3ª rama del `select!` del runner combinado, `6537d26`); el release DNS del
//!     `Removed` lo cerró #5 eviction ([`DnsMatcher::deregister_intercept`]).
//!  6. **Entradas hostname/wildcard en `allowedSourceAddresses`** → DNS (M3): se DESCARTAN del set de
//!     CIDRs de origen, lo que ENDURECE la whitelist (un origen que el oráculo resolvería por DNS no se
//!     intercepta hasta M3) = UNDER-permit seguro, NUNCA ampliando la whitelist (ver [`build_allowed_sources`](crate::tunnel::intercept::resolve::config::build_allowed_sources)).
//!
//! **Artefacto del all-capture (C):** netstack responde el SYN (SYN-ACK) ANTES de que resolvamos, así
//! que un `dst` que NINGÚN servicio intercepta recibe SYN-ACK y luego un cierre limpio (se dropea el
//! stream). La instalación de RUTAS (M3) hace que solo los CIDRs interceptados lleguen al device, así
//! que ese caso es una misconfig; el cierre limpio es la dirección segura.

use std::collections::HashMap;
use std::time::Duration;

use ipnet::IpNet;

use super::dns::DnsMatcher;

mod config;
mod entry;
mod literal;
mod lookup;
mod resolver;

#[cfg(test)]
mod tests_config;
#[cfg(test)]
mod tests_differential;
#[cfg(test)]
mod tests_match;
#[cfg(test)]
mod tests_reconcile;
#[cfg(test)]
mod tests_wildcard;
#[cfg(test)]
mod testsupport;

pub use config::{DialOptions, InterceptV1Config, intercept_v1_config};

/// El nombre del config-type `intercept.v1` (la clave bajo `Service.config`). Oráculo:
/// `InterceptV1 = "intercept.v1"` (`tunnel/entities/service.go:29`).
pub const INTERCEPT_V1_CONFIG_TYPE: &str = "intercept.v1";

/// Timeout de dial por defecto de un flujo interceptado cuando el servicio NO fija
/// `dialOptions.connectTimeoutSeconds`. Oráculo: `svc.DialTimeout = 5 * time.Second`
/// (`tunnel/intercept/svcpoll.go:184`). NUNCA se normaliza (5 ≥ 1, así que el `<1→15s` del SDK no
/// aplica, ver [`dial_timeout_for`](crate::tunnel::intercept::resolve::config::dial_timeout_for)).
pub const INTERCEPT_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// El protocolo de transporte de un flujo interceptado. Oráculo: `interceptor.go:30-32` (`TCP`/`UDP`),
/// emparejado contra `InterceptV1Config.Protocols` como string case-sensitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// El string del protocolo tal y como aparece en `intercept.v1.protocols` (match case-sensitive).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

/// Una entrada de la tabla de intercept: el producto `(cidr, [low,high], protocolo)` de un servicio,
/// con su timeout de dial y la whitelist de origen. Espejo de `interceptor.go:46-53` `InterceptAddress`
/// (más el `service`/`dialTimeout`/`allowedSources` que el oráculo lleva fuera del struct).
#[derive(Debug, Clone)]
struct InterceptEntry {
    cidr: IpNet,
    low_port: u16,
    high_port: u16,
    protocol: String,
    service: String,
    dial_timeout: Duration,
    /// Whitelist de origen: `None` = cualquier origen; `Some(cidrs)` = solo esos (ver [`self::config::build_allowed_sources`]).
    allowed_sources: Option<Vec<IpNet>>,
}

/// Una entrada de dispatch por DOMINIO WILDCARD (`*.dominio`): a diferencia de [`InterceptEntry`] no
/// tiene un CIDR propio — casa un paquete cuyo destino es una IP sintética que una query DNS asignó
/// LAZY-mente bajo este dominio wildcard. Espejo del predicado `intercept_match_addr` del oráculo
/// (`ziti_tunnel_cbs.c:510-526`) + su gate en `lookup_intercept_by_address` (`intercept.c:214-247`):
/// para el destino se hace un REVERSE lookup (`ziti_dns_reverse_lookup_domain`) IP→dominio, y una
/// entrada casa si su patrón wildcard casa ese dominio vía `ziti_address_match_s`. Se expande igual que
/// [`InterceptEntry`] sobre `protocols × portRanges` del servicio (uno por combinación), y lleva los
/// mismos `dialTimeout`/`allowedSources` porque el oráculo aplica `protocol_match`/`port_match`/la
/// whitelist de origen al MISMO intercept, no solo el match de dirección.
#[derive(Debug, Clone)]
struct WildcardEntry {
    /// El sufijo de dominio wildcard normalizado (lowercase, SIN el prefijo `"*."`), mismo shape que
    /// [`DnsMatcher::domains`] y que el valor que [`DnsMatcher::reverse_lookup_domain`] devuelve — por
    /// eso el match byte-a-byte de [`Self::suffix_matches`] es fiel sin re-normalizar.
    suffix: String,
    low_port: u16,
    high_port: u16,
    protocol: String,
    service: String,
    dial_timeout: Duration,
    /// Whitelist de origen (ver [`InterceptEntry::allowed_sources`]).
    allowed_sources: Option<Vec<IpNet>>,
}

/// El resultado de un lookup: el servicio elegido y su timeout de dial (ambos prestados/copiados del
/// resolver, sin retener el borrow tras el lookup).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptMatch<'a> {
    /// El nombre del servicio ziti a dial-ear con el `AppData` del destino.
    pub service: &'a str,
    /// El timeout de dial del flujo (5s/15s/N según el `intercept.v1` del servicio).
    pub dial_timeout: Duration,
}

/// Las direcciones literal-CIDR que una mutación del resolver RETIRÓ e INSTALÓ, en el orden del
/// oráculo (un REPLACE hace `stop_intercept` → `ziti_tunneler_intercept`, `ziti_tunnel_cbs.c:634`
/// → `:638-639`, así que `removed` se aplica ANTES que `added` — mismo churn delete-then-add que el
/// C cuando un servicio conserva un CIDR a través de un replace). Es la entrada del ciclo de vida
/// de rutas OS ([`super::routes::RouteLifecycle`]): cada dirección pasa por su tabla de refcounts
/// (`route.c:20-80`), que instala en la 1ª referencia y desinstala en la última.
///
/// Solo direcciones LITERALES (IP/CIDR por [`parse_ip_or_cidr`](crate::tunnel::resolve::parse_ip_or_cidr)), en ORDEN de config y con
/// duplicados (espejo de `i_ctx->addresses`: el C hace un `add_route`/`delete_route` por ENTRADA de
/// la lista — un config con la misma dirección dos veces refcuenta 2, simétrico en add y remove).
/// Desviación consciente: el C también rutea el `/32` SINTÉTICO de un hostname exacto
/// (`intercept_addr_from_cfg_addr` lo sintetiza en su rama hostname, `ziti_tunnel_cbs.c:529-546`, y
/// el bucle de direcciones lo mete en la lista vía `intercept_ctx_add_address`, `:568-570`) —
/// redundante, porque la IP sintética
/// cae SIEMPRE dentro de la subred on-link del utun (el pool DNS se siembra del CIDR del utun) y la
/// política de rutas la filtraría igual que ya hace el snapshot (`plan_routes` omite on-link,
/// desviación aceptada de M3-rutas); aquí se omite en ORIGEN para no acoplar el delta al estado del
/// pool. Efecto observable: idéntico.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteDelta {
    /// Direcciones del intercept SALIENTE (config instalado que se retira). Vacío si no había.
    pub removed: Vec<IpNet>,
    /// Direcciones del intercept ENTRANTE (config nuevo que se instala). Vacío si no se instala.
    pub added: Vec<IpNet>,
}

impl RouteDelta {
    /// `true` si la mutación no movió ninguna dirección (keep-old, keep-unchanged, no-op).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.added.is_empty()
    }
}

/// El resultado de aplicar UN evento de servicio a la tabla de intercept: el [`RouteDelta`] de rutas
/// OS **y** si el evento debe MATAR los flujos ACTIVOS del servicio (espejo de `tunneler_kill_active`,
/// `ziti_tunnel.c:437-465`, que `ziti_tunneler_stop_intercepting` invoca en `:493` y otra vez,
/// incondicional, en `:510`).
///
/// `kill_active` responde exactamente a "¿el oráculo habría llamado `stop_intercept` para este
/// evento?" — es decir, `curr_i != NULL` en las dos ramas que lo llaman (`ziti_tunnel_cbs.c:624`
/// lost-dial, `:632` REPLACE) y SIEMPRE en `Removed`.
///
/// **NO se deriva del [`RouteDelta`]:** un `intercept.v1` de solo-hostname produce un delta de rutas
/// VACÍO (su `/32` sintético cae on-link y se omite en origen, ver [`RouteDelta`]) y aun así el
/// oráculo mata sus flujos. Derivar uno del otro sería un under-kill silencioso.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppliedEvent {
    /// Las rutas OS que la mutación retira/instala (ver [`RouteDelta`]).
    pub routes: RouteDelta,
    /// `true` ⇒ el llamante debe cerrar los flujos vivos del servicio (`FlowRegistry::kill_service`).
    pub kill_active: bool,
}

/// Tabla de intercept `(cidr,puerto,protocolo,origen) → servicio`, construida de un snapshot de
/// servicios. Espejo del registro de `InterceptAddress`es que el interceptor mantiene (uno por servicio
/// Dial-permitido con `intercept.v1`).
///
/// ## Wiring M3-DNS (hostname/wildcard, `ziti-tunnel-sdk-c` `ziti_tunnel_cbs.c:529-546`)
/// **NO** el oráculo Go de arriba: la unión "registro de hostname ↔ contexto de intercept" vive en el
/// tunneler C (`intercept_addr_from_cfg_addr`), porque el Go tunneler tiene su DNS embebido Y su tabla
/// de intercept en el MISMO codebase, sin un seam equivalente a separar (y ese DNS es Linux-only, ver
/// el doc de [`super::dns`]). Cada dirección `ziti_address_hostname` (exacta O wildcard) se pasa a
/// `ziti_dns_register_hostname` incondicionalmente:
///  - **Hostname EXACTO** → la IP sintética asignada se añade al address-set del intercept COMO
///    CUALQUIER OTRA dirección literal (`intercept_ctx_add_address`, `:538-540,558,571`) — el
///    dispatch por-paquete (`address_match` sobre `intercept->addresses`, `intercept.c:206`) NO
///    necesita saber que es sintética. Por eso aquí se construye como un `/32` normal, reusando el
///    MISMO bucle `protocols × portRanges` que un CIDR literal — CERO lógica de dispatch nueva.
///  - **Dominio wildcard** → `ziti_dns_register_hostname` devuelve `NULL` (nunca tiene IP `/32`
///    propia); NO se añade ninguna entrada LITERAL (`intercept_addr_p` queda `NULL`, `:543`). SÍ se
///    construye una entrada de dispatch por-dominio ([`WildcardEntry`], ver abajo).
///
/// **Dispatch por dominio wildcard (M3-DNS #6, ya cableado).** El fallback per-paquete del oráculo
/// (`intercept_match_addr`, `ziti_tunnel_cbs.c:510-526`, registrado incondicional vía
/// `intercept_ctx_set_match_addr`) hace un REVERSE lookup (`ziti_dns_reverse_lookup_domain`) del
/// destino de un paquete → el dominio bajo el que se asignó su IP, y casa ese dominio contra los
/// patrones wildcard del servicio (`ziti_address_match_s`). Esa IP sólo pudo asignarse por una query
/// DNS previa bajo el dominio (`ziti_dns_lookup` LAZY, disparada por el servidor UDP:53 embebido — YA
/// portado en [`super::dns_server`]). Aquí construimos una [`WildcardEntry`] por `*.dominio × protocolo
/// × portRange`; [`Self::lookup`] la consulta como FALLBACK (sólo tras fallar el match literal, espejo
/// del scoring del oráculo: `match_addr` da el score fijo 1 en `lookup_intercept_by_address`,
/// `intercept.c:214-247`). Cerrado el diferido #6: una query wildcard vía [`super::dns_server`] asigna
/// la IP, y un paquete a esa IP despacha end-to-end al servicio dueño del dominio.
///
/// Un hostname EXACTO registrado aquí sólo es alcanzable por un paquete dirigido a su IP sintética
/// (resuelta por el cliente vía el mismo servidor DNS embebido). El **subcomando TCP+UDP combinado**
/// (diferido de M3-UDP-handler) quedó CERRADO: `main.rs` corre
/// [`super::combined::run_combined_intercept`], que monta el servidor DNS en producción y comparte
/// ESTE resolver entre el dispatch TCP y el manager UDP — el mecanismo completo
/// (query → asignación → reverse-lookup → fallback) es alcanzable por un cliente real.
#[derive(Debug, Clone, Default)]
pub struct InterceptResolver {
    entries: Vec<InterceptEntry>,
    /// Entradas de dispatch por dominio wildcard (`intercept_match_addr`, M3-DNS diferido #6): casan un
    /// paquete cuyo destino es una IP sintética asignada LAZY por una query DNS bajo un dominio
    /// wildcard. Vacío hasta que un servicio registra un `*.dominio` Y una query lo resuelve. Se
    /// consultan como FALLBACK en [`Self::lookup`], sólo tras fallar el match literal (espejo del
    /// scoring del oráculo, ver el doc de [`WildcardEntry`] y [`Self::lookup`]).
    wildcards: Vec<WildcardEntry>,
    /// El matcher M3-DNS: registra hostname/wildcard, asigna IPs sintéticas para hostnames exactos.
    /// Sin consumidor propio en esta rebanada más allá del registro (ver el doc de la struct); vive
    /// aquí porque es el hogar natural para un futuro `dst_hostname` (diferido de M2b-pre) — el mismo
    /// resolver que ya se hilvana hasta el punto de dial.
    dns: DnsMatcher,
    /// El `intercept.v1` CRUDO del intercept INSTALADO, por nombre de servicio — espejo del
    /// `curr_i` que `ziti_sdk_c_on_service` consulta (`model_map_get(&inst->intercepts, name)`,
    /// `ziti_tunnel_cbs.c:622`) con su config parseado (`curr_i->cfg`). Alimenta el gate
    /// keep-unchanged de [`Self::add_service`] (el `compare()==0` de `new_ziti_intercept`,
    /// `:449-455`): un `Changed` cuyo `intercept.v1` NO cambió (solo permissions/`host.v1`/otros
    /// campos del servicio) conserva el intercept instalado SIN reconstruir — crítico tras #5
    /// eviction, porque reconstruir deregistra+re-registra el DNS (churn de IP sintética que el
    /// oráculo evita). Se inserta al instalar (`model_map_set`, `:637`) y se retira en
    /// [`Self::remove_service`] (`model_map_remove`, `:598`/`:679`).
    installed_configs: HashMap<String, serde_json::Value>,
}
