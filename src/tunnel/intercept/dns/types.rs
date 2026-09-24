//! El vocabulario: [`DnsMatchKind`] + [`DnsMatch`] + [`RegisterOutcome`] (los 3 `pub`) +
//! `DnsEntry` (privada al directorio, la entrada resuelta). Sin lógica, solo datos (F6 tramo 15
//! troceo).

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// El TIPO de match: hostname exacto vs sufijo de dominio wildcard. Persiste con la entrada una vez
/// asignada (ver "Quirks" del doc del módulo) — no se recalcula por-llamada a partir de en qué mapa
/// se encontró la entrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMatchKind {
    /// El hostname exacto normalizado está registrado, incluido el caso literal-no-wildcard
    /// `*foo.com` (ver el doc del módulo).
    Hostname,
    /// El hostname casa (o casó originalmente) como sufijo de un dominio wildcard registrado,
    /// incluido el quirk "el dominio desnudo casa su propio wildcard".
    Domain,
}

/// El resultado de un [`crate::tunnel::intercept::dns::DnsMatcher::lookup`]: el tipo de match + el nombre de la query ya
/// normalizado (lowercase) + la IP sintética asignada (fresca o cacheada de una query anterior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsMatch {
    pub kind: DnsMatchKind,
    pub ip: Ipv4Addr,
}

/// El resultado de un [`crate::tunnel::intercept::dns::DnsMatcher::register`]. Espejo del `ip_addr_t*` que devuelve
/// `ziti_dns_register_hostname` (`ziti_dns.c:448-484`): un dominio wildcard NUNCA tiene IP propia
/// (`Domain`, aunque el registro haya tenido éxito); un hostname exacto la tiene, salvo que el pool
/// esté agotado o sin sembrar (`IpUnavailable` — el oráculo tampoco registra nada en ese caso, ver
/// el doc del módulo); un nombre que desborda `MAX_DNS_NAME` se rechaza limpio (`Rejected`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// Nombre inválido (desbordamiento ≥256 bytes) — no se registró nada.
    Rejected,
    /// Dominio wildcard registrado (o ya lo estaba) — nunca tiene IP propia.
    Domain,
    /// Hostname exacto registrado (o ya lo estaba, IP reusada sin consumir el pool otra vez).
    Hostname(Ipv4Addr),
    /// Hostname exacto válido, pero sin pool sembrado o con el pool agotado — no se registró nada,
    /// espejo de `new_ipv4_entry` devolviendo `NULL` (`ziti_dns.c:340-342`).
    IpUnavailable,
}

/// Una entrada resuelta (hostname exacto o subdominio derivado de un dominio wildcard) con su IP
/// sintética asignada. Espejo de `dns_entry_t` (`ziti_dns.c:82-90`) — incluido el `intercepts`
/// refcount (#5 eviction, CERRADO) — sin los campos ligados al protocolo de cable (deferral #4).
#[derive(Debug, Clone)]
pub(super) struct DnsEntry {
    pub(super) ip: Ipv4Addr,
    /// `Some(dominio)` (el sufijo de dominio que casó, SIN el prefijo `"*."` — mismo shape que
    /// [`crate::tunnel::intercept::dns::DnsMatcher::domains`], NO el string `"*."`-prefijado de `entry->domain->name` del oráculo)
    /// si esta entrada se creó vía un match de dominio wildcard (persiste aunque luego se
    /// re-registre explícitamente el mismo nombre, ver el doc del módulo). `None` si se registró
    /// como hostname exacto desde el principio.
    pub(super) domain: Option<String>,
    /// Los intercepts (servicios, por NOMBRE) que registraron este hostname EXPLÍCITAMENTE — espejo
    /// de `entry->intercepts` (`ziti_dns.c:88`; el oráculo keyea por el puntero `ziti_intercept_t*`,
    /// nuestro análogo estable es el nombre del servicio: un servicio tiene a lo sumo UN intercept
    /// vivo, keyed por nombre igual que `inst->intercepts`, `ziti_tunnel_cbs.c:622`). VACÍO para una
    /// entrada asignada LAZY por una query bajo un dominio wildcard (`ziti_dns_lookup` no añade
    /// intercepts, `ziti_dns.c:395-398`): su vida la gobierna el refcount del DOMINIO. Consumido por
    /// [`crate::tunnel::intercept::dns::DnsMatcher::deregister_intercept`].
    pub(super) intercepts: HashSet<String>,
}
