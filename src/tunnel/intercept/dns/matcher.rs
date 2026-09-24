//! El matcher: [`DnsMatcher`] (struct + el `impl` de 289 líneas: register/lookup/reserve/
//! deregister/reverse/matches/wildcard + `allocate_ip`). El orquestador que combina `types`+
//! `pool`+`normalize` (F6 tramo 15 troceo).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use super::normalize::{check_name, find_domain};
use super::pool::IpPool;
use super::types::{DnsEntry, DnsMatch, DnsMatchKind, RegisterOutcome};

/// Matcher de hostname/wildcard-domain + pool de IP sintética para direcciones `intercept.v1`.
/// Espejo de `check_name`+`find_domain`+`ziti_dns_lookup`+`ziti_dns_register_hostname`+
/// `ziti_dns_deregister_intercept`+`seed_dns`/`next_ipv4`/`new_ipv4_entry`. Con refcounting de
/// `intercepts` por entrada Y por dominio (#5 eviction, CERRADO) — ver "Diferidos NOMBRADOS" del
/// doc del módulo.
#[derive(Debug, Clone, Default)]
pub struct DnsMatcher {
    /// Hostnames exactos normalizados (lowercase) YA resueltos (registrados explícitamente o
    /// cacheados de un match de dominio previo), con su entrada asignada.
    hostnames: HashMap<String, DnsEntry>,
    /// Dominios wildcard normalizados, SIN el prefijo `"*."` (mismo shape que `ziti_dns.domains`) →
    /// el set de intercepts (servicios, por nombre) que los reclaman — espejo de
    /// `dns_domain_t.intercepts` (`ziti_dns.c:75`). Por construcción ningún set está vacío en estado
    /// estable: [`DnsMatcher::register`] solo inserta no-vacío y la pasada 3 de
    /// [`DnsMatcher::deregister_intercept`] retira los vacíos antes de devolver (espejo de
    /// `:436-445`), así que el gate `model_map_size(&domain->intercepts) > 0` de `ziti_dns_lookup`
    /// (`:393`) queda cubierto por `contains_key` sin rama muerta.
    domains: HashMap<String, HashSet<String>>,
    /// Mapa reverso IP sintética → hostname exacto que la tiene asignada. Espejo de
    /// `ziti_dns.ip_addresses` (`ziti_dns.c:105`); usado tanto para el chequeo de colisión/
    /// agotamiento del pool como para [`DnsMatcher::reverse_lookup`] (`dst_hostname`, wiring
    /// diferido).
    ip_addresses: HashMap<Ipv4Addr, String>,
    /// El pool de IP sintética, si se sembró. `None` = sin sembrar (nada del oráculo real llega a
    /// este estado — `ziti_dns_setup` siempre siembra antes de cualquier registro — pero un matcher
    /// de prueba puede quedarse así a propósito).
    pool: Option<IpPool>,
}

impl DnsMatcher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Siembra el pool de IP sintética desde un CIDR IPv4. Espejo de `seed_dns` (llamado desde
    /// `ziti_dns_setup`, `ziti_dns.c:181-183`). Devuelve `false` sin sembrar nada si el CIDR es
    /// inválido o degenerado (ver el doc del módulo); un `register`/`lookup` posterior de un
    /// hostname exacto devolverá `IpUnavailable`/`None` mientras no haya pool.
    #[must_use]
    pub fn seed_pool(&mut self, cidr: &str) -> bool {
        match IpPool::seed(cidr) {
            Some(pool) => {
                self.pool = Some(pool);
                true
            }
            None => false,
        }
    }

    /// Reserva `ip` directamente en el mapa reverso, SIN pasar por el pool (`next_ipv4` nunca vuelve
    /// a ofrecerla). Espejo de la reserva de `ziti_dns_setup` (`ziti_dns.c:194-201`): el oráculo
    /// inserta un `dns_entry_t` calloc'd (zeroed) para la IP del propio utun Y para la del "DNS
    /// resolver" embebido — un `struct` puesto a cero en C tiene `name[0]=='\0'`, así que
    /// [`DnsMatcher::reverse_lookup`] de una IP reservada devuelve `""`, byte-idéntico al oráculo
    /// (`ziti_dns_reverse_lookup` devuelve `entry->name`, que es `""` para la entrada zeroed). Nota: el
    /// oráculo keyea `ip_addresses` IP→`dns_entry_t` DIRECTO, así que la entrada reservada de una IP es
    /// DISTINTA de la de un hostname `""` legítimo aunque compartan `name==""`; nuestro mapa reverso es
    /// IP→String, de modo que las dos IPs comparten la clave `""` — [`DnsMatcher::reverse_lookup_domain`]
    /// compensa con un guard `entry.ip == ip` para no confundirlas (ver su doc). Idempotente (reservar
    /// la misma IP dos veces es un no-op); no toca `hostnames` (una IP reservada no tiene un hostname que
    /// la resuelva HACIA delante, solo bloquea el sentido inverso/de-asignación — igual que el oráculo).
    pub fn reserve(&mut self, ip: Ipv4Addr) {
        self.ip_addresses.entry(ip).or_default();
    }

    /// Registra una dirección `intercept.v1` (hostname exacto o `*.dominio`) A NOMBRE del intercept
    /// `intercept` (el servicio; espejo del param `void *intercept` de `ziti_dns_register_hostname`,
    /// `ziti_dns.c:448` — ver el doc de [`DnsMatcher::deregister_intercept`] para el mapeo
    /// puntero→nombre). Un dominio wildcard nunca recibe IP propia (`Domain`; el intercept se añade
    /// al set del dominio, `:462-471`); un hostname exacto la recibe EAGERLY (`Hostname(ip)`),
    /// reusando la IP ya asignada si el nombre ya estaba registrado (idempotente sobre la IP, sin
    /// consumir el pool otra vez — espejo de `ziti_dns_register_hostname` reusando la `entry`
    /// existente, `:473-474`; el intercept se añade al refcount de la entrada, `:477-478`).
    /// `Rejected` si el nombre desborda `MAX_DNS_NAME` (fail-closed a propósito, DIVERGE de la UB
    /// del oráculo real en ese camino — ver el doc del módulo). Con `IpUnavailable` (pool agotado /
    /// sin sembrar) NO se registra nada — tampoco el refcount (espejo de `new_ipv4_entry` NULL →
    /// return NULL sin `model_map_set_key`, `:474-481`).
    #[must_use]
    pub fn register(&mut self, address: &str, intercept: &str) -> RegisterOutcome {
        let Some((clean, is_domain)) = check_name(address) else {
            return RegisterOutcome::Rejected;
        };
        if is_domain {
            self.domains
                .entry(clean[2..].to_string())
                .or_default()
                .insert(intercept.to_string());
            return RegisterOutcome::Domain;
        }
        if let Some(entry) = self.hostnames.get_mut(&clean) {
            entry.intercepts.insert(intercept.to_string());
            return RegisterOutcome::Hostname(entry.ip);
        }
        match self.allocate_ip() {
            Some(ip) => {
                self.hostnames.insert(
                    clean.clone(),
                    DnsEntry {
                        ip,
                        domain: None,
                        intercepts: HashSet::from([intercept.to_string()]),
                    },
                );
                self.ip_addresses.insert(ip, clean);
                RegisterOutcome::Hostname(ip)
            }
            None => RegisterOutcome::IpUnavailable,
        }
    }

    /// Deregistra TODOS los registros del intercept `intercept` (el servicio, por nombre) y evicta
    /// el estado DNS que quede huérfano — espejo de las TRES pasadas de
    /// `ziti_dns_deregister_intercept` (`ziti_dns.c:414-446`):
    ///  1. quitar el intercept del set de CADA dominio (`:415-420`);
    ///  2. barrer `hostnames`: quitar el intercept del refcount de cada entrada; una entrada cuyo
    ///     refcount quedó vacío Y sin dominio activo (sin dominio, o con el set del dominio ya
    ///     vacío tras la pasada 1) se EVICTA junto con su IP en `ip_addresses` (`:422-434`) — el
    ///     hueco vuelve a ser asignable ([`DnsMatcher::allocate_ip`] revisa el mapa reverso EN VIVO,
    ///     como `next_ipv4` revisa `ziti_dns.ip_addresses`). Esto evicta también las entradas LAZY
    ///     (refcount vacío) de un dominio cuyo ÚLTIMO intercept se va;
    ///  3. barrer `domains`: un dominio con el set vacío se evicta (`:436-445`).
    ///
    /// Las IPs RESERVADAS ([`DnsMatcher::reserve`]) nunca se tocan: viven solo en `ip_addresses`
    /// sin entrada en `hostnames`, y la pasada 2 solo barre `hostnames` (idéntico al oráculo:
    /// `:422` itera `ziti_dns.hostnames` y las reservas solo están en `ip_addresses`, `:194-201`).
    ///
    /// **Identidad del intercept: NOMBRE del servicio, no puntero.** El oráculo keyea los sets por
    /// el puntero `ziti_intercept_t*` (uno vivo por servicio, keyed por nombre en
    /// `inst->intercepts`, `ziti_tunnel_cbs.c:622`); los tres call sites de `stop_intercept`
    /// (lost-dial `:626`, REPLACE `:634`, Removed `:681`) deregistran el puntero del intercept
    /// SALIENTE de ese servicio — deregistrar por nombre es equivalente. La única divergencia es un
    /// corner de identidad inalcanzable sin re-registro del MISMO sufijo: si un dominio se evicta y
    /// OTRO servicio re-registra el mismo sufijo mientras sobrevive una entrada explícita creada
    /// bajo el dominio viejo (`domain: Some(sufijo)` stale), el oráculo consulta el struct VIEJO
    /// (leakeado, set vacío — `model_map_it_remove` no libera el `dns_domain_t` y `entry->domain`
    /// lo sigue apuntando, `:436-445`) y evictaría la entrada al irse su último intercept propio;
    /// nosotros consultamos el sufijo ACTUAL (activo de nuevo) y la conservamos como si fuera lazy
    /// del dominio re-registrado. Safe-direction: la entrada conservada solo resuelve/despacha
    /// hacia el reclamante ACTUAL del dominio vía el fallback wildcard (el mismo servicio que una
    /// query fresca alcanzaría con una IP nueva en el oráculo); nunca hacia el servicio retirado.
    ///
    /// El gate de actividad de `ziti_dns_lookup` (`entry->intercepts` vacío y dominio inactivo →
    /// "inactive entry" → NULL, `:402-409`) NO se implementa: es inalcanzable por construcción —
    /// toda entrada/dominio cuyo refcount se vacía se evicta DENTRO de esta misma llamada (pasadas
    /// 2-3), así que [`DnsMatcher::lookup`] nunca encuentra una entrada inactiva en el mapa. El
    /// oráculo tampoco alcanza esa rama en estado estable; es defensiva.
    pub fn deregister_intercept(&mut self, intercept: &str) {
        // Borrows disjuntos: la pasada 2 muta `hostnames` mientras LEE `domains` (ya barrido por la
        // pasada 1) y muta `ip_addresses` — misma disciplina que `add_service`/`allocate_ip`.
        let Self {
            hostnames,
            domains,
            ip_addresses,
            ..
        } = self;
        // Pasada 1 (`:415-420`): quitar el intercept del set de cada dominio.
        for owners in domains.values_mut() {
            owners.remove(intercept);
        }
        // Pasada 2 (`:422-434`): barrer hostnames; evictar entrada+IP si el refcount quedó vacío y
        // el dominio (si lo hay) quedó inactivo. El orden espejo importa: la pasada 1 YA quitó el
        // intercept de los dominios, así que las entradas lazy de un dominio que este deregistro
        // vació se evictan aquí (la condición `:426` las ve con dominio-set vacío).
        hostnames.retain(|_, entry| {
            entry.intercepts.remove(intercept);
            let keep = !entry.intercepts.is_empty()
                || entry
                    .domain
                    .as_deref()
                    .is_some_and(|suffix| domains.get(suffix).is_some_and(|o| !o.is_empty()));
            if !keep {
                // `:428`: liberar la IP — vuelve asignable (allocate revisa el mapa reverso en vivo).
                ip_addresses.remove(&entry.ip);
            }
            keep
        });
        // Pasada 3 (`:436-445`): evictar los dominios cuyo set quedó vacío.
        domains.retain(|_, owners| !owners.is_empty());
    }

    /// Resuelve una query DNS. `None` si la query desborda, si ELLA MISMA tiene forma de wildcard
    /// (`ziti_dns_lookup` la rechaza SIEMPRE, `ziti_dns.c:383`), si ningún hostname/dominio
    /// registrado casa, o si el match es de dominio pero el pool está agotado/sin sembrar (espejo de
    /// `new_ipv4_entry` devolviendo `NULL` dentro de `ziti_dns_lookup`, `:395-398` — la entrada nunca
    /// se crea, así que la query entera falla como si no hubiera casado nada).
    #[must_use]
    pub fn lookup(&mut self, query: &str) -> Option<DnsMatch> {
        let (clean, is_wildcard) = check_name(query)?;
        if is_wildcard {
            return None;
        }
        if let Some(entry) = self.hostnames.get(&clean) {
            let kind = if entry.domain.is_some() {
                DnsMatchKind::Domain
            } else {
                DnsMatchKind::Hostname
            };
            return Some(DnsMatch { kind, ip: entry.ip });
        }
        let matched_domain = find_domain(&clean, &self.domains).map(str::to_string)?;
        let ip = self.allocate_ip()?;
        self.hostnames.insert(
            clean.clone(),
            DnsEntry {
                ip,
                domain: Some(matched_domain),
                // Una entrada LAZY no lleva intercepts propios (`ziti_dns_lookup` no los añade,
                // `ziti_dns.c:395-398`): su vida la gobierna el refcount del DOMINIO (ver
                // `deregister_intercept`).
                intercepts: HashSet::new(),
            },
        );
        self.ip_addresses.insert(ip, clean);
        Some(DnsMatch {
            kind: DnsMatchKind::Domain,
            ip,
        })
    }

    /// Hostname registrado para una IP sintética ya asignada (`None` si la IP no está asignada).
    /// Espejo de `ziti_dns_reverse_lookup` (`ziti_dns.c:362-368`), consumido por
    /// `ziti_tunnel_cbs.c:256` para emitir `dst_hostname` en el AppData del intercept (wiring contra
    /// `intercept/resolve`/`main.rs` diferido, ver el doc del módulo).
    #[must_use]
    pub fn reverse_lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_addresses.get(&ip).map(String::as_str)
    }

    /// El patrón de dominio wildcard que creó la entrada asignada a `ip`, como SUFIJO normalizado SIN
    /// el prefijo `"*."` (el mismo shape que [`DnsMatcher::domains`]; el oráculo devuelve el string
    /// `"*."`-prefijado `entry->domain->name` — el único consumidor real, el fallback per-paquete de
    /// [`crate::tunnel::intercept::resolve::InterceptResolver`], reconstruye el prefijo para el walk). `None` si la IP no
    /// está asignada, si está solo RESERVADA (la entrada zeroed del oráculo tiene `entry->domain ==
    /// NULL`), o si pertenece a un hostname registrado explícitamente desde el principio. Espejo de
    /// `ziti_dns_reverse_lookup_domain` (`ziti_dns.c:354-360`), el helper consumido por
    /// `intercept_match_addr` (`ziti_tunnel_cbs.c:510-526`). Su consumidor de producción es el
    /// fallback per-paquete de wildcards de [`crate::tunnel::intercept::resolve::InterceptResolver::lookup`] (diferido
    /// #6, CERRADO en `0211810`).
    #[must_use]
    pub fn reverse_lookup_domain(&self, ip: Ipv4Addr) -> Option<&str> {
        let hostname = self.ip_addresses.get(&ip)?;
        let entry = self.hostnames.get(hostname)?;
        // Guard de fidelidad (over-permit cazado por la revisión reforzada del slice #6): el oráculo
        // keyea `ip_addresses` IP→`dns_entry_t` DIRECTO, así que `ziti_dns_reverse_lookup_domain(X)`
        // resuelve a la entrada PROPIA de X (una IP RESERVADA tiene su entrada zeroed con
        // `entry->domain == NULL` → devuelve NULL). Nuestro mapa reverso es IP→String y luego
        // `hostnames[String]`, una indirección de más: una IP reservada guarda la cadena `""`
        // (`reserve`), que COLISIONA con la entrada de una query del nombre vacío `""` (un servicio
        // con la dirección degenerada `"*."` + una query de `""`). Sin este guard, `reverse_lookup_domain`
        // de la IP reservada heredaría el `domain` de la entrada `""` ajena y la despacharía al servicio
        // `"*."` — un OVER-PERMIT que el oráculo no comete. Confirmar que la entrada pertenece a ESTA IP
        // (round-trip `entry.ip == ip`) restaura el keyeo por-IP del oráculo: una IP reservada (o
        // cualquier IP cuya cadena reversa apunte a la entrada de OTRA IP) devuelve `None`.
        if entry.ip != ip {
            return None;
        }
        entry.domain.as_deref()
    }

    /// `true` si `query` casa algún dominio wildcard registrado, SIN asignar IP ni crear entrada —
    /// espejo EXACTO del gate del camino no-A/AAAA de `on_dns_req` (`ziti_dns.c:830-834`):
    /// `check_name(q->name, reqname, NULL); domain = find_domain(reqname);`. Dos quirks del oráculo
    /// replicados a propósito (difieren del camino de [`DnsMatcher::lookup`]):
    ///  - el retorno de `check_name` se IGNORA en ese call site: un nombre que desborda deja
    ///    `reqname == ""` (el bucle del oráculo resetea `p = clean_name` y el `*p = '\0'` final lo
    ///    corta a vacío), así que se busca el dominio `""` — registrable vía la dirección literal
    ///    `"*."` — en vez de rechazar la query;
    ///  - NO se rechaza una query con forma de wildcard (ese call site pasa `NULL` como `is_domain`):
    ///    la query literal `"*.foo"` normaliza a `"*.foo"` y el walk de sufijos de `find_domain` la
    ///    casa contra el dominio `foo`.
    #[must_use]
    pub fn matches_domain(&self, query: &str) -> bool {
        self.matched_domain(query).is_some()
    }

    /// El SUFIJO de dominio que casa `query` (el shape normalizado de [`DnsMatcher::domains`]), o
    /// `None` si ninguno casa — el mismo gate que [`DnsMatcher::matches_domain`] (que delega aquí,
    /// consistencia por construcción) pero devolviendo el dominio casado: es el `dns_domain_t` que
    /// el routing no-A/AAAA del oráculo entrega a `proxy_domain_req` (`find_domain` devuelve el
    /// DOMINIO registrado, no la query; `ziti_dns.c:833-835`) — M3-DNS #2 lo usa para elegir la
    /// conexión resolver por-dominio y el servicio a dial-ear. Owned: el sufijo casado es una vista
    /// del nombre normalizado LOCAL (no puede prestarse) y el llamante lo retiene como clave.
    #[must_use]
    pub fn matched_domain(&self, query: &str) -> Option<String> {
        let clean = check_name(query).map_or_else(String::new, |(clean, _)| clean);
        find_domain(&clean, &self.domains).map(str::to_string)
    }

    /// El SUFIJO de dominio normalizado (lowercase, SIN el prefijo `"*."`) de una dirección wildcard
    /// `"*.dominio"`, o `None` si `address` no es un wildcard válido (no empieza por `"*."`, o
    /// desborda `MAX_DNS_NAME`). Es EXACTAMENTE el mismo string que [`DnsMatcher::register`] guarda en
    /// [`DnsMatcher::domains`] (`clean[2..]`) y que [`DnsMatcher::reverse_lookup_domain`] devuelve para
    /// una IP asignada bajo ese dominio — compartir la normalización (una sola llamada a `check_name`)
    /// evita que el consumidor del fallback per-paquete ([`crate::tunnel::intercept::resolve::InterceptResolver`]) derive
    /// una forma divergente del sufijo y falle el match `ziti_address_match` contra su propio dominio.
    /// Asociada (sin `self`): normalización pura, no consulta el estado del matcher.
    #[must_use]
    pub fn wildcard_suffix(address: &str) -> Option<String> {
        match check_name(address) {
            Some((clean, true)) => Some(clean[2..].to_string()),
            _ => None,
        }
    }

    /// Próximo candidato del pool, o `None` si no hay pool sembrado o está agotado. El chequeo de
    /// colisión/agotamiento compara contra `ip_addresses` EN VIVO (no un set cacheado aparte) — por
    /// eso la eviction (#5, [`DnsMatcher::deregister_intercept`]) no necesitó tocar esta función:
    /// liberar una entrada de `ip_addresses` la hace asignable de nuevo en la siguiente llamada
    /// (pineado por el vector upstream `recycle_ip_equals_upstream_dns_test`).
    fn allocate_ip(&mut self) -> Option<Ipv4Addr> {
        let Self {
            pool, ip_addresses, ..
        } = self;
        let pool = pool.as_mut()?;
        pool.allocate(ip_addresses.len(), |ip| ip_addresses.contains_key(&ip))
    }
}
