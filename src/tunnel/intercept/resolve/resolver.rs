//! `impl InterceptResolver`: construcción, reconciliación por-servicio (add/remove/apply_event) y el
//! accessor `intercept_cidrs` (F6 tramo 2b troceo). El data-path caliente (`lookup`/`proxy_service`)
//! vive aparte en `lookup.rs`. La decl de struct vive en `mod.rs`. Movido verbatim del monolito de `intercept/resolve`.

use std::collections::HashMap;

use ipnet::{IpNet, Ipv4Net};

use crate::edge::model::Service;
use crate::edge::services::ServiceEvent;
use crate::tunnel::resolve::parse_ip_or_cidr;

use super::config::{build_allowed_sources, dial_timeout_for, intercept_v1_config};
use super::literal::{literal_addrs, literal_route_addrs};
use super::{
    AppliedEvent, INTERCEPT_V1_CONFIG_TYPE, InterceptEntry, InterceptResolver, RouteDelta,
    WildcardEntry,
};
use crate::tunnel::intercept::dns::{DnsMatcher, RegisterOutcome};

impl InterceptResolver {
    /// Construye el resolver de `services` con un [`DnsMatcher`] VACÍO (sin pool sembrado) — equivale
    /// a [`Self::from_services_with_dns`] con `DnsMatcher::new()`: un hostname exacto no puede
    /// asignarse IP (`IpUnavailable`) y por tanto no produce entrada, igual que el comportamiento
    /// previo a esta rebanada. Los tests que no ejercitan M3-DNS siguen usando este constructor sin
    /// cambios de comportamiento.
    #[must_use]
    pub fn from_services(services: &[Service]) -> Self {
        Self::from_services_with_dns(services, DnsMatcher::new())
    }

    /// Como [`Self::from_services`], pero con un [`DnsMatcher`] YA sembrado (típicamente con el CIDR
    /// del utun + las reservas de `main.rs`). El arranque de producción (`main.rs`) hace este MISMO
    /// fold a mano (un `add_service` por servicio) para capturar además el [`RouteDelta`] de cada
    /// alta hacia el `RouteLifecycle` (rebanada RUTAS OS); este constructor es la forma sin rutas
    /// (tests, e2e, resolvers auxiliares). Por cada servicio con
    /// permiso `Dial` (oráculo `svcpoll.go:191`) e `intercept.v1` válido, expande
    /// `addresses × protocols × portRanges` en entradas (oráculo `GetInterceptAddresses`,
    /// `interceptor.go:89-108`). Un `intercept.v1` malformado se log-and-skip-ea (oráculo `:202-204`).
    /// Las direcciones hostname/wildcard se registran en `dns` (ver el doc de la struct para el wiring
    /// M3-DNS, oráculo `ziti_tunnel_cbs.c`, DISTINTO del Go de arriba).
    #[must_use]
    pub fn from_services_with_dns(services: &[Service], dns: DnsMatcher) -> Self {
        // El arranque del tunneler llama `ziti_sdk_c_on_service(ZITI_OK)` por cada servicio del snapshot
        // en orden (`ziti_tunnel_ctrl.c:1077,1092`). El fold de [`Self::add_service`] lo reproduce
        // EXACTAMENTE: los nombres de un snapshot son únicos (una identidad no ve dos servicios con el
        // mismo nombre) → ningún `remove_service` retira nada → la construcción es idéntica a la del
        // bucle en bloque previo, y la asignación de IP sintética conserva el orden porque add_service
        // registra las direcciones en el MISMO orden por-servicio.
        let mut resolver = Self {
            entries: Vec::new(),
            wildcards: Vec::new(),
            dns,
            installed_configs: HashMap::new(),
        };
        for svc in services {
            resolver.add_service(svc);
        }
        resolver
    }

    /// Reconcilia el lado INTERCEPT de UN servicio con `status == ZITI_OK`, espejo de
    /// `ziti_sdk_c_on_service` (`ziti-tunnel-sdk-c` v1.15.1 `2addfbb`, `ziti_tunnel_cbs.c:615-649`),
    /// keyed por NOMBRE (`model_map_get(&intercepts, service->name)`, `:622`). Reproduce su tabla de ramas:
    ///  - **sin permiso `Dial`** (`(perm_flags & ZITI_CAN_DIAL) == 0`, `:623`) → PARA el intercept
    ///    anterior si lo había ([`Self::remove_service`], espejo de `stop_intercept` cuando `curr_i`
    ///    existe, `:624-626`). Un evento `Changed` que PIERDE el dial llega por aquí, no como `Removed`.
    ///  - **`Dial` pero sin `intercept.v1` válido** (`new_ziti_intercept` → NULL, `:629`,`:641-644`) →
    ///    CONSERVA el intercept anterior (return sin tocar nada). `Ok(None)` (ausente) y `Err`
    ///    (malformado) se tratan igual — extiende la desviación under-permit ya documentada en el fold
    ///    del snapshot (un config roto no intercepta), aquí también "no reemplaza por un config roto".
    ///  - **`Dial` con `intercept.v1` válido** → REEMPLAZA: para el anterior si lo había (`stop_intercept`
    ///    antes del `model_map_set`, `:632-637`) y construye las entradas nuevas — el MISMO cuerpo
    ///    `addresses × protocols × portRanges` que construía el snapshot (registra hostname/wildcard en `dns`).
    ///
    /// **Gate keep-unchanged (el `compare()==0` del oráculo, IMPLEMENTADO con #5):** cuando el
    /// `intercept.v1` nuevo es idéntico al del intercept INSTALADO para ese nombre
    /// (`cfgtype->compare(&new,&curr)==0` en `new_ziti_intercept` → `have_intercept=false` → NULL →
    /// CONSERVA sin re-instalar, `ziti_tunnel_cbs.c:449-455`+`:641-644`), se conserva sin
    /// reconstruir. ALCANZABLE vía eventos: `service_details_equal` compara el servicio ENTERO
    /// (permissions, `host.v1`, encryption…), así que un `Changed` puede llegar con el
    /// `intercept.v1` intacto — el oráculo entonces NO deregistra/re-registra su DNS (IP sintética
    /// estable); sin este gate, la reconstrucción post-#5 deregistraría y reasignaría (churn que el
    /// oráculo evita; benigno pre-#5, observable después — cazado por la verificación adversarial).
    /// **Desviación consciente DEL COMPARADOR (justificación RE-DERIVADA al cerrar `kill-active`,
    /// revisando también los casos vecinos):** comparamos el JSON CRUDO de
    /// `config["intercept.v1"]`; el oráculo compara el modelo PARSEADO (`cfgtype->compare(&zi_ctx->cfg,
    /// &curr_i->cfg) == 0`, `ziti_tunnel_cbs.c:449` → `have_intercept` sigue false → `:460-463` NULL →
    /// keep-unchanged **sin `stop_intercept`**). Raw-igual ⇒ modelo-igual, y el camino real (el
    /// controller re-sirve el config almacenado) da raw-igual para un config sin cambios.
    ///
    /// El caso divergente es un raw DISTINTO con modelo IGUAL. **Su coste ya no es solo churn de DNS:**
    /// desde `kill-active`, caer al camino REPLACE pone `kill_active = true` y **MATA los flujos vivos
    /// del servicio**, que el oráculo conservaría. La afirmación previa de esta nota ("churn, jamás
    /// over-dispatch") describía el coste PRE-kill-active y se quedó corta.
    ///
    /// Aun así el comparador crudo SE MANTIENE, y la dirección sigue siendo la segura:
    ///  - Es ESTRICTAMENTE más conservador que el del oráculo: cualquier diferencia de bytes ⇒ REPLACE.
    ///    **Jamás puede PASAR POR ALTO un cambio real de config.** Comparar por modelo sería ciego a
    ///    todo campo que `InterceptV1Config` no modele (no lleva `deny_unknown_fields`, y el esquema
    ///    puede crecer): no ver un cambio significa seguir despachando bajo un intercept OBSOLETO — la
    ///    dirección **over-permit**, la única inaceptable.
    ///  - El residual es un kill/churn ESPURIO: servimos de MENOS (under-permit), nunca de más. El
    ///    cliente reconecta y el flujo nuevo despacha bajo el config entrante.
    ///  - Sigue siendo INALCANZABLE con un controller real: `serde_json::Value` compara con igualdad
    ///    independiente del orden de claves y del whitespace (sin `preserve_order`, `Map` es un
    ///    `BTreeMap`), así que solo `null`-vs-ausente o `5`-vs-`5.0` podrían disparar el caso — y un
    ///    controller de esquema fijo no varía eso entre polls de un servicio sin cambios.
    ///
    /// Lado INTERCEPT sólo (el lado HOST/bind del oráculo, `:651-676`, está fuera del arco). Al parar
    /// (lost-dial o REPLACE) libera el estado DNS del config saliente vía [`Self::remove_service`]
    /// (`ziti_dns_deregister_intercept`, #5 eviction CERRADO) — en un REPLACE eso reasigna la IP
    /// sintética de un hostname no compartido (fiel al oráculo, ver [`Self::remove_service`]).
    ///
    /// Devuelve el [`AppliedEvent`] de la mutación: el [`RouteDelta`] (las direcciones literal-CIDR
    /// retiradas/instaladas, espejo de los `delete_route`/`add_route` que
    /// `stop_intercept`/`ziti_tunneler_intercept` harían) y el flag `kill_active` (¿el oráculo habría
    /// llamado `stop_intercept`? — es decir, ¿existía `curr_i`?). El llamante con ciclo de rutas OS
    /// ([`crate::tunnel::intercept::routes::RouteLifecycle`], el runner combinado/`main.rs`) aplica el delta; el que tiene
    /// registro de flujos ([`crate::tunnel::intercept::flows::FlowRegistry`], la rama svc-poll) dispara el kill. Los
    /// llamantes sin ninguno (tests del match) lo ignoran.
    pub fn add_service(&mut self, svc: &Service) -> AppliedEvent {
        // `curr_i != NULL` (`ziti_tunnel_cbs.c:622`): ¿había un intercept INSTALADO para este nombre
        // ANTES de mutar? Se lee AQUÍ porque `remove_service` (abajo) borra el marcador. Es el gate
        // EXACTO de las dos llamadas a `stop_intercept` de `ziti_sdk_c_on_service` (`:624` lost-dial,
        // `:632` REPLACE) y, por tanto, del `tunneler_kill_active` que ambas arrastran.
        let had_installed = self.installed_configs.contains_key(&svc.name);
        // Oráculo: el intercept se registra SOLO para un servicio con permiso `Dial`
        // (`stringz.Contains(perms, "Dial")`, svcpoll.go:191; `ZITI_CAN_DIAL`, ziti_tunnel_cbs.c:623).
        if !svc.permissions.iter().any(|p| p == "Dial") {
            // ZITI_OK + !CAN_DIAL: para el intercept existente (si lo hay). En el fold del snapshot
            // (nombre nuevo) es un no-op; como `Changed` que pierde el dial, lo retira (con sus
            // rutas en el delta, espejo del stop_intercept de `:626`) y MATA sus flujos vivos.
            return AppliedEvent {
                routes: RouteDelta {
                    removed: self.remove_service(&svc.name),
                    added: Vec::new(),
                },
                kill_active: had_installed,
            };
        }
        // Sin `intercept.v1` (→ el oráculo cae a `client.v1`, diferido #4) o malformado (el oráculo
        // log-ea y usa el config medio-decodificado, `svcpoll.go:202`): ambos → `new_ziti_intercept`
        // NULL → CONSERVA el intercept anterior (`:641-644`). No removemos (keep-old). En el fold del
        // snapshot, nombre nuevo → nada que conservar → equivalente al `continue` previo. Saltar un
        // config malformado es una desviación safe-direction (under-permit, esquema `additionalProperties:false`).
        let Ok(Some(cfg)) = intercept_v1_config(svc) else {
            // keep-old: `new_ziti_intercept` → NULL ⇒ el oráculo NO llama `stop_intercept` (`:641-643`)
            // ⇒ tampoco mata nada. El intercept viejo (y sus flujos) siguen vivos.
            return AppliedEvent::default();
        };
        let raw = svc
            .config
            .get(INTERCEPT_V1_CONFIG_TYPE)
            .expect("Ok(Some(_)) de intercept_v1_config garantiza la clave presente");
        // Gate keep-unchanged (`compare()==0`, `:449-455`): el intercept INSTALADO para este nombre
        // tiene el MISMO `intercept.v1` → conservar SIN reconstruir (el oráculo ni deregistra ni
        // re-registra su DNS: IP sintética estable ante un `Changed` de permissions/`host.v1`).
        // Delta VACÍO: el C tampoco toca rutas en este camino (ni stop_intercept ni intercept).
        if self
            .installed_configs
            .get(&svc.name)
            .is_some_and(|installed| installed == raw)
        {
            // keep-unchanged: `compare()==0` → NULL → sin `stop_intercept` ⇒ NINGÚN flujo se toca
            // (el oráculo conserva el intercept Y sus conexiones vivas).
            return AppliedEvent::default();
        }
        // `intercept.v1` válido y DISTINTO del instalado (o nombre nuevo): REEMPLAZA. El oráculo para
        // el `curr_i` (si existe) ANTES del `model_map_set` (`:632-637`); `remove_service` es
        // idempotente (no-op si no había) → replace correcto Y fold seguro (en el snapshot no retira nada).
        let removed = self.remove_service(&svc.name);
        self.installed_configs.insert(svc.name.clone(), raw.clone());
        let dial_timeout = dial_timeout_for(&cfg);
        let allowed_sources = build_allowed_sources(&cfg.allowed_source_addresses);
        // Borrows disjuntos de los campos de construcción (`entries`/`wildcards` = `&mut Vec`,
        // `dns` = `&mut DnsMatcher`), idéntico byte-a-byte al del snapshot previo.
        let InterceptResolver {
            entries,
            wildcards,
            dns,
            ..
        } = self;
        for addr in &cfg.addresses {
            // El gate DEBE espejar `check_name` EXACTO ("*." — el `*` seguido INMEDIATAMENTE de
            // un punto, `dns/`): un `starts_with('*')` más laxo (bug cazado por la revisión
            // reforzada) shuntearía un string como "*foo.com" (SIN punto tras el `*`) a este
            // bloque y tiraría su `RegisterOutcome`, cuando `check_name`/el oráculo lo clasifican
            // como hostname EXACTO — `register` devolvería `Hostname(ip)`, no `Domain`, y ESE caso
            // debe caer al `else` de abajo para construir su entrada `/32`, exactamente como
            // cualquier otro hostname.
            if addr.starts_with("*.") {
                // Dominio wildcard: registrar en el matcher (espejo `ziti_dns_register_hostname`:
                // puebla `domains`, NUNCA asigna IP propia → devuelve NULL, sin entrada IP-match).
                // A nombre de ESTE servicio (el refcount que `remove_service`→`deregister_intercept`
                // libera, #5 eviction).
                let _ = dns.register(addr, &svc.name);
                // Y construir la(s) entrada(s) de dispatch por-dominio (M3-DNS #6,
                // `intercept_match_addr`): una IP que una query DNS asigne LAZY bajo este dominio se
                // despacha a este servicio vía el fallback de `lookup`. Se expande sobre
                // `protocols × portRanges` igual que un CIDR, con el mismo `dialTimeout`/whitelist
                // (el oráculo aplica `protocol_match`/`port_match`/origen al mismo intercept).
                // `wildcard_suffix` reusa el MISMO `check_name` que `register`, así que su sufijo es
                // byte-idéntico al guardado en `domains`/devuelto por `reverse_lookup_domain` — sin
                // él, un desbordamiento (≥256 bytes) que `register` rechaza tampoco produce entrada
                // (`None`), coherente con el `Rejected` de arriba.
                if let Some(suffix) = DnsMatcher::wildcard_suffix(addr) {
                    for proto in &cfg.protocols {
                        for pr in &cfg.port_ranges {
                            wildcards.push(WildcardEntry {
                                suffix: suffix.clone(),
                                low_port: pr.low,
                                high_port: pr.high,
                                protocol: proto.clone(),
                                service: svc.name.clone(),
                                dial_timeout,
                                allowed_sources: allowed_sources.clone(),
                            });
                        }
                    }
                }
                continue;
            }
            let cidr = if let Some(cidr) = parse_ip_or_cidr(addr) {
                cidr
            } else {
                // No es IP/CIDR válido → hostname candidato (la over-permit class de `parse_ip_or_cidr`
                // — leading-zero, leading-sign, zone-id — también cae aquí, pero esos strings
                // tampoco son hostnames válidos de verdad; `DnsMatcher::register` los trata como
                // cualquier string, fail-loud solo en desbordamiento ≥256 bytes). Incluye un `*`
                // SIN punto inmediato (p. ej. "*foo.com"): el oráculo lo registra como hostname
                // LITERAL (`check_name`, sin el gate de arriba), así que aquí también.
                match dns.register(addr, &svc.name) {
                    RegisterOutcome::Hostname(ip) => IpNet::V4(
                        Ipv4Net::new(ip, 32).expect("un /32 sobre cualquier Ipv4Addr es válido"),
                    ),
                    // Rejected (nombre inválido) o IpUnavailable (pool agotado/sin sembrar): sin
                    // entrada, espejo de `intercept_addr_p` quedando NULL.
                    RegisterOutcome::Rejected | RegisterOutcome::IpUnavailable => continue,
                    RegisterOutcome::Domain => {
                        unreachable!(
                            "addr no empieza por \"*.\": check_name no puede devolver is_domain=true"
                        )
                    }
                }
            };
            for proto in &cfg.protocols {
                for pr in &cfg.port_ranges {
                    entries.push(InterceptEntry {
                        cidr,
                        low_port: pr.low,
                        high_port: pr.high,
                        protocol: proto.clone(),
                        service: svc.name.clone(),
                        dial_timeout,
                        allowed_sources: allowed_sources.clone(),
                    });
                }
            }
        }
        // Las direcciones del intercept ENTRANTE (espejo del `add_route` por dirección de
        // `ziti_tunneler_intercept`, `ziti_tunnel.c:428-430`), tras las del SALIENTE (orden del
        // oráculo: `stop_intercept` corre primero). REPLACE: mata los flujos del config SALIENTE si
        // lo había (`:632-635`, `stop_intercept(curr_i)` → kill); alta fresca (`curr_i == NULL`) no
        // mata — y no PUEDE tener flujos, porque `lookup` nunca devolvió el servicio.
        AppliedEvent {
            routes: RouteDelta {
                removed,
                added: literal_addrs(&cfg),
            },
            kill_active: had_installed,
        }
    }

    /// Retira TODO el intercept de un servicio (por nombre): espejo de `stop_intercept`
    /// (`ziti_tunnel_cbs.c:597-602`) menos el kill de flujos activos (abajo). Quita sus entradas
    /// literales y de dispatch wildcard — tras esto [`Self::lookup`] NO puede devolver el servicio
    /// (ni por match literal ni por fallback wildcard) → NINGÚN flujo NUEVO despacha a él (lo
    /// safety-critical) — Y libera su estado DNS ([`DnsMatcher::deregister_intercept`], espejo de
    /// `ziti_dns_deregister_intercept`, `:599`; cerró el deferido #5 eviction): el refcount del
    /// servicio se va de cada entrada y cada dominio; los hostnames que quedan huérfanos se evictan
    /// con su IP sintética (el hueco vuelve al pool) y los dominios sin reclamante se evictan con
    /// sus entradas lazy. Una query posterior bajo un dominio/hostname del servicio retirado →
    /// REFUSED (miss), byte-igual al oráculo.
    ///
    /// Estado compartido sobrevive por refcount, en AMBAS tablas: un dominio wildcard (o un hostname
    /// exacto) reclamado también por OTRO servicio conserva su registro DNS (y sus IPs asignadas), y
    /// la `WildcardEntry`/`InterceptEntry` del otro servicio sigue despachando.
    ///
    /// Devuelve las direcciones literal-CIDR del config INSTALADO que se retira (vacío si no había)
    /// — la lista que `ziti_tunneler_stop_intercepting` recorre con `delete_route`
    /// (`ziti_tunnel.c:500-503`); el llamante con ciclo de rutas la aplica vía
    /// [`crate::tunnel::intercept::routes::RouteLifecycle`].
    ///
    /// **Deferral CERRADO (rebanada `kill-active`):** el oráculo además MATA los flujos ACTIVOS del
    /// servicio retirado (`tunneler_kill_active`, `ziti_tunnel.c:493`/`:510` — cierra las conns ziti
    /// de sus TCP/UDP vivos). Ese kill NO vive aquí (esta fn solo mueve tabla+DNS, como el
    /// `model_map_remove`+`ziti_dns_deregister_intercept` de `stop_intercept`, `:598-599`): lo dispara
    /// el llamante con registro de flujos —la rama svc-poll del runner combinado— leyendo
    /// `AppliedEvent::kill_active` y llamando [`crate::tunnel::intercept::flows::FlowRegistry::kill_service`], espejo del
    /// `ziti_tunneler_stop_intercepting` que `stop_intercept` invoca a continuación (`:600`). Los
    /// llamantes SIN registro (fold del snapshot, tests del match, runners standalone) no matan nada
    /// — y no pueden tener flujos que matar.
    pub fn remove_service(&mut self, name: &str) -> Vec<IpNet> {
        self.entries.retain(|e| e.service != name);
        self.wildcards.retain(|w| w.service != name);
        // Espejo de `stop_intercept` (`:597-599`): retirar el intercept instalado del registro
        // (`model_map_remove(&inst->intercepts, ...)`, `:598` — el marker que alimenta el gate
        // keep-unchanged de `add_service`) y deregistrar su DNS (`:599`). En el camino REPLACE de
        // `add_service` esto corre ANTES del re-registro, así que un hostname cuyo último reclamante
        // era el config saliente se evicta y el re-registro le asigna una IP NUEVA (el contador del
        // pool avanzó) — igual que el oráculo (`ziti_sdk_c_on_service` REPLACE: `stop_intercept`
        // `:634` → `new_intercept_ctx` `:638`).
        let removed = self
            .installed_configs
            .remove(name)
            .as_ref()
            .map(literal_route_addrs)
            .unwrap_or_default();
        self.dns.deregister_intercept(name);
        removed
    }

    /// Aplica un [`ServiceEvent`](crate::edge::services::ServiceEvent) del
    /// [`ServiceWatcher`](crate::edge::services::ServiceWatcher) a la tabla de intercept, reconciliándola
    /// con el cambio — espejo del dispatch por `status` de `ziti_sdk_c_on_service`
    /// (`ziti_tunnel_cbs.c:615-691`), keyed por nombre:
    ///  - `Added`/`Changed` → [`Self::add_service`] (status `ZITI_OK`: el oráculo NO distingue alta de
    ///    cambio — ambos re-evalúan `curr_i` por nombre; `add_service` encapsula la tabla de ramas
    ///    completa: pierde-dial→para, sin-config→conserva, config-válido→reemplaza).
    ///  - `Removed` → [`Self::remove_service`] (status `ZITI_SERVICE_UNAVAILABLE`, `:677-682`).
    ///
    /// Es el PRIMITIVO de reconciliación de la tabla de match, conducido en producción por la rama
    /// svc-poll del runner combinado (`super::combined`). Devuelve el [`AppliedEvent`] del evento: su
    /// [`RouteDelta`] (vacío para keep-old/keep-unchanged/no-op), que el runner aplica a su
    /// [`crate::tunnel::intercept::routes::RouteLifecycle`] — el `delete_route`/`add_route` refcounted que
    /// `stop_intercept`/`ziti_tunneler_intercept` harían —, y su `kill_active`, que dispara el
    /// [`crate::tunnel::intercept::flows::FlowRegistry::kill_service`] de los flujos vivos.
    ///
    /// **`Removed` mata SIEMPRE (desviación consciente DV-1, misma observable).** El oráculo llega al
    /// kill solo si el map tenía el intercept (`:679-681` gatea `stop_intercept` por
    /// `model_map_remove != NULL`); nosotros llamamos incondicional. Sin intercept instalado no puede
    /// haber flujos (se crean vía el intercept instalado, que es lo único que `lookup` devuelve), así
    /// que un `kill_service` de bucket vacío ≡ el no-llamar del oráculo.
    pub fn apply_event(&mut self, ev: &ServiceEvent) -> AppliedEvent {
        match ev {
            ServiceEvent::Added(svc) | ServiceEvent::Changed(svc) => self.add_service(svc),
            ServiceEvent::Removed(svc) => AppliedEvent {
                routes: RouteDelta {
                    removed: self.remove_service(&svc.name),
                    added: Vec::new(),
                },
                kill_active: true,
            },
        }
    }

    /// Las CIDRs de intercept DISTINTAS que cubre algún servicio `intercept.v1` visible, en orden de
    /// primera aparición — la entrada de [`plan_routes`](crate::tunnel::intercept::routes::plan_routes) para un plan de
    /// rutas EN BLOQUE (el e2e root standalone con [`crate::tunnel::intercept::routes::InstalledRoutes`]). El path de
    /// PRODUCCIÓN ya no pasa por aquí: `main.rs` siembra el
    /// [`RouteLifecycle`](crate::tunnel::intercept::routes::RouteLifecycle) refcounted foldeando los [`RouteDelta`]s
    /// por-servicio (rebanada RUTAS OS), que la rama svc-poll conduce en vivo.
    ///
    /// Espejo de las direcciones que el oráculo pasa a `add_route` (`ziti_tunnel.c:428`), pero
    /// COLAPSADAS a un conjunto (un CIDR que N servicios comparten aparece UNA vez — el refcount del
    /// oráculo colapsado, equivalente para un snapshot). Nota: un hostname EXACTO con pool sembrado
    /// SÍ produce su entrada `/32` sintética y aparece aquí; cae dentro de la subred on-link del utun
    /// (el pool se siembra de su CIDR) y `plan_routes` la filtra — mismo efecto que la omisión en
    /// origen de [`RouteDelta`] (ver su doc). Los dominios wildcard no producen entrada IP (su ruteo
    /// es M3-DNS, vía IP sintética on-link).
    #[must_use]
    pub fn intercept_cidrs(&self) -> Vec<IpNet> {
        let mut out: Vec<IpNet> = Vec::new();
        for entry in &self.entries {
            if !out.contains(&entry.cidr) {
                out.push(entry.cidr);
            }
        }
        out
    }
}
