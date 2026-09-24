//! Matcher de hostname/wildcard-domain + pool de IP sintética para direcciones `intercept.v1`
//! (M3-DNS). **Rebanada 1** (`7dad52a`) entregó el matcher puro (`check_name`/`find_domain`/la
//! decisión de `ziti_dns_lookup`), SIN asignar IPs. **Esta rebanada (2ª)** añade el pool circular de
//! IPs sintéticas (`seed_dns`/`next_ipv4`) + el mapa reverso IP→hostname, cerrando los diferidos #1
//! y #2 de la rebanada 1 (ver "Diferidos NOMBRADOS" abajo — el mapa reverso se puebla en el MISMO
//! paso atómico que la asignación en el oráculo, así que pertenece a esta rebanada, no a una futura).
//!
//! ## Oráculo — `ziti-tunnel-sdk-c` (NO `openziti/ziti`; ver por qué abajo), frontera de seguridad
//! Pin `2addfbbae26be597f7a51359ea6ef069f54f6c43` (v1.15.1), `lib/ziti-tunnel-cbs/ziti_dns.c`:
//!   - `check_name` (`:310-334`): normaliza a lowercase + detecta wildcard.
//!   - `find_domain` (`:370-378`): resuelve un hostname normalizado contra el set de dominios.
//!   - `ziti_dns_lookup` (`:380-411`): la decisión de match completa + asignación LAZY de IP para
//!     un match de dominio nuevo (`new_ipv4_entry`, `:395`).
//!   - `ziti_dns_register_hostname` (`:448-484`): clasifica una dirección `intercept.v1`; para un
//!     hostname EXACTO asigna la IP EAGERLY en el registro (`new_ipv4_entry`, `:475`); un dominio
//!     wildcard nunca tiene IP propia.
//!   - `seed_dns`/`next_ipv4` (`:120-179`): siembra el pool desde un CIDR + asigna el próximo
//!     candidato circular libre.
//!   - `new_ipv4_entry` (`:336-352`): crea la entrada (nombre+ip), la inserta en AMBOS mapas
//!     (`hostnames` y `ip_addresses` — el reverso), en el MISMO paso.
//!   - `ziti_dns_reverse_lookup` (`:362-368`): usado por `ziti_tunnel_cbs.c:256` para emitir
//!     `dst_hostname` en el AppData del intercept — el consumidor real del mapa reverso (la EMISIÓN
//!     de `dst_hostname` quedó CERRADA en el slice combinado, `b2c60a2` — ver
//!     `intercept_tcp_appdata`/`intercept_udp_appdata`). `ziti_dns_reverse_lookup_domain` (`:354-360`,
//!     un helper DISTINTO usado en `ziti_tunnel_cbs.c:511-526`) se portó después como
//!     [`DnsMatcher::reverse_lookup_domain`] y su consumidor de producción (el fallback de dispatch
//!     per-paquete de wildcards, #6) quedó cerrado en `0211810`.
//!
//! **Por qué el oráculo C y no el Go de `openziti/ziti` v2.0.0:** `tunnel/dns/dns.go` gatea
//! `NewDnsServer` tras `//go:build !linux` devolviendo `nil, nil` — el DNS embebido del tunneler Go
//! es LINUX-ONLY, inaplicable a nuestro target darwin. `ziti-tunnel-sdk-c` (`ziti-edge-tunnel`) SÍ
//! corre en macOS y es el oráculo de paridad observable de este proyecto (README.md).
//!
//! ## Semántica de match (espejo de `ziti_dns_lookup`)
//! Una query se normaliza con [`crate::tunnel::intercept::dns::normalize::check_name`]; si la normalización desborda (≥256 bytes) O la query
//! EN SÍ tiene forma de wildcard (`*.algo`), se rechaza SIEMPRE — un wildcard nunca es una query DNS
//! real, `ziti_dns.c:383`. Si no, se busca primero un hostname EXACTO registrado (ya tiene IP,
//! asignada al registrar o cacheada de una query anterior); si no hay, se busca un dominio wildcard
//! cuyo sufijo case ([`crate::tunnel::intercept::dns::normalize::find_domain`]) y, si casa, se asigna una IP FRESCA para esta query concreta
//! (cacheada bajo el nombre exacto para queries futuras — mismo comportamiento observable que
//! reencontrarla directamente la próxima vez).
//!
//! **Quirks del oráculo, replicados a propósito (no son bugs nuestros):**
//!   - **Wildcard exige `'*'` seguido INMEDIATAMENTE de `'.'`.** `*foo.com` (sin punto tras el `*`)
//!     NO es un patrón de dominio — se registra/casa como el hostname LITERAL `"*foo.com"`.
//!   - **El dominio DESNUDO casa su propio wildcard.** Si se registra `*.example.com`, una query por
//!     el hostname exacto `example.com` (SIN subdominio) TAMBIÉN casa.
//!   - **Sin longest-match / sin precedencia de especificidad.**
//!   - **La procedencia de una entrada (hostname explícito vs derivada de un dominio) PERSISTE.**
//!     Una vez cacheada vía un match de dominio, queries repetidas de la MISMA query siguen
//!     reportando [`DnsMatchKind::Domain`] (el `entry->domain` del oráculo no se limpia al
//!     reencontrarla por el atajo directo de `hostnames`, `ziti_dns.c:388`) — y si más tarde se
//!     registra la MISMA query explícitamente vía [`DnsMatcher::register`], el oráculo reusa la
//!     entrada existente sin tocar su `domain` (`:473-474`): sigue reportando `Domain`.
//!
//! ## Fidelidad de `check_name` — MÁS correcto que el oráculo, no solo equivalente
//! `to_ascii_lowercase()` reescribe ÚNICAMENTE `'A'..='Z'`; un byte `>= 0x80` nunca se toca, así que
//! el resultado es UTF-8 válido POR CONSTRUCCIÓN, a diferencia de `tolower(*hp++)` sin cast a
//! `unsigned char` del oráculo (UB con `char` signed y el bit alto puesto).
//!
//! **Límite de desbordamiento** (`MAX_DNS_NAME=256`): en la QUERY es un rechazo bien definido y SÍ
//! es target de differential; en el REGISTRO el oráculo se bifurca en dos sub-caminos de
//! determinismo distinto (hostname-plano: valor portable `""` que NO reproducimos a propósito;
//! dominio: UB genuina que NO reproducir es OBLIGATORIO) — ver el test
//! `register_overflow_is_a_safe_deliberate_divergence`.
//!
//! ## Pool de IP sintética (espejo de `seed_dns`+`next_ipv4`, `ziti_dns.c:120-179`)
//! [`crate::tunnel::intercept::dns::pool::IpPool`] es un asignador circular: siembra desde un CIDR IPv4 (`base`, `counter_mask` =
//! máscara de los bits de host, `capacity` = `2^host_bits - 2` restando red y broadcast) y escanea
//! como mucho `capacity` candidatos por llamada, saltando los ya ocupados (`is_occupied`),
//! envolviendo el contador ANTES de alcanzar el valor de broadcast (nunca produce host-bits=0 ni
//! host-bits=todo-unos). Differential-verificado contra un puerto verbatim de ambas funciones
//! (`model_map` sustituido por un array lineal, mismo patrón que la rebanada 1) para el llenado
//! secuencial: exhaustion boundary desde vacío (`/29`), collision-skip, secuencia `/28` completa —
//! ver los tests de este módulo. **NO** cubre el caso de un hueco encontrado exactamente en el
//! último intento de una vuelta de escaneo — ver la divergencia consciente de `next_ipv4` abajo,
//! que ese caso SÍ dispara.
//!
//! **Divergencia consciente en `next_ipv4` (bug del oráculo, NO reproducido a propósito):** el
//! oráculo descarta un candidato LEGÍTIMAMENTE libre si lo encuentra exactamente en el intento
//! `capacity`-ésimo del escaneo: el `do-while` (`ziti_dns.c:130-136`) sale del bucle en cuanto
//! `candidate` está libre, pero el chequeo posterior `if (i == ziti_dns.ip_pool.capacity) return
//! INADDR_NONE;` (`:138`) dispara por CONTEO de intentos, no por si el bucle salió por
//! agotamiento genuino o por un match válido tardío — así que un hueco único que quede exactamente
//! a `capacity` pasos del contador actual se descarta (`INADDR_NONE`) aunque esté libre. El propio
//! comentario del oráculo en `:122` ("should never exceed pool capacity") confirma que el autor NO
//! anticipó este caso — es un bug, no una elección deliberada, así que reproducirlo sería heredar
//! UB observacional sin valor de fidelidad. [`crate::tunnel::intercept::dns::pool::IpPool::allocate`] devuelve el candidato en cuanto lo
//! encuentra libre, sin importar en qué intento — ver
//! `ip_pool_finds_a_hole_on_the_last_scan_try_where_the_oracle_would_discard_it` (differential
//! empírico contra el mismo harness C usado arriba, pineando la divergencia). **Actualizado tras el
//! wiring (rebanada 3, [`DnsMatcher::reserve`]):** el hueco YA NO se encuentra siempre en el intento
//! 1 — `main.rs::seed_and_reserve_dns_pool` reserva 2 direcciones (utun + utun+1) ANTES de cualquier
//! registro, así que el primer hostname real necesita hasta 3 intentos (ver el test
//! `seed_and_reserve_dns_pool_reserves_utun_addr_and_utun_addr_plus_one` en `main.rs`). El bug del
//! oráculo SIGUE inalcanzable: `reserve()` nunca avanza el contador y el único sitio de producción
//! reserva SIEMPRE antes de registrar, así que el ocupado sigue siendo un prefijo contiguo {1..N}
//! más el bloque fijo de 2 reservas — muy por debajo de `capacity` para cualquier CIDR razonable. La
//! conclusión de seguridad se mantiene; solo cambió el motivo concreto del "por qué" (antes: nada
//! reservaba fuera del contador; ahora: lo reservado es un bloque acotado y siempre-antes-de-registrar).
//! **También alcanzable HOY llamando [`DnsMatcher::seed_pool`] dos veces** sobre el mismo matcher
//! (resetea el contador sin limpiar `ip_addresses`): es un mal uso de la API, no un camino de
//! producción, pero real — no reseeds un matcher ya poblado en código nuevo.
//!
//! **Divergencia consciente en `seed_dns` (config LOCAL del operador, no entrada de red):**
//! `/0` y `/32` hacen que la aritmética `uint32` del oráculo (`(uint32_t)-1 << (32-bits)` con
//! `bits=0`, o `capacity=(1<<0)-2` que envuelve a un valor gigantesco con `bits=32`) sea UB o
//! sin sentido observable; [`crate::tunnel::intercept::dns::pool::IpPool::seed`] las rechaza fail-loud en vez de reproducirlas. `/31` SÍ
//! es válido (capacity=0, pool inmediatamente agotado — comportamiento REAL del oráculo, no UB, no
//! rechazado). El parseo del CIDR reusa el crate `ipnet` (ya dependencia del proyecto, ver
//! `routes/`) en vez de un `sscanf` a mano; con la versión fijada (`ipnet` 2.x, ver `Cargo.lock`)
//! NO se ha encontrado divergencia observable frente a `sscanf("%d...")` (ambos aceptan octetos y
//! longitud de prefijo con ceros a la izquierda como decimal) — reusar un crate battle-tested en
//! vez de un parser a mano sigue siendo la elección correcta, simplemente no hay una divergencia
//! conocida que documentar aquí.
//!
//! ## Diferidos NOMBRADOS (no silenciosos — cada uno cierra en una rebanada posterior de M3-DNS)
//!  1. ~~Pool de IP sintética~~ — CERRADO en esta rebanada.
//!  2. ~~Mapa reverso IP→hostname~~ — CERRADO en esta rebanada ([`DnsMatcher::reverse_lookup`]).
//!  3. ~~Wiring contra [`super::resolve::InterceptResolver`]/`from_services`+`main.rs`~~ — CERRADO
//!     en la 3ª rebanada (`from_services_with_dns` + `main.rs::seed_and_reserve_dns_pool`): un
//!     hostname exacto con pool sembrado produce una entrada `/32` dispatchable; un dominio wildcard
//!     NUNCA produce entrada `/32` propia por diseño (la IP se asigna per-query y la despacha el
//!     fallback per-paquete — el diferido #6 de abajo, ya CERRADO en `0211810`).
//!  4. ~~**Servidor de protocolo de cable UDP:53** (parseo/serialización de mensajes DNS
//!     reales)~~ — CERRADO en la 4ª rebanada (`5c367fd`, [`super::dns_server`]) y MONTADO en
//!     producción por el subcomando combinado ([`super::combined::run_combined_intercept`]).
//!  5. ~~**Ciclo activo/inactivo de `intercepts` por entrada** (`ziti_dns_deregister_intercept`,
//!     `:414-446`)~~ — CERRADO en la rebanada #5 eviction: [`DnsMatcher::register`] refcuenta
//!     registros por-intercept (por NOMBRE de servicio) en cada entrada y cada dominio, y
//!     [`DnsMatcher::deregister_intercept`] espeja las tres pasadas del oráculo, liberando
//!     entrada+IP cuando el último intercept se va (el hueco vuelve a ser asignable — el asignador
//!     revisa el mapa reverso EN VIVO en cada llamada, sin cambios). El consumidor de producción es
//!     [`super::resolve::InterceptResolver::remove_service`] (los tres caminos de `stop_intercept`:
//!     lost-dial, REPLACE, Removed).
//!  6. ~~**Dispatch per-paquete de wildcards** (`intercept_match_addr`,
//!     `ziti_tunnel_cbs.c:510-526`)~~ — CERRADO en la 5ª rebanada (`0211810`): el fallback de
//!     [`super::resolve::InterceptResolver::lookup`] consulta [`DnsMatcher::reverse_lookup_domain`]
//!     y casa contra las `WildcardEntry` per-servicio (`suffix_matches` = `ziti_address_match`,
//!     differential C 19 casos), y el subcomando combinado lo hace alcanzable por un cliente real.
//!  7. **Live e2e**: innecesario para ESTE slice — es puro, sin I/O, sin wire nuevo
//!     (regla de validación en vivo: solo exige vivo una reconstrucción de wire nueva).

mod matcher;
mod normalize;
mod pool;
mod types;

#[cfg(test)]
mod tests_eviction;
#[cfg(test)]
mod tests_matcher;
#[cfg(test)]
mod tests_pool;
#[cfg(test)]
mod tests_register_lookup;
#[cfg(test)]
mod tests_reserve;
#[cfg(test)]
mod tests_reverse_and_matches;
#[cfg(test)]
mod testsupport;

pub use matcher::DnsMatcher;
pub use types::{DnsMatch, DnsMatchKind, RegisterOutcome};
