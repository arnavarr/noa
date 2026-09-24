//! Servidor DNS embebido (M3-DNS, rebanada 4): el protocolo de CABLE UDP:53 sobre el
//! [`crate::tunnel::intercept::dns::DnsMatcher`] — parsea una query DNS real, la resuelve contra los hostnames/dominios
//! registrados por `intercept.v1`, y serializa la respuesta byte-fiel al oráculo. Cierra el
//! diferido #4 de [`super::dns`]: con esto, un cliente REAL puede resolver un hostname
//! interceptado a su IP sintética. Un hostname EXACTO resuelve a su `/32` ya dispatchable
//! (694366e) = end-to-end completo; una query bajo un dominio wildcard ASIGNA una IP sintética
//! que el dispatch per-paquete (diferido #6, `intercept_match_addr`, CERRADO en `0211810`)
//! despacha vía el fallback de [`super::resolve::InterceptResolver::lookup`]; el subcomando
//! combinado ([`super::combined::run_combined_intercept`]) monta este server en producción.
//!
//! ## Oráculo — `ziti-tunnel-sdk-c` pin `2addfbbae26be597f7a51359ea6ef069f54f6c43` (v1.15.1)
//!  - `lib/ziti-tunnel-cbs/dns_msg.c` `parse_dns_req`/`parse_dns_q` (`:20-68`): el parseo del
//!    request (id/flags/qdcount + UNA pregunta labels→dotted).
//!  - `lib/ziti-tunnel-cbs/ziti_dns.c` `on_dns_req` (`:787-848`): el routing por tipo de query;
//!    `process_host_req` (`:648-674`): A/AAAA contra `ziti_dns_lookup` (nuestro
//!    [`crate::tunnel::intercept::dns::DnsMatcher::lookup`]); `format_resp` (`:533-646`): el serializador de la respuesta;
//!    `query_upstream` (`:850-868`): sin upstream configurado (o con RD=0) devuelve `DNS_REFUSE`;
//!    con upstream activo y RD=1 reenvía el request al/los upstream (`:853-865`), M3-DNS #1.
//!  - `include/ziti/ziti_dns.h:24-29`: los rcodes (`NO_ERROR=0 FORMERR=1 SERVFAIL=2 NXDOMAIN=3
//!    NOT_IMPL=4 REFUSE=5`). El oráculo NUNCA emite NXDOMAIN: un nombre no registrado es REFUSE
//!    (vía el fallo de `query_upstream`), y lo replicamos.
//!
//! En el oráculo el servidor NO es un socket del SO: es un intercept más del tunneler
//! (`ziti_dns_setup`, `ziti_dns.c:185-192`) — dirección = la IP del resolver (`tun_ip+1`,
//! reservada por `main.rs::seed_and_reserve_dns_pool` desde la rebanada anterior), puerto 53,
//! SOLO protocolo `udp`, con callbacks propios en vez de un dial al overlay. Nuestro espejo del
//! seam es idéntico: el manager UDP de [`super::udp`] desvía los datagramas a `(dns_ip, 53)`
//! hacia [`handle_query`] en vez de resolver→dial (ver `run_udp_intercept_with_dns`).
//!
//! ## Semántica observable (las respuestas LOCALES son SÍNCRONAS; las completions ASÍNCRONAS son
//! DOS, servidas por el manager UDP: el forward a upstream — M3-DNS #1, `DnsAction::ForwardUpstream`
//! — y el proxy-resolve por el overlay — M3-DNS #2, `DnsAction::ForwardProxy`)
//!  - **A / AAAA** → [`crate::tunnel::intercept::dns::DnsMatcher::lookup`] (que puede ASIGNAR una IP fresca para un match de
//!    dominio wildcard — también en una query AAAA, espejo de `ziti_dns_lookup` siendo agnóstico
//!    al tipo): hit → `NOERROR` (con UN registro A de TTL 60 si la query era A; SIN registros si
//!    era AAAA — "el nombre existe, no tiene AAAA"); miss → `REFUSED` sin upstream (el
//!    `query_upstream` de un tunneler SIN upstream, `:867`), o `ForwardUpstream` con upstream + RD=1.
//!  - **Otros tipos** → el gate [`crate::tunnel::intercept::dns::DnsMatcher::matched_domain`]: sin dominio que case → `REFUSED`
//!    sin upstream (o `ForwardUpstream` con upstream + RD=1, `on_dns_req:836-843`); CON dominio →
//!    PROXY-RESOLVE por el overlay (`proxy_domain_req`: JSON de `dns_message` sobre una conexión
//!    ziti por-dominio) — **CABLEADO** (M3-DNS #2, [`super::proxy_resolve`]), NUNCA a upstream.
//!    Con `proxy_available` (producción — intrínseco al server embebido, como en el oráculo):
//!    MX/SRV/TXT → [`DnsAction::ForwardProxy`] (el manager asegura la conn del dominio, encola el
//!    JSON y completa async: answers del peer injertados con el status DEL REQUEST — el del peer
//!    se IGNORA, `on_proxy_data:704-710` —, o `SERVFAIL` si el write/dial falla,
//!    `on_proxy_write:736-741`); el resto → [`DnsAction::RespondAndConnectProxy`] (`NOT_IMPL`
//!    síncrono `:779-780` + la conn del dominio iniciada igual — el oráculo dial-ea ANTES del gate
//!    de tipo, `:748-753`). Con `proxy_available == false` (el modo pineado pre-#2, que conservan
//!    el ground truth de 32 casos y los tests): los rcodes del State-B-fail — `SERVFAIL` para
//!    MX/SRV/TXT (`:738`) y `NOT_IMPL` para el resto (`:779-780`) — byte-idénticos a antes.
//!  - **Parse inválido** → el paquete se DESCARTA sin respuesta (espejo del `parse_dns_req != 0`
//!    de `on_dns_req:807-813`, que cierra el cliente sin responder).
//!
//! ## Divergencias conscientes (fail-closed donde el oráculo es UB — norma de la casa)
//! El parser del oráculo NO comprueba límites: un paquete de <12 bytes, una pregunta truncada,
//! un byte de longitud de label que sale del paquete, o un datagrama de >4096 bytes (el
//! `memcpy(req->req, q_packet, q_len)` sobre `req[4096]` sin check, `ziti_dns.c:805`) leen o
//! escriben fuera de rango (UB). Todos esos caminos aquí → [`DnsAction::Drop`] limpio. Igual con
//! **clase ≠ IN**: `parse_dns_q` devuelve `-1` pero `parse_dns_req` IGNORA ese retorno
//! (`dns_msg.c:64`), dejando `name=NULL/type=0` que el routing deref-ea (`check_name(NULL)` →
//! crash) — aquí Drop. Un byte de longitud con pinta de puntero de compresión (`0xC0..`) DENTRO
//! del paquete NO es UB en el oráculo (lo trata como longitud literal, determinista) y se
//! replica tal cual; solo el que SALE del paquete se convierte en Drop.
//!
//! **Nombre de la query — corte en NUL (byte-fiel) + residual non-UTF-8 (under-permit consciente).**
//! El oráculo casa el nombre como un C-string: `check_name` copia `while (*hp != '\0')`
//! (`ziti_dns.c:324`), es decir TRUNCA en el primer `0x00` embebido en un label. [`handle_query`]
//! replica ese corte (usa `q.name[..name_strlen]`, no el nombre completo) — SIN él, un label con un
//! NUL embebido (`app\0.svc.example.com`) haría que `find_domain` casara el sufijo y asignara una IP
//! que el oráculo REFUSE (un OVER-PERMIT; la revisión reforzada lo cazó). Tras el corte, el único
//! residuo es un nombre con un byte **no-UTF8** en un label a la IZQUIERDA de un sufijo de dominio
//! ASCII registrado (`\xff.svc.example.com`): el `find_domain` del oráculo casa el sufijo ASCII y
//! asigna una IP; nosotros hacemos `str::from_utf8().ok()` sobre el nombre cortado y, al fallar, lo
//! saltamos → REFUSE. Es un **UNDER-PERMIT consciente y seguro** (nunca asignamos una IP que el
//! oráculo no asignaría; a lo sumo REHUSAMOS una que sí — en el oráculo ese flujo hoy completaría
//! e2e, #6 cerrado en `0211810`; en el nuestro falla ANTES, en la resolución DNS: under-permit,
//! nunca over-permit): un nombre DNS con un byte no-UTF8 no lo emite ningún resolver conforme
//! (los nombres reales son ASCII/punycode). Cerrarlo del todo exigiría un matcher con claves
//! `Vec<u8>` (el oráculo cachea el nombre crudo no-UTF8) — una re-arquitectura del matcher
//! byte-exacto de las rebanadas 1-2; se difiere como divergencia nombrada, no un hueco silencioso.
//!
//! ## Diferidos NOMBRADOS (cada uno con su rcode/efecto observable pinneado arriba)
//!  1. ~~**Forwarding a upstream DNS**~~ — CERRADO por M3-DNS-upstream: [`handle_query`] toma
//!     `upstream_available` y produce [`DnsAction::ForwardUpstream`] para un miss recursivo
//!     (`query_upstream`, `ziti_dns.c:850-868`); el manager UDP ([`super::udp::UpstreamDns`]) posee
//!     el socket, reenvía verbatim, dedup-ea por ID (cierra el #3 de abajo) y hace passthrough de la
//!     respuesta (`on_upstream_packet`). Sin upstream el comportamiento es byte-idéntico al de antes
//!     (miss → REFUSED, RA nunca); con upstream el bit RA se pone en TODA respuesta local
//!     (`format_resp:539-542`) y RD gobierna el forward (`:853`).
//!  2. ~~**Proxy-resolve por el overlay para MX/SRV/TXT bajo un dominio**~~ — CERRADO por M3-DNS
//!     #2 ([`super::proxy_resolve`]): `proxy_domain_req` + `intercept_resolve_connect` (dial con
//!     `RESOLVE_APP_DATA`) + el protocolo JSON de `dns_message` en ambas direcciones, con conn
//!     por-dominio cacheada y completions asíncronas por id. Ver el routing arriba y el doc del
//!     módulo nuevo (divergencias fail-closed del parser del peer incluidas).
//!  3. **Dedup de requests en vuelo** (`ziti_dns.requests`, `on_dns_req:792-799`) — PARCIAL junto
//!     al #1 y al #2, con una divergencia consciente nombrada: las DOS completions asíncronas
//!     (upstream y proxy) tienen SU mapa de pending y dedupan por ID dentro de su camino (un ID en
//!     vuelo hacia upstream no se re-reenvía; uno en vuelo hacia el proxy se descarta en silencio).
//!     Pero el oráculo dedupa TODO request por ID al ENTRAR (`:792-799`, UN mapa global poblado
//!     ANTES de rutar), descartando una 2ª query con un ID en vuelo aunque resolvería LOCAL (o por
//!     el OTRO camino async); nosotros respondemos esa 2ª query local (benigno/más correcto; ver el
//!     doc de `UpstreamDns::forward`) y un MISMO id en vuelo por ambos caminos a la vez produciría
//!     dos respuestas donde el oráculo produce una (colisión de id cross-camino, benigna — el stub
//!     casa por id y descarta la sobrante). Las respuestas LOCALES siguen síncronas (nunca entran
//!     a los mapas). Un retransmit tras la respuesta se re-reenvía, igual que el oráculo (el id ya
//!     salió del mapa).
//!  4. **DNS sobre TCP**: el intercept del oráculo registra SOLO `udp` (`ziti_dns.c:190`); el
//!     campo `is_tcp` de `ziti_dns_client_t` está declarado pero jamás se escribe en este path
//!     (vestigial) — no es un diferido nuestro, es paridad.

mod parser;
mod router;
mod serializer;
mod types;

#[cfg(test)]
mod tests_domain_assign;
#[cfg(test)]
mod tests_parse_and_ground_truth;
#[cfg(test)]
mod tests_proxy_route;
#[cfg(test)]
mod tests_shape;
#[cfg(test)]
mod tests_upstream;
#[cfg(test)]
mod testsupport;

#[cfg(test)]
pub(crate) use parser::parsed_query_parts;
pub use router::handle_query;
pub(crate) use serializer::format_resp_answers;
pub(crate) use types::{DNS_NO_ERROR, DNS_SERVFAIL, RespAnswer};
pub use types::{DnsAction, ProxyQuery};
