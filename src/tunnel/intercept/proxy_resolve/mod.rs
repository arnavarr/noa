//! M3-DNS #2: PROXY-RESOLVE por el overlay — una query MX/SRV/TXT bajo un dominio wildcard
//! interceptado se resuelve preguntando al endpoint que HOSTEA el servicio, por una conexión ziti
//! dedicada por-dominio, con el protocolo JSON de `dns_message`. Cierra el diferido #2 de
//! [`super::dns_server`].
//!
//! ## Oráculo — `ziti-tunnel-sdk-c` pin `2addfbbae26be597f7a51359ea6ef069f54f6c43` (v1.15.1)
//!  - `ziti_dns.c` `proxy_domain_req` (`:747-785`): el routing — dial LAZY de la conn por-dominio
//!    (CUALQUIER tipo no-A/AAAA bajo dominio lo dispara), MX/SRV/TXT escriben el JSON del request y
//!    difieren la completion; el resto responde `NOT_IMPL` síncrono (`:779-780`); State A
//!    (`resolv_proxy == NULL` tras quick-fail del dial) → `SERVFAIL` (`:755-756`).
//!  - `ziti_tunnel_cbs.c` `intercept_resolve_connect` (`:725-742`): el dial =
//!    `ziti_dial_with_options(service_name, app_data = RESOLVE_APP_DATA)` — appData LITERAL
//!    `{"connType":"resolver"}` (NO el mapa `dst_*` de host.v1); el servicio = el PRIMER intercept
//!    del `domain->intercepts` ([`super::resolve::InterceptResolver::proxy_service`]).
//!  - `ziti_dns.c` `on_proxy_connect`/`proxy_domain_close_cb` (`:676-692`): la conn se CACHEA en el
//!    dominio y se REUTILIZA entre requests; al morir se resetea a NULL → el siguiente request
//!    re-dial-ea. `on_proxy_write` (`:732-745`): un write fallido (async) completa ESE request con
//!    `SERVFAIL` y cierra la conn. `on_proxy_data` (`:694-717`): una respuesta se parsea del JSON,
//!    casa el request pendiente por `id` contra el mapa global (`ziti_dns.requests`) e INJERTA SOLO
//!    `msg.answer` — el `status` del peer se IGNORA (el del request sigue 0 → una respuesta REFUSED
//!    del peer sale hacia el stub como NOERROR sin registros, quirk pineado); error de conn → close
//!    (los pendientes ya escritos quedan sin respuesta — el cliente reintenta/expira).
//!  - `dns_host.h` `DNS_MSG_MODEL` + `model_support` (ziti-sdk-c; writers de `to_json` IDÉNTICOS en
//!    1.15.0 y 1.16.0, verificado por diff): el JSON del request se emite COMPACTO
//!    (`dns_message_to_json(&msg, MODEL_JSON_COMPACT)`, `:761`) con orden de campos del modelo
//!    (`status,id,recursive,question[{name,type}]` — los `model_number` SIEMPRE presentes aunque 0,
//!    strings/arrays NULL omitidos) y el escaper C (`\n \b \r \t \\ \"` + control → `\u00xx`
//!    minúscula + el RESTO de bytes VERBATIM, no-UTF8 incluido; corta en NUL). El peer
//!    (`dns_host.c` `on_dns_req:244-267`) responde el MISMO mensaje mutado (status + answer[])
//!    re-serializado con `flags = 0` (pretty) — nuestro parser es tolerante a whitespace.
//!
//! ## Espejo async (tokio) del modelo de callbacks del oráculo
//! El MANAGER ([`ProxyDns`], vive en el loop UDP de [`super::udp`]) es el dueño ÚNICO del estado
//! (conns por-dominio + pendientes por-id, espejo de `domain->resolv_proxy` + `ziti_dns.requests`)
//! y todas sus operaciones son SÍNCRONAS/no-bloqueantes (el manager JAMÁS se aparca — el invariante
//! HOL del loop). Cada dominio corre una TASK (`spawn_local`, dial `!Send`) que posee la conn: los
//! requests le llegan por un canal de jobs (espejo de `ziti_write` encolando en una conn
//! Connecting) y las respuestas/fallos vuelven al manager como [`ProxyEvent`]s por un canal de
//! eventos (rama propia del `select!` del loop). La task muere con la conn (dial fallido, write
//! fallido, EOF o error de lectura) marcando `closed`: el siguiente request la evicta y re-dial-ea
//! — el estado estable del oráculo tras `proxy_domain_close_cb` (la ventana transitoria
//! "cerrándose pero no-NULL" del oráculo, donde un write síncrono fallaría con una respuesta
//! NOERROR-vacía, aquí es inalcanzable: divergencia consciente benigna, `closed` es atómico).
//! State A (quick-fail síncrono del dial) tampoco existe aquí (el dial es async): su observable
//! (SERVFAIL) lo produce el MISMO rcode vía [`ProxyEvent::WriteFailed`] — camino async que el
//! oráculo también tiene (`on_proxy_write`). **Salvedad (divergencia nombrada) para los tipos que
//! el proxy NUNCA sirve** (no-A/AAAA y no-MX/SRV/TXT, p. ej. PTR/CNAME): en State A el oráculo
//! responde SERVFAIL a TODO tipo bajo dominio, porque el `if (resolv_proxy == NULL) { SERVFAIL }`
//! (`ziti_dns.c:755-756`) PRECEDE al gate de tipo; nosotros ya respondimos NOT_IMPL síncrono
//! ([`super::dns_server::DnsAction::RespondAndConnectProxy`]) ANTES de saber si el dial quick-falla
//! (nuestro dial es async, no puede consultarse síncronamente). Así que para esos tipos, bajo un
//! dial fallido, el rcode diverge (NOT_IMPL vs SERVFAIL). Ambos son fallo para el stub; la ventana
//! (identidad deshabilitada / sesión inválida ANTES del deregister de intercepts) es estrechísima.
//! Divergencia consciente async-vs-sync.
//!
//! ## Divergencias conscientes (nombradas)
//!  - **Pendientes con TTL** ([`PROXY_PENDING_TIMEOUT`]): el oráculo liga la vida del request al
//!    cliente DNS (idle 5s, `on_dns_client`, `ziti_dns.c:285`; `on_dns_close` los limpia). No
//!    modelamos ese ciclo (connectionless sobre netstack) → TTL de 5s barrido en el reap tick,
//!    misma clase que el pending de upstream (M3-DNS #1). Un pendiente expirado NO responde nada
//!    (como el oráculo cuando el proxy nunca contesta).
//!  - **JSON de respuesta malformado → DROP del chunk = PARIDAD con el oráculo** (conn viva): el
//!    peer devuelve rc<0, `on_proxy_data` propaga ese rc<0 (`ziti_dns.c:698-702`) y el SDK, en
//!    `flush_to_client` (`connect.c:896-911`), YA avanzó el buffer con `buffer_get_next` (`:898`,
//!    `buffer.c`) y el camino `consumed < 0` hace WARN + `break` SIN `buffer_push_back` (el
//!    push-back solo está en la rama `consumed < chunk_len` NO-negativa, `:906-907`) → el chunk
//!    malformado queda CONSUMIDO/descartado y las respuestas siguientes se entregan en el próximo
//!    flush. Es EXACTAMENTE nuestro parse→`None`→drop; la única diferencia residual es que el
//!    oráculo además CORTA el round de flush en curso (una micro-latencia, no un wedge). (Nota:
//!    una versión previa de este doc afirmaba erróneamente un "wedge" — corregido por la review.)
//!  - **Parser MÁS ESTRICTO que json-c en 4 clases → DROP donde el oráculo COMPLETA** (fail-closed,
//!    no alcanzable con un peer conforme — `dns_host.c` emite un JSON por `ziti_write`, números y
//!    strings planos, sin duplicados): (a) **bytes tras el primer valor** (`{…}basura` o `{…}{…}`):
//!    `model_parse` usa `json_tokener_parse_ex` + `get_parse_end` y IGNORA el resto
//!    (`model_support.c:193-215`); serde da `trailing characters` → drop. (b) **`null` en un campo
//!    numérico**: el oráculo lo SALTA (`json_type_null → continue`, `:644`) y completa; serde
//!    rechaza. (c) **claves DUPLICADAS**: json-c es last-wins; serde da `duplicate field`. (d)
//!    **entero en `(INT64_MAX, UINT64_MAX]`**: json-c 0.18 lo guarda como uint64 y
//!    `json_object_get_int64` lo CLAMPA a `INT64_MAX` (→ `uint16_t id` = 0xFFFF); serde rechaza
//!    `expected i64`. En los 4 el oráculo entrega respuesta y nosotros no (el cliente reexpira):
//!    fail-closed benigno, replicarlos exigiría un parser a medida que no paga un peer no-conforme.
//!    (El caso `float` en un campo numérico NO diverge: ambos rechazan.)
//!  - **Answer MX/SRV/TXT sin `data` → DROP del mensaje** (fail-closed): el oráculo haría
//!    `strlen(NULL)` (crash, UB). **`data`/JSON no-UTF8 → DROP**: serde exige UTF-8 (json-c es
//!    laxo); un TXT binario real es rarísimo y el fallo es no-completion, nunca over-emit.
//!  - **Type-mismatch en un campo del modelo → DROP = PARIDAD**: se declaran TODOS los campos de
//!    `DNS_MSG_MODEL`/`DNS_A_MODEL` en [`WireMsg`](crate::tunnel::intercept::proxy_resolve::codec::WireMsg)/[`WireAnswer`](crate::tunnel::intercept::proxy_resolve::codec::WireAnswer) para que serde rechace un
//!    type-mismatch en cualquiera (no solo `id`/`answer`), espejo del `if (rc != 0) break` de
//!    `model_from_json` (`:673`) — sin esto COMPLETARÍAMOS un mensaje que el oráculo descarta (un
//!    over-emit, cazado por la review reforzada). Ver el doc de [`WireMsg`](crate::tunnel::intercept::proxy_resolve::codec::WireMsg).
//!  - **HOL dentro de la task de conn** (misma clase que el HOL del path UDP, el HOL-coupling
//!    documentado en `pump_ziti_to_udp`, `intercept/udp/pump.rs`):
//!    mientras la task espera un `zw.write(&json).await` no polea `zr.read()`, así que las
//!    respuestas del peer se acumulan en la cola por-conn del canal edge (cap 4) y, al llenarse, el
//!    `rx_loop` COMPARTIDO del canal se aparca en su `send` con backpressure — congelando el
//!    dispatch de Data del canal (otros splices/vconns/dominios) hasta que el write complete. El
//!    oráculo no serializa (`ziti_write` encola y retorna, `on_proxy_data` dispara independiente en
//!    el uv-loop). Sin pérdida ni deadlock (el write completa por el kernel, y la latency-probe
//!    cerraría un canal starveado); es la degradación canal-wide ya diferida como clase para el
//!    path UDP, no una race del manager. Cerrarla exigiría mover los writes a una sub-task por-conn
//!    (deferral de fidelidad nombrado).
//!  - **Dedup por-camino, no global**: el mapa de pendientes del proxy es propio (como el de
//!    upstream) — el oráculo dedupa TODO request por id en UN mapa global al entrar
//!    (`on_dns_req:792-799`). Misma divergencia nombrada (benigna/más correcta) que M3-DNS #1.

mod codec;
mod manager;
mod task;

#[cfg(test)]
mod tests_codec;
#[cfg(test)]
mod tests_manager;

// `PeerResponse` no lo NOMBRA nadie (los consumidores toman el valor de `parse_peer_response` por
// inferencia), pero es el tipo de RETORNO de un ítem `pub(crate)` y el monolito lo hacía alcanzable
// como `proxy_resolve::PeerResponse`: el re-export preserva esa superficie, no la amplía.
#[allow(unused_imports)]
pub(crate) use codec::{PeerResponse, emit_dns_message_json, parse_peer_response};
pub(crate) use manager::{PROXY_PENDING_TIMEOUT, ProxyDns, ProxyEvent};
pub(crate) use task::RESOLVE_APP_DATA;
