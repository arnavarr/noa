//! Apertura del canal binario V2 al edge router. Oráculo: sdk-golang ziti.go connectEdgeRouter.
//! mTLS (id.cert/key/ca) + Hello con header 1002 = token de api-session + body = CN del leaf.
//!
//! Slice 10c añade el **race paralelo de routers en el camino de connect**: en vez de coger SOLO
//! el primer router `tls`, el connect abre el canal a TODOS los routers `tls` de la sesión en
//! paralelo y se queda con el primero que completa el handshake (failover real). La slice pool-first
//! envuelve esto en `open_or_reuse_pooled_channel`, que primero REUSA un canal ya en el pool
//! (`channel_pool`, keyed por dirección de router) y solo razea/abre en un miss, cacheando el
//! ganador. El camino de `bind` sigue usando `open_channel` (primer-router, sin pool — desviación
//! consciente). Oráculo del pool+fan-out: `ziti/ziti.go` `getEdgeRouterConn` (:1664-1733).
//!
//! **REGISTRO histórico de la slice 4c** (el conjunto VIVO de sitios lo mantiene el bloque
//! DV-4c-FILTER-SITES de abajo, sede ÚNICA): la slice 4c añadió (a) el
//! [`EdgeRouterUrlFilter`](crate::edge::router_filter::EdgeRouterUrlFilter) (`options.go:47`) a los sitios de enumeración de urls
//! de router que TENÍAN camino equivalente aquí — el conjunto del dial ([`tls_addrs`](open::tls_addrs), oráculo
//! `ziti.go:1710`) y la elección del primer router del bind ([`EdgeClient::open_channel`](crate::edge::client::EdgeClient::open_channel), oráculo
//! `ziti.go:2529`) — y (b) el **fan-out del dial TAMBIÉN en el cache-HIT** (ver
//! [`EdgeClient::open_or_reuse_pooled_channel`](crate::edge::client::EdgeClient::open_or_reuse_pooled_channel)): el oráculo lanza el fan-out sobre los routers NO
//! conectados **incondicionalmente y ANTES** del return por hit (`:1708-1714` ≺ `:1716`).
//!
//! # DV-4c-FILTER-SITES — el oráculo consulta el filtro en CINCO sitios; portamos los TRES que existen aquí
//!
//! ⚠ El cardinal **TRES** es de SITIOS DEL ORÁCULO portados y no se mueve; lo que sí cambió con la
//! rebanada `l3-listener-loop-scan` es que **uno de ellos, `:2529`, tiene DOS sedes en el puerto**
//! (ver abajo y el residuo T-13 de su spec).
//!
//! `git grep -n isEdgeRouterUrlAccepted 4b6a087` → `:845` (pre-warm del tick), `:1237`
//! (`ConnectAllAvailableErs`), `:1710` (fan-out del dial), `:2436` (`getUsableRouterCount`), `:2529`
//! (`makeMoreListeners`). **Portados:** `:1710` → [`tls_addrs`](open::tls_addrs) (el conjunto de candidatos del dial: HIT y
//! MISS), `:2529` → el BARRIDO fiel `listener_manager::scan::make_more_listeners` (T-4 re-derivada:
//! es el port literal de `makeMoreListeners`, y aplica el filtro vía la sede única `is_url_usable`),
//! con [`EdgeClient::open_channel`](crate::edge::client::EdgeClient::open_channel) como sede **INTERINA** del camino de bind del puerto — que sigue
//! eligiendo router y sigue aplicando el filtro — hasta que `l3-listener-run` cablee el bucle
//! (residuo **T-13**: duplicidad de ARQUITECTURA declarada, no de permiso; ninguna de las dos sedes
//! pierde el filtro), y `:2436` →
//! [`listener_count`](crate::edge::listener_manager::listener_count) (la puerta de conteo del arco `listenerManager`, cluster L3: su
//! predicado `USABLE` aplica el filtro además de la poda de address). Los otros **DOS** no tienen camino equivalente
//! en noa-sdk hoy; **quien los porte DEBE aplicar el filtro**:
//!
//! - **`:845`** — el pre-warm del tick de `refreshSessions`: no portado (DV-4c-PREWARM, abajo).
//! - **`:1237`** — `ConnectAllAvailableErs` (abre canal a TODOS los ERs visibles, no a los de una sesión):
//!   no existe aquí. Un futuro `connect_all_available_ers` **debe filtrar** cada url antes de abrir.
//!
//! # DV-4c-REJECTALL — con un filtro reject-all fallamos RÁPIDO; el oráculo BLOQUEA (benigna, observable)
//!
//! Si el filtro rechaza TODAS las urls de la sesión, nosotros devolvemos `NoTlsEdgeRouter` de inmediato (el
//! conjunto de candidatos queda vacío). El oráculo no: recorre el fan-out sin lanzar ninguna goroutine, con
//! `bestER == nil` entra en el `select` de `:1722-1731` sobre un `ch` en el que **nadie escribirá jamás** y
//! **bloquea hasta el `ctx.Done()`** del connect-timeout (`no edge routers connected in time`). Aguas abajo
//! el flujo coincide (el dial falla y el retry/refresh de D3 corre igual): la divergencia es el TIPO de error
//! y la LATENCIA (0 vs. connect-timeout). Benigna (fail-fast), pero **observable en cuanto se instala un
//! filtro** ⇒ declarada.
//!
//! # DV-4c-PREWARM — el PRE-WARM del tick NO se porta (desviación consciente, decisión de dueño)
//!
//! El oráculo llama a `go handleConnectEdgeRouter(name, url, nil)` (fire-and-forget, `ret == nil`) al
//! final de cada tick de `refreshSessions` (`ziti.go:857-859`), reabriendo en background un canal a cada
//! router de cada sesión de dial que refrescó OK (`:843-848`). **Nosotros NO lo portamos**, a propósito:
//!
//! 1. **La cobertura de routers ya la da el fan-out del dial**, que desde esta slice corre **también en el
//!    cache-HIT** (`:1708-1714` ≺ `:1716`) y **no cancela a los perdedores**: cada opener corre hasta el
//!    final y se auto-poolea ([`open_and_pool_router`] → `pool_store_or_reuse_into`) ⇒ **cada `connect()` de
//!    un servicio reabre en background los routers de su sesión que no estén pooleados y vivos**. Para un
//!    servicio que se dialea, el tick no añadiría ni un router más.
//! 2. **Lo ÚNICO que añadiría** es calentar canales de sesiones que **NADIE dialea** (cacheadas y ociosas),
//!    a cambio de canales TLS **ociosos** contra cada router de cada sesión de dial cacheada, cada uno con su
//!    rx-loop y su sonda de latencia, **reabiertos cada hora**.
//! 3. **Y ni siquiera acelera el arranque en frío:** el tick es **HORARIO** en ambos lados (oráculo
//!    `DefaultSessionRefreshInterval = time.Hour`, `options.go:17`; nosotros `PROD_SESSION_INTERVALS`
//!    = 3600 s, `session_refresh/intervals.rs:23-26`) y en frío el caché de dial-sessions está **vacío** ⇒ el
//!    pre-warm del oráculo **tampoco hace nada** para el primer dial.
//!
//! ⇒ **El hueco entero es:** un servicio cacheado que nadie dialea tiene sus canales calientes en el oráculo
//! y fríos aquí; el `connect()` que llegue después paga **UN handshake TLS** (en paralelo, first-OK). No es
//! corrección, no es autorización, no es robustez.
//!
//! **Cómo portarlo si algún día se quiere** (diseñado en `docs/superpowers/specs/`
//! `2026-07-11-4c-prewarm-edge-routers-design.md` §3): el tick corre en una tarea destacada con handles
//! PROPIOS (una `Arc<EdgeClient>` dentro sería un CICLO — `EdgeClient::Drop` aborta su `JoinHandle`), así
//! que hay que extraer `EdgeClient::channel_client_config` a una **fn libre**
//! `channel_client_config_from(config, session_cert, http, base_url, token)` (precedente exacto:
//! `pool_store_or_reuse` → `pool_store_or_reuse_into`), pasarle al tick un `PrewarmCtx` con los `Arc`
//! (el `SessionCertHolder` ya es un `Arc` ⇒ **mismo holder**, sin doble re-mint), recolectar
//! `BTreeMap<url, router_name>` de las sesiones VIVAS (dedup por url, `:846`) **después** de la purga
//! (`:853-855` ≺ `:857-859`) y `tokio::spawn`ear [`open_and_pool_router`] por target, sin canal de
//! resultado. **El tick NO re-autentica:** si construir `(cc, cn)` falla, se **salta** el pre-warm de ese
//! tick (el timer de api-session re-autentica igual; el peor caso es "no optimizar" = el comportamiento
//! de hoy).

mod dial;
mod fanout;
mod open;

pub(crate) use dial::leaf_common_name_for;
// Sin consumidor externo en código (la ruta `crate::edge::channel::…` se preserva para el
// doc-link de `client/pool.rs` y futuros consumidores): `open.rs` importa estos cuatro VÍA este
// re-export (`use super::{…}`), lo que lo mantiene usado bajo `-D warnings`.
pub(crate) use fanout::{
    RouterOpenerCtx, fan_out_first_ok, open_and_pool_router, spawn_router_openers,
};
// Repone el nombre que `mod tests` veía como hijo del módulo: `tests_dial` llama
// `super::build_channel_hello` verbatim. Gateado a `cfg(test)` porque su único consumidor es un
// test (sin el gate quedaría `unused` bajo `-D warnings` en el build normal).
#[cfg(test)]
use dial::build_channel_hello;

#[cfg(test)]
mod tests_dial;
#[cfg(test)]
mod tests_fanout;
#[cfg(test)]
mod tests_open;
#[cfg(test)]
mod tests_pool;
#[cfg(test)]
mod tests_recover;
#[cfg(test)]
mod testsupport;
