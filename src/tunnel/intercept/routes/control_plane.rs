//! Resuelve a IPs las URLs del controller (`ztAPI`/`ztAPIs`): el INPUT del carve-out de `policy`.
//! Función de arranque (bloqueante, one-shot), no del datapath.

use std::net::{IpAddr, ToSocketAddrs};

use reqwest::Url;

/// Resuelve a IPs las direcciones del plano de control (las URLs del controller `ztAPI`/`ztAPIs`) para
/// pasarlas como `control_plane` a [`plan_routes`](crate::tunnel::intercept::routes::plan_routes) — el
/// carve-out que impide que una ruta de intercept
/// amplia capture los dials del propio SDK al controller (self-DoS). Un host IP-literal se usa tal
/// cual; un hostname se resuelve UNA vez por el resolver del SO (ya hay conectividad tras
/// `authenticate`). Un URL no parseable o un host irresoluble se log-y-omite (mejor no proteger esa
/// dirección que abortar el intercept; el operador ve el warning). Función de arranque (bloqueante,
/// one-shot), no del datapath.
///
/// **Oráculo:** el tunneler instala una ruta de EXCLUDE (apuntada al gateway real) para el controller
/// SIEMPRE (`ziti_tunnel_ctrl.c:1044`); aquí se hace la versión ligera por rehúso (ver el doc del
/// módulo). Las direcciones de EDGE ROUTER (`:1113`) no se conocen en el snapshot de arranque → NO se
/// incluyen (diferido nombrado).
#[must_use]
pub fn control_plane_addrs(controller_urls: &[String]) -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    for raw in controller_urls {
        let Some(host) = Url::parse(raw)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
        else {
            tracing::warn!(
                url = %raw,
                "intercept: URL de controller no parseable; su dirección no se excluirá del ruteo"
            );
            continue;
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            addrs.push(ip);
        } else {
            // Puerto ficticio: `ToSocketAddrs` solo necesita `host:port` para resolver el host.
            match (host.as_str(), 0u16).to_socket_addrs() {
                Ok(resolved) => addrs.extend(resolved.map(|sa| sa.ip())),
                Err(e) => tracing::warn!(
                    host = %host, error = %e,
                    "intercept: controller irresoluble; su dirección no se excluirá del ruteo"
                ),
            }
        }
    }
    addrs.sort();
    addrs.dedup();
    addrs
}
