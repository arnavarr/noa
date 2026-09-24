//! **Superficie 1 — el plan EN BLOQUE de un snapshot:** `plan_routes` (la selección PURA, testeable
//! sin root) + `InstalledRoutes` (el RAII bulk que las instala y las borra en su `Drop`). Hoy es el
//! path del e2e root standalone; el path de producción de `noa intercept` es el ciclo vivo de
//! `lifecycle`.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};
use route_manager::{Route, RouteManager};

use super::policy::{route_allowed, warn_if_control_plane};

/// De las CIDRs de intercept, las que hay que instalar como ruta explícita: las que el utun NO cubre
/// ya on-link, que NO cubren una dirección del plano de control (`control_plane`), DISTINTAS, y v4 (ver
/// desviaciones en el doc del módulo). El resto (on-link, control-plane, v6, duplicadas) se omiten.
/// Función PURA (sin SO) → testeable sin root; es el núcleo verificable de la rebanada.
///
/// `intercept_cidrs` viene de [`crate::tunnel::intercept::InterceptResolver::intercept_cidrs`];
/// `utun_addr`/`utun_prefix`
/// son la dirección/prefijo con que se abrió el utun (su subred on-link); `control_plane` son las IPs
/// del propio plano de control del SDK (controller) que NUNCA deben ruteare al utun (self-DoS),
/// resueltas por [`control_plane_addrs`](crate::tunnel::intercept::routes::control_plane_addrs).
#[must_use]
pub fn plan_routes(
    intercept_cidrs: &[IpNet],
    utun_addr: Ipv4Addr,
    utun_prefix: u8,
    control_plane: &[IpAddr],
) -> Vec<IpNet> {
    // Subred on-link del utun: la red que el SO ya rutea al device (host bits enmascarados con
    // `trunc`). El caller real (`parse_utun_cidr`) valida el prefijo ≤32; si un caller de la API pub
    // pasa un prefijo inválido, no planificamos nada (safe-fail, sin panic).
    let Ok(on_link_v4) = Ipv4Net::new(utun_addr, utun_prefix) else {
        tracing::warn!(
            prefix = utun_prefix,
            "intercept: prefijo de utun inválido (>32); no se planifica ninguna ruta"
        );
        return Vec::new();
    };
    let on_link = IpNet::V4(on_link_v4.trunc());
    let mut planned: Vec<IpNet> = Vec::new();
    for &cidr in intercept_cidrs {
        if !route_allowed(cidr, on_link, control_plane) {
            warn_if_control_plane(cidr, control_plane);
            continue;
        }
        // Distinta (el refcount del oráculo colapsado a un conjunto para el snapshot).
        if !planned.contains(&cidr) {
            planned.push(cidr);
        }
    }
    planned
}

/// Rutas de intercept instaladas en la tabla del SO, ligadas al utun. RAII: su [`Drop`] las elimina
/// (teardown grácil, espejo del `delete_route` del oráculo). **Instalar/eliminar rutas requiere root**
/// (PF_ROUTE); la lógica pura de QUÉ rutas instalar es [`plan_routes`] (testeable sin root).
pub struct InstalledRoutes {
    manager: RouteManager,
    installed: Vec<Route>,
    iface: String,
}

impl InstalledRoutes {
    /// Instala una ruta interface-scoped (sin gateway, con el `if_index` del utun) por cada CIDR de
    /// `planned` — el mismo shape que `route -n add <ip/bits> -interface utunN` del oráculo
    /// (`gateway=None` + `if_index` ⇒ `route_manager` pone el `sockaddr_dl` del enlace en el slot
    /// RTA_GATEWAY con RTF_GATEWAY LIMPIO —ruta por interfaz, no vía gateway IP— y `RTF_HOST` para /32). Un `add`
    /// fallido (p.ej. la ruta ya existe) se log-y-omite (el oráculo ignora el retorno, `route.c:50`);
    /// NUNCA aborta el intercept por una ruta. `planned` DEBE venir de [`plan_routes`] (v4, off-on-link,
    /// distintas).
    ///
    /// # Errors
    /// Propaga solo el fallo de crear el [`RouteManager`]. Los fallos POR-RUTA no se propagan (se
    /// log-ean y se omite esa ruta).
    pub fn install(planned: &[IpNet], if_index: u32, iface: &str) -> io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let mut installed = Vec::new();
        for &net in planned {
            // gateway=None ⇒ ruta interface-scoped (por `if_index`), no vía gateway IP; prefix del CIDR
            // ⇒ RTF_HOST para /32, net-route en otro caso. Espejo byte-a-byte del shape del oráculo.
            let route = Route::new(net.network(), net.prefix_len()).with_if_index(if_index);
            match manager.add(&route) {
                Ok(()) => installed.push(route),
                Err(e) => tracing::warn!(
                    cidr = %net, %iface, error = %e,
                    "intercept: no se pudo instalar la ruta OS-level; se omite (ese destino no se interceptará)"
                ),
            }
        }
        tracing::info!(
            %iface,
            installed = installed.len(),
            planned = planned.len(),
            "intercept: rutas OS-level instaladas hacia el utun"
        );
        Ok(Self {
            manager,
            installed,
            iface: iface.to_string(),
        })
    }

    /// Número de rutas efectivamente instaladas (≤ `planned.len()`; menos si algún `add` falló).
    #[must_use]
    pub fn len(&self) -> usize {
        self.installed.len()
    }

    /// `true` si no se instaló ninguna ruta.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.installed.is_empty()
    }
}

impl Drop for InstalledRoutes {
    fn drop(&mut self) {
        // Teardown grácil: borra SOLO las rutas que instalamos (nunca la on-link del device ni una
        // ajena). Un fallo aquí no es fatal — en el peor caso el kernel purga la ruta interface-scoped
        // al cerrarse el utun (cleanup implícito, como el oráculo).
        for route in &self.installed {
            if let Err(e) = self.manager.delete(route) {
                tracing::warn!(
                    iface = %self.iface, error = %e,
                    "intercept: no se pudo eliminar una ruta OS-level al cerrar (el kernel la purga al morir el utun)"
                );
            }
        }
    }
}
