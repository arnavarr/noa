//! El seam de syscalls del ciclo de rutas vivo (`RouteOps`) y su impl de producción `OsRouteOps`
//! (PF_ROUTE, root). Es lo que hace verificable OFFLINE la lógica de `lifecycle`: los tests inyectan
//! un recorder y comprueban QUÉ syscall se emitiría sin tocar la tabla del SO.

use std::io;

use ipnet::IpNet;
use route_manager::{Route, RouteManager};

/// Seam de syscalls del ciclo de rutas vivo: instalar/borrar UNA ruta interface-scoped. La impl de
/// producción es [`OsRouteOps`] (PF_ROUTE, root); los tests inyectan un recorder para verificar el
/// refcounting de [`RouteLifecycle`](crate::tunnel::intercept::routes::RouteLifecycle) sin root — la
/// lógica de QUÉ syscall se emite es lo verificable
/// offline, el efecto OS-level real lo cubre el gate live root.
pub trait RouteOps {
    /// Instala la ruta de `cidr` hacia el utun.
    ///
    /// # Errors
    /// El fallo del syscall — el llamante lo log-y-continúa (el oráculo ignora el retorno de
    /// `tun->add_route`, `route.c:50`).
    fn add(&mut self, cidr: IpNet) -> io::Result<()>;
    /// Borra la ruta de `cidr`.
    ///
    /// # Errors
    /// El fallo del syscall — log-y-continúa (misma política; ESRCH tras el purge del kernel es
    /// normal en teardown).
    fn delete(&mut self, cidr: IpNet) -> io::Result<()>;
}

/// [`RouteOps`] de producción: el MISMO shape de ruta que
/// [`InstalledRoutes`](crate::tunnel::intercept::routes::InstalledRoutes) (interface-scoped,
/// `gateway=None` + `if_index` ⇒ `sockaddr_dl` en RTA_GATEWAY con RTF_GATEWAY limpio, `RTF_HOST`
/// para /32 — `route -n add <ip/bits> -interface utunN` del oráculo). Requiere root.
pub struct OsRouteOps {
    manager: RouteManager,
    if_index: u32,
}

impl OsRouteOps {
    /// # Errors
    /// Propaga el fallo de crear el [`RouteManager`] (socket PF_ROUTE — root).
    pub fn new(if_index: u32) -> io::Result<Self> {
        Ok(Self {
            manager: RouteManager::new()?,
            if_index,
        })
    }

    fn route_of(&self, cidr: IpNet) -> Route {
        Route::new(cidr.network(), cidr.prefix_len()).with_if_index(self.if_index)
    }
}

impl RouteOps for OsRouteOps {
    fn add(&mut self, cidr: IpNet) -> io::Result<()> {
        self.manager
            .add(&self.route_of(cidr))
            .map_err(io::Error::other)
    }
    fn delete(&mut self, cidr: IpNet) -> io::Result<()> {
        self.manager
            .delete(&self.route_of(cidr))
            .map_err(io::Error::other)
    }
}
