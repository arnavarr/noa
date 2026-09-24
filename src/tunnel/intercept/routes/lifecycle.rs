//! **Superficie 2 — el ciclo de vida de rutas OS refcounted y VIVO:** `RouteLifecycle` (espejo de la
//! tabla `route_counts` del oráculo) más el `RouteApplier` object-safe con que la rama svc-poll del
//! runner combinado le entrega cada `RouteDelta`. Es el path de producción de `noa intercept`.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use ipnet::{IpNet, Ipv4Net};

use crate::tunnel::intercept::resolve::RouteDelta;

use super::ops::RouteOps;
use super::policy::{route_allowed, warn_if_control_plane};

/// Aplicador del [`RouteDelta`] de una mutación del resolver — object-safe para cruzar la firma del
/// runner combinado sin genéricos (la rama svc-poll recibe `Option<Box<dyn RouteApplier>>`).
pub trait RouteApplier {
    /// Aplica el delta en el ORDEN del oráculo: `removed` primero (`stop_intercept` corre antes),
    /// `added` después.
    fn apply_delta(&mut self, delta: &RouteDelta);
}

/// El ciclo de vida de rutas OS refcounted — espejo de la tabla `route_counts` de `route.c:20-80`:
/// [`RouteLifecycle::add`] instala la ruta SOLO en la primera referencia (`:43-51`: existente →
/// `count += 1` sin syscall; nueva → count=1 + `tun->add_route`); [`RouteLifecycle::delete`] la
/// desinstala SOLO en la última (`:69-76`: `count -= 1`, a 0 → evict + `tun->delete_route`) y es un
/// NO-OP sobre una ruta desconocida (`:69`, `r == NULL`). Igual que el C, la referencia se cuenta
/// AUNQUE el syscall falle (`route.c` inserta en la lista antes de llamar `add_route` y no revisa el
/// retorno) — un fallo se log-y-continúa y el delete de última referencia / el `Drop` intentarán
/// borrar igual. Residual HEREDADO del oráculo (que también `tun->delete_route`-a una ruta cuyo add
/// falló): si el add falló por EEXIST contra una ruta AJENA idéntica preexistente, ese delete
/// posterior la borraría — el C se comporta exactamente igual (paridad bug-for-bug; el caso exige
/// que el operador tuviera una ruta propia idéntica a un CIDR de intercept).
///
/// La política por-CIDR ([`route_allowed`]) se aplica SIMÉTRICAMENTE antes de contar: un CIDR
/// rehusado en add (on-link / v6 / control-plane) tampoco se descuenta en delete → los counts solo
/// contienen CIDRs realmente ruteados, nunca se desbalancean.
///
/// Keyed por [`IpNet`] — el oráculo refcuenta por el STRING `dest->str` (`ziti_address_print`
/// emite `ip/bits`, host → `/32`, HOST BITS VERBATIM — `internal_model.c:294-303` no enmascara);
/// `IpNet` de [`crate::tunnel::resolve::parse_ip_or_cidr`] conserva igualmente los host bits (una
/// IP pelada parsea a `/32`) → clave equivalente, INCLUIDA la paridad bug-for-bug del aliasing:
/// dos spellings de la misma red OS (`10.7.0.1/24` vs `10.7.0.2/24`) son DOS claves en ambos lados
/// (dos add del mismo destino OS; el delete de una borra la ruta que la otra aún referencia — el C
/// hace lo mismo).
///
/// Su [`Drop`] borra las rutas que sigan instaladas (una vez cada una, ignorando counts — son
/// rutas OS únicas), espejo del teardown de
/// [`InstalledRoutes`](crate::tunnel::intercept::routes::InstalledRoutes); en la salida real el kernel suele
/// haberlas purgado ya al morir el utun (ESRCH → warn inofensivo).
pub struct RouteLifecycle<O: RouteOps> {
    /// `route_counts` (`route.c:26`): CIDR ruteado → número de referencias (servicios × apariciones
    /// de la dirección en su config, simétrico en add/remove).
    counts: HashMap<IpNet, usize>,
    on_link: IpNet,
    control_plane: Vec<IpAddr>,
    ops: O,
}

impl<O: RouteOps> RouteLifecycle<O> {
    /// `utun_addr`/`utun_prefix` = la subred on-link del device (mismos params que
    /// [`plan_routes`](crate::tunnel::intercept::routes::plan_routes));
    /// `control_plane` = las IPs del controller
    /// ([`control_plane_addrs`](crate::tunnel::intercept::routes::control_plane_addrs)). Un prefijo inválido
    /// (>32) es un error del llamante (el path real lo valida al parsear el CIDR del utun).
    ///
    /// # Errors
    /// `InvalidInput` si `utun_prefix` > 32.
    pub fn new(
        ops: O,
        utun_addr: Ipv4Addr,
        utun_prefix: u8,
        control_plane: Vec<IpAddr>,
    ) -> io::Result<Self> {
        let on_link = Ipv4Net::new(utun_addr, utun_prefix)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Self {
            counts: HashMap::new(),
            on_link: IpNet::V4(on_link.trunc()),
            control_plane,
            ops,
        })
    }

    /// `add_route` (`route.c:33-53`): política → refcount → syscall solo en la 1ª referencia.
    pub fn add(&mut self, cidr: IpNet) {
        if !route_allowed(cidr, self.on_link, &self.control_plane) {
            // Path de ADD: el rehúso por carve-out del controller SÍ es un evento operativo (un
            // servicio vivo cuyo destino no se ruteará) → warn. El skip del delete es silencioso.
            warn_if_control_plane(cidr, &self.control_plane);
            return;
        }
        let count = self.counts.entry(cidr).or_insert(0);
        *count += 1;
        if *count == 1 {
            if let Err(e) = self.ops.add(cidr) {
                tracing::warn!(
                    %cidr, error = %e,
                    "intercept: no se pudo instalar la ruta OS-level; se omite (ese destino no se interceptará)"
                );
            } else {
                tracing::info!(%cidr, "intercept: ruta OS-level instalada hacia el utun");
            }
        }
    }

    /// `delete_route` (`route.c:59-80`): política → refcount → syscall solo en la última referencia;
    /// no-op sobre un CIDR desconocido.
    pub fn delete(&mut self, cidr: IpNet) {
        if !route_allowed(cidr, self.on_link, &self.control_plane) {
            return;
        }
        let Some(count) = self.counts.get_mut(&cidr) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            self.counts.remove(&cidr);
            if let Err(e) = self.ops.delete(cidr) {
                tracing::warn!(
                    %cidr, error = %e,
                    "intercept: no se pudo eliminar la ruta OS-level (el kernel la purga al morir el utun)"
                );
            } else {
                tracing::info!(%cidr, "intercept: ruta OS-level eliminada (último servicio que la referenciaba)");
            }
        }
    }

    /// Número de rutas OS actualmente instaladas (CIDRs distintos con al menos una referencia).
    #[must_use]
    pub fn installed(&self) -> usize {
        self.counts.len()
    }
}

impl<O: RouteOps> RouteApplier for RouteLifecycle<O> {
    fn apply_delta(&mut self, delta: &RouteDelta) {
        for &cidr in &delta.removed {
            self.delete(cidr);
        }
        for &cidr in &delta.added {
            self.add(cidr);
        }
    }
}

impl<O: RouteOps> Drop for RouteLifecycle<O> {
    fn drop(&mut self) {
        for cidr in self.counts.keys() {
            if let Err(e) = self.ops.delete(*cidr) {
                tracing::warn!(
                    cidr = %cidr, error = %e,
                    "intercept: no se pudo eliminar una ruta OS-level al cerrar (el kernel la purga al morir el utun)"
                );
            }
        }
    }
}
