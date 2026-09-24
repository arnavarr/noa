//! La política POR-CIDR compartida de instalación de rutas: v4-only → off-on-link → carve-out del
//! plano de control. Vive en su propio fragmento porque las DOS superficies del módulo (el snapshot
//! de `plan_routes` y el ciclo vivo de `RouteLifecycle`) la aplican SIMÉTRICAMENTE llamando a la
//! MISMA función — duplicarla dejaría que un servicio añadido en vivo self-DoSease el controller.

use std::net::IpAddr;

use ipnet::IpNet;

/// La política POR-CIDR de instalación de rutas — compartida por
/// [`plan_routes`](crate::tunnel::intercept::routes::plan_routes) (snapshot) y
/// [`RouteLifecycle`](crate::tunnel::intercept::routes::RouteLifecycle) (ciclo vivo), así ambas
/// superficies rehúsan EXACTAMENTE lo mismo por
/// construcción. Función PURA y silenciosa (el `warn!` del carve-out lo emiten los call sites de
/// ADD — `plan_routes` y `RouteLifecycle::add` —, no el path de delete, cuyo skip simétrico de un
/// CIDR jamás contado no es un evento operativo):
///  - **v6**: no ruteable por un utun v4-direccionado → diferido. Nota (desviación heredada del
///    match, ahora también visible en rutas): un CIDR **v4-mapped** (`::ffff:a.b.c.d/n`) llega aquí
///    ya DESMAPEADO a su v4 (prefijo −96) por `parse_ip_or_cidr` (Go-fiel, `GetCidr`) → produce una
///    ruta v4 donde el oráculo C lo trataría como v6 inerte; coherente con la tabla de match (el
///    dispatch y la ruta ven el MISMO v4 — nunca se rutea lo que no despacharía).
///  - **on-link**: ya cubierto por la subred del utun → instalarlo sería redundante → NO tocar
///    (desviación aceptada de M3-rutas; el oráculo, con utun /32 punto-a-punto, rutea todo).
///  - **carve-out del plano de control**: NUNCA rutear al utun una CIDR que cubra una dirección del
///    propio plano de control del SDK (controller) — capturaría los dials de renovación/reauth/
///    svc-poll → self-DoS (versión LIGERA del exclude del oráculo; el exclude de edge routers +
///    bypass al gateway queda DIFERIDO, ver el doc del módulo). En vivo este guard es tan
///    load-bearing como en el snapshot: un servicio AÑADIDO por el poller con una CIDR que cubra el
///    controller se rehúsa aquí.
pub(super) fn route_allowed(cidr: IpNet, on_link: IpNet, control_plane: &[IpAddr]) -> bool {
    if !matches!(cidr, IpNet::V4(_)) {
        return false;
    }
    if on_link.contains(&cidr) {
        return false;
    }
    if control_plane.iter().any(|cp| cidr.contains(cp)) {
        return false;
    }
    true
}

/// El `warn!` operativo del carve-out, emitido SOLO desde los caminos de ADD (instalar): el skip
/// simétrico del delete no es un evento (ese CIDR nunca se contó).
pub(super) fn warn_if_control_plane(cidr: IpNet, control_plane: &[IpAddr]) {
    if matches!(cidr, IpNet::V4(_)) && control_plane.iter().any(|cp| cidr.contains(cp)) {
        tracing::warn!(
            %cidr,
            "intercept: la CIDR cubre una dirección del plano de control (controller); NO se rutea (evita self-DoS). Ese destino no se interceptará."
        );
    }
}
