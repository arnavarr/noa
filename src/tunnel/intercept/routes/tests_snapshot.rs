// F6 tramo 11 troceo: tests movidos verbatim del monolito de `intercept/routes` (mod tests).

use super::testsupport::*;
use super::{InstalledRoutes, plan_routes};

#[test]
fn plan_routes_keeps_a_cidr_outside_the_on_link_subnet() {
    // 192.168.5.0/24 está FUERA del on-link 10.99.0.0/24 → necesita ruta explícita al utun.
    let planned = plan_routes(&[net("192.168.5.0/24")], v4("10.99.0.1"), 24, NO_CP);
    assert_eq!(planned, vec![net("192.168.5.0/24")]);
}

#[test]
fn plan_routes_skips_a_cidr_inside_the_on_link_subnet() {
    // 10.99.0.128/25 ⊂ on-link 10.99.0.0/24 → el SO ya lo rutea; NO instalar (redundante).
    let planned = plan_routes(&[net("10.99.0.128/25")], v4("10.99.0.1"), 24, NO_CP);
    assert!(
        planned.is_empty(),
        "un CIDR dentro del on-link no debe instalarse"
    );
}

#[test]
fn plan_routes_skips_the_exact_on_link_subnet() {
    // El propio on-link ya lo rutea el device → instalarlo es redundante.
    let planned = plan_routes(&[net("10.99.0.0/24")], v4("10.99.0.1"), 24, NO_CP);
    assert!(planned.is_empty());
}

#[test]
fn plan_routes_keeps_a_host_route_outside_on_link() {
    // /32 fuera del on-link → ruta host (route_manager pone RTF_HOST por prefix 32, como el oráculo).
    let planned = plan_routes(&[net("203.0.113.7/32")], v4("10.99.0.1"), 24, NO_CP);
    assert_eq!(planned, vec![net("203.0.113.7/32")]);
}

#[test]
fn plan_routes_skips_a_host_inside_on_link() {
    let planned = plan_routes(&[net("10.99.0.2/32")], v4("10.99.0.1"), 24, NO_CP);
    assert!(planned.is_empty());
}

#[test]
fn plan_routes_keeps_a_supernet_that_contains_the_on_link() {
    // Un /16 que CONTIENE el on-link /24 NO está cubierto por él (es mayor) → se rutea; el /24
    // on-link más específico sigue ganando por longest-prefix del kernel.
    let planned = plan_routes(&[net("10.99.0.0/16")], v4("10.99.0.1"), 24, NO_CP);
    assert_eq!(planned, vec![net("10.99.0.0/16")]);
}

#[test]
fn plan_routes_dedups_identical_cidrs() {
    let planned = plan_routes(
        &[
            net("192.168.5.0/24"),
            net("192.168.5.0/24"),
            net("10.0.0.0/8"),
        ],
        v4("10.99.0.1"),
        24,
        NO_CP,
    );
    assert_eq!(planned, vec![net("192.168.5.0/24"), net("10.0.0.0/8")]);
}

#[test]
fn plan_routes_defers_v6_cidrs() {
    // El utun se direcciona v4 → un CIDR v6 no es ruteable; se omite (diferido).
    let planned = plan_routes(
        &[net("2001:db8::/32"), net("192.168.5.0/24")],
        v4("10.99.0.1"),
        24,
        NO_CP,
    );
    assert_eq!(
        planned,
        vec![net("192.168.5.0/24")],
        "v6 diferido; el v4 del mismo lote se conserva"
    );
}

#[test]
fn plan_routes_with_a_slash32_utun_routes_everything_like_the_oracle() {
    // Un utun /32 (el modelo del oráculo, `utun.c:281`) no tiene subred on-link real → TODO
    // destino se rutea explícitamente, igual que hace el tunneler C.
    let planned = plan_routes(
        &[net("192.168.5.0/24"), net("10.0.0.0/8")],
        v4("100.64.0.1"),
        32,
        NO_CP,
    );
    assert_eq!(planned, vec![net("192.168.5.0/24"), net("10.0.0.0/8")]);
}

#[test]
fn plan_routes_refuses_a_cidr_that_covers_a_control_plane_addr() {
    // El escenario self-DoS de la review: un servicio anuncia 10.0.0.0/8 y el underlay del
    // controller (o un ER) es 10.0.0.5. Rutear el /8 capturaría los dials del propio SDK →
    // NO se instala (rehúso), aunque el /8 esté fuera del on-link.
    let planned = plan_routes(&[net("10.0.0.0/8")], v4("10.99.0.1"), 24, &[ip("10.0.0.5")]);
    assert!(
        planned.is_empty(),
        "una CIDR que cubre el plano de control NO debe ruteare (evita self-DoS)"
    );
}

#[test]
fn plan_routes_refuses_when_control_plane_host_is_inside_the_cidr_but_keeps_a_sibling() {
    // El carve-out es por-CIDR: se rehúsa SOLO la que cubre el controller; una CIDR hermana que
    // NO lo cubre se conserva.
    let planned = plan_routes(
        &[net("10.0.0.0/8"), net("192.168.5.0/24")],
        v4("10.99.0.1"),
        24,
        &[ip("10.0.0.5")],
    );
    assert_eq!(
        planned,
        vec![net("192.168.5.0/24")],
        "se rehúsa la CIDR que cubre el controller; la hermana no-cubridora se conserva"
    );
}

#[test]
fn plan_routes_keeps_a_cidr_that_does_not_cover_the_control_plane() {
    // Un controller FUERA de la CIDR de intercept no la bloquea.
    let planned = plan_routes(
        &[net("192.168.5.0/24")],
        v4("10.99.0.1"),
        24,
        &[ip("203.0.113.9")],
    );
    assert_eq!(planned, vec![net("192.168.5.0/24")]);
}

#[test]
fn plan_routes_with_an_invalid_prefix_returns_empty_without_panicking() {
    // Un caller de la API pub que pase un prefijo >32 no debe pánicar; se planifica vacío.
    let planned = plan_routes(&[net("192.168.5.0/24")], v4("10.99.0.1"), 33, NO_CP);
    assert!(planned.is_empty());
}

#[test]
fn install_with_an_empty_plan_installs_nothing_and_needs_no_privilege() {
    // Sin rutas planificadas no se toca la tabla del SO: `RouteManager::new` no abre socket ni
    // requiere root, y el bucle es vacío (el add/delete real es live-gated → prueba en vivo con root, ejecutada a mano).
    let routes = InstalledRoutes::install(&[], 42, "utun-test").expect("empty install ok");
    assert!(routes.is_empty());
    assert_eq!(routes.len(), 0);
    drop(routes); // Drop sobre 0 rutas = no-op (no toca el SO).
}
