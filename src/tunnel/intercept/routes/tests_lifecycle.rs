// F6 tramo 11 troceo: tests movidos verbatim del monolito de `intercept/routes` (mod tests).

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use ipnet::IpNet;

use crate::tunnel::intercept::resolve::RouteDelta;

use super::testsupport::*;
use super::{RouteApplier, RouteLifecycle, RouteOps};

// ───────────── RouteLifecycle (refcount vivo, espejo de route.c:20-80) ─────────────

/// [`RouteOps`] recorder: registra los syscalls que el lifecycle EMITIRÍA — la lógica de refcount
/// y política es lo verificable offline; el efecto OS real es el gate live root.
struct RecOps(Rc<RefCell<Vec<String>>>);
impl RouteOps for RecOps {
    fn add(&mut self, cidr: IpNet) -> io::Result<()> {
        self.0.borrow_mut().push(format!("+{cidr}"));
        Ok(())
    }
    fn delete(&mut self, cidr: IpNet) -> io::Result<()> {
        self.0.borrow_mut().push(format!("-{cidr}"));
        Ok(())
    }
}

/// Lifecycle de la rig: utun `10.99.0.1/24` (on-link `10.99.0.0/24`), sin control-plane.
fn rig_lifecycle() -> (RouteLifecycle<RecOps>, Rc<RefCell<Vec<String>>>) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let lc = RouteLifecycle::new(RecOps(Rc::clone(&calls)), v4("10.99.0.1"), 24, Vec::new())
        .expect("prefijo válido");
    (lc, calls)
}

/// `route.c:43-51`/`:69-76`: la 1ª referencia instala (syscall), las siguientes solo cuentan; el
/// delete descuenta y solo la ÚLTIMA desinstala. El caso compartido: dos servicios con el mismo
/// CIDR → retirar uno NO quita la ruta del superviviente.
#[test]
fn lifecycle_installs_on_first_ref_and_deletes_on_last() {
    let (mut lc, calls) = rig_lifecycle();
    let shared = net("192.168.5.0/24");
    lc.add(shared); // servicio A
    lc.add(shared); // servicio B
    assert_eq!(
        *calls.borrow(),
        vec!["+192.168.5.0/24"],
        "solo la 1ª ref instala"
    );
    assert_eq!(lc.installed(), 1);
    lc.delete(shared); // A se retira → la ruta de B sobrevive
    assert_eq!(
        *calls.borrow(),
        vec!["+192.168.5.0/24"],
        "la ref restante conserva la ruta"
    );
    lc.delete(shared); // B se retira → última ref
    assert_eq!(
        *calls.borrow(),
        vec!["+192.168.5.0/24", "-192.168.5.0/24"],
        "la última ref desinstala"
    );
    assert_eq!(lc.installed(), 0);
    // Y el Drop NO re-borra (la clave se evictó al llegar a 0): dropear ahora no añade syscalls.
    drop(lc);
    assert_eq!(
        *calls.borrow(),
        vec!["+192.168.5.0/24", "-192.168.5.0/24"],
        "el Drop sobre counts vacíos es un no-op"
    );
}

/// `route.c:69` (`r == NULL`): borrar una ruta desconocida es un no-op sin syscall ni underflow.
#[test]
fn lifecycle_delete_of_an_unknown_route_is_a_noop() {
    let (mut lc, calls) = rig_lifecycle();
    lc.delete(net("192.168.5.0/24"));
    assert_eq!(lc.installed(), 0);
    drop(lc);
    assert!(
        calls.borrow().is_empty(),
        "ni el no-op ni el Drop emiten syscalls"
    );
}

/// La política ([`route_allowed`](crate::tunnel::intercept::routes::policy::route_allowed)) se
/// aplica SIMÉTRICAMENTE: un CIDR on-link, v6 o que cubre el
/// control-plane no se instala NI se cuenta en add, y su delete tampoco toca nada (sin
/// desbalanceo). El carve-out del controller protege también las rutas de servicios AÑADIDOS en
/// vivo (el guard anti-self-DoS del snapshot, ahora en el ciclo vivo).
#[test]
fn lifecycle_policy_filters_symmetrically_in_add_and_delete() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut lc = RouteLifecycle::new(
        RecOps(Rc::clone(&calls)),
        v4("10.99.0.1"),
        24,
        vec![ip("172.16.0.10")], // el controller
    )
    .expect("prefijo válido");
    lc.add(net("10.99.0.0/25")); // on-link (dentro de 10.99.0.0/24)
    lc.add(net("2001:db8::/64")); // v6
    lc.add(net("172.16.0.0/16")); // cubre el controller → rehusado (anti-self-DoS)
    assert!(
        calls.borrow().is_empty(),
        "ningún syscall para CIDRs rehusados"
    );
    assert_eq!(lc.installed(), 0, "tampoco se cuentan");
    lc.delete(net("10.99.0.0/25"));
    lc.delete(net("2001:db8::/64"));
    lc.delete(net("172.16.0.0/16"));
    drop(lc);
    assert!(
        calls.borrow().is_empty(),
        "ni el delete de un rehusado ni el Drop tocan nada (nada se contó)"
    );
}

/// [`RouteApplier::apply_delta`] aplica `removed` ANTES que `added` (orden del oráculo:
/// `stop_intercept` corre antes que `ziti_tunneler_intercept` en un REPLACE, `:634`/`:638`): un
/// CIDR conservado a través de un replace con única referencia CHURNEA delete→add, igual que el C.
#[test]
fn apply_delta_removes_before_adding_mirroring_the_replace_churn() {
    let (mut lc, calls) = rig_lifecycle();
    let kept = net("192.168.5.0/24");
    lc.add(kept);
    lc.apply_delta(&RouteDelta {
        removed: vec![kept],
        added: vec![kept],
    });
    assert_eq!(
        *calls.borrow(),
        vec!["+192.168.5.0/24", "-192.168.5.0/24", "+192.168.5.0/24"],
        "churn delete-then-add del replace (route.c vía stop_intercept→intercept)"
    );
    assert_eq!(lc.installed(), 1);
    drop(lc);
    assert_eq!(
        *calls.borrow(),
        vec![
            "+192.168.5.0/24",
            "-192.168.5.0/24",
            "+192.168.5.0/24",
            "-192.168.5.0/24"
        ],
        "el Drop borra la única instalada que quedó"
    );
}

/// El `Drop` borra las rutas que sigan instaladas (una vez cada una) — teardown grácil, espejo
/// del de `InstalledRoutes`.
#[test]
fn lifecycle_drop_deletes_the_remaining_installed_routes() {
    let (mut lc, calls) = rig_lifecycle();
    lc.add(net("192.168.5.0/24"));
    lc.add(net("192.168.6.0/24"));
    lc.add(net("192.168.6.0/24")); // 2ª ref: el drop borra UNA vez igualmente
    drop(lc);
    let recorded = calls.borrow();
    let deletes: Vec<_> = recorded.iter().filter(|c| c.starts_with('-')).collect();
    assert_eq!(
        deletes.len(),
        2,
        "una eliminación por CIDR instalado: {recorded:?}"
    );
    assert!(recorded.contains(&"-192.168.5.0/24".to_string()));
    assert!(recorded.contains(&"-192.168.6.0/24".to_string()));
}
