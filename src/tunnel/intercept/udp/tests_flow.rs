// F6 tramo 3a troceo: tests movidos verbatim del monolito de `intercept/udp` (mod tests).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::tunnel::intercept::resolve::{InterceptResolver, Protocol};

use super::flow::{RouteAction, drop_expired, route_decision};
use super::testsupport::*;
use super::{FlowKey, Vconn};

/// **Test 9 (§7):** tras el kill, un datagrama POSTERIOR de la misma 4-tupla **no recrea el flujo**.
/// Ejerce la cadena EXACTA que `route_datagram` recorre antes de descartar (no se instancia un
/// `EdgeClient` real: el camino termina ANTES de tocarlo, en el `let Some(m) = … else { return }`):
/// `route_decision` ve la entrada `closed` → la evicta → `CreateNew` → `lookup` ya no devuelve el
/// servicio (lo retiró `remove_service` en el mismo evento que disparó el kill) → drop.
///
/// Esto es lo que cierra el residual del flujo de un servicio retirado por `remove_service`: antes, un emisor UDP
/// constante hacía `Deliver` directo al vconn vivo SIN re-lookup y refrescaba su idle-timer, así que
/// el flujo de un servicio retirado sobrevivía indefinidamente. Con el kill, el vconn queda `closed`
/// y el primer datagrama posterior lo evicta en vez de alimentarlo.
#[test]
fn datagram_after_kill_does_not_recreate_flow() {
    let mut conns: HashMap<FlowKey, Vconn> = HashMap::new();
    let src = v4(10, 0, 0, 5, 1234);
    let dst = v4(100, 64, 0, 7, 9999);

    // Un vconn del servicio retirado, ya MATADO (su task seteó `closed` al hacer el full-close).
    let (handle, _rx, closed) = vconn_handle();
    conns.insert((src, dst), handle);
    closed.store(true, Ordering::Release);

    // 1) El datagrama siguiente NO se entrega al vconn matado: se evicta y cae a CreateNew.
    assert_eq!(
        route_decision(&mut conns, (src, dst)),
        RouteAction::CreateNew,
        "un vconn `closed` no recibe: se evicta (nunca `Deliver`, que era el residual on-link)"
    );
    assert!(conns.is_empty(), "la entrada matada desapareció del map");

    // 2) …y el resolver ya no conoce el servicio (el svc-poll aplicó `Removed` antes del kill), así
    //    que `route_datagram` retorna en su `lookup → None` sin crear vconn ni tocar el registro.
    let resolver = InterceptResolver::from_services(&[]);
    assert!(
        resolver
            .lookup(dst.ip(), dst.port(), Protocol::Udp, src.ip())
            .is_none(),
        "ningún servicio intercepta ya el destino → el datagrama se descarta"
    );
}

/// LA decisión de diseño clave del intercept UDP: el flujo se keyea por `(src, dst)`, NO por `src`
/// solo (T3). Dos datagramas del MISMO `src` a DSTS distintos son flujos DISTINTOS (servicios
/// distintos) → `CreateNew` para cada uno; el mismo `(src, dst)` con un vconn vivo → `Deliver`.
/// Mutación-RED: keyear por `src` solo (perder el `dst` de la clave) colapsaría los dos dsts en un
/// flujo → el 2º daría `Deliver` (al servicio equivocado) en vez de `CreateNew`.
#[test]
fn flows_are_keyed_by_src_and_dst_not_src_alone() {
    let mut conns: HashMap<FlowKey, Vconn> = HashMap::new();
    let src = v4(10, 0, 0, 5, 1234);
    let dst_a = v4(100, 64, 0, 7, 53);
    let dst_b = v4(100, 64, 0, 8, 443);

    // Flujo nuevo (src, dst_a): CreateNew.
    assert_eq!(
        route_decision(&mut conns, (src, dst_a)),
        RouteAction::CreateNew
    );
    let (handle_a, _rx_a, _closed_a) = vconn_handle();
    conns.insert((src, dst_a), handle_a);

    // MISMO src, OTRO dst: sigue siendo un flujo nuevo (CreateNew), no se entrega al vconn de dst_a.
    assert_eq!(
        route_decision(&mut conns, (src, dst_b)),
        RouteAction::CreateNew,
        "mismo src a otro dst = flujo distinto (servicio distinto)"
    );
    let (handle_b, _rx_b, _closed_b) = vconn_handle();
    conns.insert((src, dst_b), handle_b);

    // El mismo (src, dst_a) con su vconn vivo: Deliver (reusa el flujo).
    assert_eq!(
        route_decision(&mut conns, (src, dst_a)),
        RouteAction::Deliver,
        "el mismo (src, dst) reusa su vconn"
    );
}

/// Un vconn marcado `closed` (su task hizo teardown) se EVICTA y se trata como ausente → CreateNew
/// (espejo de `GetWriteQueue` borrando un closed). Pinea que un dial fallido / EOF no deja un flujo
/// fantasma que tragaría datagramas futuros.
#[test]
fn closed_vconn_is_evicted_and_recreated() {
    let mut conns: HashMap<FlowKey, Vconn> = HashMap::new();
    let key = (v4(10, 0, 0, 5, 1234), v4(100, 64, 0, 7, 53));
    let (handle, _rx, closed) = vconn_handle();
    conns.insert(key, handle);
    assert_eq!(route_decision(&mut conns, key), RouteAction::Deliver);

    closed.store(true, Ordering::Release); // el task del vconn hizo teardown
    assert_eq!(
        route_decision(&mut conns, key),
        RouteAction::CreateNew,
        "un vconn closed se evicta → flujo nuevo"
    );
    assert!(!conns.contains_key(&key), "el closed se borró del mapa");
}

/// El reaper barre los vconns closed y los idle más allá del umbral, conservando los activos
/// recientes (espejo de `dropExpired`).
#[test]
fn drop_expired_sweeps_closed_and_idle_keeps_fresh() {
    let mut conns: HashMap<FlowKey, Vconn> = HashMap::new();
    let now = Instant::now();
    let idle = Duration::from_secs(60);

    // Fresco y activo → se conserva.
    let fresh_key = (v4(10, 0, 0, 1, 1), v4(100, 64, 0, 7, 53));
    let (fresh, _rxf, _cf) = vconn_handle();
    conns.insert(fresh_key, fresh);

    // Idle (last_use antiguo) → se reapea.
    let idle_key = (v4(10, 0, 0, 2, 2), v4(100, 64, 0, 8, 53));
    let (idle_h, _rxi, _ci) = vconn_handle();
    *idle_h.last_use.lock().unwrap() = now
        .checked_sub(Duration::from_secs(120))
        .expect("test instant in range");
    conns.insert(idle_key, idle_h);

    // Closed → se reapea (aunque su last_use sea reciente).
    let closed_key = (v4(10, 0, 0, 3, 3), v4(100, 64, 0, 9, 53));
    let (closed_h, _rxc, cc) = vconn_handle();
    cc.store(true, Ordering::Release);
    conns.insert(closed_key, closed_h);

    drop_expired(&mut conns, idle, now);

    assert!(
        conns.contains_key(&fresh_key),
        "el activo reciente sobrevive"
    );
    assert!(!conns.contains_key(&idle_key), "el idle se reapea");
    assert!(!conns.contains_key(&closed_key), "el closed se reapea");
}
