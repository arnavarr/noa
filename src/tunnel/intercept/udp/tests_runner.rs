// F6 tramo 3a troceo: tests movidos verbatim del monolito de `intercept/udp` (mod tests).

use super::MAX_CONSECUTIVE_RECV_NONE;
use super::runner::{RecvStep, classify_recv};
use super::testsupport::*;

/// Pin de la lógica de seguridad NUEVA del slice (sin análogo en T3): el bounded-continue del `None`
/// de `recv_from`. Un datagrama válido `Route`-a y RESETEA el contador; un `None` por debajo del límite
/// `Continue`-a (recupera de un datagrama malformado transitorio); el límite se alcanza SOLO tras
/// `MAX_CONSECUTIVE_RECV_NONE` `None`s CONSECUTIVOS, y un datagrama válido intermedio resetea la cuenta
/// (consecutivo, no acumulativo). Mutación-RED: break-on-first-None (quitar el contador / `>= 1`) haría
/// que el 1er `None` devolviese `Stop` en vez de `Continue`.
#[test]
fn classify_recv_is_bounded_continue_on_none() {
    let mut n = 0u32;
    let dg = (b"x".to_vec(), v4(100, 64, 0, 7, 53), v4(10, 0, 0, 5, 1234));

    // Un datagrama válido: Route + reset.
    match classify_recv(Some(dg.clone()), &mut n) {
        RecvStep::Route(p, d, s) => {
            assert_eq!(p, b"x");
            assert_eq!((d, s), (dg.1, dg.2), "Route entrega (payload, dst, src)");
        }
        _ => panic!("un datagrama válido debe Route"),
    }
    assert_eq!(n, 0);

    // `None`s por debajo del límite: Continue, acumulando.
    for i in 1..MAX_CONSECUTIVE_RECV_NONE {
        assert!(
            matches!(classify_recv(None, &mut n), RecvStep::Continue),
            "None #{i} por debajo del límite continúa"
        );
        assert_eq!(n, i);
    }
    // Un datagrama válido RESETEA la cuenta consecutiva → el límite es consecutivo, no acumulativo.
    assert!(matches!(
        classify_recv(Some(dg.clone()), &mut n),
        RecvStep::Route(..)
    ));
    assert_eq!(n, 0, "un datagrama válido resetea la cuenta de None");

    // Ahora MAX `None`s consecutivos: el último (el nº MAX) hace Stop.
    for _ in 1..MAX_CONSECUTIVE_RECV_NONE {
        assert!(matches!(classify_recv(None, &mut n), RecvStep::Continue));
    }
    assert!(
        matches!(classify_recv(None, &mut n), RecvStep::Stop),
        "el None nº MAX consecutivo hace Stop"
    );
}
