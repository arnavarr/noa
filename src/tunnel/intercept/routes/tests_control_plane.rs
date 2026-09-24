// F6 tramo 11 troceo: tests movidos verbatim del monolito de `intercept/routes` (mod tests).

use super::control_plane_addrs;
use super::testsupport::*;

#[test]
fn control_plane_addrs_resolves_ip_literals_and_skips_garbage() {
    // Host IP-literal → se usa tal cual; URL no parseable → se omite (sin panic). Solo IP-literales
    // para no depender del DNS en el test.
    let addrs = control_plane_addrs(&[
        "https://10.10.0.1:1280".to_string(),
        "tls://192.168.9.9:443".to_string(),
        "not a url".to_string(),
    ]);
    assert!(addrs.contains(&ip("10.10.0.1")), "IP del 1er controller");
    assert!(addrs.contains(&ip("192.168.9.9")), "IP del 2º controller");
    assert_eq!(addrs.len(), 2, "el URL basura se omite, sin duplicados");
}
