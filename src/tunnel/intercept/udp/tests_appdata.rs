// F6 tramo 3a troceo: tests movidos verbatim del monolito de `intercept/udp` (mod tests).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::testsupport::*;
use super::vconn::intercept_udp_appdata;

/// GATE emitter-equivalence (UDP IP-path v4): el emisor de intercept UDP produce EXACTAMENTE el mapa
/// del `GetAppInfo("udp", "", dstIp, dstPort, "")` — `dst_protocol == "udp"`, `dst_ip`/`dst_port` con
/// los valores del destino, y NINGÚN otro campo. El `assert_eq!(map, expected)` (mapa de 3 claves
/// EXACTO) es el pin LOAD-BEARING: cualquier campo extra/cambiado o protocolo distinto va RED. Las dos
/// aserciones negativas que siguen son documentación EXPLÍCITA (redundante con la igualdad): sin
/// entrada DNS no se emite `dst_hostname` (omit-empty) y `source_addr` sigue DIFERIDO.
#[test]
fn intercept_udp_appdata_matches_oracle_get_app_info_ip_path_v4() {
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)), 53);
    let map = parse(&intercept_udp_appdata(dst, None));

    let mut expected = BTreeMap::new();
    expected.insert("dst_protocol".to_string(), "udp".to_string());
    expected.insert("dst_ip".to_string(), "100.64.0.7".to_string());
    expected.insert("dst_port".to_string(), "53".to_string());
    assert_eq!(
        map, expected,
        "mapa AppData == GetAppInfo('udp', ...) IP-path"
    );

    assert!(
        !map.contains_key("dst_hostname"),
        "sin entrada DNS no hay dst_hostname: omitido como GetAppInfo con dstHostname vacío"
    );
    assert!(
        !map.contains_key("source_addr"),
        "source_addr DIFERIDO (SourceAddrProvider/M3-rutas): omitido como GetSourceAddr nil"
    );
}

/// GATE del hostname-path UDP (desviación consciente Go-vs-C resuelta a favor del C, ver el doc
/// de `intercept_udp_appdata`): con reverse-lookup resuelto el emisor añade `dst_hostname`,
/// espejo del `get_app_data` COMPARTIDO del tunneler C (`ziti_dns_reverse_lookup(dst_ip)`,
/// `ziti_tunnel_cbs.c:255-259` — UDP incluido). Hostname vacío (entrada reservada) → omitido.
#[test]
fn intercept_udp_appdata_emits_dst_hostname_when_reverse_lookup_knows_it() {
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)), 5353);
    let map = parse(&intercept_udp_appdata(dst, Some("app.wild.ziti.test")));

    let mut expected = BTreeMap::new();
    expected.insert("dst_protocol".to_string(), "udp".to_string());
    expected.insert("dst_ip".to_string(), "100.64.0.3".to_string());
    expected.insert("dst_port".to_string(), "5353".to_string());
    expected.insert("dst_hostname".to_string(), "app.wild.ziti.test".to_string());
    assert_eq!(map, expected, "mapa == get_app_data con reverse-lookup hit");

    let empty = parse(&intercept_udp_appdata(dst, Some("")));
    assert!(
        !empty.contains_key("dst_hostname"),
        "un hostname vacío se omite del mapa (omit-empty)"
    );
    assert_eq!(empty.len(), 3);
}

/// GATE emitter-equivalence (UDP IP-path v6): la forma del IPv6 destino en `dst_ip` es la canónica
/// comprimida (espejo de `net.IP.String()`) y `dst_protocol == "udp"`. (Los tests de M3-UDP-stack
/// eran IPv4-only; este cubre la familia v6 del emisor.)
#[test]
fn intercept_udp_appdata_ipv6_canonical_form() {
    let dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), 443);
    let map = parse(&intercept_udp_appdata(dst, None));

    assert_eq!(map.get("dst_protocol").map(String::as_str), Some("udp"));
    assert_eq!(map.get("dst_ip").map(String::as_str), Some("fd00::1"));
    assert_eq!(map.get("dst_port").map(String::as_str), Some("443"));
    assert_eq!(map.len(), 3, "solo los 3 campos del caso IP-puro");
}
