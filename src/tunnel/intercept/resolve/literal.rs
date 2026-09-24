//! Direcciones literal-CIDR de un `intercept.v1` (F6 tramo 2b troceo). Movido verbatim del monolito de `intercept/resolve`.

use ipnet::IpNet;

use crate::tunnel::resolve::parse_ip_or_cidr;

use super::InterceptV1Config;

/// Las direcciones literal-CIDR de un `intercept.v1` CRUDO (el shape de `installed_configs`), en
/// orden de config y con duplicados — la lista que `stop_intercept`/`ziti_tunneler_intercept`
/// recorren para `delete_route`/`add_route`. Un raw que no parsea (imposible por construcción: solo
/// se instala un config que ya parseó Ok) devuelve vacío, defensivo.
pub(super) fn literal_route_addrs(raw: &serde_json::Value) -> Vec<IpNet> {
    serde_json::from_value::<InterceptV1Config>(raw.clone())
        .map(|cfg| literal_addrs(&cfg))
        .unwrap_or_default()
}

/// Como [`literal_route_addrs`] sobre un config YA parseado.
pub(super) fn literal_addrs(cfg: &InterceptV1Config) -> Vec<IpNet> {
    cfg.addresses
        .iter()
        .filter_map(|a| parse_ip_or_cidr(a))
        .collect()
}
