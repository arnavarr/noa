//! Fixtures compartidos por los `tests_*` de las rutas OS del intercept (F6 tramo 11 troceo).

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

pub(super) fn net(s: &str) -> IpNet {
    s.parse().expect("CIDR de test válido")
}
pub(super) fn v4(s: &str) -> Ipv4Addr {
    s.parse().expect("IPv4 de test válida")
}
pub(super) fn ip(s: &str) -> IpAddr {
    s.parse().expect("IP de test válida")
}
/// Sin plano de control (el caso de la mayoría de los tests de selección on-link).
pub(super) const NO_CP: &[IpAddr] = &[];
