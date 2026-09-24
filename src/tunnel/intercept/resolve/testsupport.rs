//! Fixtures compartidos por los `tests_*` del resolver del intercept (F6 tramo 2b troceo).

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;

use crate::edge::model::Service;

use super::InterceptResolver;
use crate::tunnel::intercept::dns::DnsMatcher;

/// Construye un `Service` con un `config` JSON (espejo del helper de `model.rs`), permiso `Dial`
/// por defecto (el caso interceptable).
pub(crate) fn svc(name: &str, config_json: &str) -> Service {
    svc_perms(name, config_json, &["Dial"])
}

pub(crate) fn svc_perms(name: &str, config_json: &str, perms: &[&str]) -> Service {
    let config: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(config_json).unwrap();
    Service {
        id: format!("id-{name}"),
        name: name.into(),
        encryption_required: false,
        permissions: perms.iter().map(|s| (*s).to_string()).collect(),
        config,
        configs: vec![],
    }
}

pub(crate) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(crate) const ANY_SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));

pub(crate) fn one_svc_resolver(config_json: &str) -> InterceptResolver {
    InterceptResolver::from_services(&[svc("svc", config_json)])
}

pub(crate) fn one_svc_resolver_with_dns(config_json: &str, dns: DnsMatcher) -> InterceptResolver {
    InterceptResolver::from_services_with_dns(&[svc("svc", config_json)], dns)
}

pub(crate) fn seeded_dns() -> DnsMatcher {
    let mut dns = DnsMatcher::new();
    assert!(dns.seed_pool("10.99.0.0/24"));
    dns
}

pub(crate) const CIDR_A: &str = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.0.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#;
pub(crate) const CIDR_B: &str = r#"{"intercept.v1":{"protocols":["tcp"],"addresses":["10.1.0.0/24"],"portRanges":[{"low":80,"high":80}]}}"#;

pub(crate) fn cidr(s: &str) -> IpNet {
    s.parse().expect("CIDR de test válido")
}
