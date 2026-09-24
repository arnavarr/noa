//! Shared test fixtures for the `resolve` submodules (F6 tramo 2a troceo).

use crate::edge::model::{AddressTranslation, HostV1Config, HostV1ListenOptions, PortRange};

use super::translate::{AddressTranslationPrefix, build_address_translations};

/// A `forwardAddress`+`forwardPort` host.v1 with a flat CIDR allow-list and a port range — the
/// shape T4b-1 resolves (mirrors the live spike config exactly).
pub(crate) fn fwd_ip_cfg() -> HostV1Config {
    HostV1Config {
        protocol: "tcp".to_string(),
        forward_address: true,
        allowed_addresses: vec!["127.0.0.1/32".to_string()],
        forward_port: true,
        allowed_port_ranges: vec![PortRange {
            low: 19000,
            high: 19100,
        }],
        ..Default::default()
    }
}
/// A `forwardAddress`+`forwardPort`+`forwardProtocol` host.v1 with a protocol allow-list, the shape
/// a forwardProtocol service serves. Reuses the address/port allow-lists from [`fwd_ip_cfg`].
pub(crate) fn fwd_proto_cfg(allowed_protocols: &[&str]) -> HostV1Config {
    HostV1Config {
        forward_protocol: true,
        allowed_protocols: allowed_protocols.iter().map(|s| (*s).to_string()).collect(),
        ..fwd_ip_cfg()
    }
}
pub(crate) fn listen_opts(ct: Option<&str>, secs: Option<u32>) -> HostV1ListenOptions {
    HostV1ListenOptions {
        connect_timeout: ct.map(str::to_string),
        connect_timeout_seconds: secs,
    }
}
/// Build translations from `(from, to, prefix)` tuples via the real [`build_address_translations`]
/// (so the DESC sort + strict parse are exercised), under a `forwardAddress` config.
pub(crate) fn xlat(entries: &[(&str, &str, u8)]) -> Vec<AddressTranslationPrefix> {
    let cfg = HostV1Config {
        forward_address: true,
        allowed_addresses: vec!["0.0.0.0/0".to_string()],
        forward_address_translations: entries
            .iter()
            .map(|(f, t, p)| AddressTranslation {
                from: (*f).to_string(),
                to: (*t).to_string(),
                prefix_length: *p,
            })
            .collect(),
        ..Default::default()
    };
    build_address_translations(&cfg).expect("translations build")
}
