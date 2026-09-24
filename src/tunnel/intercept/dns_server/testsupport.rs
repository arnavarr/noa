//! Fixtures compartidos por los 5 `tests_*` de `dns_server` (F6 tramo 14 troceo): los 6 helpers
//! del preamble son TODOS 4-way o 5-way compartidos entre los 5 banners del autor — ninguno es
//! exclusivo de un solo fichero de test.

use crate::tunnel::intercept::dns::{DnsMatcher, RegisterOutcome};

use super::router::handle_query;
use super::types::DnsAction;

/// Construye una query DNS válida: id, flags, UNA pregunta `(name, qtype, class)`.
pub(super) fn query(id: u16, flags: u16, name: &str, qtype: u16, class: u16) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&flags.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    if !name.is_empty() {
        for label in name.split('.') {
            pkt.push(u8::try_from(label.len()).expect("label < 256"));
            pkt.extend_from_slice(label.as_bytes());
        }
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&class.to_be_bytes());
    pkt
}

/// Una query estándar recursiva (RD=1, como manda un stub resolver real).
pub(super) fn std_query(name: &str, qtype: u16) -> Vec<u8> {
    query(0x1234, 0x0100, name, qtype, 1)
}

pub(super) fn matcher_with(addresses: &[&str]) -> DnsMatcher {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("100.64.0.0/24"));
    m.reserve("100.64.0.1".parse().unwrap()); // el utun (espejo de main.rs)
    m.reserve("100.64.0.2".parse().unwrap()); // el propio resolver
    for a in addresses {
        assert!(!matches!(m.register(a, "i"), RegisterOutcome::Rejected));
    }
    m
}

pub(super) fn respond(m: &mut DnsMatcher, pkt: &[u8]) -> Vec<u8> {
    // Modo sin-upstream (`false`): el pineado byte-exacto pre-upstream.
    match handle_query(m, pkt, false, false) {
        DnsAction::Respond(bytes) => bytes,
        other => panic!("se esperaba una respuesta, fue {other:?}"),
    }
}

/// El rcode de una respuesta (4 bits bajos del byte 3).
pub(super) fn rcode(resp: &[u8]) -> u8 {
    resp[3] & 0x0f
}

pub(super) fn ancount(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}
