//! Fixtures compartidos por `tests_matcher`/`tests_eviction` (F6 tramo 15 troceo): `matcher_of`
//! lo comparten b1 y b7, NO contiguos, así que el preamble entero viaja aquí (3 ítems, todos
//! `pub(super)`).

use super::matcher::DnsMatcher;
use super::types::{DnsMatchKind, RegisterOutcome};

/// Rango de prueba generoso (16M IPs) para que ningún test de match/desbordamiento tropiece con
/// agotamiento del pool por accidente; el agotamiento tiene sus propios tests dedicados abajo.
pub(super) const TEST_CIDR: &str = "10.0.0.0/8";

pub(super) fn matcher_of(addresses: &[&str]) -> DnsMatcher {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool(TEST_CIDR), "el CIDR de prueba debe sembrar");
    for addr in addresses {
        assert!(
            !matches!(m.register(addr, "i"), RegisterOutcome::Rejected),
            "registro de '{addr}' no debe desbordar"
        );
    }
    m
}

pub(super) fn kind_of(addresses: &[&str], query: &str) -> Option<DnsMatchKind> {
    matcher_of(addresses).lookup(query).map(|m| m.kind)
}
