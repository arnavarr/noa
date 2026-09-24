//! La normalización: `check_name` (lowercase + detección de wildcard, límite `MAX_DNS_NAME`) +
//! `find_domain` (walk de sufijos contra el set de dominios). Funciones libres, espejo de
//! `ziti_dns.c:310-334`/`:370-378` (F6 tramo 15 troceo).

use std::collections::{HashMap, HashSet};

/// Normaliza `name`: ASCII-lowercase + detección de wildcard-domain (byte 0 == `'*'` Y byte 1 ==
/// `'.'`, EXACTO). Oráculo: `check_name`, `ziti_dns.c:310-334` (ver el doc del módulo para la
/// justificación de fidelidad de `to_ascii_lowercase` y el límite de 255 bytes). Devuelve `None` si
/// el nombre normalizado (prefijo `"*."` incluido si aplica) alcanzaría/excedería 256 bytes.
pub(super) fn check_name(name: &str) -> Option<(String, bool)> {
    const MAX_DNS_NAME: usize = 256;
    let (prefix, rest, is_domain) = match name.strip_prefix("*.") {
        Some(rest) => ("*.", rest, true),
        None => ("", name, false),
    };
    if prefix.len() + rest.len() >= MAX_DNS_NAME {
        return None;
    }
    let lowered = rest.to_ascii_lowercase();
    Some((format!("{prefix}{lowered}"), is_domain))
}

/// `find_domain` (`ziti_dns.c:370-378`): `hostname` (ya normalizado, no-wildcard) casa un dominio
/// registrado si el hostname COMPLETO es él mismo un dominio registrado (quirk: un dominio desnudo
/// casa su propio wildcard), o si alguna de sus etiquetas-sufijo (recortando de izquierda a derecha,
/// una etiqueta cada vez) lo es. Devuelve el sufijo de dominio QUE CASÓ (no el hostname completo de
/// la query) para que el llamante pueda asociar la entrada con el dominio real, espejo de
/// `entry->domain` apuntando al `dns_domain_t` casado (`ziti_dns.c:397`), no a la query.
pub(super) fn find_domain<'a>(
    hostname: &'a str,
    domains: &HashMap<String, HashSet<String>>,
) -> Option<&'a str> {
    if domains.contains_key(hostname) {
        return Some(hostname);
    }
    let mut rest = hostname;
    while let Some(idx) = rest.find('.') {
        rest = &rest[idx + 1..];
        if domains.contains_key(rest) {
            return Some(rest);
        }
    }
    None
}
