//! `impl` de los matchers `InterceptEntry`/`WildcardEntry` (F6 tramo 2b troceo). Las decls de struct
//! viven en `mod.rs` (campos privados vistos por descendencia). Movido verbatim del monolito de `intercept/resolve`.

use std::net::IpAddr;

use super::{InterceptEntry, Protocol, WildcardEntry};

impl InterceptEntry {
    /// `InterceptAddress.Contains(ip,port)` (`interceptor.go:76`) + protocolo + whitelist de origen.
    pub(super) fn matches(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: Protocol,
        src_ip: IpAddr,
    ) -> bool {
        self.protocol == proto.as_str()
            && self.cidr.contains(&dst_ip)
            && dst_port >= self.low_port
            && dst_port <= self.high_port
            && self.source_allowed(src_ip)
    }

    /// `allowedSourceAddresses` (`tproxy_linux.go:567-568` iptables `-s`): `None` = cualquier origen;
    /// `Some(cidrs)` = el origen debe estar en algún CIDR (un set vacío → casa con NINGÚN origen).
    fn source_allowed(&self, src_ip: IpAddr) -> bool {
        match &self.allowed_sources {
            None => true,
            Some(cidrs) => cidrs.iter().any(|c| c.contains(&src_ip)),
        }
    }
}

impl WildcardEntry {
    /// `true` si un flujo `(dst→dominio, dst_port, proto, src)` casa esta entrada wildcard. Espejo del
    /// gate completo de la rama `match_addr` de `lookup_intercept_by_address`: `protocol_match` **Y**
    /// el dominio del destino casa el patrón wildcard (`intercept_match_addr`) **Y** `port_match` **Y**
    /// la whitelist de origen — todo sobre el MISMO intercept. `domain` es el resultado del reverse
    /// lookup del destino (el sufijo bajo el que la IP se asignó), ya calculado UNA vez por el llamante.
    pub(super) fn claims(
        &self,
        domain: &str,
        dst_port: u16,
        proto: Protocol,
        src_ip: IpAddr,
    ) -> bool {
        self.protocol == proto.as_str()
            && self.suffix_matches(domain)
            && dst_port >= self.low_port
            && dst_port <= self.high_port
            && self.source_allowed(src_ip)
    }

    /// `ziti_address_match(parse("*.domain"), "*.suffix") >= 0` (`internal_model.c:327-360`): el sufijo
    /// de servicio casa el dominio del destino si es IDÉNTICO (`W == D`, incluye el quirk dominio-desnudo
    /// del oráculo) o si el dominio TERMINA en `".<suffix>"` (frontera de etiqueta — el walk de sufijos
    /// del oráculo solo avanza tras un punto, así que `axample.com` NO casa `xample.com`). Ambos ya
    /// lowercased por `check_name`, así que la comparación byte-a-byte espeja el `strcasecmp` del oráculo
    /// sin re-lowercasear. El `strip_suffix('.')` sobre el head deja el caso degenerado del sufijo vacío
    /// (dirección literal `"*."`) fiel: `W == ""` casa `D` sólo si `D` termina en `'.'` (o `D == ""`),
    /// exactamente como el walk del oráculo sobre `range+2 == ""`.
    pub(super) fn suffix_matches(&self, domain: &str) -> bool {
        self.suffix == domain
            || domain
                .strip_suffix(self.suffix.as_str())
                .and_then(|head| head.strip_suffix('.'))
                .is_some()
    }

    /// Whitelist de origen — idéntica a [`InterceptEntry::source_allowed`].
    fn source_allowed(&self, src_ip: IpAddr) -> bool {
        match &self.allowed_sources {
            None => true,
            Some(cidrs) => cidrs.iter().any(|c| c.contains(&src_ip)),
        }
    }
}
