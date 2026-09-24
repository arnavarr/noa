//! El pool circular de IP sintética: `IpPool` + su `impl` (`seed` + `allocate`). Autocontenido
//! (aritmética de CIDR + escaneo circular con guard de agotamiento) — no referencia `DnsMatcher`/
//! `DnsEntry`/`check_name` (F6 tramo 15 troceo).

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// Pool circular de IPs sintéticas IPv4 dentro de un rango CIDR. Espejo de `seed_dns`+`next_ipv4`
/// (`ziti_dns.c:120-179`, ver el doc del módulo para el differential y las divergencias conscientes
/// de `seed`).
#[derive(Debug, Clone)]
pub(super) struct IpPool {
    base: u32,
    counter: u32,
    counter_mask: u32,
    capacity: u32,
}

impl IpPool {
    /// Siembra desde un CIDR IPv4 `"n.n.n.n/m"`. `None` si el CIDR es sintácticamente inválido, o
    /// degenerado (`/0`, `/32` — ver el doc del módulo).
    pub(super) fn seed(cidr: &str) -> Option<Self> {
        let net: Ipv4Net = cidr.parse().ok()?;
        let bits = u32::from(net.prefix_len());
        if !(1..=31).contains(&bits) {
            return None;
        }
        let host_bits = 32 - bits;
        let counter_mask = u32::MAX >> (32 - host_bits);
        let base = u32::from(net.addr()) & !counter_mask;
        let capacity = (1u32 << host_bits) - 2;
        Some(Self {
            base,
            counter: 1,
            counter_mask,
            capacity,
        })
    }

    /// Próximo candidato circular libre según `is_occupied` + `occupied_count` (el tamaño actual del
    /// mapa reverso del llamante — espejo de `model_map_size(&ziti_dns.ip_addresses)`, el chequeo de
    /// agotamiento rápido de `ziti_dns.c:124-128` antes de escanear). Escanea como mucho `capacity`
    /// candidatos distintos por llamada (el contador cicla sin repetir dentro de una vuelta), nunca
    /// produce la dirección de red (host-bits=0, el contador arranca en 1) ni la de broadcast (se
    /// resetea a 1 justo ANTES de alcanzar `counter_mask`, ese valor de host-bits nunca se usa).
    /// Desviación consciente no-observable: el gate rápido usa `>=` donde el oráculo usa `==`
    /// (`:124`) — `occupied_count > capacity` solo es construible reservando IPs FUERA del rango del
    /// pool (ningún camino de producción: `main.rs` reserva utun/dns DENTRO del CIDR); en ese estado
    /// el oráculo escanearía las `capacity` vueltas y fallaría igual, nosotros fallamos rápido —
    /// mismo observable (`None`) en todo estado.
    pub(super) fn allocate(
        &mut self,
        occupied_count: usize,
        is_occupied: impl Fn(Ipv4Addr) -> bool,
    ) -> Option<Ipv4Addr> {
        if u32::try_from(occupied_count).unwrap_or(u32::MAX) >= self.capacity {
            return None;
        }
        for _ in 0..self.capacity {
            let candidate = self.base | (self.counter & self.counter_mask);
            self.counter += 1;
            if self.counter == self.counter_mask {
                self.counter = 1;
            }
            let addr = Ipv4Addr::from(candidate);
            if !is_occupied(addr) {
                return Some(addr);
            }
        }
        None
    }
}
