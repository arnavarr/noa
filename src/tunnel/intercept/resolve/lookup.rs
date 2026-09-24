//! `impl InterceptResolver`: el data-path caliente `lookup`/`proxy_service` (resolución por-paquete
//! del dst→servicio) + los accessors `is_empty`/`dns`/`dns_mut` (F6 tramo 2b troceo). Aislado del
//! resto del `impl` para minimizar la superficie re-verificada en vivo. Movido verbatim del monolito de `intercept/resolve`.

use std::net::IpAddr;

use super::{InterceptMatch, InterceptResolver, Protocol};
use crate::tunnel::intercept::dns::DnsMatcher;

impl InterceptResolver {
    /// Resuelve el flujo `(dst_ip, dst_port, proto, src_ip)` al servicio que lo intercepta, o `None`
    /// si ninguno casa (→ el llamante cierra el flujo limpio). FIRST-MATCH en el orden de la lista de
    /// servicios (ver el doc del módulo: el oráculo no define precedencia portable en solapamiento).
    #[must_use]
    pub fn lookup(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: Protocol,
        src_ip: IpAddr,
    ) -> Option<InterceptMatch<'_>> {
        // 1. Match LITERAL (CIDR / hostname exacto → /32). El oráculo puntúa esta rama por delante del
        //    fallback wildcard: `address_match` da score 0 (hostname exacto / CIDR /32) o `bits`-diff,
        //    mientras `match_addr` da el score FIJO 1 (`intercept.c:214-221`), así que un match literal
        //    con score < 1 (exacto/32) gana. Probamos TODO lo literal primero: un match literal sobre la
        //    IP gana a un match por dominio wildcard. DESVIACIÓN consciente (misma clase que el first-match
        //    ya documentado en el doc del módulo): el oráculo dejaría a un CIDR ANCHO (p.ej. /8, score
        //    24 > 1) PERDER contra el fallback wildcard; nosotros mantenemos el first-match literal-primero.
        //    No es over-permit — un CIDR que cubre la IP es un intercept legítimamente configurado hacia
        //    ese servicio; sólo cambia CUÁL de dos servicios autorizados gana el solapamiento (ver el
        //    doc del módulo: la identidad está autorizada para todos los que ve).
        if let Some(m) = self
            .entries
            .iter()
            .find(|e| e.matches(dst_ip, dst_port, proto, src_ip))
            .map(|e| InterceptMatch {
                service: &e.service,
                dial_timeout: e.dial_timeout,
            })
        {
            return Some(m);
        }
        // 2. Fallback por DOMINIO WILDCARD (`intercept_match_addr`): sólo si NINGÚN match literal casó
        //    (espejo de que el oráculo consulta `match_addr` únicamente cuando `address_match` da NULL).
        //    El destino debe ser una IP sintética v4 asignada por una query DNS bajo un dominio wildcard;
        //    `reverse_lookup_domain` devuelve el sufijo bajo el que se asignó. Una IP v6, una IP no
        //    asignada, una RESERVADA (utun/DNS-resolver, `entry->domain == NULL`) o de un hostname EXACTO
        //    (que ya habría despachado por su `/32` en el paso 1) → `None` aquí, sin fallback
        //    (under-dispatch seguro: nunca despachamos una IP que el oráculo no rutearía).
        let IpAddr::V4(v4) = dst_ip else {
            return None;
        };
        let domain = self.dns.reverse_lookup_domain(v4)?;
        self.wildcards
            .iter()
            .find(|w| w.claims(domain, dst_port, proto, src_ip))
            .map(|w| InterceptMatch {
                service: &w.service,
                dial_timeout: w.dial_timeout,
            })
    }

    /// El servicio (y su dial-timeout) para la conexión PROXY-RESOLVE de `domain` (M3-DNS #2):
    /// la primera [`super::WildcardEntry`] cuyo sufijo es EXACTAMENTE `domain` — espejo de
    /// `proxy_domain_req` tomando el PRIMER intercept del set `domain->intercepts` del oráculo
    /// (`model_map_iterator(&domain->intercepts)` → `intercept_resolve_connect(intercept, …)`,
    /// `ziti_dns.c:749-752`). `domain` es el sufijo que [`DnsMatcher::matched_domain`] devolvió
    /// (mismo shape normalizado que `WildcardEntry::suffix`), así que la igualdad byte-a-byte es
    /// el match correcto — sin walk de sufijos (ese ya ocurrió en el gate).
    ///
    /// Dos interpretaciones deterministas de ambigüedades del oráculo (documentadas):
    ///  - el "primer intercept" del oráculo depende del orden de iteración del `model_map` (hash);
    ///    aquí es el primer servicio REGISTRADO que reclama el dominio (orden de `Vec`, estable);
    ///  - `ziti_dial_with_options` no fija timeout propio; usamos el dial-timeout del intercept
    ///    elegido (el mismo que gobernaría un dial de datos de ese servicio, el seam disponible).
    ///
    /// `None` = ningún servicio reclama el dominio (estado inconsistente matcher/resolver — ambos
    /// se construyen del MISMO snapshot — o un dominio evictado): el llamante degrada a SERVFAIL,
    /// espejo del quick-fail State A del oráculo (`resolv_proxy == NULL`, `ziti_dns.c:755-756`).
    #[must_use]
    pub(crate) fn proxy_service(&self, domain: &str) -> Option<InterceptMatch<'_>> {
        self.wildcards
            .iter()
            .find(|w| w.suffix == domain)
            .map(|w| InterceptMatch {
                service: &w.service,
                dial_timeout: w.dial_timeout,
            })
    }

    /// `true` si el resolver no tiene NINGUNA vía de dispatch: ni una entrada literal (servicio
    /// Dial-permitido con un `intercept.v1` IP/CIDR-direccionado o un hostname exacto con IP sintética
    /// asignada) NI una entrada por dominio wildcard (`intercept_match_addr`, M3-DNS #6). Un servicio
    /// con SÓLO dominios wildcard YA cuenta como no-vacío: en cuanto una query DNS resuelve un nombre
    /// bajo ese dominio, [`Self::lookup`] lo despacha por el fallback wildcard (y el subcomando
    /// combinado monta ese servidor DNS en producción, `combined::run_combined_intercept`). Útil
    /// para el llamante (advertir que nada se interceptará).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.wildcards.is_empty()
    }

    /// El [`DnsMatcher`] de este resolver (hostnames/dominios registrados + su pool de IP sintética).
    /// Sin consumidor en ESTA rebanada; hogar natural para un futuro `dst_hostname` (diferido de
    /// M2b-pre) en el punto de dial, que ya recibe este mismo resolver.
    #[must_use]
    pub fn dns(&self) -> &DnsMatcher {
        &self.dns
    }

    /// Acceso MUTABLE al [`DnsMatcher`] — lo consume el servidor DNS embebido (M3-DNS, `dns_server`):
    /// una query bajo un dominio wildcard ASIGNA una IP sintética fresca dentro de
    /// [`DnsMatcher::lookup`], así que el resolver debe prestar el matcher `&mut` a
    /// [`crate::tunnel::intercept::dns_server::handle_query`]. Es el MISMO matcher que puebla el dispatch-table de
    /// hostnames exactos (`from_services_with_dns`), así que una query por un hostname exacto
    /// devuelve la MISMA IP que su entrada `/32` despacha — el server y la tabla comparten estado,
    /// espejo del `ziti_dns` global único del oráculo (el DNS y la tabla de intercept son el mismo
    /// mapa). Una query bajo un dominio wildcard asigna una IP sintética que [`Self::lookup`] YA
    /// despacha por el fallback per-paquete (`intercept_match_addr`, M3-DNS #6, ver el doc de la
    /// struct y [`WildcardEntry`](crate::tunnel::intercept::resolve::WildcardEntry)): reverse-lookup IP→dominio y match contra los `*.dominio` del
    /// servicio. Los hostnames EXACTOS despachan por su `/32`. Ver el doc de [`crate::tunnel::intercept::dns_server`].
    pub fn dns_mut(&mut self) -> &mut DnsMatcher {
        &mut self.dns
    }
}
