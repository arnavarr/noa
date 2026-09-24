//! El parser: [`ParsedQuery`] + `parse_query` (deserializa un datagrama UDP real, fail-closed
//! sobre las zonas UB del oráculo) + `parsed_query_parts` (seam de test, consumido por
//! `proxy_resolve/tests_codec.rs`).

use super::types::{DNS_BUF, DNS_HEADER_LEN};

/// Una query parseada (espejo del subconjunto de `dns_message` que el routing consume).
pub(super) struct ParsedQuery {
    /// El flag RD (`DNS_FLAG_RD`, bit 0x0100). Gobierna el forward a upstream (M3-DNS #1):
    /// `query_upstream` solo reenvía si `avail && req->msg.recursive` (`ziti_dns.c:853`) — sin RD,
    /// un miss responde REFUSE aunque haya upstream configurado.
    pub(super) recursive: bool,
    /// El tipo de la pregunta (u16 BE tras el nombre).
    pub(super) qtype: u16,
    /// El nombre en forma punteada: los bytes CRUDOS de cada label unidos con `'.'` (espejo del
    /// rebuild de `parse_dns_q:37-46` — SIN normalizar; `check_name` normaliza después dentro
    /// del matcher). Bytes arbitrarios: puede no ser UTF-8.
    pub(super) name: Vec<u8>,
    /// El `strlen()` C del nombre punteado: la posición del primer byte `0x00`, o la longitud
    /// total si no hay ninguno. `format_resp` dimensiona la sección de pregunta con
    /// `strlen(name) + 2 + 4` (`ziti_dns.c:544`) — un label con un `0x00` embebido acorta la
    /// copia EXACTAMENTE como en C, y se replica.
    pub(super) name_strlen: usize,
}

/// Parsea el request (espejo de `parse_dns_req` + `parse_dns_q` con bounds fail-closed, ver el
/// doc del módulo). `None` = descartar sin responder.
pub(super) fn parse_query(packet: &[u8]) -> Option<ParsedQuery> {
    // Divergencia consciente: <12 bytes o >4096 bytes son UB en el oráculo (lectura OOB /
    // desbordamiento del memcpy a req[4096]) → Drop limpio.
    if packet.len() < DNS_HEADER_LEN || packet.len() > DNS_BUF {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    // DNS_FLAG_QR (0x8000): una RESPUESTA no se procesa (parse_dns_req:56 → -1 → drop).
    if flags & 0x8000 != 0 {
        return None;
    }
    // qdcount != 1 → -1 → drop (parse_dns_req:58-59).
    if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return None;
    }
    let recursive = flags & 0x0100 != 0;

    // parse_dns_q: labels → dotted. El oráculo NO comprueba límites (UB si un label sale del
    // buffer) → aquí cada avance se comprueba (fail-closed). Un byte de longitud 0xC0.. DENTRO
    // del paquete es una longitud literal también en el oráculo (determinista) y se replica.
    let mut name = Vec::new();
    let mut p = DNS_HEADER_LEN;
    loop {
        let len = usize::from(*packet.get(p)?);
        if len == 0 {
            break;
        }
        let label = packet.get(p + 1..p + 1 + len)?;
        if !name.is_empty() {
            name.push(b'.');
        }
        name.extend_from_slice(label);
        p += 1 + len;
    }
    // Tras el 0 terminador: type (u16 BE) + class (u16 BE).
    let tail = packet.get(p + 1..p + 5)?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let class = u16::from_be_bytes([tail[2], tail[3]]);
    // Clase != IN: parse_dns_q devuelve -1 pero parse_dns_req lo IGNORA y el routing deref-ea un
    // name NULL (UB, crash) → divergencia consciente: Drop limpio.
    if class != 1 {
        return None;
    }
    let name_strlen = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    Some(ParsedQuery {
        recursive,
        qtype,
        name,
        name_strlen,
    })
}

/// Solo-tests: las piezas de una query parseada `(id, rd, nombre_crudo, qtype, name_strlen)` —
/// el seam que los differentials del JSON ([`crate::tunnel::intercept::proxy_resolve`]) usan para derivar los inputs
/// del emisor EXACTAMENTE como los deriva [`crate::tunnel::intercept::dns_server::handle_query`] (mismo parseo, sin duplicar el parser).
#[cfg(test)]
pub(crate) fn parsed_query_parts(packet: &[u8]) -> Option<(u16, bool, Vec<u8>, u16, usize)> {
    let q = parse_query(packet)?;
    Some((
        u16::from_be_bytes([packet[0], packet[1]]),
        q.recursive,
        q.name,
        q.qtype,
        q.name_strlen,
    ))
}
