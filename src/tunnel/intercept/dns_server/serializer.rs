//! El serializador: `format_name` + `c_str` + `format_resp_answers` + `format_resp` — espejo byte
//! a byte de `format_resp`/`format_name` del oráculo, con TODOS los quirks (truncación `SET_U8`,
//! punteros de compresión fijos, guards saturados). AUTOCONTENIDO salvo tipos.

use std::net::Ipv4Addr;

use super::types::{
    DNS_A_TTL, DNS_BUF, DNS_HEADER_LEN, DNS_NO_ERROR, DNS_OPT, NS_T_A, NS_T_MX, NS_T_SRV, NS_T_TXT,
    RespAnswer,
};

/// `format_name` (`ziti_dns.c:511-531`): nombre punteado → labels de cable, SIN compresión.
/// Quirks replicados a propósito:
///  - la longitud de label es `uint8_t` (`uint8_t len = dot - np`): un label de >255 bytes TRUNCA
///    su byte de longitud mod 256 y copia SOLO esos bytes, pero salta el label ENTERO (`np = dot+1`);
///    un label de exactamente 256 da `len == 0` → corta el nombre ahí (rama del label vacío);
///  - un label VACÍO (nombre `""`, un `..` interior, o el punto FINAL) escribe su `0` y CORTA el
///    nombre en ese punto (el `if (len == 0) break`);
///  - un nombre sin punto final recibe su `0` terminador tras el último label.
fn format_name(out: &mut Vec<u8>, name: &[u8]) {
    let mut np = name;
    loop {
        let dot = np.iter().position(|&b| b == b'.');
        #[allow(clippy::cast_possible_truncation)] // uint8_t len = …: la truncación ES el espejo
        let len = dot.unwrap_or(np.len()) as u8;
        out.push(len);
        if len == 0 {
            break;
        }
        out.extend_from_slice(&np[..usize::from(len)]);
        match dot {
            None => {
                out.push(0);
                break;
            }
            Some(d) => np = &np[d + 1..],
        }
    }
}

/// La vista C-string de `data`: los bytes hasta el primer `0x00` (todo uso de `a->data` en el
/// oráculo es vía `strlen`/`strchr`/`memcpy` sobre `char*` — un NUL interior corta).
fn c_str(data: &str) -> &[u8] {
    let b = data.as_bytes();
    &b[..b.iter().position(|&x| x == 0).unwrap_or(b.len())]
}

/// Serializa la respuesta (espejo BYTE a byte de `format_resp`, `ziti_dns.c:533-646`). `answers` es
/// la sección answer a emitir: `None` = `msg.answer == NULL` (el bloque NO corre y el ANCOUNT del
/// request hace passthrough); `Some(&[])` = un array PRESENTE pero vacío (el bloque corre y escribe
/// ANCOUNT=0 — distinguible del passthrough con un request de ANCOUNT sucio, quirk replicado).
/// `addr` = `req->addr`: la IP que la rama A escribe en el cable — la del registro local en el
/// camino `process_host_req`, y `0.0.0.0` (nunca asignada) para un answer A injertado por el proxy
/// (M3-DNS #2), quirk del oráculo replicado.
///
/// Quirks del oráculo replicados a propósito (además de los de [`format_name`]):
///  - la cabecera del request se copia VERBATIM y solo se orquestan bits encima: QDCOUNT (bytes
///    4-5), ANCOUNT (6-7) y NSCOUNT (8-9) del REQUEST sobreviven en la respuesta salvo que el
///    camino los pise (ANCOUNT solo se escribe cuando el bloque de respuesta corre; NSCOUNT nunca);
///    los bits de rcode se OR-ean sobre los que trajera el request (`DNS_SET_CODE` es `|=`);
///  - la sección de pregunta se copia con `strlen(name) + 2 + 4` bytes desde el offset 12 — para
///    una query de nombre VACÍO eso copia 1 byte de más que la pregunta real; como el buffer del
///    request del oráculo es calloc'd (cero-relleno más allá de `q_len`), el byte extra es
///    SIEMPRE `0x00` y aquí se lee de la misma vista cero-rellenada (determinista, portable);
///  - ARCOUNT (bytes 10-11) se fuerza a 1 SIEMPRE (`DNS_SET_AARS(resp, 1)`) y el OPT de 11 bytes
///    se anexa solo si queda sitio — con lo que un ARCOUNT=1 sin OPT es posible en el borde;
///  - el bit RA se pone en TODA respuesta formateada localmente SI Y SOLO SI el socket upstream
///    está activo (`recursion_avail = uv_is_active(&ziti_dns.upstream)`, `ziti_dns.c:539-542`) —
///    `recursion_available` es el espejo de ese estado (M3-DNS #1); sin upstream, NUNCA;
///  - `ans_count++` va ANTES de los guards: un registro que NO cupo SÍ cuenta en ANCOUNT, y se
///    pone TC; en las ramas MX/SRV la truncación deja además los 2 bytes CERO del hueco de
///    rdlength ya "escritos" (`rp += 2` antes del guard, buffer calloc'd) — replicado; en la rama
///    A deja el prefijo de 10 bytes huérfano;
///  - un `a->type` sin rama (AAAA incluido — el switch no lo tiene) cae al `default`: el oráculo
///    LOGUEA y SIGUE, dejando el registro SIN rdlength/rdata (prefijo de 10 bytes malformado) y
///    contándolo en ANCOUNT — replicado;
///  - TXT: el byte de longitud del char-string es `SET_U8` (solo el byte bajo de `txtlen`), pero
///    el `memcpy` copia `txtlen` (u16) bytes y el RDLENGTH es `1+txtlen` — un data de >255 bytes
///    emite un TXT malformado determinista, replicado.
///
/// **Divergencia consciente (guards saturados sobre la zona UB del oráculo):** con una pregunta
/// cercana a los 4096 bytes, el eco de la pregunta del oráculo (`memcpy` de `strlen(name)+2+4`
/// bytes sobre `resp[4096]`, `:544-545`) puede DESBORDAR su buffer (heap overflow, UB) — aquí el
/// eco se emite entero (el `Vec` crece) y los guards de sitio usan resta SATURADA: más allá de
/// 4096 todo guard "no cabe" (truncation/sin-OPT), nunca aritmética desbordada ni panic.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // SET_U16/SET_U32: el espejo
pub(crate) fn format_resp_answers(
    packet: &[u8],
    name_strlen: usize,
    status: u8,
    answers: Option<&[RespAnswer]>,
    addr: Ipv4Addr,
    recursion_available: bool,
) -> Vec<u8> {
    // La vista cero-rellenada del request (espejo del `req[4096]` calloc'd).
    let req_byte = |i: usize| -> u8 { packet.get(i).copied().unwrap_or(0) };

    let mut resp = Vec::with_capacity(DNS_BUF.min(packet.len() + 64));
    // Cabecera verbatim + bits.
    resp.extend((0..DNS_HEADER_LEN).map(&req_byte));
    resp[2] |= 0x80; // DNS_SET_ANS (QR=respuesta)
    resp[3] |= status & 0x0f; // DNS_SET_CODE (OR sobre los bits del request)
    if recursion_available {
        resp[3] |= 0x80; // DNS_SET_RA — solo con el socket upstream activo (ziti_dns.c:539-542)
    }

    // Sección de pregunta: strlen(name)+2+4 bytes verbatim desde el offset 12 (cero-rellenados).
    let query_section_len = name_strlen + 2 + 4;
    resp.extend((DNS_HEADER_LEN..DNS_HEADER_LEN + query_section_len).map(&req_byte));

    // Bloque de respuesta: SOLO con status NOERROR y answer no-NULL (`:551`).
    if status == DNS_NO_ERROR
        && let Some(answers) = answers
    {
        let mut ans_count: u16 = 0;
        let mut truncated = false;
        'done: for a in answers {
            // ans_count++ ANTES de los guards (quirk: un registro truncado se cuenta igual).
            ans_count = ans_count.wrapping_add(1);
            // Guard del prefijo: 2 (name ref) + 2 (type) + 2 (class) + 4 (ttl).
            if DNS_BUF.saturating_sub(resp.len()) < 10 {
                truncated = true;
                break 'done;
            }
            resp.extend_from_slice(&[0xc0, 0x0c]); // puntero al nombre de la pregunta (offset 12)
            resp.extend_from_slice(&(a.atype as u16).to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes()); // clase IN
            resp.extend_from_slice(&(a.ttl as u32).to_be_bytes());
            match a.atype {
                t if t == i64::from(NS_T_A) => {
                    // Guard rama A: 2 (rdlen) + 4 (addr).
                    if DNS_BUF.saturating_sub(resp.len()) < 2 + 4 {
                        truncated = true;
                        break 'done;
                    }
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&addr.octets());
                }
                t if t == i64::from(NS_T_TXT) => {
                    let data = c_str(&a.data);
                    let txtlen = data.len() as u16; // uint16_t txtlen = strlen (wrap mod 2^16)
                    let datalen = txtlen.wrapping_add(1);
                    if DNS_BUF.saturating_sub(resp.len()) < 3 + usize::from(txtlen) {
                        truncated = true;
                        break 'done;
                    }
                    resp.extend_from_slice(&datalen.to_be_bytes());
                    resp.push((txtlen & 0xff) as u8); // SET_U8: solo el byte bajo (quirk >255)
                    resp.extend_from_slice(&data[..usize::from(txtlen)]);
                }
                t if t == i64::from(NS_T_MX) => {
                    let data = c_str(&a.data);
                    let hold = resp.len();
                    resp.extend_from_slice(&[0, 0]); // rp += 2 (el hueco cero del calloc)
                    let est = (data.len() as u16).wrapping_add(1); // uint16_t datalen_est
                    if DNS_BUF.saturating_sub(hold) < 4 + usize::from(est) {
                        truncated = true;
                        break 'done;
                    }
                    resp.extend_from_slice(&(a.priority as u16).to_be_bytes());
                    format_name(&mut resp, data);
                    let datalen = ((resp.len() - hold - 2) as u16).to_be_bytes();
                    resp[hold..hold + 2].copy_from_slice(&datalen);
                }
                t if t == i64::from(NS_T_SRV) => {
                    let data = c_str(&a.data);
                    let hold = resp.len();
                    resp.extend_from_slice(&[0, 0]);
                    let est = (data.len() as u16).wrapping_add(1);
                    if DNS_BUF.saturating_sub(hold) < 8 + usize::from(est) {
                        truncated = true;
                        break 'done;
                    }
                    resp.extend_from_slice(&(a.priority as u16).to_be_bytes());
                    resp.extend_from_slice(&(a.weight as u16).to_be_bytes());
                    resp.extend_from_slice(&(a.port as u16).to_be_bytes());
                    format_name(&mut resp, data);
                    let datalen = ((resp.len() - hold - 2) as u16).to_be_bytes();
                    resp[hold..hold + 2].copy_from_slice(&datalen);
                }
                other => {
                    // default (`:628-629`): el oráculo LOGUEA y SIGUE — el registro queda SIN
                    // rdlength/rdata (prefijo de 10 bytes malformado) y cuenta en ANCOUNT.
                    tracing::warn!(
                        atype = other,
                        "dns: tipo de respuesta no manejado (registro sin rdata, como el oráculo)"
                    );
                }
            }
        }
        if truncated {
            resp[2] |= 0x02; // DNS_SET_TC
        }
        // DNS_SET_ARS: ANCOUNT se escribe SOLO cuando este bloque corre (si no, queda el del request).
        resp[6..8].copy_from_slice(&ans_count.to_be_bytes());
    }

    // DNS_SET_AARS(resp, 1): ARCOUNT=1 SIEMPRE, haya o no sitio para el OPT.
    resp[10..12].copy_from_slice(&1u16.to_be_bytes());
    if DNS_BUF.saturating_sub(resp.len()) > 11 {
        resp.extend_from_slice(&DNS_OPT);
    }
    resp
}

/// El caso particular LOCAL de [`format_resp_answers`]: cero o un registro A (`process_host_req` —
/// hit A = un registro con TTL 60 y la IP asignada; hit AAAA / error = sin registros). Se mantiene
/// como wrapper para que los caminos previos (ground truth de 32 casos incluido) queden
/// byte-INTACTOS por construcción.
pub(super) fn format_resp(
    packet: &[u8],
    name_strlen: usize,
    status: u8,
    a_answer: Option<Ipv4Addr>,
    recursion_available: bool,
) -> Vec<u8> {
    match a_answer {
        Some(ip) => format_resp_answers(
            packet,
            name_strlen,
            status,
            Some(&[RespAnswer {
                atype: i64::from(NS_T_A),
                ttl: i64::from(DNS_A_TTL),
                priority: 0,
                weight: 0,
                port: 0,
                // `a->data = strdup(entry->ip)` — el oráculo solo lo loguea; la rama A escribe
                // `req->addr`, no el string.
                data: ip.to_string(),
            }]),
            ip,
            recursion_available,
        ),
        None => format_resp_answers(
            packet,
            name_strlen,
            status,
            None,
            Ipv4Addr::UNSPECIFIED,
            recursion_available,
        ),
    }
}
