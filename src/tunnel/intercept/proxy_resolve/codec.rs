//! El códec del `dns_message` JSON, byte-exacto vs el C en las DOS direcciones: el emisor del
//! request (`MODEL_JSON_COMPACT` + el escaper del writer) y el parser de la respuesta del peer
//! (fail-closed). F6 tramo 12: movido verbatim del monolito de `intercept/proxy_resolve`.

use serde::Deserialize;

use crate::tunnel::intercept::dns_server::RespAnswer;

/// Emite el JSON COMPACTO del request `dns_message` — espejo byte-exacto de
/// `dns_message_to_json(&req->msg, MODEL_JSON_COMPACT, …)` (`proxy_domain_req`, `ziti_dns.c:761`)
/// sobre el mensaje que `parse_dns_req` construyó: `status` 0 (calloc, nunca asignado en este
/// punto), `id`, `recursive` 0/1 (`DNS_FLAG_RD`), UNA question `{name, type}`; `answer`/`comment`
/// NULL → omitidos. `name` = el nombre punteado CRUDO cortado en el primer NUL (la vista C-string
/// del writer; el llamante pasa `&q.name[..q.name_strlen]`) con el case ORIGINAL de la query — la
/// normalización de `check_name` es solo para el matching, el JSON lleva el nombre verbatim.
/// Diferencial: `request_json_equals_dns_message_to_json_c_oracle`.
#[must_use]
pub(crate) fn emit_dns_message_json(id: u16, recursive: bool, name: &[u8], qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + name.len());
    out.extend_from_slice(b"{\"status\":0,\"id\":");
    out.extend_from_slice(id.to_string().as_bytes());
    out.extend_from_slice(b",\"recursive\":");
    out.push(if recursive { b'1' } else { b'0' });
    out.extend_from_slice(b",\"question\":[{\"name\":\"");
    escape_json_c(&mut out, name);
    out.extend_from_slice(b"\",\"type\":");
    out.extend_from_slice(qtype.to_string().as_bytes());
    out.extend_from_slice(b"}]}");
    out
}

/// El escaper de strings del writer C (`m_string_to_json`, `model_support.c`; idéntico
/// 1.15.0/1.16.0): `\n \b \r \t \\ \"` con escape propio, el resto de bytes < 0x20 como `\u00xx`
/// (hex MINÚSCULA), y TODO lo demás VERBATIM — bytes ≥ 0x80 incluidos (el writer no valida UTF-8).
/// El corte en NUL del `while (*s != '\0')` lo garantiza el llamante (pasa el slice ya cortado).
fn escape_json_c(out: &mut Vec<u8>, s: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in s {
        match b {
            b'\n' => out.extend_from_slice(b"\\n"),
            0x08 => out.extend_from_slice(b"\\b"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b if b < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(b >> 4)]);
                out.push(HEX[usize::from(b & 0xf)]);
            }
            b => out.push(b),
        }
    }
}

/// Una respuesta del resolver hostante, parseada del JSON: el `id` con el que casar el pendiente y
/// los answers a injertar. `answers` distingue ausente (`None` = `msg.answer` NULL → el bloque de
/// respuesta no corre, ANCOUNT passthrough) de presente-vacío (`Some(vec![])` → ANCOUNT=0
/// explícito, la variante Windows del peer) — [`format_resp_answers`](crate::tunnel::intercept::dns_server::format_resp_answers) replica ambos.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PeerResponse {
    pub(crate) id: u16,
    pub(crate) answers: Option<Vec<RespAnswer>>,
}

/// El shape del JSON del peer, espejo de `parse_dns_message` → `model_from_json`
/// (`model_support.c:624-679`): itera los campos del modelo `DNS_MSG_MODEL`/`DNS_A_MODEL`
/// (`dns_host.h:57-74`) y un type-mismatch en CUALQUIERA aborta el mensaje ENTERO
/// (`rc = parser(...); if (rc != 0) break;` → `on_proxy_data` `rc < 0` → sin completion). Por eso
/// se declaran TODOS los campos del modelo aunque solo se consuman `id` y `answer`: así serde
/// rechaza un type-mismatch en `status`/`recursive`/`comment`/`question[].name` con el MISMO
/// veredicto que el oráculo (drop del chunk), en vez de ignorarlos como unknown y COMPLETAR un
/// mensaje que el oráculo descarta (un over-emit, cazado por la review reforzada). Un campo FUERA
/// del modelo (no en `DNS_MSG_MODEL`) sí se ignora — el oráculo tampoco lo mira (`json_object_object_get`
/// solo busca los paths del modelo), así que serde sin `deny_unknown_fields` es fiel. `on_proxy_data`
/// solo LEE `id` y `answer` (IGNORA `status`/`recursive`/… — el `status` del peer incluido, quirk);
/// los demás campos se declaran para VALIDARLOS, no para usarlos.
///
/// Divergencia consciente (misma clase que el drop-del-chunk): un campo del modelo con valor `null`
/// el oráculo lo SALTA (`json_type_null → continue`, `:644`, campo en su default y el mensaje se
/// ACEPTA); serde rechaza `null` en un campo `i64`/`String` no-`Option` → drop. Fail-closed / no
/// alcanzable con un peer conforme (`dns_host.c` emite números y strings planos). Ver el doc del
/// módulo (divergencias del parser del peer).
#[derive(Deserialize)]
#[allow(dead_code)] // status/recursive/comment/question se declaran para VALIDAR, no para leer
pub(super) struct WireMsg {
    #[serde(default)]
    status: i64,
    #[serde(default)]
    id: i64,
    #[serde(default)]
    recursive: i64,
    #[serde(default)]
    question: Vec<WireQuestion>,
    answer: Option<Vec<WireAnswer>>,
    #[serde(default)]
    comment: String,
}

/// El `dns_question` del modelo (`DNS_Q_MODEL`): se valida (type-mismatch en `name`/`type` aborta
/// el mensaje, espejo del C) aunque `on_proxy_data` no lo lea.
#[derive(Deserialize)]
#[allow(dead_code)] // validado, no leído
struct WireQuestion {
    #[serde(default)]
    name: String,
    #[serde(rename = "type", default)]
    atype: i64,
}

#[derive(Deserialize)]
#[allow(dead_code)] // `name` se valida (está en DNS_A_MODEL), no se lee
pub(super) struct WireAnswer {
    #[serde(rename = "type", default)]
    atype: i64,
    #[serde(default)]
    ttl: i64,
    #[serde(default)]
    priority: i64,
    #[serde(default)]
    weight: i64,
    #[serde(default)]
    port: i64,
    #[serde(default)]
    name: String,
    data: Option<String>,
}

/// Los tipos cuya rama de `format_resp` deref-ea `a->data` (`strlen`/`format_name`): sin data el
/// oráculo haría `strlen(NULL)` (UB) → aquí el mensaje entero se rechaza fail-closed.
fn needs_data(atype: i64) -> bool {
    atype == 15 || atype == 16 || atype == 33 // MX, TXT, SRV
}

/// Parsea el chunk de una conn proxy como UNA respuesta `dns_message` (espejo de `on_proxy_data`:
/// un `ziti_write` del peer = un Data frame = un JSON). `None` = descartar el chunk (JSON
/// malformado/no-UTF8, o un answer MX/SRV/TXT sin `data` — ver las divergencias fail-closed del
/// doc del módulo). El `id` es el `uint16_t id = msg.id` del oráculo (`:703`): truncación i64→u16.
#[must_use]
pub(crate) fn parse_peer_response(chunk: &[u8]) -> Option<PeerResponse> {
    let msg: WireMsg = serde_json::from_slice(chunk).ok()?;
    let answers = match msg.answer {
        None => None,
        Some(list) => Some(
            list.into_iter()
                .map(|a| {
                    let data = match a.data {
                        Some(d) => d,
                        None if needs_data(a.atype) => return None,
                        // A/default no leen data (el oráculo solo lo loguearía): placeholder vacío.
                        None => String::new(),
                    };
                    Some(RespAnswer {
                        atype: a.atype,
                        ttl: a.ttl,
                        priority: a.priority,
                        weight: a.weight,
                        port: a.port,
                        data,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
        ),
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // uint16_t id = msg.id
    Some(PeerResponse {
        id: msg.id as u16,
        answers,
    })
}
