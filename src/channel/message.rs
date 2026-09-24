//! Codec del wire OpenZiti channel V2 (puro, sin IO). Oráculo: channel/message.go.
//!
//! Formato (little-endian, sección fija de 20 bytes):
//! `magic[4]=03 06 09 0c` + `content-type:i32` + `sequence:i32` + `headers-length:i32`
//! + `body-length:i32`, luego headers (TLV `key:i32`+`len:i32`+data) y body.

use std::collections::BTreeMap;

use crate::channel::error::ChannelError;

/// Marcador de versión del framing V2.
pub const MAGIC_V2: [u8; 4] = [0x03, 0x06, 0x09, 0x0c];
/// Marcador de "unknown version response" (el peer no acepta la versión enviada).
pub const MAGIC_UNKNOWN_VERSION: [u8; 4] = [0x03, 0x06, 0x09, 0x0a];
/// Tamaño fijo de la sección de mensaje (magic + 4 campos i32).
pub const DATA_SECTION_V2: usize = 20;
/// Cap defensivo de lectura (el oráculo `ReadV2` no tiene cap; nosotros sí, por seguridad).
pub const MAX_DATA_SECTION: u32 = 1 << 20;

// Content types (core del canal). Oráculo: channel/messages.go:19-27.
pub const CT_HELLO: i32 = 0;
pub const CT_PING: i32 = 1;
pub const CT_RESULT: i32 = 2;
/// Sonda de latencia (request). Oráculo `channel/v4 messages.go:23` `ContentTypeLatencyType`.
/// El SDK la envía periódicamente como detector de muerte INDEPENDIENTE del rx-loop; el router
/// responde con un `Result` correlado por `ReplyFor` (router `LatencyHandler` → `NewResult+ReplyTo`).
pub const CT_LATENCY: i32 = 3;
/// Respuesta de latencia dedicada (`ContentTypeLatencyResponseType`, `:24`). El edge router NO la usa
/// (su `LatencyHandler` responde con un `CT_RESULT` + `ReplyTo`); la definimos por completitud del wire.
/// Correlamos por `HDR_REPLY_FOR`, así que el tipo del reply es indiferente.
pub const CT_LATENCY_RESPONSE: i32 = 4;

// Header IDs (core del canal). Oráculo: channel/message.go:41-54.
pub const HDR_CONNECTION_ID: i32 = 0;
pub const HDR_REPLY_FOR: i32 = 1;
pub const HDR_RESULT_SUCCESS: i32 = 2;
pub const HDR_HELLO_VERSION: i32 = 4;
pub const HDR_ID: i32 = 8;
/// Timestamp de envío de la sonda de latencia (uint64 nanos). Oráculo `channel/v4 latency/latency.go:27`
/// (`probeTime = 128`). Es un **reflected header** (`128 & ReflectedHeaderBitMask(1<<7) != 0`, `<= 255`),
/// así que el `ReplyTo` del router lo COPIA de vuelta → la medición de latencia SÍ está disponible en
/// canales edge; deliberadamente NO la consumimos (scoring DIFERIDO por decisión, no por imposibilidad).
pub const HDR_PROBE_TIME: i32 = 128;

// Predicado del REFLEJO de headers en una respuesta (`ReplyTo`, `channel/v4@v4.3.9
// message.go:390-399`: `if key&ReflectedHeaderBitMask != 0 && key <= MaxReflectedHeader`). Viven
// aquí, junto a [`HDR_REPLY_FOR`], porque son del CANAL: su sede en el oráculo es
// `channel/v4 message.go:57-58`, NO `ziti/edge/`.
//
// ⚠ El comentario del oráculo (`«Headers in the range 128-255 inclusive will be reflected»`,
// `message.go:56`) NO describe su propio predicado: la clave es `int32` (`type Headers
// map[int32][]byte`, `message.go:193`), así que toda clave NEGATIVA con el bit 7 puesto TAMBIÉN
// refleja (`-1` refleja; `-129` no). Se porta el PREDICADO LITERAL, no el comentario — medido con
// el golden `tests/fixtures/conninspect_golden.json` (vector `V4-reflect-all-frontiers`).
/// Bit que marca un header reflejable. Oráculo: `channel/v4@v4.3.9/message.go:57`.
pub const REFLECTED_HEADER_BIT_MASK: i32 = 1 << 7;
/// Techo del reflejo. Oráculo: `channel/v4@v4.3.9/message.go:58`.
pub const MAX_REFLECTED_HEADER: i32 = (1 << 8) - 1;

/// Secuencia del Hello. Oráculo: channel/channel.go:210 (`HelloSequence = -1`).
pub const HELLO_SEQUENCE: i32 = -1;

/// Un mensaje del canal V2. `headers` usa `BTreeMap` (orden por clave determinista;
/// el oráculo itera un mapa Go sin orden, pero el lector es orden-independiente).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub content_type: i32,
    pub sequence: i32,
    pub headers: BTreeMap<i32, Vec<u8>>,
    pub body: Vec<u8>,
}

impl Message {
    /// Nuevo mensaje con `sequence = -1` (como `NewMessage` del oráculo).
    #[must_use]
    pub fn new(content_type: i32, body: Vec<u8>) -> Self {
        Self {
            content_type,
            sequence: -1,
            headers: BTreeMap::new(),
            body,
        }
    }

    /// Serializa a bytes del wire V2 (little-endian).
    #[must_use]
    pub fn marshal_v2(&self) -> Vec<u8> {
        let mut hdr = Vec::new();
        for (k, v) in &self.headers {
            let len = u32::try_from(v.len()).expect("header value fits u32");
            hdr.extend_from_slice(&k.to_le_bytes());
            hdr.extend_from_slice(&len.to_le_bytes());
            hdr.extend_from_slice(v);
        }
        let hlen = u32::try_from(hdr.len()).expect("headers section fits u32");
        let blen = u32::try_from(self.body.len()).expect("body fits u32");

        let mut out = Vec::with_capacity(DATA_SECTION_V2 + hdr.len() + self.body.len());
        out.extend_from_slice(&MAGIC_V2);
        out.extend_from_slice(&self.content_type.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&hlen.to_le_bytes());
        out.extend_from_slice(&blen.to_le_bytes());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&self.body);
        out
    }
}

/// Lee magic + longitudes de una sección de 20 bytes. Valida el magic y aplica el cap.
///
/// # Errors
/// `ChannelError::Frame` si la sección es corta, el magic no es V2 (incluida la respuesta
/// `unknown-version`), o las longitudes superan [`MAX_DATA_SECTION`].
pub fn frame_lengths(section: &[u8]) -> Result<(u32, u32), ChannelError> {
    if section.len() < DATA_SECTION_V2 {
        return Err(ChannelError::Frame(format!(
            "short message section: {} < {DATA_SECTION_V2}",
            section.len()
        )));
    }
    if section[0..4] == MAGIC_UNKNOWN_VERSION {
        return Err(ChannelError::Frame(
            "router replied with unknown-version response (V2 not accepted)".into(),
        ));
    }
    if section[0..4] != MAGIC_V2 {
        return Err(ChannelError::Frame(format!(
            "bad magic: {:02x?}",
            &section[0..4]
        )));
    }
    let headers_length = u32::from_le_bytes(section[12..16].try_into().unwrap());
    let body_length = u32::from_le_bytes(section[16..20].try_into().unwrap());
    if headers_length.saturating_add(body_length) > MAX_DATA_SECTION {
        return Err(ChannelError::Frame(format!(
            "message too large: headers={headers_length} body={body_length}"
        )));
    }
    Ok((headers_length, body_length))
}

/// Parsea un frame V2 COMPLETO (sección + data) desde un buffer.
///
/// # Errors
/// `ChannelError::Frame` si el buffer es más corto que `20 + headers + body` o los headers
/// están truncados.
pub fn parse_frame(full: &[u8]) -> Result<Message, ChannelError> {
    let (hlen, blen) = frame_lengths(full)?;
    let hlen = hlen as usize;
    let blen = blen as usize;
    let total = DATA_SECTION_V2 + hlen + blen;
    if full.len() < total {
        return Err(ChannelError::Frame(format!(
            "short frame: {} < {total}",
            full.len()
        )));
    }
    let content_type = i32::from_le_bytes(full[4..8].try_into().unwrap());
    let sequence = i32::from_le_bytes(full[8..12].try_into().unwrap());
    let headers = parse_headers(&full[DATA_SECTION_V2..DATA_SECTION_V2 + hlen])?;
    let body = full[DATA_SECTION_V2 + hlen..total].to_vec();
    Ok(Message {
        content_type,
        sequence,
        headers,
        body,
    })
}

fn parse_headers(data: &[u8]) -> Result<BTreeMap<i32, Vec<u8>>, ChannelError> {
    let mut out = BTreeMap::new();
    let mut i = 0usize;
    while i < data.len() {
        if i + 8 > data.len() {
            return Err(ChannelError::Frame("truncated header meta-data".into()));
        }
        let key = i32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        let len = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap()) as usize;
        if i + 8 + len > data.len() {
            return Err(ChannelError::Frame("truncated header data".into()));
        }
        out.insert(key, data[i + 8..i + 8 + len].to_vec());
        i += 8 + len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El Hello real que `er1` aceptó en el de-risk (header 1002 = token de api-session,
    /// body = CN del leaf). Con un solo header el orden TLV es determinista, así que la
    /// comparación byte-a-byte contra el frame real es una puerta de equivalencia válida.
    #[test]
    fn marshal_v2_matches_real_hello_fixture() {
        let token = "cdb8dc09-2d47-4111-9599-9bce4324ae79"; // 36 bytes
        let cn = "PU61hCaVsk";
        let mut headers = BTreeMap::new();
        headers.insert(1002_i32, token.as_bytes().to_vec());
        let mut msg = Message::new(CT_HELLO, cn.as_bytes().to_vec());
        msg.sequence = HELLO_SEQUENCE;
        msg.headers = headers;

        let expected = include_bytes!("../../tests/fixtures/channel_hello_sent.bin");
        assert_eq!(msg.marshal_v2(), expected.as_slice());
    }

    #[test]
    fn parse_frame_decodes_real_result_fixture() {
        let bytes = include_bytes!("../../tests/fixtures/channel_result_recv.bin");
        let msg = parse_frame(bytes).expect("real result parses");
        assert_eq!(msg.content_type, CT_RESULT);
        assert_eq!(msg.sequence, HELLO_SEQUENCE);
        // ReplyFor(1) == -1 (0xffffffff) — la correlación va por header, no por el campo sequence.
        assert_eq!(
            msg.headers.get(&HDR_REPLY_FOR).unwrap().as_slice(),
            &[0xff, 0xff, 0xff, 0xff]
        );
        // ResultSuccess(2) primer byte == 1.
        assert_eq!(
            msg.headers.get(&HDR_RESULT_SUCCESS).unwrap().first(),
            Some(&1)
        );
        // Id(8) = id del router er1.
        assert_eq!(msg.headers.get(&HDR_ID).unwrap().as_slice(), b"QbJdVoaq8");
        // HelloVersion(4) empieza por "v2.0.0".
        assert!(
            msg.headers
                .get(&HDR_HELLO_VERSION)
                .unwrap()
                .starts_with(b"v2.0.0")
        );
        assert!(msg.body.is_empty());
    }

    #[test]
    fn parse_frame_rejects_bad_magic() {
        let mut bytes = vec![0u8; DATA_SECTION_V2];
        bytes[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(matches!(parse_frame(&bytes), Err(ChannelError::Frame(_))));
    }

    #[test]
    fn parse_frame_rejects_unknown_version_magic() {
        let mut bytes = vec![0u8; DATA_SECTION_V2];
        bytes[0..4].copy_from_slice(&MAGIC_UNKNOWN_VERSION);
        assert!(matches!(parse_frame(&bytes), Err(ChannelError::Frame(_))));
    }

    #[test]
    fn parse_frame_rejects_short_section() {
        assert!(matches!(
            parse_frame(&[0x03, 0x06, 0x09]),
            Err(ChannelError::Frame(_))
        ));
    }

    #[test]
    fn marshal_then_parse_roundtrips() {
        let mut msg = Message::new(CT_RESULT, b"hi".to_vec());
        msg.sequence = 7;
        msg.headers.insert(HDR_RESULT_SUCCESS, vec![1]);
        msg.headers.insert(99, vec![0xaa, 0xbb]);
        let parsed = parse_frame(&msg.marshal_v2()).unwrap();
        assert_eq!(parsed, msg);
    }
}
