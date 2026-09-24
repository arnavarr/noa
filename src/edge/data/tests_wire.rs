//! Split test module (F6 tramo 1b), byte-identical bodies.
use super::testsupport::*;
use super::wire::{header_i32, header_u32};

// ───────────────────────── OIDC-2: UpdateToken wire (ct 60803) ─────────────────────────

/// Byte-exact: an `UpdateToken` is ct 60803, body = the raw token BYTES, with NO headers (the
/// caller sets `sequence` at send time). Oracle: `NewUpdateTokenMsg` = `NewMessage(60803, token)`.
#[test]
fn build_update_token_is_ct_60803_body_token_no_headers() {
    let msg = build_update_token(b"ey.access.jwt");
    assert_eq!(msg.content_type, 60803);
    assert_eq!(msg.content_type, CT_UPDATE_TOKEN);
    assert_eq!(msg.body, b"ey.access.jwt");
    assert!(
        msg.headers.is_empty(),
        "UpdateToken carries the token in the BODY, no headers"
    );
}

/// The success/failure content-type constants match the protobuf enum (60801/60802).
#[test]
fn update_token_reply_constants_match_oracle() {
    assert_eq!(CT_UPDATE_TOKEN_SUCCESS, 60801);
    assert_eq!(CT_UPDATE_TOKEN_FAILURE, 60802);
}

/// The production budget is 10s (oracle `erConn.UpdateToken(token, 10*time.Second)`, `ziti.go:981`).
#[test]
fn update_token_timeout_is_ten_seconds() {
    assert_eq!(UPDATE_TOKEN_TIMEOUT, Duration::from_secs(10));
}

/// `build_latency_probe` is `CT_LATENCY`(3) with a single `probeTime`(128) header and an empty body.
#[test]
fn build_latency_probe_is_ct_3_with_probe_time_header() {
    let msg = build_latency_probe(0x0102_0304_0506_0708);
    assert_eq!(msg.content_type, CT_LATENCY);
    assert_eq!(CT_LATENCY, 3);
    assert!(msg.body.is_empty());
    assert_eq!(
        msg.headers.get(&HDR_PROBE_TIME).unwrap().as_slice(),
        &0x0102_0304_0506_0708u64.to_le_bytes()
    );
}

/// Production probe cadence is pinned to the oracle's `LatencyCheckInterval`/`Timeout` (ziti.go:74-75).
#[test]
fn latency_probe_constants_match_oracle() {
    assert_eq!(LATENCY_CHECK_INTERVAL, Duration::from_secs(30));
    assert_eq!(LATENCY_CHECK_TIMEOUT, Duration::from_secs(10));
}

// ───────────────── qw-wire-header-len: longitud EXACTA de los headers enteros ─────────────────

/// `T-1`: barrido del dominio ENTERO de `v.len()` para los DOS lectores de headers enteros del
/// módulo. El predicado del oráculo es de longitud EXACTA, no de longitud MÍNIMA:
/// `Headers.GetUint32Header` hace `if !ok || len(encoded) != 4 { return 0, false }`
/// (`channel/v4@v4.3.9 message.go:216-223`), y `header_i32` — que no tiene homónimo en el paquete
/// (`grep Int32Header` sobre `channel@v4.3.9` ⇒ 0 hits) — se adjudica por la MISMA clase
/// (`:201-208`, `:216-223`, `:231-238`, anchura exacta del tipo) y por su único consumidor real, la
/// correlación por `ReplyFor`, que también exige exactamente 4 bytes.
///
/// Las dos filas DECISIVAS son `len == 5` y `len == 8`: con el predicado viejo (`len() >= 4`) los
/// helpers TRUNCABAN y devolvían `Some(1)`; con `== 4` devuelven `None`, que es el `(0, false)` del
/// oráculo. Las filas `0`/`1`/`3` cubren el lado INFERIOR de la frontera (ahí los dos predicados ya
/// coincidían) y la fila de SIGNO separa los dos helpers, que si no compartirían todos los asserts.
///
/// MUTACIÓN ASESINA: devolver `v.len() >= 4` en cualquiera de los dos helpers ⇒ la fila `len == 5`
/// de ESE helper da `Some(1)`. Son DOS sedes independientes y sus mutaciones son SEPARADORAS: se
/// distinguen por el ASERTO del panic, no por el nombre del test — MEDIDO, `header_u32` mata en su
/// `assert_eq!` (mensaje `u32: len …`) y `header_i32` en el suyo (`i32: len …`), sedes distintas y
/// ordenadas del MISMO bucle (u32 antes que i32); ancladas por su literal, no por su línea, porque el
/// número se desplaza al crecer este doc-comment. ⚠ Este test agrupa el dominio ENTERO
/// en UN `#[test]` secuencial, así que bajo cada mutación solo ACREDITA las filas ANTERIORES al
/// aserto que panica: la fila `len == 8` y la de SIGNO quedan detrás y son INFERIDAS, no medidas.
/// Mutación del otro lado: `v.len() <= 4` ⇒ MEDIDO, panica en `wire.rs` con
/// `range end index 4 out of range for slice of length 0` (el `v[..4]` sobre un slice más corto) en
/// la PRIMERA fila corta, `len == 0`; es un panic de índice en runtime, no un `assert_eq` fallado ni
/// un error de compilación.
#[test]
fn header_u32_and_i32_accept_exactly_four_bytes_over_the_whole_domain() {
    const KEY: i32 = 1000;

    // header AUSENTE (el mapa vacío): la clase que el oráculo hace INDISTINGUIBLE de la longitud
    // mal formada — las dos son `(0, false)`.
    let absent = Message::new(CT_DATA, vec![]);
    assert_eq!(header_u32(&absent, KEY), None, "u32: header ausente");
    assert_eq!(header_i32(&absent, KEY), None, "i32: header ausente");

    // (bytes del header, esperado u32, esperado i32)
    let table: &[(&[u8], Option<u32>, Option<i32>)] = &[
        (&[], None, None),                       // len 0
        (&[1], None, None),                      // len 1 (la frontera del vec![1u8] saliente)
        (&[1, 0, 0], None, None),                // len 3 (frontera inferior)
        (&[1, 0, 0, 0], Some(1), Some(1)),       // len 4: el ÚNICO valor legítimo
        (&[1, 0, 0, 0, 9], None, None),          // len 5: frontera superior, +1
        (&[1, 0, 0, 0, 0, 0, 0, 0], None, None), // len 8
    ];
    for (bytes, want_u32, want_i32) in table {
        let mut msg = Message::new(CT_DATA, vec![]);
        msg.headers.insert(KEY, (*bytes).to_vec());
        assert_eq!(
            header_u32(&msg, KEY),
            *want_u32,
            "u32: len {} => {want_u32:?}",
            bytes.len()
        );
        assert_eq!(
            header_i32(&msg, KEY),
            *want_i32,
            "i32: len {} => {want_i32:?}",
            bytes.len()
        );
    }

    // Fila de SIGNO: el mismo vector de 4 bytes se decodifica distinto por helper, así que
    // `header_i32` tiene un aserto que `header_u32` no puede dar (y viceversa).
    let mut signed = Message::new(CT_DATA, vec![]);
    signed
        .headers
        .insert(KEY, 0xFFFF_FFFFu32.to_le_bytes().to_vec());
    assert_eq!(header_u32(&signed, KEY), Some(u32::MAX), "u32: 0xFFFFFFFF");
    assert_eq!(header_i32(&signed, KEY), Some(-1), "i32: 0xFFFFFFFF => -1");
}
