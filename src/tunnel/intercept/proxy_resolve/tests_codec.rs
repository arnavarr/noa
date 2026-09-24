//! Los tests del códec: los 2 differential contra los harnesses C reales (request JSON y
//! composición del injerto) + la regresión del over-emit de type-mismatch. F6 tramo 12: movidos
//! verbatim del `mod tests` del monolito de `intercept/proxy_resolve`.

use std::net::Ipv4Addr;

use crate::tunnel::intercept::dns_server::{DNS_NO_ERROR, format_resp_answers, parsed_query_parts};

use super::codec::{emit_dns_message_json, parse_peer_response};

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes_to_hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        write!(s, "{x:02x}").expect("write a String no falla");
    }
    s
}

/// DIFFERENTIAL empírico del JSON del request contra el oráculo C: `dns_message_to_json` REAL
/// (el `model_support` de ziti-sdk-c — writers idénticos 1.15.0/1.16.0, verificado por diff —
/// compilado y linkado en el harness) sobre `parse_dns_req` verbatim @2addfbb, con
/// `MODEL_JSON_COMPACT` (el flag de `proxy_domain_req:761`). Cubre: nombres normales/underscore
/// (SRV), case ORIGINAL verbatim, RD 0/1, ids extremos (0/0xffff), nombre vacío, tipo ANY,
/// los escapes del writer (`\"` `\\` `\t` + control → `\u00xx`), un byte no-UTF8 VERBATIM y el
/// corte en NUL. **0 divergencias.**
#[test]
fn request_json_equals_dns_message_to_json_c_oracle() {
    let cases: &[(&str, &str, &str)] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tunnel/intercept/dns_reqjson_ground_truth.rs"
    ));
    for (name, req_hex, json_hex) in cases {
        let packet = hex_to_bytes(req_hex);
        let (id, recursive, qname, qtype, name_strlen) =
            parsed_query_parts(&packet).expect("las queries del harness parsean");
        let got = emit_dns_message_json(id, recursive, &qname[..name_strlen], qtype);
        assert_eq!(
            bytes_to_hex(&got),
            *json_hex,
            "caso '{name}': el JSON del request debe ser byte-idéntico al del oráculo C"
        );
    }
}

/// DIFFERENTIAL de COMPOSICIÓN contra los dos harnesses C: la respuesta REAL del resolver
/// hostante (`dns_host.c`: `parse_dns_message` de NUESTRO request JSON → status + answers →
/// `dns_message_to_json(flags=0)`, pretty) pasa por NUESTRO parser ([`parse_peer_response`]) y
/// NUESTRO serializador ([`format_resp_answers`] con el injerto del cliente: answers del peer,
/// status DEL REQUEST = 0, `addr` 0.0.0.0) — y el cable resultante debe ser byte-idéntico al
/// `format_resp` C verbatim con los mismos answers. Pinea además los quirks del cliente:
/// el `status` del peer se IGNORA (REFUSED/SERVFAIL del peer → NOERROR nuestro), `answer`
/// ausente vs `[]` (passthrough vs ANCOUNT=0), y los DROP fail-closed nombrados (data ausente
/// en MX/SRV/TXT, data no-UTF8, JSON inválido). **0 divergencias.**
#[test]
fn peer_response_grafting_composes_byte_identical_to_c() {
    let cases: &[(&str, &str, bool, &str, Option<&str>)] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tunnel/intercept/dns_peer_fixtures.rs"
    ));
    for (name, req_hex, ra, peer_json_hex, expect) in cases {
        let packet = hex_to_bytes(req_hex);
        let peer_json = hex_to_bytes(peer_json_hex);
        let parsed = parse_peer_response(&peer_json);
        match expect {
            None => {
                assert!(
                    parsed.is_none(),
                    "caso '{name}': el fixture debe rechazarse fail-closed"
                );
            }
            Some(want_wire) => {
                let resp = parsed.unwrap_or_else(|| {
                    panic!("caso '{name}': la respuesta real del peer debe parsear")
                });
                let (id, _, _, _, name_strlen) =
                    parsed_query_parts(&packet).expect("query del harness");
                assert_eq!(resp.id, id, "caso '{name}': el peer ecoa el id del request");
                let got = format_resp_answers(
                    &packet,
                    name_strlen,
                    DNS_NO_ERROR, // el status del PEER se ignora; el del request sigue 0
                    resp.answers.as_deref(),
                    Ipv4Addr::UNSPECIFIED, // req->addr nunca asignado en el camino proxy
                    *ra,
                );
                assert_eq!(
                    &bytes_to_hex(&got),
                    want_wire,
                    "caso '{name}': el injerto debe componer byte-idéntico al oráculo C"
                );
            }
        }
    }
}

/// Regresión del over-emit que la review reforzada cazó: un type-mismatch en un campo del
/// modelo que NO leemos (`recursive`/`status`/`comment`/`question[].name`) DEBE dropear el
/// mensaje entero, espejo del `if (rc != 0) break` de `model_from_json` (`model_support.c:673`)
/// → `on_proxy_data` `rc<0` → sin completion. Sin declarar esos campos, serde los ignoraría
/// como unknown y COMPLETARÍAMOS un mensaje que el oráculo descarta (over-emit). Un campo FUERA
/// del modelo (que el oráculo tampoco mira) sí se tolera. MUTACIÓN-RED: quitar los campos extra
/// de `WireMsg`/`WireAnswer` reabre el over-emit (estos casos volverían a parsear OK).
#[test]
fn type_mismatch_in_a_model_field_drops_the_whole_message_like_the_oracle() {
    // Type-mismatch en campos que NO leemos → drop (el oráculo rechaza en model_from_json).
    let over_emit_cases: &[&[u8]] = &[
        br#"{"id":8193,"recursive":true,"answer":[{"type":15,"ttl":300,"priority":10,"data":"mx1.example.com"}]}"#,
        br#"{"status":"5","id":8193,"answer":[]}"#,
        br#"{"id":8193,"comment":42,"answer":[]}"#,
        br#"{"id":8193,"question":[{"name":42,"type":15}],"answer":[]}"#,
        br#"{"id":8193,"answer":[{"type":15,"name":99,"data":"m.example.com"}]}"#,
    ];
    for c in over_emit_cases {
        assert!(
            parse_peer_response(c).is_none(),
            "type-mismatch en un campo del modelo debe dropear (paridad con model_from_json): {}",
            std::str::from_utf8(c).unwrap()
        );
    }
    // Campos FUERA del modelo (el oráculo tampoco los mira) → tolerados, se completa.
    let benign = br#"{"id":8193,"totally_unknown_field":true,"answer":[]}"#;
    assert_eq!(
        parse_peer_response(benign).map(|r| r.id),
        Some(8193),
        "un campo fuera del modelo se ignora, como json_object_object_get del oráculo"
    );
    // Un mensaje BIEN tipado con todos los campos presentes se sigue aceptando.
    let ok = br#"{"status":0,"id":8193,"recursive":1,"question":[{"name":"mail.svc.example.com","type":15}],"answer":[{"type":15,"ttl":300,"priority":10,"weight":0,"port":0,"name":"","data":"mx1.example.com"}],"comment":"ok"}"#;
    let r = parse_peer_response(ok).expect("mensaje bien tipado completo se acepta");
    assert_eq!(r.id, 8193);
    assert_eq!(r.answers.as_ref().map(Vec::len), Some(1));
}
