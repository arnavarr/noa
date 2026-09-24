//! Banner 4 del autor: "parse fail-closed (Drop, espejo + divergencias UB)" — F6 tramo 14 troceo:
//! movidos verbatim del `mod tests` del monolito de `intercept/dns_server`. Contiene además los 2
//! differentials byte-exactos contra el harness C real y 1 test de quirk del serializador (el
//! banner del autor es heterogéneo, ver el spec §0.5).

use crate::tunnel::intercept::dns::{DnsMatcher, RegisterOutcome};

use super::parser::parse_query;
use super::testsupport::*;
use super::types::{DNS_REFUSE, NS_T_A};
use super::*;

// ───────────────────────── parse fail-closed (Drop, espejo + divergencias UB) ─────────────────────────

/// Los caminos de Drop: QR puesto (una respuesta), qdcount != 1 (espejo del oráculo), y las
/// divergencias fail-closed sobre UB: paquete corto, clase != IN, label que sale del paquete,
/// cola type/class truncada, y un datagrama de >4096 bytes.
#[test]
fn malformed_or_ub_path_packets_are_dropped_without_a_response() {
    let mut m = matcher_with(&["app.example.com"]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("QR=1 (respuesta)", query(1, 0x8000, "a.b", NS_T_A, 1)),
        ("qdcount=0", {
            let mut p = query(1, 0x0100, "a.b", NS_T_A, 1);
            p[5] = 0;
            p
        }),
        ("qdcount=2", {
            let mut p = query(1, 0x0100, "a.b", NS_T_A, 1);
            p[5] = 2;
            p
        }),
        ("corto (<12)", vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01]),
        ("clase CHAOS (3)", query(1, 0x0100, "a.b", NS_T_A, 3)),
        ("label sale del paquete", {
            let mut p = query(1, 0x0100, "", NS_T_A, 1);
            // Sustituye el 0 terminador por una longitud que apunta fuera.
            p[12] = 63;
            p
        }),
        ("sin type/class tras el nombre", {
            let mut p = query(1, 0x0100, "a.b", NS_T_A, 1);
            p.truncate(p.len() - 3);
            p
        }),
        (">4096 bytes", {
            let mut p = query(1, 0x0100, "a.b", NS_T_A, 1);
            p.resize(4097, 0);
            p
        }),
    ];
    for (why, pkt) in cases {
        assert_eq!(
            handle_query(&mut m, &pkt, false, false),
            DnsAction::Drop,
            "{why}: debe descartarse sin respuesta"
        );
    }
}

/// Un byte de longitud con pinta de puntero de compresión (0xC0..) DENTRO del paquete es una
/// longitud LITERAL también en el oráculo (determinista, no UB) — el nombre resultante no
/// casa nada → REFUSED, no Drop.
#[test]
fn in_bounds_compression_like_length_byte_is_a_literal_label_like_the_oracle() {
    let mut m = matcher_with(&["app.example.com"]);
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1, resto 0
    pkt.push(0xC0); // "puntero" = longitud literal 192
    pkt.extend_from_slice(&[b'x'; 192]);
    pkt.push(0);
    pkt.extend_from_slice(&NS_T_A.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    let resp = respond(&mut m, &pkt);
    assert_eq!(
        rcode(&resp),
        DNS_REFUSE,
        "label de 192 bytes: parsea, no casa, REFUSED"
    );
}

/// Un nombre con bytes no-UTF8 en un label SIN sufijo de dominio registrado: el oráculo lo
/// arrastra como bytes (no casa) y nosotros saltamos el lookup → ambos REFUSED (mismo resultado).
#[test]
fn non_utf8_name_without_a_registered_suffix_is_refused_on_both_sides() {
    let mut m = matcher_with(&["app.example.com"]);
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x0001u16.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&[3, 0xff, 0xfe, 0xfd, 0]); // label de 3 bytes no-UTF8, sin dominio
    pkt.extend_from_slice(&NS_T_A.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    let resp = respond(&mut m, &pkt);
    assert_eq!(rcode(&resp), DNS_REFUSE);
}

/// DIVERGENCIA CONSCIENTE (under-permit seguro, cazada por la revisión reforzada, manifestación
/// A3): un nombre con un byte NO-UTF8 en un label a la IZQUIERDA de un sufijo de dominio ASCII
/// registrado (`\xff.svc.example.com`). El `find_domain` del oráculo casa el sufijo `svc.example.com`
/// y ASIGNA una IP (NOERROR+A); nuestro `str::from_utf8` sobre el nombre cortado falla → REFUSE.
/// Es UNDER-permit (rehusamos una IP que el oráculo asignaría; nunca al revés — con #6 cerrado
/// en `0211810`, en el oráculo ese flujo completaría e2e y en el nuestro falla ANTES, en la
/// resolución DNS). Ver el doc del módulo: cerrarlo exigiría un matcher con claves `Vec<u8>`
/// (re-arquitectura de las rebanadas 1-2), diferido como divergencia nombrada.
#[test]
fn non_utf8_subdomain_over_registered_domain_is_a_conscious_safe_under_permit() {
    let mut m = matcher_with(&["*.svc.example.com"]);
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1262u16.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    pkt.push(1);
    pkt.push(0xff); // label no-UTF8 de 1 byte
    for lab in ["svc", "example", "com"] {
        pkt.push(u8::try_from(lab.len()).unwrap());
        pkt.extend_from_slice(lab.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&NS_T_A.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    let resp = respond(&mut m, &pkt);
    assert_eq!(
        rcode(&resp),
        DNS_REFUSE,
        "under-permit consciente: el oráculo casaría el sufijo ASCII y asignaría IP (NOERROR+A); \
         nosotros REHUSAMOS — seguro (nunca asignamos de más)"
    );
}

/// Regresión del OVER-PERMIT que la revisión reforzada cazó (manifestación A1): un `0x00` embebido
/// en un label DEBE truncar el nombre casado como el C-string del oráculo (`check_name`,
/// `while (*hp != '\0')`), NO usar el nombre completo. Sin el corte, `app\0.svc.example.com`
/// casaría el sufijo `svc.example.com` y ASIGNARÍA una IP que el oráculo (que corta en `app`)
/// REFUSE. Con el corte: `app` → sin match → REFUSE, byte-fiel. MUTACIÓN-RED: usar `&q.name`
/// completo en vez de `&q.name[..name_strlen]` reabre el over-permit (Respond con NOERROR+A).
#[test]
fn embedded_nul_truncates_the_matched_name_closing_the_over_permit() {
    let mut m = matcher_with(&["app.example.com", "*.svc.example.com"]);
    // Label "app\0" (len 4) + svc + example + com, tipo A.
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1260u16.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    pkt.extend_from_slice(&[4, b'a', b'p', b'p', 0]); // label "app\0"
    for lab in ["svc", "example", "com"] {
        pkt.push(u8::try_from(lab.len()).unwrap());
        pkt.extend_from_slice(lab.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&NS_T_A.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    let resp = respond(&mut m, &pkt);
    assert_eq!(
        rcode(&resp),
        DNS_REFUSE,
        "el nombre se trunca en el NUL a `app` → sin match → REFUSE, NO asigna una IP wildcard"
    );
    assert_eq!(
        ancount(&resp),
        0,
        "sin registro A: el over-permit está cerrado"
    );
}

/// Quirk del nombre VACÍO (query por la raíz): `format_resp` dimensiona la pregunta con
/// `strlen("")+2+4 = 6` bytes cuando la pregunta real son 5 — el 6º byte se lee de la vista
/// cero-rellenada (el calloc del oráculo) y es SIEMPRE 0x00. Determinista y replicado.
#[test]
fn empty_name_query_echoes_one_extra_zero_byte_like_the_oracle() {
    let mut m = matcher_with(&["app.example.com"]);
    let pkt = std_query("", NS_T_A); // pregunta real: 1 (raíz) + 4 = 5 bytes
    let resp = respond(&mut m, &pkt);
    assert_eq!(rcode(&resp), DNS_REFUSE, "\"\" no registrado → REFUSED");
    let qlen = 2 + 4; // strlen("")+2+4 = 6: un byte MÁS que la pregunta real (raíz = 1 byte)
    assert_eq!(resp.len(), 12 + qlen + 11, "pregunta de 6 bytes + OPT");
    assert_eq!(
        resp[12 + 5],
        0x00,
        "el byte extra es el cero-relleno del calloc"
    );
}

/// El resultado esperado de un caso differential: la respuesta byte-exacta del oráculo C, un
/// descarte, o un caminho de proxy-diferido (el oráculo va al overlay = `PROXY`; nosotros
/// respondemos el rcode observable del proxy no disponible, ver el doc del módulo).
enum Expect {
    Resp(&'static str),
    Drop,
    ProxyDeferral(u8),
}

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

/// DIFFERENTIAL empírico contra el oráculo C: `parse_dns_req`/`parse_dns_q` (`dns_msg.c`) +
/// `on_dns_req`/`process_host_req`/`format_resp`/`query_upstream`-sin-upstream (`ziti_dns.c`),
/// extracción VERBATIM a un harness `clang -O2` (`ziti-tunnel-sdk-c` @
/// `2addfbbae26be597f7a51359ea6ef069f54f6c43`). El ground truth (los bytes de respuesta EXACTOS
/// del oráculo) está pineado abajo; una divergencia de un solo byte va RED. Cubre: hits A/AAAA,
/// asignación LAZY vía dominio wildcard (+ caché), miss→REFUSED, quirks del serializador
/// (nombre vacío copia un byte cero extra, ANCOUNT/NSCOUNT passthrough, rcode OR, RD irrelevante
/// sin upstream, dig-style OPT en el request ignorado), caminos fail-closed (QR=1/qdcount≠1 =
/// DROP como el oráculo; y las divergencias UB documentadas — corto/clase≠IN/labels OOB — que
/// aquí también son DROP), y label no-UTF8/`0xC0`-literal/nul-embebido. Los 4 casos
/// `ProxyDeferral` son direcciones bajo un dominio con un tipo no-A/AAAA: el oráculo las
/// PROXY-resuelve por el overlay (M3-DNS #2, CERRADO; el harness corre el modo
/// `proxy_available == false`) — pineamos el rcode observable del proxy no disponible
/// (SERVFAIL para MX/SRV/TXT, NOT_IMPL para el resto), NO los bytes del oráculo.
#[test]
fn dns_server_wire_equals_ziti_dns_c_oracle() {
    let mut m = DnsMatcher::new();
    assert!(m.seed_pool("100.64.0.0/24"));
    m.reserve("100.64.0.1".parse().unwrap()); // el utun (espejo de ziti_dns_setup)
    m.reserve("100.64.0.2".parse().unwrap()); // el propio DNS resolver
    let z255 = format!("{0}.{0}.{0}.{1}", "z".repeat(63), "z".repeat(61));
    for addr in ["app.example.com", "*.svc.example.com", z255.as_str()] {
        assert!(!matches!(m.register(addr, "i"), RegisterOutcome::Rejected));
    }

    // (id, query_hex, esperado) — ground truth generado por el harness C, ver el doc del test.
    // El ORDEN importa: los casos wildcard asignan IPs incrementales (100.64.0.3, .4) y el
    // oráculo fue sembrado/consultado en este MISMO orden.
    let cases: &[(&str, &str, Expect)] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tunnel/intercept/dns_server_ground_truth.rs"
    ));

    for (id, query_hex, expect) in cases {
        // El harness C corre SIN upstream configurado → `false` (RA nunca, miss → REFUSE).
        let action = handle_query(&mut m, &hex_to_bytes(query_hex), false, false);
        match (expect, &action) {
            (Expect::Resp(want), DnsAction::Respond(got)) => {
                assert_eq!(
                    &bytes_to_hex(got),
                    want,
                    "caso '{id}': la respuesta debe ser byte-idéntica al oráculo C"
                );
            }
            (Expect::Drop, DnsAction::Drop) => {}
            (Expect::ProxyDeferral(rcode), DnsAction::Respond(got)) => {
                assert_eq!(
                    got[3] & 0x0f,
                    *rcode,
                    "caso '{id}': el oráculo PROXY-resuelve (overlay; aquí modo sin-proxy \
                     pineado, el cableado es M3-DNS #2); pineamos el rcode del proxy no disponible"
                );
            }
            _ => panic!("caso '{id}': desajuste de veredicto (esperado vs {action:?})"),
        }
    }
}

/// DIFFERENTIAL empírico de la sección ANSWER (M3-DNS #2) contra el oráculo C: `format_resp`
/// ENTERO (las ramas MX/TXT/SRV/A/default + `format_name`) extraído VERBATIM de
/// `ziti_dns.c:486-646` @ `2addfbb` a un harness `clang -O2` que construye `dns_answer[]`
/// arbitrarios (el estado que `on_proxy_data` injerta desde el JSON del resolver hostante) y
/// pinea la respuesta byte-exacta. Cubre: MX/SRV/TXT simples y múltiples (orden), A injertado
/// (escribe `req->addr` = 0.0.0.0, quirk), `default` (AAAA / tipo 65537: prefijo de 10 bytes
/// SIN rdata, contado en ANCOUNT), TXT vacío / 255 / 256 (byte de longitud `SET_U8` wrap),
/// labels >255 (`format_name` trunca el byte de longitud), punto final / label vacío / NULs
/// interiores (semántica C-string), truncación en cada guard (prefijo / rama A / TXT / MX con
/// sus 2 bytes fantasma / 2º answer contado), el borde del OPT (leftover 11 vs 12), status≠0
/// con answers (bloque saltado), array vacío vs NULL (ANCOUNT=0 vs passthrough), truncación
/// `SET_U16`/`SET_U32` de `int64_t`, y RA on/off. **0 divergencias.**
#[test]
#[allow(clippy::unreadable_literal)] // ground truth GENERADO (ttl 2^32+61 sin separadores)
fn answer_section_wire_equals_ziti_dns_c_oracle() {
    type AnswerSpec = (i64, i64, i64, i64, i64, Option<&'static [u8]>);
    type AnswerCase = (
        &'static str,
        &'static str,
        u8,
        bool,
        &'static str,
        Option<&'static [AnswerSpec]>,
        &'static str,
    );
    let cases: &[AnswerCase] = &include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/tunnel/intercept/dns_answers_ground_truth.rs"
    ));

    for (name, req_hex, status, ra, addr, answers, want_hex) in cases {
        let packet = hex_to_bytes(req_hex);
        let q = parse_query(&packet).expect("las queries del harness son bien formadas");
        let answers: Option<Vec<RespAnswer>> = answers.map(|specs| {
            specs
                .iter()
                .map(|&(atype, ttl, priority, weight, port, data)| RespAnswer {
                    atype,
                    ttl,
                    priority,
                    weight,
                    port,
                    // data None = a->data NULL (solo ramas A/default, que no lo leen).
                    data: data.map_or_else(String::new, |d| {
                        String::from_utf8(d.to_vec()).expect("data del harness es UTF-8")
                    }),
                })
                .collect()
        });
        let got = format_resp_answers(
            &packet,
            q.name_strlen,
            *status,
            answers.as_deref(),
            addr.parse().expect("addr del harness"),
            *ra,
        );
        assert_eq!(
            &bytes_to_hex(&got),
            want_hex,
            "caso '{name}': la sección answer debe ser byte-idéntica al oráculo C"
        );
    }
}

/// Los bits de rcode que trajera el REQUEST se OR-ean (DNS_SET_CODE es `|=` sobre la copia
/// verbatim) — un request con byte 3 sucio produce una respuesta con esos bits mezclados.
/// Quirk replicado, no un bug nuestro.
#[test]
fn request_rcode_bits_survive_via_the_or_quirk() {
    let mut m = matcher_with(&["app.example.com"]);
    // flags 0x0102: RD + un bit bajo (rcode 2) que un request normal jamás lleva.
    let pkt = query(7, 0x0102, "app.example.com", NS_T_A, 1);
    let resp = respond(&mut m, &pkt);
    assert_eq!(
        rcode(&resp),
        0x02,
        "NOERROR(0) | los bits sucios del request (2)"
    );
}
