// F6 tramo 3a troceo: tests movidos verbatim del monolito de `intercept/udp` (mod tests).

use super::dns_dispatch::{dns_response, is_dns_server_datagram};
use super::testsupport::*;

/// El discriminante de routing: SOLO `(dns_server_ip, 53)` va al DNS embebido; otra IP, otro
/// puerto, o `dns_server_ip == None` van al resolver dst→servicio. Espejo del intercept
/// dedicado del oráculo (dirección exacta + puerto 53 exacto).
#[test]
fn is_dns_server_datagram_matches_only_the_dns_addr_and_port_53() {
    let dns = v4(100, 64, 0, 2, 53);
    assert!(is_dns_server_datagram(dns, Some(DNS_SRV_IP)));
    // Puerto distinto → no es DNS.
    assert!(!is_dns_server_datagram(
        v4(100, 64, 0, 2, 54),
        Some(DNS_SRV_IP)
    ));
    // IP distinta (aunque puerto 53) → no es DNS.
    assert!(!is_dns_server_datagram(
        v4(100, 64, 0, 3, 53),
        Some(DNS_SRV_IP)
    ));
    // Sin servidor DNS configurado → nunca.
    assert!(!is_dns_server_datagram(dns, None));
}

/// El camino DNS del manager (extraído a `dns_response`): una query por un hostname registrado
/// produce una respuesta NOERROR con la IP sintética; el matcher es `&mut` porque una query de
/// dominio asignaría IP. Byte-exactitud completa vive en `dns_server/`; aquí basta con
/// confirmar el cableado (Respond→Some, Drop→None).
#[test]
fn dns_response_answers_registered_hostname_and_drops_malformed() {
    let mut m = dns_matcher_with("app.example.com");
    let resp = dns_response(&mut m, &dns_a_query(0x1234, "app.example.com"))
        .expect("hostname registrado → respuesta");
    assert_eq!(resp[3] & 0x0f, 0, "NOERROR");
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "1 registro A");
    // La IP en el registro A (últimos 4 bytes antes del OPT de 11) = la asignada (100.64.0.3).
    let ip = &resp[resp.len() - 11 - 4..resp.len() - 11];
    assert_eq!(ip, &[100, 64, 0, 3]);

    // Un paquete malformado (QR=1, una respuesta) → Drop → None (sin respuesta).
    let mut qr = dns_a_query(0x1235, "app.example.com");
    qr[2] |= 0x80; // QR
    assert!(
        dns_response(&mut m, &qr).is_none(),
        "un paquete malformado se descarta sin responder"
    );
}

/// Un miss (hostname no registrado) al servidor DNS produce REFUSED (no NXDOMAIN), no un Drop:
/// el server SÍ responde, solo que rehúsa. Confirma que el manager encolaría esa respuesta.
#[test]
fn dns_response_refuses_unregistered_name() {
    let mut m = dns_matcher_with("app.example.com");
    let resp = dns_response(&mut m, &dns_a_query(1, "unknown.example.org"))
        .expect("un miss también responde (REFUSED)");
    assert_eq!(resp[3] & 0x0f, 5, "REFUSED");
}
