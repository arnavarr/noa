//! Ciclo 0/1: local + framing + RA. F6 tramo 13: movidos verbatim del `mod tests` del monolito de
//! `intercept/dns_tcp`.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::testsupport::*;
use super::*;

// ───────────────────────── Ciclo 0/1: local + framing + RA ─────────────────────────

/// El corazón del framing: dos queries SECUENCIALES sobre UNA conexión (reuse, RFC 7766 §6.2.1) →
/// cada respuesta va enmarcada con su longitud en 2B big-endian (RFC 1035 §4.2.2) y su payload es
/// BYTE-IDÉNTICO al del path UDP local (heredando el ground truth de 32 casos de `handle_query`).
/// Caso LISTA-VACÍA de upstream (RA=0, byte-igual a #4). El prefijo se asierta `== len(payload)` BE
/// para cazar el off-by-two clásico y un endianness invertido.
#[tokio::test]
async fn dns_over_tcp_frames_two_queries_like_udp_then_eof() {
    let (mut client, server) = tokio::io::duplex(4096);
    let resolver = Rc::new(RefCell::new(dns_resolver()));
    let serve = serve_dns_over_tcp(server, resolver, test_client(), no_upstream());
    let drive = async move {
        // Query 1: HIT (nombre registrado) → NOERROR + registro A con la IP sintética.
        let q1 = dns_a_query(0x1234, "svc.example.com");
        write_framed(&mut client, &q1).await;
        let (p1, r1) = read_framed(&mut client).await;
        let exp1 = udp_local_response(&q1, false);
        assert_eq!(
            p1,
            u16::try_from(exp1.len()).unwrap().to_be_bytes(),
            "prefijo = len(payload) BE (sin off-by-two, big-endian)"
        );
        assert_eq!(
            r1, exp1,
            "payload byte-idéntico al del path UDP local (hit A)"
        );

        // Query 2 en la MISMA conexión: MISS (no registrado, sin dominio, sin upstream) → REFUSE.
        let q2 = dns_a_query(0x5678, "nope.example.org");
        write_framed(&mut client, &q2).await;
        let (p2, r2) = read_framed(&mut client).await;
        let exp2 = udp_local_response(&q2, false);
        assert_eq!(p2, u16::try_from(exp2.len()).unwrap().to_be_bytes());
        assert_eq!(
            r2, exp2,
            "payload byte-idéntico al del path UDP local (miss)"
        );
        assert_eq!(r2[3] & 0x0f, 5, "REFUSED (rcode 5): sin upstream sobre TCP");
        assert_eq!(r2[2] & 0x80, 0x80, "QR=1 (respuesta)");
        assert_eq!(r2[3] & 0x80, 0, "RA=0 (caso lista-vacía de upstream)");

        drop(client); // EOF → serve_dns_over_tcp retorna limpio
    };
    tokio::join!(serve, drive);
}

/// **Ciclo 1 (RA):** el bit RA de una respuesta local sobre TCP refleja `!upstream_servers.is_empty()`
/// — con upstream configurado, un hit A da RA=1 y bytes == `handle_query(dns, q, true, true)`; con
/// lista vacía, RA=0 y los bytes de #4. Pinea el threading del contexto: sin él, el path cablearía
/// `(false, false)` y la mitad RA=1 fallaría.
#[tokio::test]
async fn dns_over_tcp_local_hit_ra_tracks_upstream_config() {
    // (a) Con upstream configurado (nunca contactado en un hit local) → RA=1.
    let (mut client, server) = tokio::io::duplex(4096);
    let up = some_upstream(vec![SocketAddr::from(([127, 0, 0, 1], 9))]);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        up,
    );
    let drive = async move {
        let q = dns_a_query(0x1111, "svc.example.com");
        write_framed(&mut client, &q).await;
        let (_p, r) = read_framed(&mut client).await;
        assert_eq!(
            r,
            udp_local_response(&q, true),
            "bytes == handle_query(true,true)"
        );
        assert_eq!(r[3] & 0x0f, 0, "NOERROR (hit A)");
        assert_eq!(r[3] & 0x80, 0x80, "RA=1 con upstream configurado");
        drop(client);
    };
    tokio::join!(serve, drive);

    // (b) Sin upstream → RA=0 (byte-igual a #4).
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        no_upstream(),
    );
    let drive = async move {
        let q = dns_a_query(0x2222, "svc.example.com");
        write_framed(&mut client, &q).await;
        let (_p, r) = read_framed(&mut client).await;
        assert_eq!(
            r,
            udp_local_response(&q, false),
            "bytes == handle_query(false,true)"
        );
        assert_eq!(r[3] & 0x80, 0, "RA=0 sin upstream");
        drop(client);
    };
    tokio::join!(serve, drive);
}

/// **Ciclo 1 (pipelining):** DOS queries A escritas BACK-TO-BACK en la misma conn ANTES de leer
/// ninguna respuesta → dos respuestas correctas y EN ORDEN de llegada (servicio in-order por
/// conexión, desviación §7.2). Pinea el observable de la desviación (reuse RFC 7766 §6.2.1 +
/// in-order) que ningún test previo ejercía con pipelining.
#[tokio::test]
async fn dns_over_tcp_pipelined_queries_answered_in_order() {
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        no_upstream(),
    );
    let drive = async move {
        let q1 = dns_a_query(0xAAAA, "svc.example.com"); // hit
        let q2 = dns_a_query(0xBBBB, "miss.example.org"); // miss
        // Back-to-back, sin leer entre medias.
        write_framed(&mut client, &q1).await;
        write_framed(&mut client, &q2).await;
        let (_p1, r1) = read_framed(&mut client).await;
        let (_p2, r2) = read_framed(&mut client).await;
        assert_eq!(
            &r1[0..2],
            &[0xAA, 0xAA],
            "1ª respuesta = 1ª query (en orden)"
        );
        assert_eq!(r1[3] & 0x0f, 0, "hit → NOERROR");
        assert_eq!(
            &r2[0..2],
            &[0xBB, 0xBB],
            "2ª respuesta = 2ª query (en orden)"
        );
        assert_eq!(r2[3] & 0x0f, 5, "miss → REFUSED");
        drop(client);
    };
    tokio::join!(serve, drive);
}

/// Un prefijo que anuncia >`DNS_TCP_MAX_MSG` → cierra la conexión SIN responder (mensaje
/// sobredimensionado, RFC 7766 §6.2.4); el cliente ve EOF.
#[tokio::test]
async fn dns_over_tcp_closes_on_oversized_prefix() {
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        no_upstream(),
    );
    let drive = async move {
        client.write_all(&5000u16.to_be_bytes()).await.unwrap(); // 5000 > 4096
        client.flush().await.unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(
            client.read(&mut buf).await.unwrap(),
            0,
            "conexión cerrada sin responder al prefijo sobredimensionado"
        );
    };
    tokio::join!(serve, drive);
}

/// Un mensaje enmarcado pero MALFORMADO (cuerpo < 12B de header DNS) → `handle_query` da `Drop` →
/// cierra la conexión (RFC 7766 §6.2.4), sin responder.
#[tokio::test]
async fn dns_over_tcp_closes_on_malformed_query() {
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        no_upstream(),
    );
    let drive = async move {
        write_framed(&mut client, &[0u8; 3]).await; // 3B < 12 → parse_query None → Drop
        let mut buf = [0u8; 64];
        assert_eq!(
            client.read(&mut buf).await.unwrap(),
            0,
            "Drop cierra la conexión sin responder"
        );
    };
    tokio::join!(serve, drive);
}

/// Idle timeout: una conexión abierta que no envía nada se cierra tras `DNS_TCP_IDLE_TIMEOUT`
/// (conn ociosa / slow-loris, RFC 7766 §6.2.3). Reloj PAUSADO + duplex (sin socket real): el
/// runtime auto-avanza al timer cuando ambas tasks quedan idle.
#[tokio::test(start_paused = true)]
async fn dns_over_tcp_closes_on_idle_timeout() {
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        no_upstream(),
    );
    let drive = async move {
        let mut buf = [0u8; 64];
        assert_eq!(
            client.read(&mut buf).await.unwrap(),
            0,
            "conn ociosa cerrada por idle timeout"
        );
    };
    tokio::join!(serve, drive);
}

/// Slow-loris del CUERPO: prefijo válido y luego silencio → el idle timeout también cubre la
/// lectura del cuerpo (no solo la espera entre queries) → cierra.
#[tokio::test(start_paused = true)]
async fn dns_over_tcp_idle_timeout_covers_body_read() {
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        no_upstream(),
    );
    let drive = async move {
        client.write_all(&50u16.to_be_bytes()).await.unwrap(); // prefijo dice 50B…
        client.flush().await.unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(
            client.read(&mut buf).await.unwrap(),
            0,
            "cuerpo que no llega → idle timeout cierra"
        );
    };
    tokio::join!(serve, drive);
}
