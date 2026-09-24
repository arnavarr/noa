// F6 tramo 3a troceo: tests movidos verbatim del monolito de `intercept/udp` (mod tests).

use std::time::{Duration, Instant};

use super::testsupport::*;
use super::{DNS_UPSTREAM_BUF, DNS_UPSTREAM_TIMEOUT, PendingUpstream, UpstreamDns};

/// `UpstreamDns` real de punta a punta con sockets REALES: `forward` reenvía el request VERBATIM
/// al fake upstream, el fake responde, y `match_response` casa por ID y devuelve el par
/// `(server, client)` para el passthrough. Cubre además el dedup (2º forward del mismo ID no
/// reenvía) y la eviction por TTL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_forward_matches_response_and_dedups() {
    // Fake upstream en v6 loopback (el socket de UpstreamDns bindea `[::]:0` → puede alcanzarlo).
    let fake = tokio::net::UdpSocket::bind("[::1]:0")
        .await
        .expect("bind fake upstream");
    let fake_addr = fake.local_addr().unwrap();
    let mut up = UpstreamDns::bind(vec![fake_addr])
        .await
        .expect("bind upstream");
    // `bind` ya calienta la readiness de ESCRITURA del socket (ver su doc), así que el 1er
    // `forward` de abajo tiene éxito de forma determinista sin calentarlo aquí a mano — este test
    // se apoya en (y ejercita) ese calentamiento. Antes hacía falta un `writable().await` manual;
    // el comentario decía que el `select!` del runner combinado lo calentaba, lo cual era FALSO
    // (solo espera lectura) y ES la causa del flake que el warm de `bind` cierra.

    let server = v4(100, 64, 0, 2, 53); // (dns_ip, 53)
    let client = v4(100, 64, 0, 200, 40000);
    // Request con ID 0xABCD.
    let request = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];

    assert!(
        up.forward(&request, server, client),
        "1er forward → registrado"
    );
    assert_eq!(up.pending.len(), 1);

    // El fake upstream recibe el request VERBATIM.
    let mut buf = [0u8; 512];
    let (n, from) = tokio::time::timeout(TEST_TIMEOUT, fake.recv_from(&mut buf))
        .await
        .expect("timeout esperando el forward")
        .unwrap();
    assert_eq!(&buf[..n], &request[..], "el request se reenvía verbatim");

    // Dedup: un 2º forward del MISMO ID no reenvía otra vez (sigue habiendo 1 pending).
    assert!(
        up.forward(&request, server, client),
        "dedup → true sin reenviar"
    );
    assert_eq!(up.pending.len(), 1, "el ID duplicado no crea otro pending");

    // El fake responde (mismo ID); match_response casa y devuelve (server, client).
    let response = vec![0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    fake.send_to(&response, from).await.unwrap();
    let mut rbuf = [0u8; DNS_UPSTREAM_BUF];
    let m = tokio::time::timeout(TEST_TIMEOUT, up.socket.recv(&mut rbuf))
        .await
        .expect("timeout esperando la respuesta upstream")
        .unwrap();
    assert_eq!(&rbuf[..m], &response[..], "la respuesta llega verbatim");
    let (got_server, got_client) = up
        .match_response(&rbuf[..m])
        .expect("el ID casa un pending");
    assert_eq!((got_server, got_client), (server, client));
    assert!(up.pending.is_empty(), "match_response consume el pending");

    // Una respuesta de ID desconocido no casa nada.
    assert!(up.match_response(&[0x00, 0x01, 0, 0]).is_none());
}

/// La eviction por TTL barre un pending viejo (una respuesta upstream perdida no lo deja
/// colgado para siempre — divergencia consciente vs el ciclo-de-cliente del oráculo). Inserta el
/// pending directamente (no vía `forward`) porque este test solo ejercita la eviction, no el
/// envío — así queda desacoplado del socket. (Nota histórica: `bind` ahora calienta la readiness
/// de escritura, así que el `WouldBlock` en frío del 1er `try_send_to` — que era un problema real
/// de producción, no un no-issue — ya no ocurre; ver el doc de `bind`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_pending_evicts_after_ttl() {
    let fake = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let mut up = UpstreamDns::bind(vec![fake.local_addr().unwrap()])
        .await
        .unwrap();
    let now = Instant::now();
    up.pending.insert(
        0x1122,
        PendingUpstream {
            server_addr: v4(100, 64, 0, 2, 53),
            client_addr: v4(10, 0, 0, 1, 5),
            at: now,
        },
    );
    assert_eq!(up.pending.len(), 1);

    // Justo en el borde del TTL: sobrevive. Más allá: se evicta.
    up.evict_expired(now + DNS_UPSTREAM_TIMEOUT);
    assert_eq!(up.pending.len(), 1, "en el borde del TTL sobrevive");
    up.evict_expired(now + DNS_UPSTREAM_TIMEOUT + Duration::from_secs(1));
    assert!(up.pending.is_empty(), "pasado el TTL se evicta");
}
