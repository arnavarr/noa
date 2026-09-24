//! Ciclo 2: upstream-forward sobre TCP. F6 tramo 13: movidos verbatim del `mod tests` del monolito
//! de `intercept/dns_tcp`.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::forward_tcp::forward_upstream_tcp;
use super::testsupport::*;
use super::*;

// ───────────────────────── Ciclo 2: upstream-forward sobre TCP ─────────────────────────

/// Spawnea un upstream TCP falso que acepta UNA conn, lee la query enmarcada y responde enmarcado
/// (el id de la query ecoado + `suffix`). El handle yield-ea la query recibida (asserto verbatim).
async fn spawn_upstream_canned(
    suffix: &'static [u8],
) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut prefix = [0u8; 2];
        sock.read_exact(&mut prefix).await.unwrap();
        let mut query = vec![0u8; u16::from_be_bytes(prefix) as usize];
        sock.read_exact(&mut query).await.unwrap();
        let mut resp = vec![query[0], query[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        resp.extend_from_slice(suffix);
        let len = u16::try_from(resp.len()).unwrap();
        sock.write_all(&len.to_be_bytes()).await.unwrap();
        sock.write_all(&resp).await.unwrap();
        sock.flush().await.unwrap();
        query
    });
    (addr, handle)
}

/// Un puerto TCP CERRADO (bind + drop del listener): un `connect` a él da ECONNREFUSED rápido.
async fn dead_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap() // `l` se dropea al salir → puerto cerrado
}

/// Una query recursiva por un nombre NO interceptado se reenvía al upstream SOBRE TCP y su
/// respuesta se releva VERBATIM enmarcada; el upstream ve el request VERBATIM; una 2ª query LOCAL
/// en la MISMA conn sigue sirviéndose (reuse). (Mutación: re-emitir/mutar; cerrar la conn tras el
/// forward.)
#[tokio::test]
async fn dns_over_tcp_forwards_external_to_upstream_verbatim_both_ways() {
    let (up_addr, up_handle) = spawn_upstream_canned(b"UPSTREAM-TCP-ANSWER").await;
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        some_upstream(vec![up_addr]),
    );
    let q1 = dns_a_query(0x5afe, "notlocal.example.org");
    let q1c = q1.clone();
    let drive = async move {
        write_framed(&mut client, &q1c).await;
        let (_p, r1) = read_framed(&mut client).await;
        assert_eq!(&r1[0..2], &q1c[0..2], "id preservado (passthrough)");
        assert!(
            r1.ends_with(b"UPSTREAM-TCP-ANSWER"),
            "cuerpo upstream verbatim"
        );
        // 2ª query LOCAL (hit) en la MISMA conn → servida localmente (la conn no se cerró).
        let q2 = dns_a_query(0x0002, "svc.example.com");
        write_framed(&mut client, &q2).await;
        let (_p2, r2) = read_framed(&mut client).await;
        assert_eq!(
            r2[3] & 0x0f,
            0,
            "hit local NOERROR tras el forward (conn reutilizada)"
        );
        drop(client);
    };
    tokio::join!(serve, drive);
    let received = up_handle.await.unwrap();
    assert_eq!(received, q1, "el upstream recibió el request VERBATIM");
}

/// Failover: server1 acepta-y-cierra (EOF = intento fallido), server2 responde → llega server2.
/// (Mutación: abortar al primer fallo.)
#[tokio::test]
async fn dns_over_tcp_upstream_failover_tries_next_server() {
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a1 = l1.local_addr().unwrap();
    let _s1 = tokio::spawn(async move {
        let (sock, _) = l1.accept().await.unwrap();
        drop(sock); // EOF inmediato
    });
    let (a2, h2) = spawn_upstream_canned(b"SECOND").await;
    let q = dns_a_query(0x0002, "x.example.org");
    let resp = forward_upstream_tcp(&[a1, a2], &q, Duration::from_secs(5))
        .await
        .expect("server2 responde tras el fallo de server1");
    assert!(
        resp.ends_with(b"SECOND"),
        "la respuesta vino de server2 (failover)"
    );
    assert_eq!(&resp[0..2], &q[0..2], "id casado");
    let _ = h2.await;
}

/// Todos los upstreams caídos (puertos cerrados) → el cliente recibe el `on_send_failure` (REFUSED,
/// RA=1) enmarcado tras agotar la lista, y la conn SIGUE sirviendo. (Mutación: cerrar la conn o
/// fabricar otra respuesta en el todo-fallo.)
#[tokio::test]
async fn dns_over_tcp_all_upstreams_down_yields_refused_fallback() {
    let d1 = dead_port().await;
    let d2 = dead_port().await;
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        some_upstream(vec![d1, d2]),
    );
    let drive = async move {
        let q = dns_a_query(0x00aa, "external.example.org");
        write_framed(&mut client, &q).await;
        let (_p, r) = read_framed(&mut client).await;
        assert_eq!(r[3] & 0x0f, 5, "REFUSED tras agotar upstreams");
        assert_eq!(r[3] & 0x80, 0x80, "RA=1 (on_send_failure)");
        assert_eq!(&r[0..2], &q[0..2], "id de la query");
        // La conn sigue viva: una 2ª query local se sirve.
        let q2 = dns_a_query(0x00ab, "svc.example.com");
        write_framed(&mut client, &q2).await;
        let (_p2, r2) = read_framed(&mut client).await;
        assert_eq!(
            r2[3] & 0x0f,
            0,
            "conn viva tras el todo-fallo (hit local NOERROR)"
        );
        drop(client);
    };
    tokio::join!(serve, drive);
}

/// RD=0 → REFUSE local (con RA=1 porque hay upstream configurado); el upstream NO ve NINGUNA conn.
/// (Mutación: reenviar sin el gate RD, el over-permit espejo de `query_upstream:853`.)
#[tokio::test]
async fn dns_over_tcp_rd0_never_dials_upstream() {
    let accepts = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let a2 = Arc::clone(&accepts);
    let _counter = tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            a2.fetch_add(1, Ordering::SeqCst);
        }
    });
    let (mut client, server) = tokio::io::duplex(4096);
    let serve = serve_dns_over_tcp(
        server,
        Rc::new(RefCell::new(dns_resolver())),
        test_client(),
        some_upstream(vec![addr]),
    );
    let drive = async move {
        let q = dns_a_query_no_rd(0x00cc, "external.example.org");
        write_framed(&mut client, &q).await;
        let (_p, r) = read_framed(&mut client).await;
        assert_eq!(r[3] & 0x0f, 5, "RD=0 miss → REFUSE local (sin forward)");
        assert_eq!(r[3] & 0x80, 0x80, "RA=1 (upstream configurado)");
        drop(client);
    };
    tokio::join!(serve, drive);
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "el upstream no vio ninguna conexión (RD=0 no reenvía)"
    );
}

/// Server mudo (acepta y calla) + `attempt_timeout` diminuto → `None` (fallback REFUSED). Timeout
/// por PARÁMETRO con I/O real, no reloj pausado (un socket recién creado puede tardar más en la primera operación).
#[tokio::test]
async fn dns_over_tcp_upstream_mute_times_out_to_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _mute = tokio::spawn(async move {
        let (_sock, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await; // retiene la conn, nunca responde
    });
    let q = dns_a_query(0x1234, "x.example.org");
    let res = forward_upstream_tcp(&[addr], &q, Duration::from_millis(80)).await;
    assert!(
        res.is_none(),
        "server mudo → timeout → None (→ REFUSED de fallback)"
    );
}

/// El upstream responde primero un id AJENO y luego el bueno → `forward_one` descarta el espurio y
/// releva el bueno. (Mutación: relay del primer mensaje sin casar id, la clase misdelivery.)
#[tokio::test]
async fn dns_over_tcp_upstream_mismatched_id_is_discarded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _srv = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut prefix = [0u8; 2];
        sock.read_exact(&mut prefix).await.unwrap();
        let mut q = vec![0u8; u16::from_be_bytes(prefix) as usize];
        sock.read_exact(&mut q).await.unwrap();
        // 1º: id ajeno (0xFFFF); 2º: el id de la query + marcador.
        let wrong = vec![0xFF, 0xFF, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut good = vec![q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        good.extend_from_slice(b"GOOD");
        for msg in [wrong, good] {
            let len = u16::try_from(msg.len()).unwrap();
            sock.write_all(&len.to_be_bytes()).await.unwrap();
            sock.write_all(&msg).await.unwrap();
        }
        sock.flush().await.unwrap();
    });
    let q = dns_a_query(0x4d58, "x.example.org");
    let resp = forward_upstream_tcp(&[addr], &q, Duration::from_secs(5))
        .await
        .expect("el 2º mensaje (id bueno) completa");
    assert_eq!(&resp[0..2], &q[0..2], "el id casa el de la query");
    assert!(
        resp.ends_with(b"GOOD"),
        "es el mensaje bueno, no el espurio"
    );
}
