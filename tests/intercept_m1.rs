//! M1 del arco intercept: un flujo TCP REAL atraviesa el utun y la pila netstack-smoltcp.
//!
//! Un cliente del SO (la pila TCP del kernel) conecta a una IP on-link ruteada al utun → el kernel
//! manda el SYN al device → nuestra [`InterceptStack`] lo acepta como `TcpStream`, lee la petición y
//! responde; el cliente lee la respuesta de vuelta a través del utun. Prueba el contrato de M1: el
//! `TcpStream` interceptado es usable desde un cliente real, en ambos sentidos, incl. el half-close.
//!
//! REQUIERE ROOT y un SO con TUN (macOS/Linux): abre un utun real. Gated con `#[ignore]` para no
//! romper CI sin privilegios (compila siempre, solo se ejecuta a mano). Ejecútalo:
//!
//! ```sh
//! sudo cargo test --features intercept --test intercept_m1 -- --ignored --nocapture
//! ```
#![cfg(feature = "intercept")]

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use noa_sdk::tunnel::intercept::{InterceptStack, UtunDevice};

const RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nnoa-1";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requiere root + un device TUN (macOS/Linux): abre un utun real"]
async fn m1_real_client_round_trips_through_the_intercept_stack() {
    // utun on-link: el SO ruteará 10.99.0.0/24 hacia el device. El cliente conectará a 10.99.0.2
    // (on-link, distinta del addr de la interfaz 10.99.0.1) → el SYN entra a la pila.
    let dev = UtunDevice::open(Ipv4Addr::new(10, 99, 0, 1), 24, UtunDevice::DEFAULT_MTU)
        .expect("abrir utun (¿se ejecuta como root?)");
    let mut stack = InterceptStack::new(dev).expect("montar la pila intercept");

    // Accept-loop: por cada flujo interceptado, lee la petición y responde un HTTP fijo, luego
    // medio-cierra (FIN) — el camino que `splice` ejercitará en M2.
    tokio::spawn(async move {
        while let Some((mut s, dst, src)) = stack.accept().await {
            println!("intercept: flujo aceptado dst={dst} src={src}");
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                // Lee la petición del cliente (curl manda al menos la request-line).
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(RESPONSE).await;
                let _ = s.shutdown().await; // FIN → el cliente verá EOF tras la respuesta
            });
        }
    });

    // Cliente REAL del SO: conecta a la IP on-line ruteada al utun.
    let mut client =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect("10.99.0.2:80"))
            .await
            .expect("timeout conectando a través del utun")
            .expect("connect a 10.99.0.2:80");

    client
        .write_all(b"GET / HTTP/1.0\r\nHost: 10.99.0.2\r\n\r\n")
        .await
        .expect("enviar petición");

    // Lee la respuesta completa hasta EOF (el FIN del lado intercept).
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut resp))
        .await
        .expect("timeout leyendo la respuesta")
        .expect("leer respuesta");

    println!(
        "respuesta ({} bytes): {}",
        resp.len(),
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(
        resp, RESPONSE,
        "el round-trip a través del utun debe devolver la respuesta exacta"
    );
}
