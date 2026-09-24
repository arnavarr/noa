//! M0 del arco intercept: el dispositivo utun vive y entrega paquetes IP CRUDOS (el prefijo AF de
//! 4 bytes de macOS lo gestiona tun-rs → leemos IP desnuda).
//!
//! REQUIERE ROOT y un SO con TUN (macOS/Linux): abre un utun real. Gated con `#[ignore]` para no
//! romper CI sin privilegios (compila siempre, solo se ejecuta a mano). Ejecútalo:
//!
//! ```sh
//! sudo cargo test --features intercept --test intercept_m0 -- --ignored --nocapture
//! ```
#![cfg(feature = "intercept")]

use std::net::Ipv4Addr;
use std::time::Duration;

use noa_sdk::tunnel::intercept::{IpPacketDevice, UtunDevice};

#[tokio::test]
#[ignore = "requiere root + un device TUN (macOS/Linux): abre un utun real"]
async fn m0_utun_captures_a_raw_ip_packet() {
    // Levanta el utun con una IPv4 on-link; el SO ruteará 10.99.0.0/24 hacia el device.
    let dev = UtunDevice::open(Ipv4Addr::new(10, 99, 0, 1), 24, UtunDevice::DEFAULT_MTU)
        .expect("abrir utun (¿se ejecuta como root?)");
    let name = dev.name().expect("nombre de interfaz");
    println!("utun abierto: {name} mtu={}", dev.mtu());
    assert!(
        name.starts_with("utun") || name.starts_with("tun"),
        "se esperaba un nombre utunN/tunN, fue {name}"
    );

    // Genera tráfico hacia una dirección on-link → el kernel lo entrega al utun. No necesita
    // respuesta: solo queremos ver UN paquete IP crudo entrar.
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            let _ = sock.send_to(b"m0-probe", "10.99.0.2:9999").await;
        }
    });

    // Lee el primer paquete IP crudo del device.
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), dev.recv(&mut buf))
        .await
        .expect("timeout esperando un paquete del utun")
        .expect("recv del utun");
    assert!(n > 0, "paquete vacío");

    // tun-rs ya quitó el prefijo AF → el byte 0 es el nibble de versión IP (4 o 6). Esto prueba
    // que leemos IP DESNUDA, que es el contrato sobre el que se montará la pila smoltcp en M1.
    let version = buf[0] >> 4;
    println!("primer paquete: {n} bytes, versión IP = {version}");
    assert!(
        version == 4 || version == 6,
        "no parece IP crudo: nibble={version}"
    );
}
