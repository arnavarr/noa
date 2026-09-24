//! Fuente de paquetes IP crudos, abstraída del origen del fd (§4.1 / §5c del diseño).
//!
//! Hoy el único origen es un dispositivo utun abierto por `tun-rs` ([`UtunDevice`]). El trait
//! [`IpPacketDevice`] mantiene la pila (netstack/smoltcp, M1+) INDEPENDIENTE de cómo se obtuvo el
//! fd, dejando la puerta abierta a un `NEPacketTunnelProvider` (macOS sandbox) o `/dev/net/tun`
//! (Linux) sin tocar la pila. tun-rs unifica el formato entre plataformas: entrega/acepta paquetes
//! IP DESNUDOS (el prefijo AF de 4 bytes de macOS se gestiona dentro del crate), así que el trait
//! opera siempre sobre IP cruda — la pila nunca ve la cabecera de enlace.

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use tun_rs::{AsyncDevice, DeviceBuilder};

use super::error::InterceptError;

/// Origen/sumidero de paquetes IP crudos (sin cabecera de enlace).
///
/// `recv`/`send` devuelven futuros `Send` para poder conducirse desde tasks del runtime
/// multi-thread de tokio (las glue-tasks tun↔pila de M1+). El tipo es `Send + Sync` para
/// poder compartirse (`Arc`) entre la task que lee del device y la que escribe en él.
pub trait IpPacketDevice: Send + Sync {
    /// Lee un paquete IP crudo en `buf`; devuelve su longitud en bytes.
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Escribe un paquete IP crudo; devuelve los bytes escritos.
    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;

    /// Nombre de la interfaz del SO (p. ej. `utun7`).
    ///
    /// # Errors
    /// Propaga el error del SO si no se puede consultar el nombre de la interfaz.
    fn name(&self) -> io::Result<String>;

    /// MTU configurado de la interfaz, en bytes.
    fn mtu(&self) -> u16;
}

/// Dispositivo utun de macOS (o TUN en Linux) abierto por `tun-rs`.
///
/// Envuelve un [`AsyncDevice`] en un `Arc` para poder clonarse y compartirse entre las dos
/// glue-tasks (tun→pila y pila→tun) sin un `&mut` que serialice la E/S — `AsyncDevice::recv`/`send`
/// toman `&self`, así que el acceso concurrente lectura/escritura es seguro.
#[derive(Clone)]
pub struct UtunDevice {
    dev: Arc<AsyncDevice>,
    mtu: u16,
}

impl UtunDevice {
    /// MTU por defecto del intercept (Ethernet-like). La pila la respeta al trocear/reensamblar.
    pub const DEFAULT_MTU: u16 = 1500;

    /// Abre un dispositivo utun con la IPv4 dada. **Requiere root** en macOS/Linux.
    ///
    /// `address`/`prefix` configuran la dirección de la interfaz; el SO ruteará la subred on-link
    /// hacia el utun. La instalación de rutas adicionales (para CIDRs de servicios `intercept.v1`)
    /// es scope de M3 — aquí solo se levanta el device.
    ///
    /// # Errors
    /// Devuelve [`InterceptError::DeviceOpen`] si el SO rechaza abrir/configurar el device
    /// (típicamente por falta de privilegios).
    pub fn open(address: Ipv4Addr, prefix: u8, mtu: u16) -> Result<Self, InterceptError> {
        let dev = DeviceBuilder::new()
            .ipv4(address, prefix, None)
            .mtu(mtu)
            .build_async()
            .map_err(InterceptError::DeviceOpen)?;
        Ok(Self {
            dev: Arc::new(dev),
            mtu,
        })
    }

    /// Índice de interfaz del SO (el `N` de `utunN`), para scopear al device las rutas de intercept
    /// (M3-rutas, [`super::routes::InstalledRoutes`]). Vía `tun-rs` (`AsyncDevice: Deref<DeviceImpl>` →
    /// `DeviceImpl::if_index`, que resuelve por `libc::if_nametoindex`).
    ///
    /// # Errors
    /// Propaga el error del SO si no se puede resolver el índice de la interfaz.
    pub fn if_index(&self) -> io::Result<u32> {
        self.dev.if_index()
    }
}

impl IpPacketDevice for UtunDevice {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send {
        self.dev.recv(buf)
    }

    fn send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>> + Send {
        self.dev.send(buf)
    }

    fn name(&self) -> io::Result<String> {
        self.dev.name()
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }
}
