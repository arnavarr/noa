//! Error del canal binario. Una variante por modo de fallo.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChannelError {
    /// Frame mal formado: magic inválido, short read, o cap excedido.
    #[error("channel frame error: {0}")]
    Frame(String),

    /// Error de IO del stream (read/write/timeout).
    #[error("channel io error: {0}")]
    Io(String),

    /// El router rechazó el handshake (`Result` con `success == false`); lleva el motivo (body).
    #[error("channel handshake rejected by router: {0}")]
    HandshakeRejected(String),

    /// Frame de respuesta con un content-type distinto de `Result` (2).
    #[error("unexpected channel content-type: {0}")]
    UnexpectedContentType(i32),

    /// Transport address no parseable (`tls:host:port`).
    #[error("invalid transport address: {0}")]
    AddressParse(String),
}
