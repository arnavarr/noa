//! Tipo de error de la capa de intercept. `thiserror`, un variant por etapa de fallo
//! (misma disciplina que [`crate::edge::error::EdgeError`]).

use thiserror::Error;

/// Errores de la capa de intercept de host.
#[derive(Debug, Error)]
pub enum InterceptError {
    /// Fallo al abrir/configurar el dispositivo utun. Casi siempre por falta de privilegios
    /// (abrir un utun requiere root) o por una IP/MTU inválida.
    #[error("failed to open the tun device: {0}")]
    DeviceOpen(#[source] std::io::Error),
}
