//! Reingeniería en Rust del edge client / tunneler de OpenZiti.
//!
//! Referencia upstream: ver `README.md` (componente, versión/commit y enlace).
//! La fidelidad funcional con el tunneler original es el criterio de éxito;
//! la API pública de este crate se irá fijando a medida que se porten los
//! módulos del data plane (enrolment, conexión edge, mTLS, intercept/host).

pub mod channel;
pub mod edge;
pub mod enroll;
pub mod tunnel;

/// Versión del crate, expuesta para diagnósticos del binario.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!VERSION.is_empty());
    }
}
