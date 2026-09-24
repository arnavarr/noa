//! Build a verified mTLS reqwest client from an enrolled identity.
//! RootCAs = id.ca; client cert = id.cert chain + id.key. Oracle: edge-apis credentials.go.

use std::io::Cursor;

use crate::edge::error::EdgeError;
use crate::enroll::identity::Config;
use crate::enroll::trust::ensure_crypto_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Strip the `pem:` prefix the enrolment writes; returns the raw PEM text.
fn pem_value(v: &str) -> Result<&str, EdgeError> {
    v.strip_prefix("pem:")
        .ok_or_else(|| EdgeError::IdentityLoad("identity value is not an inline `pem:` PEM".into()))
}

fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, EdgeError> {
    let mut reader = Cursor::new(pem.as_bytes());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| EdgeError::IdentityLoad(format!("certs: {e}")))?;
    if certs.is_empty() {
        return Err(EdgeError::IdentityLoad("no certificates in PEM".into()));
    }
    Ok(certs)
}

/// Construye un `rustls::ClientConfig` verificado desde una identidad enrolada:
/// `RootCAs = id.ca`, cert cliente = cadena `id.cert` + clave `id.key`. Instala el
/// provider cripto (aws-lc-rs). Lo consumen tanto
/// `mtls_client` (reqwest/controller) como el dial del canal al edge router.
pub fn client_config(cfg: &Config) -> Result<rustls::ClientConfig, EdgeError> {
    ensure_crypto_provider();

    let cert_chain = parse_certs(pem_value(&cfg.id.cert)?)?;

    let key_pem = pem_value(&cfg.id.key)?;
    let mut key_reader = Cursor::new(key_pem.as_bytes());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| EdgeError::IdentityLoad(format!("key: {e}")))?
        .ok_or_else(|| EdgeError::IdentityLoad("no private key in id.key".into()))?;

    let mut roots = rustls::RootCertStore::empty();
    for ca in parse_certs(pem_value(&cfg.id.ca)?)? {
        roots
            .add(ca)
            .map_err(|e| EdgeError::TlsSetup(format!("add ca: {e}")))?;
    }

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| EdgeError::TlsSetup(e.to_string()))
}

/// Build a verified-mTLS reqwest client: trusts `id.ca`, presents `id.cert`+`id.key`.
pub fn mtls_client(cfg: &Config) -> Result<reqwest::Client, EdgeError> {
    let tls = client_config(cfg)?;
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|e| EdgeError::TlsSetup(e.to_string()))
}

/// An mTLS client cert client that does NOT auto-follow redirects — for the OIDC PKCE flow, which is
/// driven step-by-step (each 302's `Location` is read by hand; the final redirect targets a
/// non-listening sentinel). Same TLS identity as [`mtls_client`]; only the redirect policy differs.
/// Oracle: the OIDC authenticator uses a `RedirectUntilUrlPrefix` policy (`clients_shared.go:356`);
/// disabling auto-redirect and stepping by hand is the faithful equivalent.
pub fn oidc_mtls_client(cfg: &Config) -> Result<reqwest::Client, EdgeError> {
    let tls = client_config(cfg)?;
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| EdgeError::TlsSetup(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::identity::{Config, Id};

    /// Build a self-consistent identity with rcgen (CA-signed leaf + the CA) and
    /// confirm the mTLS client constructs without error (structural).
    #[test]
    fn builds_mtls_client_from_identity() {
        let cfg = sample_identity();
        mtls_client(&cfg).expect("mTLS client builds from a valid identity");
    }

    #[test]
    fn client_config_builds_from_identity() {
        let cfg = sample_identity();
        client_config(&cfg).expect("client_config builds from a valid identity");
    }

    fn sample_identity() -> Config {
        let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_kp).unwrap();

        let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
        let leaf = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();

        let cert_pem = format!("{}{}", leaf.pem(), ca.pem());
        Config {
            zt_api: "https://localhost:1280/edge/client/v1".into(),
            zt_apis: None,
            config_types: None,
            id: Id {
                key: format!("pem:{}", leaf_kp.serialize_pem()),
                cert: format!("pem:{cert_pem}"),
                ca: format!("pem:{}", ca.pem()),
            },
        }
    }
}
