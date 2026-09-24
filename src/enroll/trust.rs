//! TLS trust bootstrap and CA-bundle (PKCS7) handling.

use base64::Engine;
use cms::{cert::CertificateChoices, content_info::ContentInfo, signed_data::SignedData};
use der::{Decode, Encode};

/// Parse the EST `/.well-known/est/cacerts` body: a base64-encoded degenerate
/// certs-only PKCS7 SignedData. Returns each certificate as DER bytes.
/// Oracle: enroll.go FetchCertificates (base64-decode → pkcs7.Parse → certs).
///
/// # Errors
///
/// Returns [`EnrollError::Pkcs7Parse`] if the body is not valid base64, not a
/// valid DER `ContentInfo`/`SignedData`, or a certificate cannot be re-encoded;
/// returns [`EnrollError::EmptyCaPool`] if the bundle contains no certificates.
pub fn parse_cacerts_b64(body: &[u8]) -> Result<Vec<Vec<u8>>, crate::enroll::error::EnrollError> {
    use crate::enroll::error::EnrollError;
    // Strip ALL ASCII whitespace (not just leading/trailing) so a body wrapped
    // at 64 columns (MIME convention) still decodes, matching Go's base64 decoder.
    let cleaned: Vec<u8> = body
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let der_bytes = base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| EnrollError::Pkcs7Parse(format!("base64: {e}")))?;
    let info = ContentInfo::from_der(&der_bytes)
        .map_err(|e| EnrollError::Pkcs7Parse(format!("content_info: {e}")))?;
    let signed: SignedData = info
        .content
        .decode_as()
        .map_err(|e| EnrollError::Pkcs7Parse(format!("signed_data: {e}")))?;
    let mut out = Vec::new();
    if let Some(set) = signed.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                out.push(
                    cert.to_der()
                        .map_err(|e| EnrollError::Pkcs7Parse(format!("cert der: {e}")))?,
                );
            }
        }
    }
    if out.is_empty() {
        return Err(EnrollError::EmptyCaPool);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_degenerate_certs_only_pkcs7() {
        let b64 = include_bytes!("../../tests/fixtures/cacerts.p7b.b64");
        let certs = parse_cacerts_b64(b64).expect("must parse EST cacerts");
        assert_eq!(certs.len(), 2, "fixture has a 2-cert bundle");
        for der in &certs {
            x509_cert::Certificate::from_der(der).expect("valid DER cert");
        }
    }

    #[test]
    fn rejects_malformed_base64() {
        use crate::enroll::error::EnrollError;
        let err = parse_cacerts_b64(b"this is not base64!!!").unwrap_err();
        assert!(matches!(err, EnrollError::Pkcs7Parse(_)));
    }

    #[test]
    fn tolerates_wrapped_base64_whitespace() {
        // The same fixture but with injected newlines must still parse (Go-parity).
        let b64 = include_bytes!("../../tests/fixtures/cacerts.p7b.b64");
        let mut wrapped = Vec::new();
        for (i, b) in b64.iter().enumerate() {
            wrapped.push(*b);
            if i % 16 == 0 {
                wrapped.push(b'\n');
            }
        }
        let certs = parse_cacerts_b64(&wrapped).expect("wrapped base64 must still parse");
        assert_eq!(certs.len(), 2);
    }
}

use crate::enroll::error::EnrollError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Ec,
    Rsa,
}

/// Extract the subjectPublicKeyInfo as SPKI PEM (`-----BEGIN PUBLIC KEY-----`)
/// plus whether it is EC or RSA, from a DER-encoded X.509 leaf certificate.
/// Used to verify the enrolment JWT against the controller's TLS leaf key.
///
/// # Errors
///
/// Returns [`EnrollError::JwtSignature`] if the certificate cannot be parsed,
/// the SPKI cannot be PEM-encoded, or the public-key algorithm OID is neither
/// EC nor RSA.
pub fn spki_pem_from_cert_der(der: &[u8]) -> Result<(String, KeyKind), EnrollError> {
    use x509_cert::der::pem::LineEnding;
    use x509_cert::der::{Decode, EncodePem};
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| EnrollError::JwtSignature(format!("leaf cert parse: {e}")))?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let pem = spki
        .to_pem(LineEnding::LF)
        .map_err(|e| EnrollError::JwtSignature(format!("spki pem: {e}")))?;
    let kind = match spki.algorithm.oid.to_string().as_str() {
        "1.2.840.10045.2.1" => KeyKind::Ec,
        "1.2.840.113549.1.1.1" => KeyKind::Rsa,
        other => {
            return Err(EnrollError::JwtSignature(format!(
                "unsupported key OID {other}"
            )));
        }
    };
    Ok((pem, kind))
}

#[cfg(test)]
mod spki_tests {
    use super::*;

    #[test]
    fn extracts_ec_spki_from_self_signed() {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let der = cert.der().as_ref().to_vec();
        let (pem, kind) = spki_pem_from_cert_der(&der).unwrap();
        assert_eq!(kind, KeyKind::Ec);
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }
}

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::sync::Arc;
use std::sync::Mutex;

/// Verifier that accepts ANY server certificate and records the presented leaf.
/// This is the `InsecureSkipVerify` equivalent used ONLY for the bootstrap GET
/// to the issuer, whose sole purpose is to capture the leaf cert. Oracle:
/// enroll.go `FetchServerCert` (`InsecureSkipVerify` + `PeerCertificates[0]`).
#[derive(Debug)]
pub struct CapturingVerifier {
    leaf: Mutex<Option<Vec<u8>>>,
}

impl CapturingVerifier {
    #[allow(clippy::new_ret_no_self)]
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            leaf: Mutex::new(None),
        })
    }

    #[must_use]
    pub fn captured_leaf(&self) -> Option<Vec<u8>> {
        self.leaf.lock().unwrap().clone()
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        *self.leaf.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod capturing_verifier_tests {
    use super::*;

    #[test]
    fn captures_presented_leaf() {
        let verifier = CapturingVerifier::new();
        let leaf = CertificateDer::from(vec![1u8, 2, 3]);
        let server_name = ServerName::try_from("localhost").unwrap();
        verifier
            .verify_server_cert(&leaf, &[], &server_name, &[], UnixTime::now())
            .unwrap();
        assert_eq!(verifier.captured_leaf(), Some(vec![1u8, 2, 3]));
    }
}

/// The rustls [`CryptoProvider`](rustls::crypto::CryptoProvider): **aws-lc-rs**, the single crypto
/// backend of this crate (rustls' default; FFI over AWS-LC in C/asm).
///
/// There used to be a `graviola` feature swapping this for a pure-Rust provider. It was removed
/// (D5, 2026-07-11): it could only swap the TLS *handshake* provider, while `rcgen`, `jsonwebtoken`
/// and `rustls` itself keep aws-lc-rs in the binary regardless — so it never delivered the pure-Rust
/// build it advertised.
fn selected_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// Ensure a process-wide crypto provider is installed. Idempotent.
///
/// Installs the [`selected_provider`] (aws-lc-rs).
pub fn ensure_crypto_provider() {
    let _ = selected_provider().install_default();
}

#[cfg(test)]
mod crypto_provider_tests {
    use super::*;

    #[test]
    fn selected_provider_exposes_suites_kx_and_sig_algs() {
        let provider = selected_provider();
        assert!(
            !provider.cipher_suites.is_empty(),
            "provider must offer TLS cipher suites"
        );
        assert!(
            !provider.kx_groups.is_empty(),
            "provider must offer key-exchange groups"
        );
        assert!(
            !provider
                .signature_verification_algorithms
                .supported_schemes()
                .is_empty(),
            "provider must offer signature-verification schemes"
        );
    }

    #[test]
    fn ensure_crypto_provider_is_idempotent() {
        // install_default only succeeds once per process; calling it again must
        // not panic and a default must remain installed.
        ensure_crypto_provider();
        ensure_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}

/// reqwest client that captures the issuer's leaf cert (insecure; bootstrap only).
///
/// # Errors
///
/// Returns [`EnrollError::BootstrapTls`] if the reqwest client cannot be built.
pub fn insecure_capturing_client(
    verifier: Arc<CapturingVerifier>,
) -> Result<reqwest::Client, EnrollError> {
    ensure_crypto_provider();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| EnrollError::BootstrapTls(e.to_string()))
}

/// reqwest client that trusts exactly the given DER certs (the fetched CA pool).
///
/// # Errors
///
/// Returns [`EnrollError::CaFetch`] if a root cannot be added to the store or
/// the reqwest client cannot be built.
pub fn verified_client(roots_der: &[Vec<u8>]) -> Result<reqwest::Client, EnrollError> {
    build_verified_client(roots_der, false)
}

/// Like [`verified_client`] but does NOT auto-follow redirects — for the password OIDC PKCE flow,
/// which is driven step-by-step (each 302's `Location` is read by hand). Same RootCAs-only TLS; only
/// the redirect policy differs.
///
/// # Errors
/// Returns [`EnrollError::CaFetch`] if a root cannot be added or the client cannot be built.
pub fn verified_client_no_redirect(roots_der: &[Vec<u8>]) -> Result<reqwest::Client, EnrollError> {
    build_verified_client(roots_der, true)
}

fn build_verified_client(
    roots_der: &[Vec<u8>],
    no_redirect: bool,
) -> Result<reqwest::Client, EnrollError> {
    ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    for der in roots_der {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| EnrollError::CaFetch(format!("add root: {e}")))?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut builder = reqwest::Client::builder().use_preconfigured_tls(config);
    if no_redirect {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }
    builder
        .build()
        .map_err(|e| EnrollError::CaFetch(e.to_string()))
}

/// reqwest client that trusts the given CA roots AND presents a client cert for mTLS
/// (client-auth). Used by `ottca` enrolment, where a pre-existing CA-issued identity
/// authenticates the empty-body enrolment POST. Oracle: enroll.go enrollCA's
/// `tls.Config{RootCAs: caPool, Certificates: [clientCert]}` (:454-456). The cert+key
/// are raw PEM (no `pem:` prefix); parsed with `rustls-pemfile` (same as the data-plane
/// `identity_tls::client_config`, replicated here to keep enroll independent of edge).
///
/// # Errors
///
/// Returns [`EnrollError::CaFetch`] if a root can't be added, and
/// [`EnrollError::EnrollResponse`] if the cert/key PEM can't be parsed or the client
/// can't be built (cert/key mismatch surfaces here).
pub fn client_auth_client(
    client_cert_pem: &str,
    client_key_pem: &str,
    roots_der: &[Vec<u8>],
) -> Result<reqwest::Client, EnrollError> {
    use std::io::Cursor;
    ensure_crypto_provider();

    let mut cert_reader = Cursor::new(client_cert_pem.as_bytes());
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<_, _>>()
        .map_err(|e| EnrollError::EnrollResponse(format!("client cert pem: {e}")))?;
    if cert_chain.is_empty() {
        return Err(EnrollError::EnrollResponse(
            "no certificates in client identity PEM".into(),
        ));
    }

    let mut key_reader = Cursor::new(client_key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| EnrollError::EnrollResponse(format!("client key pem: {e}")))?
        .ok_or_else(|| {
            EnrollError::EnrollResponse("no private key in client identity PEM".into())
        })?;

    let mut roots = rustls::RootCertStore::empty();
    for der in roots_der {
        roots
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| EnrollError::CaFetch(format!("add root: {e}")))?;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|e| EnrollError::EnrollResponse(format!("client auth cert: {e}")))?;
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| EnrollError::EnrollResponse(e.to_string()))
}

/// Parse caller-supplied additional-CA certificates from a PEM string into DER bytes.
/// BEST-EFFORT, mirroring the oracle's `GetCertPool` (enroll.go:70-84): non-`CERTIFICATE` blocks,
/// unparseable blocks, AND base64-valid-but-not-a-real-cert blocks are silently skipped, so an input
/// with no valid certs simply contributes nothing (the fetched controller CA bundle still anchors
/// trust). Used to seed the enrolment trust pool + identity CA bundle with extra CAs.
#[must_use]
pub(crate) fn parse_ca_pems(pem: &str) -> Vec<Vec<u8>> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .filter_map(Result::ok)
        // Keep ONLY certs that pass the trust-anchor parse `RootCertStore::add` performs — exactly
        // what `verified_client`/`client_auth_client` feed these DERs into. A base64-valid but
        // X.509-invalid CERTIFICATE block frames cleanly yet is NOT a real cert; without this gate it
        // would reach `roots.add(...)?` and abort the WHOLE enrolment (and a good+corrupt bundle would
        // lose the good cert too). The oracle drops bad blocks silently (`PemStringToCertificates` +
        // x509.ParseCertificate, enroll.go:77). Anchor-parse is provider-independent (pure DER → no
        // crypto provider needed).
        .filter(|der| {
            let mut store = rustls::RootCertStore::empty();
            store.add(der.clone()).is_ok()
        })
        .map(|c| c.as_ref().to_vec())
        .collect()
}

#[cfg(test)]
mod ca_pem_tests {
    use super::*;

    fn self_signed_pem() -> (String, Vec<u8>) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = rcgen::CertificateParams::new(vec!["ca".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (cert.pem(), cert.der().as_ref().to_vec())
    }

    #[test]
    fn parses_one_and_two_cert_bundles_into_der() {
        let (one_pem, one_der) = self_signed_pem();
        let parsed = parse_ca_pems(&one_pem);
        assert_eq!(parsed, vec![one_der]);

        let (a, _) = self_signed_pem();
        let (b, _) = self_signed_pem();
        assert_eq!(parse_ca_pems(&format!("{a}{b}")).len(), 2);
    }

    #[test]
    fn best_effort_skips_non_certificate_and_garbage() {
        // A private-key PEM is not a CERTIFICATE block → contributes nothing (oracle GetCertPool).
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        assert!(parse_ca_pems(&kp.serialize_pem()).is_empty());
        assert!(parse_ca_pems("not pem at all").is_empty());
        assert!(parse_ca_pems("").is_empty());
    }

    #[test]
    fn drops_framed_but_x509_invalid_certificate_block() {
        // A CERTIFICATE block whose body is valid base64 ("hello") but NOT a real X.509 cert frames
        // cleanly yet must be dropped — without the anchor gate it parses as a DER and then poisons
        // `RootCertStore::add(...)?`, aborting the whole enrolment (the bug this slice's review caught).
        let framed_invalid = "-----BEGIN CERTIFICATE-----\naGVsbG8=\n-----END CERTIFICATE-----\n";
        assert!(parse_ca_pems(framed_invalid).is_empty());

        // And a good cert alongside a framed-invalid block keeps ONLY the good one (no `?`-bail).
        let (good_pem, good_der) = self_signed_pem();
        let mixed = format!("{good_pem}{framed_invalid}");
        assert_eq!(parse_ca_pems(&mixed), vec![good_der]);
    }
}

/// Verifier that trusts ONLY the exact pinned leaf certificate (trust-on-first-use
/// by DER identity), mirroring the Go client's leaf pinning. The leaf was already
/// validated out-of-band by verifying the enrolment JWT against its public key, so
/// pinning the cacerts TLS connection to this exact DER is the correct trust anchor.
///
/// This deliberately does NOT chain-build to the leaf as a CA anchor (as a
/// `RootCertStore` would), because OpenZiti controllers normally present a
/// CA-signed leaf, which webpki rejects when treated as a self-signed root.
pub struct PinnedLeafVerifier {
    pinned: Vec<u8>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for PinnedLeafVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedLeafVerifier")
            .field("pinned_len", &self.pinned.len())
            .finish_non_exhaustive()
    }
}

impl PinnedLeafVerifier {
    #[allow(clippy::new_ret_no_self)]
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub fn new(leaf_der: Vec<u8>) -> Arc<Self> {
        ensure_crypto_provider();
        let supported = selected_provider().signature_verification_algorithms;
        Arc::new(Self {
            pinned: leaf_der,
            supported,
        })
    }
}

impl ServerCertVerifier for PinnedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.pinned.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "server certificate does not match pinned leaf".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// reqwest client that trusts ONLY the exact pinned leaf cert (trust-on-first-use),
/// for the cacerts fetch. The leaf was already validated by verifying the enrolment
/// JWT against its public key. Mirrors the Go client's leaf-pinning (it does NOT
/// chain-build to the leaf as a CA, which rustls would reject for CA-signed leaves).
///
/// # Errors
///
/// Returns [`EnrollError::CaFetch`] if the reqwest client cannot be built.
pub fn pinned_leaf_client(leaf_der: Vec<u8>) -> Result<reqwest::Client, EnrollError> {
    ensure_crypto_provider();
    let verifier = PinnedLeafVerifier::new(leaf_der);
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| EnrollError::CaFetch(e.to_string()))
}

#[cfg(test)]
mod pinned_verifier_tests {
    use super::*;

    #[test]
    fn pinned_verifier_accepts_only_matching_leaf() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        ensure_crypto_provider();
        // Build a CA-signed leaf so this also guards the original bug (CA-signed != self-signed).
        let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["ctrl.example".to_string()]).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
        let leaf = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();
        let leaf_der = leaf.der().as_ref().to_vec();

        let verifier = PinnedLeafVerifier::new(leaf_der.clone());
        let name = ServerName::try_from("ctrl.example").unwrap();
        // matching leaf accepted
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(leaf_der.clone()),
                    &[],
                    &name,
                    &[],
                    UnixTime::now()
                )
                .is_ok()
        );
        // a different cert rejected
        let other = rcgen::CertificateParams::new(vec!["evil".to_string()])
            .unwrap()
            .self_signed(&rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap())
            .unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &CertificateDer::from(other.der().as_ref().to_vec()),
                    &[],
                    &name,
                    &[],
                    UnixTime::now()
                )
                .is_err()
        );
    }
}
