//! Key generation and CSR construction. Oracle: enroll.go generateECKey/generateRSAKey + certtools.
//!
//! The controller only ever sees the CSR (public key + self-signature); the private key never
//! leaves the client, so the local key encoding is our choice. Both algorithms reuse one CSR
//! builder — only the key (and thus the CSR's signature algorithm) differs.

use crate::enroll::error::EnrollError;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256, RsaKeySize,
};

/// Client key algorithm for enrolment. Mirrors the oracle's `KeyAlgVar` (`EC`|`RSA`), defaulting
/// to EC P-384 so existing callers (`EnrollOptions::default()`) keep their behaviour. RSA is 4096-bit
/// to match `generateRSAKey` (enroll.go:290).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum KeyAlg {
    /// EC P-384 (oracle `generateECKey`). The default.
    #[default]
    EcP384,
    /// RSA 4096-bit (oracle `generateRSAKey`).
    Rsa4096,
}

impl KeyAlg {
    /// Parse a CLI/config key-algorithm string, mirroring the oracle's `KeyAlgVar.Set`
    /// (key_alg_var.go:31-38): uppercases the value, accepts ONLY `EC` or `RSA`, else the byte-exact
    /// error. Used by the `noa enroll --keyAlg` flag (oracle CLI `-a, --keyAlg RSA|EC`).
    ///
    /// Uses Unicode `to_uppercase` (not ASCII-only) to match Go's `strings.ToUpper` exactly — e.g.
    /// `"rſa"` (U+017F) uppercases to `"RSA"` and is accepted, as in Go.
    ///
    /// # Errors
    /// Returns [`EnrollError::InvalidKeyAlg`] for any value other than `EC`/`RSA` (any case).
    pub fn parse(value: &str) -> Result<Self, EnrollError> {
        match value.to_uppercase().as_str() {
            "EC" => Ok(KeyAlg::EcP384),
            "RSA" => Ok(KeyAlg::Rsa4096),
            _ => Err(EnrollError::InvalidKeyAlg),
        }
    }
}

/// A freshly generated key and the matching CSR, both PEM-encoded.
pub struct KeyAndCsr {
    /// PKCS#8 private key PEM (`-----BEGIN PRIVATE KEY-----`).
    pub key_pem: String,
    /// CSR PEM (`-----BEGIN CERTIFICATE REQUEST-----`).
    pub csr_pem: String,
}

/// Generate a key of the requested algorithm and a CSR with subject `C=US, O=NetFoundry, CN=<cn>`.
///
/// # Errors
/// Returns [`EnrollError::KeyGen`] if key generation fails and [`EnrollError::CsrBuild`] if building
/// or PEM-encoding the CSR fails.
pub fn generate_csr(common_name: &str, key_alg: KeyAlg) -> Result<KeyAndCsr, EnrollError> {
    match key_alg {
        KeyAlg::EcP384 => generate_ec_p384_csr(common_name),
        KeyAlg::Rsa4096 => generate_rsa_4096_csr(common_name),
    }
}

/// Generate an EC P-384 key and a CSR. Oracle: `generateECKey` (enroll.go:284).
///
/// # Errors
/// See [`generate_csr`].
pub fn generate_ec_p384_csr(common_name: &str) -> Result<KeyAndCsr, EnrollError> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
        .map_err(|e| EnrollError::KeyGen(e.to_string()))?;
    build_csr(common_name, &key_pair)
}

/// Generate an RSA 4096-bit key and a CSR. Oracle: `generateRSAKey` (enroll.go:290), signed
/// SHA256WithRSA (Go's `x509.CreateCertificateRequest` default for RSA keys). The key comes from
/// rcgen's aws-lc-rs backend (`generate_rsa_for`) — no `ring`.
///
/// # Errors
/// See [`generate_csr`].
pub fn generate_rsa_4096_csr(common_name: &str) -> Result<KeyAndCsr, EnrollError> {
    let key_pair = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_4096)
        .map_err(|e| EnrollError::KeyGen(e.to_string()))?;
    build_csr(common_name, &key_pair)
}

/// Generate an EC **P-256** key and a CSR, for the api-session certificate flow (NOT enrolment).
/// Oracle: `NewApiSessionCertificate` (`ziti/client.go:334`) generates an `ecdsa.P256` key, signs the
/// CSR `ecdsa-with-SHA256`, and POSTs it to mint an ephemeral mTLS client cert for the edge router.
///
/// This is a SEPARATE curve from enrolment (EC P-384 / RSA-4096): P-256 is fidelity to the oracle's
/// session-cert path, not an `--keyAlg` option, so it deliberately does NOT go through the public
/// [`KeyAlg`] enum. It reuses the shared [`build_csr`] (subject + no-SANs) — only the key differs. The
/// key comes from rcgen's aws-lc-rs backend (no `ring`).
///
/// # Errors
/// See [`generate_csr`].
pub fn generate_session_cert_csr(common_name: &str) -> Result<KeyAndCsr, EnrollError> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| EnrollError::KeyGen(e.to_string()))?;
    build_csr(common_name, &key_pair)
}

/// Build a CSR from an ALREADY-EXISTING key (PEM), reusing the same key instead of generating a
/// fresh one. For the session-cert RENEWAL path (a conscious improvement beyond the oracle —
/// `EnsureApiSessionCertificate` never renews): the oracle's key model stores ONE ephemeral key
/// per api-session (`ApiSessionPrivateKey`, `ziti/client.go:330`), so each re-mint must present the
/// SAME public key. We reload the stored PKCS#8 PEM via `rcgen::KeyPair::from_pem` and rebuild the
/// CSR over it; the SPKI (public key) is therefore identical across renewals.
///
/// `key_pem` is the PKCS#8 PEM previously produced by [`generate_session_cert_csr`]. The CSR carries
/// the same EC P-256 subject (`C=US, O=NetFoundry, CN=<common_name>`, no SANs) via the shared
/// [`build_csr`].
///
/// # Errors
/// [`EnrollError::KeyGen`] if the stored key PEM cannot be reloaded; [`EnrollError::CsrBuild`] if
/// building or PEM-encoding the CSR fails.
pub fn session_cert_csr_from_key(
    common_name: &str,
    key_pem: &str,
) -> Result<KeyAndCsr, EnrollError> {
    let key_pair = KeyPair::from_pem(key_pem).map_err(|e| EnrollError::KeyGen(e.to_string()))?;
    build_csr(common_name, &key_pair)
}

/// Build a CSR with subject `C=US, O=NetFoundry, CN=<common_name>`, no SANs, no extra extensions —
/// matching the Go client exactly. Shared by both key algorithms.
fn build_csr(common_name: &str, key_pair: &KeyPair) -> Result<KeyAndCsr, EnrollError> {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "US");
    dn.push(DnType::OrganizationName, "NetFoundry");
    dn.push(DnType::CommonName, common_name);

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| EnrollError::CsrBuild(e.to_string()))?;
    params.distinguished_name = dn;

    let csr = params
        .serialize_request(key_pair)
        .map_err(|e| EnrollError::CsrBuild(e.to_string()))?;
    let csr_pem = csr
        .pem()
        .map_err(|e| EnrollError::CsrBuild(e.to_string()))?;
    let key_pem = key_pair.serialize_pem();

    Ok(KeyAndCsr { key_pem, csr_pem })
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::DecodePem;
    use x509_cert::der::asn1::ObjectIdentifier;
    use x509_cert::request::CertReq;

    // OIDs of the SubjectPublicKeyInfo algorithm (RFC 5480 / PKCS#1).
    const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    // CSR signature algorithm for an RSA key = Go's `SHA256WithRSA` default.
    const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
    // EC named-curve OIDs (RFC 5480 §2.1.1.1) carried in the SPKI algorithm parameters.
    const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";
    // CSR signature algorithm for a P-256 key = `ecdsa-with-SHA256` (P-384 signs ecdsa-with-SHA384).
    const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

    fn parse(csr_pem: &str) -> CertReq {
        CertReq::from_pem(csr_pem.as_bytes()).expect("valid CSR PEM")
    }

    fn spki_oid(req: &CertReq) -> String {
        req.info.public_key.algorithm.oid.to_string()
    }

    #[test]
    fn ec_csr_has_expected_subject_and_no_sans() {
        let out = generate_ec_p384_csr("my-identity").unwrap();
        assert!(out.key_pem.contains("PRIVATE KEY"));
        assert!(out.csr_pem.contains("CERTIFICATE REQUEST"));

        let req = parse(&out.csr_pem);
        let subject = req.info.subject.to_string();
        assert!(subject.contains("CN=my-identity"), "subject was {subject}");
        assert!(subject.contains("O=NetFoundry"), "subject was {subject}");
        assert!(subject.contains("C=US"), "subject was {subject}");
        assert_eq!(spki_oid(&req), OID_EC_PUBLIC_KEY, "expected ecPublicKey");
        // Oracle builds the CSR with no SANs / no extra extensions (certtools.NewCertRequest(.., nil)).
        assert!(
            req.info.attributes.is_empty(),
            "CSR must carry no attributes (no SAN/extension request)"
        );
    }

    #[test]
    fn rsa_csr_has_rsa4096_key_and_expected_subject() {
        let out = generate_rsa_4096_csr("rsa-identity").unwrap();
        // rcgen serialises every key as PKCS#8 ("BEGIN PRIVATE KEY"), RSA included — a conscious, local
        // deviation from the oracle's PKCS#1 "RSA PRIVATE KEY" (the controller never sees the key).
        assert!(
            out.key_pem.contains("BEGIN PRIVATE KEY") && !out.key_pem.contains("RSA PRIVATE KEY"),
            "key must be PKCS#8, not PKCS#1"
        );
        assert!(out.csr_pem.contains("CERTIFICATE REQUEST"));

        let req = parse(&out.csr_pem);
        let subject = req.info.subject.to_string();
        assert!(subject.contains("CN=rsa-identity"), "subject was {subject}");
        assert!(subject.contains("O=NetFoundry"), "subject was {subject}");
        assert!(subject.contains("C=US"), "subject was {subject}");
        assert_eq!(spki_oid(&req), OID_RSA_ENCRYPTION, "expected rsaEncryption");
        // A 4096-bit RSA SPKI key is ~526 B; RSA-3072 ~398, RSA-2048 ~270, EC P-384 ~97. >500 pins 4096
        // (a downgrade to 3072 or 2048 falls below the threshold).
        let key_len = req.info.public_key.subject_public_key.raw_bytes().len();
        assert!(
            key_len > 500,
            "expected a 4096-bit RSA key, SPKI key bytes = {key_len}"
        );
        // CSR self-signature algorithm = sha256WithRSAEncryption (mutating PKCS_RSA_SHA256 changes this).
        assert_eq!(
            req.algorithm.oid.to_string(),
            OID_SHA256_WITH_RSA,
            "expected sha256WithRSAEncryption"
        );
    }

    #[test]
    fn session_cert_csr_is_ec_p256() {
        // Oracle NewApiSessionCertificate uses EC P-256 (client.go:334), NOT the enrolment P-384.
        // Three independent P-256 discriminators (any one goes RED on a P-384 regression):
        //   1. SPKI curve parameter OID = secp256r1 (the most literal "this is P-256").
        //   2. CSR signature algorithm = ecdsa-with-SHA256 (P-384 would sign ecdsa-with-SHA384).
        //   3. SPKI public key = 65 bytes (uncompressed P-256 point 0x04|X32|Y32; P-384 = 97).
        let out = generate_session_cert_csr("apiSession").unwrap();
        // rcgen serialises the key as PKCS#8 ("BEGIN PRIVATE KEY"), as for the enrolment EC path.
        assert!(
            out.key_pem.contains("BEGIN PRIVATE KEY"),
            "key must be PKCS#8"
        );
        assert!(out.csr_pem.contains("CERTIFICATE REQUEST"));

        let req = parse(&out.csr_pem);
        assert_eq!(spki_oid(&req), OID_EC_PUBLIC_KEY, "expected ecPublicKey");

        // 1. Curve OID from the SPKI algorithm parameters.
        let params = req
            .info
            .public_key
            .algorithm
            .parameters
            .clone()
            .expect("EC SPKI carries named-curve parameters");
        let curve: ObjectIdentifier = params.decode_as().expect("curve OID");
        assert_eq!(
            curve.to_string(),
            OID_SECP256R1,
            "expected secp256r1 (P-256)"
        );

        // 2. CSR self-signature algorithm.
        assert_eq!(
            req.algorithm.oid.to_string(),
            OID_ECDSA_WITH_SHA256,
            "expected ecdsa-with-SHA256 (P-384 would be ecdsa-with-SHA384)"
        );

        // 3. Uncompressed P-256 point length.
        let key_len = req.info.public_key.subject_public_key.raw_bytes().len();
        assert_eq!(key_len, 65, "expected a 65-byte uncompressed P-256 point");

        // Subject CN is present (cosmetic — the controller overwrites the Subject; spec §5.4).
        assert!(
            req.info.subject.to_string().contains("CN=apiSession"),
            "CN present"
        );
    }

    #[test]
    fn session_cert_csr_from_key_reuses_the_same_public_key() {
        // The renewal path (a conscious improvement beyond the oracle) must REUSE the stored
        // ephemeral key (oracle's `ApiSessionPrivateKey` model), so a re-minted CSR carries the
        // SAME public key as the original. Generate one CSR (the original mint), then rebuild a CSR
        // from its stored key (a re-mint) and assert the two SPKIs are byte-identical — the
        // mutation-killer for "did we actually reuse the key" (a fresh-key impl would differ).
        let first = generate_session_cert_csr("apiSession").unwrap();
        let second = session_cert_csr_from_key("apiSession", &first.key_pem).unwrap();

        let req1 = parse(&first.csr_pem);
        let req2 = parse(&second.csr_pem);
        let spki1 = req1.info.public_key.subject_public_key.raw_bytes();
        let spki2 = req2.info.public_key.subject_public_key.raw_bytes();
        assert_eq!(
            spki1, spki2,
            "the re-minted CSR must carry the SAME public key (key reuse)"
        );
        // Still an EC P-256 CSR with the expected subject (it reuses build_csr).
        assert_eq!(spki_oid(&req2), OID_EC_PUBLIC_KEY, "still ecPublicKey");
        assert_eq!(spki2.len(), 65, "still a 65-byte uncompressed P-256 point");
        assert!(
            req2.info.subject.to_string().contains("CN=apiSession"),
            "CN present on the re-minted CSR"
        );
    }

    #[test]
    fn session_cert_csr_from_key_errors_on_garbage_key() {
        // KeyAndCsr is intentionally non-Debug (it holds a key), so match instead of expect_err.
        match session_cert_csr_from_key("apiSession", "not a pem key") {
            Err(EnrollError::KeyGen(_)) => {}
            Err(other) => panic!("expected KeyGen, got {other:?}"),
            Ok(_) => panic!("a non-PEM key must error"),
        }
    }

    #[test]
    fn generate_csr_dispatches_on_key_alg() {
        let ec = parse(&generate_csr("d", KeyAlg::EcP384).unwrap().csr_pem);
        let rsa = parse(&generate_csr("d", KeyAlg::Rsa4096).unwrap().csr_pem);
        assert_eq!(spki_oid(&ec), OID_EC_PUBLIC_KEY);
        assert_eq!(spki_oid(&rsa), OID_RSA_ENCRYPTION);
    }

    #[test]
    fn key_alg_defaults_to_ec() {
        assert_eq!(KeyAlg::default(), KeyAlg::EcP384);
    }

    #[test]
    fn key_alg_parse_is_case_insensitive_ec_rsa() {
        // Oracle KeyAlgVar.Set uppercases then matches EC|RSA exactly (key_alg_var.go:31-38).
        for ec in ["EC", "ec", "Ec", "eC"] {
            assert_eq!(KeyAlg::parse(ec).unwrap(), KeyAlg::EcP384, "{ec}");
        }
        for rsa in ["RSA", "rsa", "Rsa", "rSa"] {
            assert_eq!(KeyAlg::parse(rsa).unwrap(), KeyAlg::Rsa4096, "{rsa}");
        }
        // Unicode uppercase (Go's strings.ToUpper) — U+017F LONG S uppercases to ASCII 'S'.
        assert_eq!(KeyAlg::parse("rſa").unwrap(), KeyAlg::Rsa4096);
    }

    #[test]
    fn key_alg_parse_rejects_other_with_byte_exact_message() {
        for bad in ["", "ecdsa", "RSA4096", "p384", "x"] {
            let err = KeyAlg::parse(bad).expect_err(bad);
            assert!(matches!(err, EnrollError::InvalidKeyAlg), "{bad}: {err:?}");
            // Byte-exact oracle string (key_alg_var.go:34).
            assert_eq!(
                err.to_string(),
                "invalid option -- must specify either 'EC' or 'RSA'"
            );
        }
    }
}
