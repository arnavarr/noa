//! Enrolment JWT claims, parsing, and URL derivation. Oracle: sdk-golang token.go.

use crate::enroll::error::EnrollError;
use serde::Deserialize;

const EDGE_CLIENT_BASE: &str = "/edge/client/v1";

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentClaims {
    pub iss: String,
    pub sub: String,
    #[serde(rename = "jti")]
    pub jti: String,
    #[serde(rename = "em")]
    pub method: String,
    #[serde(rename = "exp", default)]
    pub exp: Option<i64>,
}

impl EnrollmentClaims {
    fn issuer_base(&self) -> Result<String, EnrollError> {
        let trimmed = self.iss.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(EnrollError::InvalidToken("empty issuer".into()));
        }
        Ok(trimmed.to_string())
    }

    /// `<iss>/edge/client/v1`
    ///
    /// # Errors
    /// Returns [`EnrollError::InvalidToken`] if the issuer is empty.
    pub fn zt_api(&self) -> Result<String, EnrollError> {
        Ok(format!("{}{}", self.issuer_base()?, EDGE_CLIENT_BASE))
    }

    /// `<iss>/edge/client/v1/enroll?method=<em>&token=<jti>` (token omitted for `ca`).
    ///
    /// # Errors
    /// Returns [`EnrollError::InvalidToken`] if the issuer is empty.
    pub fn enroll_url(&self) -> Result<String, EnrollError> {
        let base = format!(
            "{}{}/enroll?method={}",
            self.issuer_base()?,
            EDGE_CLIENT_BASE,
            self.method
        );
        if self.method == "ca" {
            Ok(base)
        } else {
            Ok(format!("{base}&token={}", self.jti))
        }
    }

    /// `<iss>/edge/client/v1/.well-known/est/cacerts`
    ///
    /// # Errors
    /// Returns [`EnrollError::InvalidToken`] if the issuer is empty.
    pub fn cacerts_url(&self) -> Result<String, EnrollError> {
        Ok(format!(
            "{}{}/.well-known/est/cacerts",
            self.issuer_base()?,
            EDGE_CLIENT_BASE
        ))
    }
}

/// Parse the JWT WITHOUT verifying the signature, to read the issuer first.
/// Mirrors the Go flow: claims (esp. `iss`) are needed before the signature key
/// (the issuer's TLS leaf cert) can be fetched. Verification happens later in
/// `token::verify`. Oracle: enroll.go ParseToken + ValidateToken split.
///
/// # Errors
/// Returns [`EnrollError::InvalidToken`] if the input is not a JWT, the payload
/// is not valid base64url JSON, or the `iss` claim is missing.
pub fn parse(jwt: &str) -> Result<EnrollmentClaims, EnrollError> {
    use base64::Engine;
    let jwt = jwt.trim();
    let payload_b64 = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| EnrollError::InvalidToken("not a JWT (missing payload)".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| EnrollError::InvalidToken(format!("payload base64: {e}")))?;
    let claims: EnrollmentClaims = serde_json::from_slice(&bytes)
        .map_err(|e| EnrollError::InvalidToken(format!("payload json: {e}")))?;
    if claims.iss.trim().is_empty() {
        return Err(EnrollError::InvalidToken("missing iss".into()));
    }
    // Validate the issuer is a proper URL WITH A HOST. The oracle calls `url.Parse(claims.Issuer)`
    // (ValidateToken, enroll.go:118), but Go's `url.Parse` is LENIENT — it accepts `not-a-url` (a
    // relative ref) and `host:1280` (scheme=`host`, no host) WITHOUT error, so it gates almost nothing.
    // We are deliberately STRICTER: require a parseable URL that HAS a host — a fail-fast on a malformed
    // issuer (which would otherwise fail later, opaquely, at the bootstrap GET). PURELY ADDITIVE: the
    // endpoint URL derivation (`zt_api`/`enroll_url`/`cacerts_url`) still concatenates the issuer + path
    // verbatim (see `issuer_base`), which CONSCIOUSLY KEEPS any non-root issuer path — a fix over the
    // oracle's inconsistent `EnrolmentUrl` (its `ResolveReference` with an absolute-path ref DROPS it).
    let parsed = url::Url::parse(claims.iss.trim())
        .map_err(|e| EnrollError::InvalidToken(format!("issuer is not a valid URL: {e}")))?;
    if parsed.host_str().is_none() {
        return Err(EnrollError::InvalidToken(format!(
            "issuer URL has no host: {}",
            claims.iss
        )));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn jwt_with_payload(json: &str) -> String {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b.encode(b"{\"alg\":\"ES384\"}"),
            b.encode(json.as_bytes()),
            b.encode(b"sig")
        )
    }

    #[test]
    fn parses_claims_and_derives_urls() {
        let jwt = jwt_with_payload(
            r#"{"iss":"https://ctrl.example:1280/","sub":"abc","jti":"TOK","em":"ott","exp":9999999999}"#,
        );
        let c = parse(&jwt).unwrap();
        assert_eq!(c.method, "ott");
        assert_eq!(
            c.zt_api().unwrap(),
            "https://ctrl.example:1280/edge/client/v1"
        );
        assert_eq!(
            c.enroll_url().unwrap(),
            "https://ctrl.example:1280/edge/client/v1/enroll?method=ott&token=TOK"
        );
        assert_eq!(
            c.cacerts_url().unwrap(),
            "https://ctrl.example:1280/edge/client/v1/.well-known/est/cacerts"
        );
    }

    #[test]
    fn rejects_non_jwt() {
        assert!(parse("garbage").is_err());
    }

    #[test]
    fn validates_issuer_url_and_rejects_garbage_or_hostless() {
        let with_iss = |iss: &str| {
            jwt_with_payload(&format!(
                r#"{{"iss":"{iss}","sub":"s","jti":"j","em":"ott"}}"#
            ))
        };
        // Valid https issuer with a host → Ok.
        assert!(parse(&with_iss("https://ctrl:1280")).is_ok());
        // Garbage (not a URL) → rejected. STRICTER than the oracle: Go's `url.Parse` accepts `not-a-url`
        // (a relative ref) without error; we additionally require a host (deliberate fail-fast).
        assert!(matches!(
            parse(&with_iss("not-a-url")),
            Err(EnrollError::InvalidToken(_))
        ));
        // Scheme-less `host:port`: url parses it as scheme=`localhost` with NO host → rejected
        // (Go's url.Parse also accepts this without error; we reject it).
        assert!(matches!(
            parse(&with_iss("localhost:1280")),
            Err(EnrollError::InvalidToken(_))
        ));
    }

    #[test]
    fn keeps_non_root_issuer_path_in_derived_urls() {
        // Conscious improvement over the oracle's inconsistent `EnrolmentUrl` (its `ResolveReference`
        // DROPS the issuer path): a path-prefixed controller's path is PRESERVED in every derived URL.
        let jwt =
            jwt_with_payload(r#"{"iss":"https://host/ziti","sub":"s","jti":"TOK","em":"ott"}"#);
        let c = parse(&jwt).unwrap();
        assert_eq!(c.zt_api().unwrap(), "https://host/ziti/edge/client/v1");
        assert_eq!(
            c.enroll_url().unwrap(),
            "https://host/ziti/edge/client/v1/enroll?method=ott&token=TOK"
        );
    }
}

use crate::enroll::trust::KeyKind;

/// Verify the enrolment JWT signature against the controller's TLS leaf cert
/// public key (SPKI PEM) and return the validated claims. Algorithm family is
/// pinned to the leaf key type (EC→ES*, RSA→RS*/PS*) to close alg-confusion.
/// Oracle: enroll.go `ValidateToken` (verifies against `FetchServerCert` pubkey).
///
/// # Errors
///
/// Returns [`EnrollError::JwtSignature`] if the decoding key cannot be built
/// from the SPKI PEM, or if the JWT signature/claims fail validation.
pub fn verify(
    jwt: &str,
    leaf_spki_pem: &str,
    kind: KeyKind,
) -> Result<EnrollmentClaims, EnrollError> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    let key = match kind {
        KeyKind::Ec => DecodingKey::from_ec_pem(leaf_spki_pem.as_bytes()),
        KeyKind::Rsa => DecodingKey::from_rsa_pem(leaf_spki_pem.as_bytes()),
    }
    .map_err(|e| EnrollError::JwtSignature(format!("decoding key: {e}")))?;

    let mut validation = match kind {
        KeyKind::Ec => Validation::new(Algorithm::ES384),
        KeyKind::Rsa => Validation::new(Algorithm::RS256),
    };
    validation.algorithms = match kind {
        KeyKind::Ec => vec![Algorithm::ES256, Algorithm::ES384],
        KeyKind::Rsa => vec![
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
        ],
    };
    validation.validate_aud = false;
    validation.validate_exp = true;
    validation.required_spec_claims.clear(); // Go-parity: exp validated only if present, not required

    let data = decode::<EnrollmentClaims>(jwt.trim(), &key, &validation)
        .map_err(|e| EnrollError::JwtSignature(e.to_string()))?;
    Ok(data.claims)
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use crate::enroll::trust::spki_pem_from_cert_der;

    #[test]
    fn verifies_jwt_signed_by_leaf_key() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        #[derive(serde::Serialize)]
        struct C<'a> {
            iss: &'a str,
            sub: &'a str,
            jti: &'a str,
            em: &'a str,
            exp: i64,
        }

        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let priv_pem = kp.serialize_pem();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let (spki_pem, kind) = spki_pem_from_cert_der(cert.der().as_ref()).unwrap();

        let claims = C {
            iss: "https://ctrl/",
            sub: "id1",
            jti: "TOK",
            em: "ott",
            exp: 9_999_999_999,
        };
        let enc = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
        let jwt = encode(&Header::new(Algorithm::ES384), &claims, &enc).unwrap();

        let out = verify(&jwt, &spki_pem, kind).unwrap();
        assert_eq!(out.jti, "TOK");
        assert_eq!(out.method, "ott");
    }

    #[test]
    fn rejects_tampered_signature() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        #[derive(serde::Serialize)]
        struct C {
            iss: String,
            sub: String,
            jti: String,
            em: String,
            exp: i64,
        }

        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let (spki_pem, kind) = spki_pem_from_cert_der(cert.der().as_ref()).unwrap();
        let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let claims = C {
            iss: "https://ctrl/".into(),
            sub: "x".into(),
            jti: "T".into(),
            em: "ott".into(),
            exp: 9_999_999_999,
        };
        let enc = EncodingKey::from_ec_pem(other.serialize_pem().as_bytes()).unwrap();
        let jwt = encode(&Header::new(Algorithm::ES384), &claims, &enc).unwrap();
        assert!(verify(&jwt, &spki_pem, kind).is_err());
    }

    #[test]
    fn rejects_alg_confusion_hs256() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        #[derive(serde::Serialize)]
        struct C {
            iss: String,
            sub: String,
            jti: String,
            em: String,
            exp: i64,
        }
        // EC leaf → its SPKI PEM is public; an attacker tries to use it as an HMAC secret.
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let (spki_pem, kind) =
            crate::enroll::trust::spki_pem_from_cert_der(cert.der().as_ref()).unwrap();

        let claims = C {
            iss: "https://ctrl/".into(),
            sub: "x".into(),
            jti: "T".into(),
            em: "ott".into(),
            exp: 9_999_999_999,
        };
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(spki_pem.as_bytes()),
        )
        .unwrap();
        assert!(
            verify(&forged, &spki_pem, kind).is_err(),
            "HS256 alg-confusion must be rejected"
        );
    }

    #[test]
    fn verifies_rsa_jwt_round_trip() {
        use crate::enroll::trust::KeyKind;
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use x509_cert::der::{DecodePem, Encode};
        #[derive(serde::Serialize)]
        struct C {
            iss: String,
            sub: String,
            jti: String,
            em: String,
            exp: i64,
        }

        // A committed openssl fixture: an RSA-2048 self-signed leaf cert + its private key.
        // (rcgen can now generate RSA keys via its aws-lc-rs backend — see csr::generate_rsa_4096_csr,
        // slice E1 — but a fixed fixture keeps this JWT-verification test deterministic.)
        let cert_pem = include_bytes!("../../tests/fixtures/rsa_leaf.pem");
        let key_pem = include_bytes!("../../tests/fixtures/rsa_leaf.key");
        let cert = x509_cert::Certificate::from_pem(cert_pem).unwrap();
        let der = cert.to_der().unwrap();
        let (spki_pem, kind) = spki_pem_from_cert_der(&der).unwrap();
        assert_eq!(kind, KeyKind::Rsa);

        let claims = C {
            iss: "https://ctrl/".into(),
            sub: "id".into(),
            jti: "TOK".into(),
            em: "ott".into(),
            exp: 9_999_999_999,
        };
        let enc = EncodingKey::from_rsa_pem(key_pem).unwrap();
        let jwt = encode(&Header::new(Algorithm::RS256), &claims, &enc).unwrap();
        let out = verify(&jwt, &spki_pem, kind).unwrap();
        assert_eq!(out.jti, "TOK");
    }

    // Build an EC leaf + its private signing key, returning (priv_pem, spki_pem, kind).
    fn ec_leaf() -> (String, String, KeyKind) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let priv_pem = kp.serialize_pem();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let (spki_pem, kind) = spki_pem_from_cert_der(cert.der().as_ref()).unwrap();
        (priv_pem, spki_pem, kind)
    }

    #[test]
    fn accepts_token_without_exp() {
        // Go-parity: exp is optional. A token with no exp claim must verify.
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        #[derive(serde::Serialize)]
        struct C {
            iss: String,
            sub: String,
            jti: String,
            em: String,
        }
        let (priv_pem, spki_pem, kind) = ec_leaf();
        let claims = C {
            iss: "https://ctrl/".into(),
            sub: "x".into(),
            jti: "NOEXP".into(),
            em: "ott".into(),
        };
        let enc = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
        let jwt = encode(&Header::new(Algorithm::ES384), &claims, &enc).unwrap();
        let out = verify(&jwt, &spki_pem, kind).unwrap();
        assert_eq!(out.jti, "NOEXP");
        assert!(out.exp.is_none());
    }

    #[test]
    fn rejects_expired_exp() {
        // A present-but-expired exp must still be rejected (validate_exp = true).
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        #[derive(serde::Serialize)]
        struct C {
            iss: String,
            sub: String,
            jti: String,
            em: String,
            exp: i64,
        }
        let (priv_pem, spki_pem, kind) = ec_leaf();
        let claims = C {
            iss: "https://ctrl/".into(),
            sub: "x".into(),
            jti: "OLD".into(),
            em: "ott".into(),
            exp: 1, // 1970; long expired
        };
        let enc = EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap();
        let jwt = encode(&Header::new(Algorithm::ES384), &claims, &enc).unwrap();
        assert!(verify(&jwt, &spki_pem, kind).is_err());
    }
}
