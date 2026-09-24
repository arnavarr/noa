//! OTT enrolment orchestration. Oracle: enroll.go enrollOTT + Enroll.

use crate::enroll::error::EnrollError;
use crate::enroll::{csr, identity, token, trust};

/// A pre-existing, CA-issued client identity (cert + key, raw PEM) supplied for `ottca`
/// enrolment. Mirrors the oracle's `EnrollmentFlags.CertFile`/`KeyFile` (enroll.go:60-61):
/// `ottca` does NOT generate a key/CSR — it authenticates the enrolment over mTLS with this
/// cert and reuses it as the identity's cert. Ignored for `ott` (which generates its own key).
#[derive(Clone)]
pub struct ProvidedIdentity {
    /// Client certificate chain, raw PEM (no `pem:` prefix).
    pub cert_pem: String,
    /// Client private key, raw PEM (no `pem:` prefix).
    pub key_pem: String,
}

// Manual Debug: NEVER format `key_pem` (private key material) — a derived Debug would leak it via
// `{:?}` on `EnrollOptions`. Mirrors `trust::PinnedLeafVerifier`'s redacting Debug.
impl std::fmt::Debug for ProvidedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvidedIdentity")
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Options for the enrolment flow. `key_alg` selects the client key algorithm for `ott`
/// (EC P-384 by default, or RSA-4096), mirroring the oracle's `KeyAlgVar`. `client_identity`
/// supplies the pre-existing identity required by `ottca`. Adding fields keeps existing
/// `EnrollOptions::default()` callers source-compatible.
#[derive(Clone, Default)]
pub struct EnrollOptions {
    /// Client key algorithm for `ott`. Defaults to EC P-384 (`KeyAlg::EcP384`).
    pub key_alg: csr::KeyAlg,
    /// Pre-existing CA-issued identity, required for `ottca` (ignored by `ott`).
    pub client_identity: Option<ProvidedIdentity>,
    /// Extra trusted CAs (raw PEM) to add to the enrolment trust pool AND the resulting identity's
    /// CA bundle, beyond those fetched from the controller. Mirrors `EnrollmentFlags.AdditionalCAs`
    /// (enroll.go:64) — but the oracle takes a FILE PATH there; we take the PEM CONTENT (the `noa`
    /// bin reads the `--ca <path>` file, same pattern as the JWT). Best-effort parse (see
    /// `trust::parse_ca_pems`). Applies to every method.
    pub additional_cas: Option<String>,
}

// Manual Debug: `additional_cas` is a PEM the caller controls and MAY mistakenly contain private-key
// material (e.g. a combined cert+key file) — redact it to a length, mirroring the redaction the
// `client_identity` field already gets via `ProvidedIdentity`'s Debug. (A derived Debug would print it.)
impl std::fmt::Debug for EnrollOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollOptions")
            .field("key_alg", &self.key_alg)
            .field("client_identity", &self.client_identity)
            .field(
                "additional_cas",
                &self
                    .additional_cas
                    .as_ref()
                    .map(|s| format!("<{} bytes>", s.len())),
            )
            .finish()
    }
}

/// GET the EST cacerts bundle and return the raw response body bytes.
/// Caller provides the client (verified, anchored to the issuer leaf).
///
/// # Errors
/// Returns [`EnrollError::CaFetch`] if the request fails or the status is not 2xx.
pub async fn fetch_cacerts(
    client: &reqwest::Client,
    cacerts_url: &str,
) -> Result<Vec<u8>, EnrollError> {
    let resp = client
        .get(cacerts_url)
        .header("Accept", "application/pkcs7-mime")
        .send()
        .await
        .map_err(|e| EnrollError::CaFetch(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(EnrollError::CaFetch(format!("status {}", resp.status())));
    }
    Ok(resp
        .bytes()
        .await
        .map_err(|e| EnrollError::CaFetch(e.to_string()))?
        .to_vec())
}

/// POST the CSR to the enroll endpoint and return the signed client cert PEM.
/// Oracle: enroll.go enrollOTT (Content-Type application/x-pem-file; response
/// is JSON {data:{cert}} or raw PEM; error envelope {error:{code,message}}).
///
/// # Errors
/// Returns [`EnrollError::EnrollResponse`] on transport/decoding failures or a
/// malformed success body, and [`EnrollError::EnrollHttp`] on a non-2xx status.
pub async fn request_cert(
    client: &reqwest::Client,
    enroll_url: &str,
    csr_pem: &str,
) -> Result<String, EnrollError> {
    let resp = client
        .post(enroll_url)
        .header("Content-Type", "application/x-pem-file")
        .body(csr_pem.to_string())
        .send()
        .await
        .map_err(|e| EnrollError::EnrollResponse(e.to_string()))?;

    let status = resp.status();
    let ctype = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = resp
        .text()
        .await
        .map_err(|e| EnrollError::EnrollResponse(e.to_string()))?;

    if !status.is_success() {
        let (code, message) = parse_error_envelope(&body);
        return Err(EnrollError::EnrollHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }
    if ctype.contains("application/json") {
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| EnrollError::EnrollResponse(format!("json: {e}")))?;
        v.get("data")
            .and_then(|d| d.get("cert"))
            .and_then(|c| c.as_str())
            .map(std::string::ToString::to_string)
            .ok_or_else(|| EnrollError::EnrollResponse("missing data.cert".into()))
    } else {
        Ok(body)
    }
}

pub(crate) fn parse_error_envelope(body: &str) -> (String, String) {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let e = v.get("error")?;
            let code = e
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let msg = e
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            Some((code, msg))
        })
        .unwrap_or_else(|| ("UNKNOWN".into(), body.chars().take(200).collect()))
}

/// Enrol an identity, dispatching by the token's `enrollmentMethod` (oracle: enroll.go
/// `switch` :235-251). Currently supports `ott` (generate key/CSR) and `ottca` (mTLS with a
/// pre-existing identity); other methods return [`EnrollError::UnsupportedMethod`].
///
/// This wires real TLS IO; covered by the `#[ignore]` integration tests.
///
/// # Errors
/// Returns an [`EnrollError`] if the method is unsupported or any stage (token parse/verify,
/// TLS bootstrap, CA fetch/parse, CSR/key, cert request) fails.
pub async fn enroll(jwt: &str, opts: EnrollOptions) -> Result<identity::Config, EnrollError> {
    let claims = token::parse(jwt)?;
    match claims.method.as_str() {
        "ott" => enroll_ott(jwt, opts).await,
        "ottca" => crate::enroll::ottca::enroll_ottca(jwt, opts).await,
        // updb needs username+password (not in the JWT) → its own entry point, `enroll_updb`.
        "updb" => Err(EnrollError::UpdbRequiresCredentials),
        other => Err(EnrollError::UnsupportedMethod(other.to_string())),
    }
}

/// Combine the caller's additional CAs (parsed from PEM, FIRST) with the controller-fetched CA DERs,
/// mirroring the oracle's `GetCertPool` → append-controller order (enroll.go:214,227-230). The result
/// seeds BOTH the enrolment trust pool and the identity's CA bundle. Pure (testable without IO).
pub(crate) fn prepend_additional_cas(
    additional: Option<&str>,
    controller_ders: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let mut ders = match additional {
        // The oracle trims the PATH before deciding the file is "provided" (TrimSpace, enroll.go:74);
        // we take PEM CONTENT, so we trim THAT — net effect converges (empty/whitespace → no extra CAs).
        Some(pem) if !pem.trim().is_empty() => trust::parse_ca_pems(pem),
        _ => Vec::new(),
    };
    ders.extend(controller_ders);
    ders
}

/// Shared trust bootstrap for every method: insecure GET to capture the issuer's TLS leaf,
/// verify the JWT against that leaf's key, then fetch + parse the CA bundle over a connection
/// pinned to the exact captured leaf. Returns the VERIFIED claims and the CA DERs.
///
/// # Errors
/// Returns an [`EnrollError`] if the bootstrap, JWT verification, or CA fetch/parse fails.
pub(crate) async fn resolve_trust(
    jwt: &str,
    additional_cas: Option<&str>,
) -> Result<(token::EnrollmentClaims, Vec<Vec<u8>>), EnrollError> {
    // 1. Bootstrap: insecure GET to capture the issuer's TLS leaf cert.
    let unverified = token::parse(jwt)?;
    let verifier = trust::CapturingVerifier::new();
    let boot_client = trust::insecure_capturing_client(verifier.clone())?;
    boot_client
        .get(unverified.zt_api()?)
        .send()
        .await
        .map_err(|e| EnrollError::BootstrapTls(e.to_string()))?;
    let leaf_der = verifier
        .captured_leaf()
        .ok_or_else(|| EnrollError::BootstrapTls("no server cert captured".into()))?;

    // 2. Verify the JWT against the leaf key.
    let (spki_pem, kind) = trust::spki_pem_from_cert_der(&leaf_der)?;
    let claims = token::verify(jwt, &spki_pem, kind)?;

    // 3. Fetch + parse the CA bundle over a TLS connection pinned to the EXACT captured leaf
    //    (trust-on-first-use). The leaf was already validated by verifying the JWT against its
    //    key; chain-building it as a CA root would fail for the normal CA-signed controller leaf.
    let leaf_client = trust::pinned_leaf_client(leaf_der.clone())?;
    let p7 = fetch_cacerts(&leaf_client, &claims.cacerts_url()?).await?;
    let controller_ders = trust::parse_cacerts_b64(&p7)?;
    // Seed the pool + identity CA bundle with the caller's extra CAs first (oracle GetCertPool order).
    let ca_ders = prepend_additional_cas(additional_cas, controller_ders);
    Ok((claims, ca_ders))
}

/// `ott` enrolment: generate a key + CSR, POST it, store the signed cert.
async fn enroll_ott(jwt: &str, opts: EnrollOptions) -> Result<identity::Config, EnrollError> {
    let (claims, ca_ders) = resolve_trust(jwt, opts.additional_cas.as_deref()).await?;

    // Generate key + CSR (EC P-384 or RSA-4096 per opts; oracle enroll.go:191-201).
    let kc = csr::generate_csr(&claims.sub, opts.key_alg)?;

    // POST the CSR over TLS verified against the fetched CA pool.
    let enroll_client = trust::verified_client(&ca_ders)?;
    let cert_pem = request_cert(&enroll_client, &claims.enroll_url()?, &kc.csr_pem).await?;

    // Assemble identity (ca = concatenated fetched CA PEMs).
    let ca_pem = ders_to_pem(&ca_ders)?;
    Ok(identity::Config::from_enrolment(
        claims.zt_api()?,
        &kc.key_pem,
        &cert_pem,
        &ca_pem,
    ))
}

// Signature kept fallible to mirror the surrounding `?`-based pipeline and to
// leave room for a future encoder that can fail; current body is infallible.
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn ders_to_pem(ders: &[Vec<u8>]) -> Result<String, EnrollError> {
    use base64::Engine;
    let mut out = String::new();
    for der in ders {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An UNSIGNED JWT with the given payload JSON (`token::parse` does not verify signatures —
    /// it base64-decodes the payload — so this suffices to drive the method dispatch).
    fn jwt_with(payload: &str) -> String {
        use base64::Engine;
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        format!(
            "{}.{}.{}",
            b.encode(b"{\"alg\":\"ES384\"}"),
            b.encode(payload.as_bytes()),
            b.encode(b"sig")
        )
    }

    // Dispatch happens BEFORE any network IO, so these reach no controller.

    #[tokio::test]
    async fn enroll_rejects_unsupported_method() {
        // Oracle: switch default -> "enrollment method '%s' is not supported" (enroll.go:250).
        let jwt = jwt_with(r#"{"iss":"https://x","sub":"s","jti":"j","em":"webauthn"}"#);
        let err = enroll(&jwt, EnrollOptions::default())
            .await
            .expect_err("unknown method must error");
        assert!(
            matches!(&err, EnrollError::UnsupportedMethod(m) if m == "webauthn"),
            "got {err:?}"
        );
        // Byte-exact oracle message (enroll.go:250) — pin it, not just the variant.
        assert_eq!(
            err.to_string(),
            "enrollment method 'webauthn' is not supported"
        );
    }

    #[tokio::test]
    async fn enroll_routes_ottca_and_requires_client_identity() {
        // method=ottca with no client_identity -> MissingClientIdentity, proving enroll() routes to
        // the ottca path (which validates the identity before any network IO).
        let jwt = jwt_with(r#"{"iss":"https://x","sub":"s","jti":"j","em":"ottca"}"#);
        let err = enroll(&jwt, EnrollOptions::default())
            .await
            .expect_err("ottca without a client identity must error");
        assert!(
            matches!(err, EnrollError::MissingClientIdentity),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn enroll_routes_updb_to_specific_credentials_error() {
        // updb IS supported, but via enroll_updb — enroll() (no username/password) returns a specific,
        // actionable error, NOT a generic UnsupportedMethod (which would falsely claim it's unsupported).
        let jwt = jwt_with(r#"{"iss":"https://x","sub":"s","jti":"j","em":"updb"}"#);
        let err = enroll(&jwt, EnrollOptions::default())
            .await
            .expect_err("updb via enroll() must error");
        assert!(
            matches!(err, EnrollError::UpdbRequiresCredentials),
            "got {err:?}"
        );
    }

    fn ca_pem_and_der() -> (String, Vec<u8>) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = rcgen::CertificateParams::new(vec!["extra-ca".to_string()]).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        (cert.pem(), cert.der().as_ref().to_vec())
    }

    #[test]
    fn prepend_additional_cas_puts_additional_before_controller() {
        let (extra_pem, extra_der) = ca_pem_and_der();
        let controller = vec![vec![0xAA_u8, 0xBB, 0xCC]];
        let combined = prepend_additional_cas(Some(&extra_pem), controller.clone());
        // Oracle order: additional first, then the controller-fetched CAs.
        assert_eq!(combined, vec![extra_der, controller[0].clone()]);
    }

    #[test]
    fn prepend_additional_cas_none_whitespace_or_garbage_is_just_controller() {
        let controller = vec![vec![1u8], vec![2u8]];
        assert_eq!(prepend_additional_cas(None, controller.clone()), controller);
        assert_eq!(
            prepend_additional_cas(Some("   \n"), controller.clone()),
            controller
        );
        // Best-effort: a non-empty but cert-less input contributes nothing (no error).
        assert_eq!(
            prepend_additional_cas(Some("garbage"), controller.clone()),
            controller
        );
    }

    #[test]
    fn provided_identity_debug_redacts_private_key() {
        let id = ProvidedIdentity {
            cert_pem: "CERT-PEM".into(),
            key_pem: "SUPER-SECRET-KEY".into(),
        };
        let dbg = format!("{id:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-KEY"),
            "Debug leaked the key: {dbg}"
        );
        assert!(
            dbg.contains("redacted"),
            "Debug should mark the key redacted: {dbg}"
        );
        // And via EnrollOptions (manual Debug): neither the client key NOR a key mistakenly placed
        // in `additional_cas` may appear.
        let opts = EnrollOptions {
            client_identity: Some(id),
            additional_cas: Some("CA-PEM-with-A-LEAKED-KEY-INSIDE".into()),
            ..Default::default()
        };
        let opts_dbg = format!("{opts:?}");
        assert!(
            !opts_dbg.contains("SUPER-SECRET-KEY"),
            "EnrollOptions Debug must not leak the client key: {opts_dbg}"
        );
        assert!(
            !opts_dbg.contains("LEAKED-KEY"),
            "EnrollOptions Debug must redact additional_cas: {opts_dbg}"
        );
    }
}
