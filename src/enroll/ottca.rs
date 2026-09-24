//! `ottca` enrolment: a pre-existing, CA-issued identity (cert + key the client already holds)
//! authenticates the enrolment POST over mTLS. Oracle: enroll.go `enrollCA` (:444-475).
//!
//! Unlike `ott`, `ottca` generates NO key and NO CSR, and receives NO new cert: the controller
//! recognises the client's CA-issued cert (trusted via a registered + verified CA) and registers
//! the identity. The resulting `Config` reuses the PROVIDED cert + key for subsequent mTLS auth.

use crate::enroll::error::EnrollError;
use crate::enroll::identity::Config;
use crate::enroll::ott::{EnrollOptions, ders_to_pem, resolve_trust};
use crate::enroll::trust;

/// Full `ottca` enrolment. Requires `opts.client_identity` (the pre-existing cert + key).
///
/// # Errors
/// [`EnrollError::MissingClientIdentity`] if no client identity is supplied; otherwise any
/// trust/transport error from [`resolve_trust`], the mTLS client build, or the POST.
pub(crate) async fn enroll_ottca(jwt: &str, opts: EnrollOptions) -> Result<Config, EnrollError> {
    let provided = opts
        .client_identity
        .ok_or(EnrollError::MissingClientIdentity)?;

    // `client_identity` above is a partial move; `additional_cas` (a different field) is still readable.
    let (claims, ca_ders) = resolve_trust(jwt, opts.additional_cas.as_deref()).await?;

    // mTLS client presenting the provided cert, trusting the fetched CA pool. Oracle:
    // tls.Config{RootCAs: caPool, Certificates: [clientCert]} (enroll.go:454-456).
    let client = trust::client_auth_client(&provided.cert_pem, &provided.key_pem, &ca_ders)?;
    request_ottca(&client, &claims.enroll_url()?).await?;

    // ottca reuses the PROVIDED cert + key (the controller registers the identity; no new cert
    // is returned — enrollCA does not parse a cert from the response, enroll.go:466-473).
    let ca_pem = ders_to_pem(&ca_ders)?;
    Ok(Config::from_enrolment(
        claims.zt_api()?,
        &provided.key_pem,
        &provided.cert_pem,
        &ca_pem,
    ))
}

/// POST an empty body over the mTLS client to the enrolment URL. Oracle: enroll.go enrollCA
/// `client.Post(url, "text/plain", empty)` (:461) → `200`=OK, `409`=already enrolled, else error.
async fn request_ottca(client: &reqwest::Client, enroll_url: &str) -> Result<(), EnrollError> {
    let resp = client
        .post(enroll_url)
        .header("Content-Type", "text/plain")
        .body(Vec::<u8>::new())
        .send()
        .await
        .map_err(|e| EnrollError::EnrollResponse(e.to_string()))?;

    let status = resp.status();
    // Oracle: ONLY 200 is success — enrollCA checks `resp.StatusCode != http.StatusOK` (enroll.go:466),
    // so a non-200 2xx (201/204) is an error path there too. Match strictly, not `is_success()`.
    if status == reqwest::StatusCode::OK {
        return Ok(());
    }
    if status == reqwest::StatusCode::CONFLICT {
        // Oracle: 409 -> "the provided identity has already been enrolled" (enroll.go:468).
        return Err(EnrollError::AlreadyEnrolled);
    }
    // Oracle: else -> "enroll error: <status>" (enroll.go:470). enrollCA does NOT parse an error
    // envelope (unlike enrollCAAuto); we keep the status, no body parse.
    Err(EnrollError::EnrollHttp {
        status: status.as_u16(),
        code: String::new(),
        message: status.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enroll::ott::ProvidedIdentity;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // A plain-HTTP reqwest client for the wiremock tests. `Client::new()` builds a rustls config
    // (we use `rustls-tls-no-provider`), so the process crypto provider must be installed first.
    fn http_client() -> reqwest::Client {
        crate::enroll::trust::ensure_crypto_provider();
        reqwest::Client::new()
    }

    // A self-consistent client identity (CA-signed leaf + its key, raw PEM) for the tests.
    fn provided_identity() -> ProvidedIdentity {
        let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_kp).unwrap();

        let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["client".to_string()]).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
        let leaf = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();

        ProvidedIdentity {
            cert_pem: format!("{}{}", leaf.pem(), ca.pem()),
            key_pem: leaf_kp.serialize_pem(),
        }
    }

    #[test]
    fn client_auth_client_builds_from_provided_identity() {
        let id = provided_identity();
        // Roots can be any CA der; reuse the leaf's CA as a stand-in root.
        let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root = ca_params.self_signed(&ca_kp).unwrap();
        trust::client_auth_client(&id.cert_pem, &id.key_pem, &[root.der().to_vec()])
            .expect("client-auth client builds from a valid cert+key");
    }

    // `request_ottca` is the new wire delta. The mTLS handshake itself is already live-proven by
    // EdgeClient auth, so here we exercise the request shape (empty body, text/plain) and the
    // 200 / 409 / other status mapping over plain HTTP (wiremock can't do TLS client-auth).
    #[tokio::test]
    async fn request_ottca_posts_empty_body_and_accepts_200() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/enroll"))
            .and(header("Content-Type", "text/plain"))
            // Pin the EMPTY body — ottca's distinguishing wire feature vs ott (which posts the CSR).
            // Without this, mutating `.body(Vec::new())` to a non-empty body still passes.
            .and(body_bytes(Vec::<u8>::new()))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        request_ottca(&http_client(), &url)
            .await
            .expect("200 -> Ok");
    }

    #[tokio::test]
    async fn request_ottca_maps_409_to_already_enrolled() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/enroll"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let err = request_ottca(&http_client(), &url)
            .await
            .expect_err("409 -> error");
        assert!(
            matches!(err, EnrollError::AlreadyEnrolled),
            "409 must map to AlreadyEnrolled, got {err:?}"
        );
        // Byte-exact oracle message (enroll.go:468) — pin it, not just the variant.
        assert_eq!(
            err.to_string(),
            "the provided identity has already been enrolled"
        );
    }

    #[tokio::test]
    async fn request_ottca_maps_other_status_to_http_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/enroll"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let err = request_ottca(&http_client(), &url)
            .await
            .expect_err("500 -> error");
        assert!(
            matches!(err, EnrollError::EnrollHttp { status: 500, .. }),
            "500 must map to EnrollHttp, got {err:?}"
        );
    }

    // Oracle treats ONLY 200 as success (enrollCA `!= http.StatusOK`); a non-200 2xx is an error
    // path there too. This pins the strict `== OK` (a `.is_success()` regression would pass 204).
    #[tokio::test]
    async fn request_ottca_treats_non200_2xx_as_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/enroll"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let url = format!("{}/enroll", server.uri());
        let err = request_ottca(&http_client(), &url)
            .await
            .expect_err("204 must NOT be success");
        assert!(
            matches!(err, EnrollError::EnrollHttp { status: 204, .. }),
            "204 must map to EnrollHttp, got {err:?}"
        );
    }

    // A cert that does NOT match the key must be rejected (proves the cert+key are actually bound
    // into the mTLS config — a `with_no_client_auth` regression would silently accept the mismatch).
    #[test]
    fn client_auth_client_rejects_cert_key_mismatch() {
        let id = provided_identity();
        let other_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let err = trust::client_auth_client(&id.cert_pem, &other_key.serialize_pem(), &[])
            .expect_err("cert/key mismatch must error");
        assert!(matches!(err, EnrollError::EnrollResponse(_)), "got {err:?}");
    }

    #[test]
    fn client_auth_client_rejects_empty_cert_chain() {
        let id = provided_identity();
        let err = trust::client_auth_client("", &id.key_pem, &[])
            .expect_err("empty cert chain must error");
        assert!(matches!(err, EnrollError::EnrollResponse(_)), "got {err:?}");
    }
}
