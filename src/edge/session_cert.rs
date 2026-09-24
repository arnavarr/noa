//! Acquire an ephemeral api-session client certificate. Oracle: `NewApiSessionCertificate`
//! (`sdk-golang` v1.7.0 `ziti/client.go:327-382`).
//!
//! An authenticated api-session (any method) can mint a short-lived (~12h) mTLS client cert via
//! `POST /current-api-session/certificates`: the client generates an EC **P-256** keypair + CSR
//! (`client.go:334`), POSTs `{csr}`, and keeps the returned **leaf** cert (`certs[0]`, `:371-379`)
//! paired with the ephemeral key. The oracle mints this cert only for credentials WITHOUT a client
//! identity (updb, ext-jwt): `GetIdentity` (`client.go:298-312`) returns the enrolment cert when the
//! credentials implement `IdentityProvider` (cert/ott — `edge-apis/credentials.go:62-65`) and only
//! falls through to `EnsureApiSessionCertificate` otherwise. Our SDK mirrors this: it mints only on
//! the `updb` path (slice S2 `from_updb`, no enrolment cert); cert/ott reuse the enrolment cert.
//!
//! This slice (S1) only acquires the cert; wiring it into a synthetic `Config` for the channel mTLS
//! is S2. The control-plane keeps using the api-session token (`zt-session`); the session-cert is for
//! the router handshake only.

use std::time::Duration;

use serde::Deserialize;

use crate::edge::auth_token::AuthToken;
use crate::edge::client::{apply_access_header, parse_error_envelope};
use crate::edge::error::EdgeError;
use crate::edge::model::Envelope;
use crate::enroll::csr::{KeyAndCsr, generate_session_cert_csr, session_cert_csr_from_key};

/// CSR Subject CommonName. Cosmetic: the controller overwrites the Subject with the identity id
/// (spec §5.4 / `client.go` — the CN is ignored), so any stable value works.
pub(crate) const SESSION_CERT_CN: &str = "apiSession";

const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_CERT_END: &str = "-----END CERTIFICATE-----";

/// Per-REQUEST timeout on the cert-mint POST (S1 acquire AND the renewal re-mint). `trust`'s reqwest
/// client has no client-wide timeout, and on the `bind()` path the re-mint `.await` is held across
/// the holder `tokio::sync::Mutex` with no outer connect-timeout (unlike `connect()`, slice 10b),
/// so a black-holed controller answering this POST would hang indefinitely while holding the guard.
/// Bounding the POST itself caps that. Mirrors [`crate::edge::conn::DEFAULT_CONNECT_TIMEOUT`] (15s,
/// slice 10b) for consistency; a fired timeout surfaces as [`EdgeError::SessionCertResponse`] (the
/// existing transport-error path), not a hang.
const SESSION_CERT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The `data` payload of the api-session certificate response. Oracle: edge-api rest_model
/// `CurrentApiSessionCertificateCreateResponse` (`certificate` required, `cas` omitempty, plus `id`).
#[derive(Debug, Clone, Deserialize)]
struct ApiSessionCertificate {
    /// Controller's id for the minted cert. TOLERANT (`#[serde(default)]`): upstream `edge-api`
    /// marks the embedded `CreateLocation.ID` `omitempty` and `NewApiSessionCertificate` never reads
    /// it, so a schema-valid 201 omitting `id` decodes fine in Go (ID="", unused). We mirror that —
    /// informational only, never load-bearing (spec §5.4 / §6).
    #[serde(default)]
    id: String,
    /// The minted cert chain (leaf + intermediate), PEM, possibly multiple blocks.
    certificate: String,
    /// CA bundle the controller suggests. IGNORED (the oracle uses the existing transport RootCAs,
    /// `client.go:311`); kept here only to document the wire field.
    #[serde(default)]
    #[allow(dead_code)]
    cas: Option<String>,
}

/// A minted api-session client certificate + its ephemeral private key.
///
/// `leaf_pem` is the first (leaf) certificate block on its own — faithful to the oracle keeping
/// `certs[0]`. `chain_pem` is the full `data.certificate` verbatim (leaf + intermediate), kept as a
/// cheap fallback for S2's router handshake should leaf-only ever fail (spec §6 note). All fields are
/// RAW PEM (no `pem:` prefix); S2 adds the prefix when synthesising the `Config`.
pub struct SessionCert {
    /// The leaf certificate, PEM (one `BEGIN CERTIFICATE` block, trailing newline).
    pub leaf_pem: String,
    /// The full returned chain (leaf + intermediate), PEM verbatim.
    pub chain_pem: String,
    /// The ephemeral PKCS#8 EC P-256 private key, PEM. **Secret** — redacted in `Debug`.
    pub key_pem: String,
    /// The controller's id for the minted cert.
    pub id: String,
}

// Manual Debug: NEVER format `key_pem` (the private key) — a derived Debug would leak it via `{:?}`.
// Mirrors the redaction on `UpdbConfig`/`ProvidedIdentity`.
impl std::fmt::Debug for SessionCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCert")
            .field("id", &self.id)
            .field("leaf_pem_len", &self.leaf_pem.len())
            .field("chain_pem_len", &self.chain_pem.len())
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

/// Mint an api-session client certificate. POSTs a freshly generated EC P-256 CSR to
/// `POST {base_url}/current-api-session/certificates` with the api-session `token` in `zt-session`,
/// and returns the leaf cert paired with the ephemeral key. Oracle: `NewApiSessionCertificate`
/// (`ziti/client.go:327-382`).
///
/// `base_url` is the ztAPI (`https://host:port/edge/client/v1`). Success is **strictly 201**
/// (`client.go:367` checks `StatusCreated`); any other status maps to [`EdgeError::SessionCertHttp`]
/// (400 `COULD_NOT_PROCESS_CSR` for a bad CSR, 401 for missing/invalid auth).
///
/// # Errors
/// - [`EdgeError::SessionCertResponse`] on key/CSR generation failure, transport failure, or an
///   unparseable 201 body.
/// - [`EdgeError::SessionCertHttp`] on any non-201 status.
pub async fn acquire_api_session_cert(
    http: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
) -> Result<SessionCert, EdgeError> {
    let KeyAndCsr { key_pem, csr_pem } = generate_session_cert_csr(SESSION_CERT_CN)
        .map_err(|e| EdgeError::SessionCertResponse(format!("csr: {e}")))?;
    post_csr_and_parse(
        http,
        base_url,
        token,
        &csr_pem,
        key_pem,
        SESSION_CERT_REQUEST_TIMEOUT,
    )
    .await
}

/// RE-MINT an api-session certificate **reusing an existing ephemeral key** (the renewal path — a
/// conscious improvement beyond the oracle, which never renews; see `edge::session_cert_renew`).
/// Builds a fresh CSR over the stored `key_pem` (the SAME public key, faithful to the oracle's
/// single-`ApiSessionPrivateKey` model) and POSTs it to the SAME endpoint as
/// [`acquire_api_session_cert`]. Returns a new [`SessionCert`] (new leaf, same key).
///
/// `base_url` is the ztAPI; `token` is the api-session token (`zt-session`). A re-mint with an
/// expired api-session yields the endpoint's 401 → [`EdgeError::SessionCertHttp`] (propagated, NOT
/// re-authenticated — re-auth is a deferred follow-up, spec §2).
///
/// # Errors
/// - [`EdgeError::SessionCertResponse`] on CSR-from-key failure, transport failure, or an
///   unparseable 201 body.
/// - [`EdgeError::SessionCertHttp`] on any non-201 status (e.g. 401 for an expired api-session).
pub(crate) async fn remint_api_session_cert(
    http: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
    key_pem: &str,
) -> Result<SessionCert, EdgeError> {
    let KeyAndCsr { key_pem, csr_pem } = session_cert_csr_from_key(SESSION_CERT_CN, key_pem)
        .map_err(|e| EdgeError::SessionCertResponse(format!("csr: {e}")))?;
    post_csr_and_parse(
        http,
        base_url,
        token,
        &csr_pem,
        key_pem,
        SESSION_CERT_REQUEST_TIMEOUT,
    )
    .await
}

/// Shared core of the mint (S1, fresh key) and the re-mint (renewal, reused key): POST the `csr_pem`
/// to `POST {base_url}/current-api-session/certificates` with the api-session `token` in
/// `zt-session`, enforce the strict 201, parse the chain, and pair the leaf with `key_pem`.
///
/// `key_pem` is moved in (it is the caller's already-encoded key, fresh or reused) and lands in the
/// returned `SessionCert.key_pem` verbatim — the POST body carries only the CSR, never the key.
///
/// `request_timeout` bounds THIS POST only (per-request, not client-wide): if the controller hangs,
/// the timeout fires during `.send()`/body-read and maps to [`EdgeError::SessionCertResponse`] (the
/// existing transport-error path) — bounded, never a hang. Callers pass [`SESSION_CERT_REQUEST_TIMEOUT`].
async fn post_csr_and_parse(
    http: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
    csr_pem: &str,
    key_pem: String,
    request_timeout: Duration,
) -> Result<SessionCert, EdgeError> {
    let url = format!("{base_url}/current-api-session/certificates");
    let body = serde_json::json!({ "csr": csr_pem }).to_string();
    let resp = apply_access_header(http.post(&url), token)
        .header("Content-Type", "application/json")
        .timeout(request_timeout)
        .body(body)
        .send()
        .await
        .map_err(|e| EdgeError::SessionCertResponse(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| EdgeError::SessionCertResponse(e.to_string()))?;
    // Strict 201 (oracle checks StatusCreated exactly). A 200 with a valid-looking body must NOT be
    // accepted — it would mean the controller did something unexpected.
    if status.as_u16() != 201 {
        let (code, message) = parse_error_envelope(&text);
        return Err(EdgeError::SessionCertHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }

    let env: Envelope<ApiSessionCertificate> = serde_json::from_str(&text)
        .map_err(|e| EdgeError::SessionCertResponse(format!("json: {e}")))?;
    let chain_pem = env.data.certificate;
    let leaf_pem = extract_leaf_pem(&chain_pem)?;
    Ok(SessionCert {
        leaf_pem,
        chain_pem,
        key_pem,
        id: env.data.id,
    })
}

/// Extract the first `BEGIN CERTIFICATE`…`END CERTIFICATE` block (the leaf) as a standalone PEM,
/// with a trailing newline. Faithful to the oracle keeping `certs[0]` (`client.go:371-379`): we take
/// the leaf's exact bytes (no re-encode), which is robust for any well-formed cert and lets the
/// router (which trusts the controller's intermediate, like the oracle) verify it.
///
/// # Errors
/// [`EdgeError::SessionCertResponse`] if there is no complete certificate block.
fn extract_leaf_pem(chain: &str) -> Result<String, EdgeError> {
    let begin = chain.find(PEM_CERT_BEGIN).ok_or_else(|| {
        EdgeError::SessionCertResponse("response certificate has no PEM block".into())
    })?;
    let rel_end = chain[begin..].find(PEM_CERT_END).ok_or_else(|| {
        EdgeError::SessionCertResponse("response certificate PEM block is unterminated".into())
    })?;
    let end = begin + rel_end + PEM_CERT_END.len();
    let mut leaf = chain[begin..end].to_string();
    // Trailing newline so rustls-pemfile parses it cleanly when S2 feeds it to the channel mTLS.
    leaf.push('\n');
    Ok(leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

    const LEAF: &str = "-----BEGIN CERTIFICATE-----\nTEAFLEAFLEAFblock0\n-----END CERTIFICATE-----";
    const INTER: &str =
        "-----BEGIN CERTIFICATE-----\nINTERMEDIATEblock1\n-----END CERTIFICATE-----";

    fn http_client() -> reqwest::Client {
        crate::enroll::trust::ensure_crypto_provider();
        reqwest::Client::new()
    }

    fn count_certs(pem: &str) -> usize {
        pem.matches(PEM_CERT_BEGIN).count()
    }

    /// Pins the request body to EXACTLY `{"csr": "<a CSR PEM>"}`: one key, named `csr`, whose value is
    /// a CSR PEM. A subset/contains matcher would let a wrong key or extra fields slip through.
    struct CsrBodyMatcher;
    impl Match for CsrBodyMatcher {
        fn matches(&self, req: &Request) -> bool {
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
                return false;
            };
            let Some(obj) = v.as_object() else {
                return false;
            };
            obj.len() == 1
                && obj
                    .get("csr")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|s| s.contains("BEGIN CERTIFICATE REQUEST"))
        }
    }

    #[tokio::test]
    async fn acquire_posts_csr_and_extracts_leaf_only() {
        let server = MockServer::start().await;
        let chain = format!("{LEAF}\n{INTER}\n");
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            // zt-session + Content-Type are load-bearing (the spike: missing auth → 401,
            // missing Content-Type → 415). If the impl drops either, the mock won't match → 404.
            .and(header("zt-session", "tok-abc"))
            .and(header("Content-Type", "application/json"))
            .and(CsrBodyMatcher)
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "data": { "id": "cert-123", "certificate": chain, "cas": "\n<ca-bundle>" },
                "meta": {}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let out = acquire_api_session_cert(
            &http_client(),
            &server.uri(),
            &AuthToken::Legacy("tok-abc".into()),
        )
        .await
        .expect("201 -> SessionCert");

        assert_eq!(out.id, "cert-123");
        // leaf_pem = ONLY the first block (the intermediate is dropped — oracle keeps certs[0]).
        assert_eq!(count_certs(&out.leaf_pem), 1, "leaf is a single block");
        assert!(
            out.leaf_pem.contains("TEAFLEAFLEAFblock0"),
            "leaf body kept"
        );
        assert!(
            !out.leaf_pem.contains("INTERMEDIATEblock1"),
            "intermediate dropped from leaf"
        );
        assert!(out.leaf_pem.ends_with('\n'), "leaf has a trailing newline");
        // chain_pem = the FULL returned certificate verbatim (both blocks), the S2 fallback.
        assert_eq!(count_certs(&out.chain_pem), 2, "chain keeps both blocks");
        assert!(out.chain_pem.contains("INTERMEDIATEblock1"));
        // `cas` is ignored (SessionCert has no cas field — nothing to assert beyond it not leaking).
    }

    #[tokio::test]
    async fn acquire_tolerates_missing_id_in_response() {
        // Oracle fidelity: upstream marks `id` (embedded CreateLocation.ID) omitempty and
        // NewApiSessionCertificate never reads it, so a schema-valid 201 WITHOUT `id` decodes fine in
        // Go (ID="", unused). A 201 omitting `id` must therefore still yield the leaf/chain here, with
        // `id` defaulting to "". RED if `id` is reverted to hard-required.
        let server = MockServer::start().await;
        let chain = format!("{LEAF}\n{INTER}\n");
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                // NOTE: no `id` field — only the required `certificate`.
                "data": { "certificate": chain },
                "meta": {}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let out = acquire_api_session_cert(
            &http_client(),
            &server.uri(),
            &AuthToken::Legacy("tok-abc".into()),
        )
        .await
        .expect("201 without id -> SessionCert");

        assert_eq!(out.id, "", "missing id defaults to empty string");
        assert_eq!(count_certs(&out.leaf_pem), 1, "leaf is a single block");
        assert!(
            out.leaf_pem.contains("TEAFLEAFLEAFblock0"),
            "leaf body kept"
        );
        assert_eq!(count_certs(&out.chain_pem), 2, "chain keeps both blocks");
    }

    #[tokio::test]
    async fn acquire_maps_400_could_not_process_csr() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": { "code": "COULD_NOT_PROCESS_CSR", "message": "bad csr" }
            })))
            .mount(&server)
            .await;

        let err = acquire_api_session_cert(
            &http_client(),
            &server.uri(),
            &AuthToken::Legacy("tok".into()),
        )
        .await
        .expect_err("400 -> error");
        match err {
            EdgeError::SessionCertHttp {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 400);
                assert_eq!(code, "COULD_NOT_PROCESS_CSR");
                assert_eq!(message, "bad csr");
            }
            other => panic!("expected SessionCertHttp, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn acquire_maps_401_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "code": "UNAUTHORIZED", "message": "no session" }
            })))
            .mount(&server)
            .await;

        let err = acquire_api_session_cert(
            &http_client(),
            &server.uri(),
            &AuthToken::Legacy("stale".into()),
        )
        .await
        .expect_err("401 -> error");
        assert!(
            matches!(err, EdgeError::SessionCertHttp { status: 401, .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn acquire_rejects_non_201_even_with_valid_body() {
        // STRICT 201: a 200 carrying a perfectly valid cert body must still be an error (mutant-killer
        // for an accidental `is_success()`; the 4xx tests do not catch that).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "id": "x", "certificate": format!("{LEAF}\n") },
                "meta": {}
            })))
            .mount(&server)
            .await;

        let err = acquire_api_session_cert(
            &http_client(),
            &server.uri(),
            &AuthToken::Legacy("tok".into()),
        )
        .await
        .expect_err("200 must not be accepted (strict 201)");
        assert!(
            matches!(err, EdgeError::SessionCertHttp { status: 200, .. }),
            "got {err:?}"
        );
    }

    /// The cert-mint POST is BOUNDED by its per-request timeout: a controller that answers slowly
    /// (here a valid 201 delayed 2s) must NOT hang the mint — with a short injected timeout (100ms)
    /// the POST fails fast with `SessionCertResponse`. This is the renewal-review LOW fix: on the
    /// `bind()` path the re-mint `.await` is held across the holder mutex with no outer timeout, so an
    /// unbounded POST would block indefinitely. MUTATION CHECK: the discriminator is Err-vs-Ok — drop
    /// the `.timeout(...)` in `post_csr_and_parse` and this returns `Ok(SessionCert)` after 2s
    /// (mutant survives `expect_err` only WITHOUT the timeout), so this test pins the bound itself.
    #[tokio::test]
    async fn cert_mint_post_is_bounded_by_request_timeout() {
        let server = MockServer::start().await;
        let chain = format!("{LEAF}\n");
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            // Valid 201 — but delayed WELL past the short injected timeout. Without the per-request
            // timeout the client would happily wait the full 2s and return Ok.
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({
                        "data": { "id": "cert-slow", "certificate": chain },
                        "meta": {}
                    }))
                    .set_delay(Duration::from_secs(2)),
            )
            .mount(&server)
            .await;

        let KeyAndCsr { key_pem, csr_pem } =
            generate_session_cert_csr(SESSION_CERT_CN).expect("gen key+csr");

        let start = std::time::Instant::now();
        let err = post_csr_and_parse(
            &http_client(),
            &server.uri(),
            &AuthToken::Legacy("tok".into()),
            &csr_pem,
            key_pem,
            // Short injected timeout: comfortably under the 2s delay, comfortably over jitter.
            Duration::from_millis(100),
        )
        .await
        .expect_err("the slow 201 must be cut off by the request timeout, not awaited");
        // Bounded: it returned long before the 2s delay (proves the timeout fired, not the response).
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "mint returned in {:?}, expected < 1s (timeout-bounded)",
            start.elapsed()
        );
        // A reqwest timeout maps through the existing transport-error path, not swallowed.
        assert!(
            matches!(err, EdgeError::SessionCertResponse(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn extract_leaf_pem_errors_without_a_cert_block() {
        let err = extract_leaf_pem("not a pem at all").expect_err("no block -> error");
        assert!(
            matches!(err, EdgeError::SessionCertResponse(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn session_cert_debug_redacts_key_pem() {
        let sc = SessionCert {
            leaf_pem: format!("{LEAF}\n"),
            chain_pem: format!("{LEAF}\n{INTER}\n"),
            key_pem:
                "-----BEGIN PRIVATE KEY-----\nSUPER-SECRET-EPHEMERAL-KEY\n-----END PRIVATE KEY-----"
                    .into(),
            id: "cert-123".into(),
        };
        let dbg = format!("{sc:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-EPHEMERAL-KEY"),
            "Debug leaked the private key: {dbg}"
        );
        assert!(dbg.contains("redacted"));
        assert!(dbg.contains("cert-123")); // id is not secret
    }
}
