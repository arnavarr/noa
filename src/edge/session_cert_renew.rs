//! Expiry-driven RE-MINT of the api-session certificate — a CONSCIOUS IMPROVEMENT beyond the oracle.
//!
//! # Deviation from the oracle (deliberate, maintainer decision 2026-06-19)
//!
//! The oracle's `EnsureApiSessionCertificate` (`sdk-golang` v1.7.0 `ziti/client.go`) is a LAZY
//! create-if-nil initializer that NEVER renews:
//!
//! ```go
//! func (self *CtrlClient) EnsureApiSessionCertificate() error {
//!     if self.ApiSessionCertificate == nil {   // ← the ONLY guard
//!         return self.NewApiSessionCertificate()
//!     }
//!     return nil
//! }
//! ```
//!
//! There is no `NotAfter` check and no re-mint: once the cert exists, it is never replaced. Our S2
//! `from_updb` already replicates that single-mint model faithfully. This module ADDS expiry-driven
//! renewal so a continuously-active long-lived client (a daemon / tunneler) survives the ~12h
//! session-cert. Allowed by CLAUDE.md ("conservando o **mejorando** su comportamiento").
//!
//! # Key model (faithful to the oracle)
//!
//! The oracle stores ONE ephemeral key per api-session (`ApiSessionPrivateKey`, `client.go:330`).
//! We mirror that: the key is minted once (in `from_updb`) and REUSED on every re-mint — the
//! re-mint CSR carries the same public key (`session_cert::remint_api_session_cert` →
//! `csr::session_cert_csr_from_key`).
//!
//! # Out of scope (deferred, spec §2)
//!
//! Renewal of the api-session itself. A re-mint POSTs with the `zt-session` token; if the api-session
//! expired the controller answers 401 → we PROPAGATE the error (no re-authentication). The driver
//! verified live that the api-session is a 30-min SLIDING idle window (no absolute cap), so a
//! continuously-active client keeps it alive and renewal fires usefully; an idle client loses the
//! api-session first and a fresh `from_updb` re-mints anyway.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Cursor;

use crate::edge::error::EdgeError;
use crate::edge::session_cert::{SessionCert, remint_api_session_cert};

/// How long before `NotAfter` we re-mint. A conscious threshold (the oracle has none): we renew with
/// margin so an in-flight handshake never races the expiry. 5 minutes against a ~12h cert.
pub(crate) const RENEW_BUFFER: Duration = Duration::from_secs(5 * 60);

/// The renewable state of a `updb` client's api-session certificate. Lives behind a
/// `tokio::sync::Mutex` on the `EdgeClient` (NOT the crate's `std::sync::Mutex`: `ensure_fresh`
/// holds the guard across the re-mint `.await`, which would trip `clippy::await_holding_lock` under
/// `-D warnings` with a std mutex, and risks a deadlock). Holding the guard across the whole ensure
/// gives no-double-mint AND dedups the 10c parallel-router race (N racing `open_channel_to` → 1
/// re-mint, the rest see the fresh cert).
///
/// `None` on the `EdgeClient` for cert-identities (the validated path, byte-identical to before);
/// `Some` only for `updb`.
pub(crate) struct SessionCertState {
    /// Current leaf certificate, PEM (one block). Replaced on each re-mint.
    leaf_pem: String,
    /// The ephemeral PKCS#8 EC P-256 private key, PEM. **Secret** (redacted in `Debug`). REUSED on
    /// every re-mint — never regenerated (oracle's `ApiSessionPrivateKey` model).
    key_pem: String,
    /// The controller-CA trust anchors (DERs) the channel TLS verifies the router against. Parsed
    /// once from `cfg.ca`; the same roots survive a re-mint (only the leaf changes).
    root_ders: Vec<CertificateDer<'static>>,
    /// `NotAfter` of the current `leaf_pem`, parsed from the cert. The re-mint trigger.
    not_after: SystemTime,
    /// Test/diagnostic clock override. `None` ⇒ the real `SystemTime::now()`. A field (not a method
    /// param) so the live renewal-proof test can advance the clock past `NotAfter` THROUGH the
    /// production `connect()` path (which calls `ensure_fresh` with no args, deep under
    /// `open_channel_to`).
    now_override: Option<SystemTime>,
}

// Manual Debug: NEVER format `key_pem` (the private key) — a derived Debug would leak it via `{:?}`.
// Mirrors the redaction on `SessionCert`/`UpdbConfig`.
impl std::fmt::Debug for SessionCertState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCertState")
            .field("leaf_pem_len", &self.leaf_pem.len())
            .field("key_pem", &"<redacted>")
            .field("root_ders_count", &self.root_ders.len())
            .field("not_after", &self.not_after)
            .field("now_override", &self.now_override)
            .finish()
    }
}

impl SessionCertState {
    /// Build the initial state from a freshly minted [`SessionCert`] (in `from_updb`) and the
    /// controller-CA trust anchors (RAW DER bytes, as `enroll::trust::parse_ca_pems` yields them).
    /// Parses the leaf's `NotAfter`.
    ///
    /// # Errors
    /// [`EdgeError::SessionCertResponse`] if the leaf's `NotAfter` cannot be parsed.
    pub(crate) fn new(cert: &SessionCert, root_ders: Vec<Vec<u8>>) -> Result<Self, EdgeError> {
        let not_after = parse_not_after(&cert.leaf_pem)?;
        let root_ders = root_ders.into_iter().map(CertificateDer::from).collect();
        Ok(Self {
            leaf_pem: cert.leaf_pem.clone(),
            key_pem: cert.key_pem.clone(),
            root_ders,
            not_after,
            now_override: None,
        })
    }

    /// Force the next [`Self::ensure_fresh`] to RE-MINT, regardless of the real clock. Used on a
    /// reactive re-auth (slice reauth-401) to match the oracle's `setUnauthenticated` nil-ing of the
    /// api-session cert: the current leaf was minted under the now-stale api-session, so it must be
    /// re-minted under the fresh one. Sets `not_after` to the epoch, so `is_stale()` is true under any
    /// real clock; the next re-mint overwrites it with the new leaf's `NotAfter`.
    pub(crate) fn invalidate(&mut self) {
        self.not_after = SystemTime::UNIX_EPOCH;
    }

    /// The current effective time (override or wall clock).
    fn now(&self) -> SystemTime {
        self.now_override.unwrap_or_else(SystemTime::now)
    }

    /// Whether the current leaf is due for renewal: `now + RENEW_BUFFER >= NotAfter`. Computed as an
    /// addition on `now` (not a subtraction on `NotAfter`) to avoid `SystemTime` underflow when the
    /// cert's `NotAfter` is itself near the epoch in a test.
    fn is_stale(&self) -> bool {
        self.now() + RENEW_BUFFER >= self.not_after
    }

    /// Force-advance the clock so the NEXT `ensure_fresh` re-mints, regardless of the real cert
    /// lifetime. The live renewal-proof drives this through the production `connect()` path.
    #[cfg(test)]
    pub(crate) fn set_now(&mut self, now: SystemTime) {
        self.now_override = Some(now);
    }

    /// The current leaf's `NotAfter` (test introspection: lets a test position the clock relative to
    /// the real cert without knowing rcgen's default validity).
    #[cfg(test)]
    pub(crate) fn not_after(&self) -> SystemTime {
        self.not_after
    }

    /// The current leaf PEM (test introspection: assert the holder was updated after a re-mint).
    #[cfg(test)]
    pub(crate) fn leaf_pem(&self) -> &str {
        &self.leaf_pem
    }

    /// Set the clock far past `NotAfter` so the next ensure ALWAYS re-mints. Used by the live
    /// renewal-proof to prove re-mint + reconnect end-to-end through `connect()`. Test-only (the
    /// production trigger is the real clock against the real `NotAfter`).
    #[cfg(test)]
    pub(crate) fn force_renew_from_now(&mut self) {
        // `NotAfter` + 1h is comfortably past the renew threshold for any real cert.
        self.now_override = Some(self.not_after + Duration::from_secs(3600));
    }

    /// Ensure the leaf is fresh, RE-MINTING (reusing the key) if it is within `RENEW_BUFFER` of
    /// `NotAfter`, then return the components to build the channel's mTLS `ClientConfig`: the current
    /// leaf certs, the key, and the trust-anchor roots. The caller builds the `ClientConfig` AFTER
    /// releasing the guard (this returns owned data, not a config under the lock).
    ///
    /// On a re-mint the holder is updated in place (new leaf + new `NotAfter`; key + roots unchanged)
    /// before returning, so a concurrent caller that already observed the guard sees the fresh cert
    /// and does NOT re-mint (no double-mint; 10c race dedup).
    ///
    /// # Errors
    /// - [`EdgeError::SessionCertResponse`]/[`EdgeError::SessionCertHttp`] from the re-mint (e.g. 401
    ///   if the api-session expired — propagated, not re-authenticated).
    /// - [`EdgeError::IdentityLoad`] if the (possibly re-minted) leaf/key fails to parse to DER.
    pub(crate) async fn ensure_fresh(
        &mut self,
        http: &reqwest::Client,
        base_url: &str,
        token: &crate::edge::auth_token::AuthToken,
    ) -> Result<ChannelTlsParts, EdgeError> {
        if self.is_stale() {
            // O-style: log the renewal at debug (the oracle never renews, so there is no oracle log
            // to mirror; this is our diagnostic for the improvement).
            tracing::debug!(
                not_after = ?self.not_after,
                "session-cert near expiry; re-minting (reusing key)"
            );
            let fresh = remint_api_session_cert(http, base_url, token, &self.key_pem).await?;
            self.not_after = parse_not_after(&fresh.leaf_pem)?;
            self.leaf_pem = fresh.leaf_pem;
            // key + roots are unchanged (the oracle's single-key model); `fresh.key_pem` is the same
            // key we sent, so we keep our stored one.
        }
        // Build the DER parts AFTER any re-mint, from the (now fresh) holder.
        let cert_chain = parse_leaf_to_der(&self.leaf_pem)?;
        let key = parse_key_to_der(&self.key_pem)?;
        let cn = crate::edge::channel::leaf_common_name_for(&self.leaf_pem).unwrap_or_default();
        Ok(ChannelTlsParts {
            cert_chain,
            key,
            roots: self.root_ders.clone(),
            cn,
        })
    }
}

/// The owned components needed to build the channel's mTLS `ClientConfig` + the leaf CN for the
/// channel Hello. Returned by [`SessionCertState::ensure_fresh`] so the config is built OUTSIDE the
/// holder's lock.
pub(crate) struct ChannelTlsParts {
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    roots: Vec<CertificateDer<'static>>,
    cn: String,
}

impl ChannelTlsParts {
    /// Build a verified mTLS `rustls::ClientConfig` (roots = controller CA, client cert = the
    /// session-cert leaf) + the leaf CN. Mirrors `identity_tls::client_config`, but from already-DER
    /// components (the updb path holds DERs in the renewable holder, not a `pem:`-prefixed `Config`).
    ///
    /// # Errors
    /// [`EdgeError::TlsSetup`] if a root cannot be added or the client cert is rejected.
    pub(crate) fn into_config(self) -> Result<(rustls::ClientConfig, String), EdgeError> {
        crate::enroll::trust::ensure_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        for ca in self.roots {
            roots
                .add(ca)
                .map_err(|e| EdgeError::TlsSetup(format!("add ca: {e}")))?;
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(self.cert_chain, self.key)
            .map_err(|e| EdgeError::TlsSetup(e.to_string()))?;
        Ok((config, self.cn))
    }
}

/// Parse the leaf PEM's `NotAfter` to a `SystemTime`.
fn parse_not_after(leaf_pem: &str) -> Result<SystemTime, EdgeError> {
    let chain = x509_cert::Certificate::load_pem_chain(leaf_pem.as_bytes())
        .map_err(|e| EdgeError::SessionCertResponse(format!("parse leaf: {e}")))?;
    let leaf = chain.first().ok_or_else(|| {
        EdgeError::SessionCertResponse("session-cert leaf PEM has no certificate".into())
    })?;
    Ok(leaf.tbs_certificate.validity.not_after.to_system_time())
}

/// Parse the leaf PEM to DER cert(s) for rustls.
fn parse_leaf_to_der(leaf_pem: &str) -> Result<Vec<CertificateDer<'static>>, EdgeError> {
    let mut reader = Cursor::new(leaf_pem.as_bytes());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| EdgeError::IdentityLoad(format!("session-cert leaf: {e}")))?;
    if certs.is_empty() {
        return Err(EdgeError::IdentityLoad(
            "no certificate in session-cert leaf".into(),
        ));
    }
    Ok(certs)
}

/// Parse the ephemeral key PEM to a DER private key for rustls. `Arc`-cloned-free: the holder keeps
/// the PEM and we re-derive the DER per ensure (a `ClientConfig` is per-handshake anyway).
fn parse_key_to_der(key_pem: &str) -> Result<PrivateKeyDer<'static>, EdgeError> {
    let mut reader = Cursor::new(key_pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| EdgeError::IdentityLoad(format!("session-cert key: {e}")))?
        .ok_or_else(|| EdgeError::IdentityLoad("no private key in session-cert key".into()))
}

/// A `tokio::sync::Mutex`-wrapped, `Arc`-shared holder. The `EdgeClient` keeps `Option<SessionCertHolder>`.
pub(crate) type SessionCertHolder = Arc<tokio::sync::Mutex<SessionCertState>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::auth_token::AuthToken;
    use crate::edge::session_cert::SESSION_CERT_CN;
    use crate::enroll::csr::generate_session_cert_csr;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

    /// A self-signed P-256 leaf signed by `key_pem`'s key + the CN, with rcgen's default validity
    /// (`not_after` = year 4096, far future). Returns the leaf PEM. The key MUST be the one whose CSR
    /// was POSTed (so the re-minted CSR's pubkey equals the holder's key — the renewal model). We
    /// build the leaf FROM the key PEM via `rcgen::KeyPair::from_pem` so the cert's SPKI matches the
    /// stored key.
    fn p256_leaf_from_key(key_pem: &str, cn: &str) -> String {
        let kp = rcgen::KeyPair::from_pem(key_pem).expect("reload P-256 key");
        let params = rcgen::CertificateParams::new(vec![cn.to_string()]).expect("params");
        let cert = params.self_signed(&kp).expect("self-sign leaf");
        cert.pem()
    }

    /// A self-signed P-256 leaf with an EXPLICIT past `not_after` (year 2000), so it is stale against
    /// the real wall clock without any clock override. `rcgen::date_time_ymd` yields the validity
    /// instants (no `time` dep needed). `not_before` stays at rcgen's 1975 default so it still parses.
    fn p256_leaf_expired(key_pem: &str, cn: &str) -> String {
        let kp = rcgen::KeyPair::from_pem(key_pem).expect("reload P-256 key");
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).expect("params");
        params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        let cert = params.self_signed(&kp).expect("self-sign leaf");
        cert.pem()
    }

    /// Build a `SessionCert` with a real P-256 key + a matching self-signed leaf. The CA roots for
    /// the holder are irrelevant to the renewal logic tests (they never build TLS here), so we hand
    /// a single dummy DER.
    fn fresh_session_cert(cn: &str) -> SessionCert {
        let KeyAndCsr { key_pem, .. } =
            generate_session_cert_csr(SESSION_CERT_CN).expect("gen P-256 key+csr");
        let leaf_pem = p256_leaf_from_key(&key_pem, cn);
        SessionCert {
            leaf_pem,
            chain_pem: String::new(),
            key_pem,
            id: "cert-0".into(),
        }
    }

    /// Like [`fresh_session_cert`] but with a leaf already EXPIRED against the real clock (year-2000
    /// `not_after`). Lets the concurrency test stay stale under the real wall clock — more honest than
    /// a frozen-future override (mirrors production, where the clock never jumps past a fresh ~12h cert).
    fn stale_session_cert(cn: &str) -> SessionCert {
        let KeyAndCsr { key_pem, .. } =
            generate_session_cert_csr(SESSION_CERT_CN).expect("gen P-256 key+csr");
        let leaf_pem = p256_leaf_expired(&key_pem, cn);
        SessionCert {
            leaf_pem,
            chain_pem: String::new(),
            key_pem,
            id: "cert-0".into(),
        }
    }

    use crate::enroll::csr::KeyAndCsr;

    /// Pin the re-mint request body to `{"csr": "<a CSR PEM>"}` AND capture the CSR's public key so a
    /// test can assert the re-mint reused the holder's key. The captured SPKI is stored in `captured`.
    struct CaptureCsrPubkey {
        captured: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }
    impl Match for CaptureCsrPubkey {
        fn matches(&self, req: &Request) -> bool {
            use x509_cert::der::DecodePem;
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
                return false;
            };
            let Some(csr_pem) = v.get("csr").and_then(serde_json::Value::as_str) else {
                return false;
            };
            let Ok(req_csr) = x509_cert::request::CertReq::from_pem(csr_pem.as_bytes()) else {
                return false;
            };
            let spki = req_csr
                .info
                .public_key
                .subject_public_key
                .raw_bytes()
                .to_vec();
            self.captured.lock().unwrap().push(spki);
            true
        }
    }

    fn spki_of_key_pem(key_pem: &str) -> Vec<u8> {
        // Derive the SPKI from the key by building a CSR over it and reading its public key.
        use x509_cert::der::DecodePem;
        let KeyAndCsr { csr_pem, .. } =
            crate::enroll::csr::session_cert_csr_from_key(SESSION_CERT_CN, key_pem).unwrap();
        let req = x509_cert::request::CertReq::from_pem(csr_pem.as_bytes()).unwrap();
        req.info.public_key.subject_public_key.raw_bytes().to_vec()
    }

    /// Mount a re-mint endpoint returning a fresh leaf signed by `reuse_key_pem` (so the holder's key
    /// is what verifies it) with rcgen's FAR-FUTURE default validity. Returns the server + the SPKI
    /// captures + the far-future leaf PEM it will return.
    async fn mint_server(
        reuse_key_pem: &str,
        captured: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        expect: u64,
    ) -> (MockServer, String) {
        let server = MockServer::start().await;
        // The returned leaf is FAR-FUTURE (rcgen default not_after ~4096), so after one re-mint the
        // holder reads fresh and a second racer does NOT re-mint (the concurrency `expect(1)`).
        let new_leaf = p256_leaf_from_key(reuse_key_pem, "reminted");
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            .and(header("zt-session", "API-TOK"))
            .and(header("Content-Type", "application/json"))
            .and(CaptureCsrPubkey { captured })
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "data": { "id": "cert-1", "certificate": new_leaf },
                "meta": {}
            })))
            .expect(expect)
            .mount(&server)
            .await;
        (server, new_leaf)
    }

    fn http() -> reqwest::Client {
        crate::enroll::trust::ensure_crypto_provider();
        reqwest::Client::new()
    }

    fn holder_from(cert: &SessionCert) -> SessionCertState {
        // One dummy root DER — the renewal logic never builds TLS in these unit tests.
        SessionCertState::new(cert, vec![vec![0x30, 0x00]])
            .expect("holder builds (NotAfter parses)")
    }

    /// STALE → re-mint: with the clock advanced past `NotAfter`, `ensure_fresh` re-mints exactly once
    /// (`expect(1)`), REUSES the key (the re-mint CSR's pubkey == the holder's key SPKI), and updates
    /// the holder to the new leaf.
    #[tokio::test]
    async fn ensure_fresh_remints_when_stale_reusing_key() {
        let cert = fresh_session_cert("original");
        let original_key_spki = spki_of_key_pem(&cert.key_pem);
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (server, new_leaf) = mint_server(&cert.key_pem, captured.clone(), 1).await;

        let mut holder = holder_from(&cert);
        let original_leaf = holder.leaf_pem().to_string();
        // Advance the clock well past NotAfter → stale.
        holder.set_now(holder.not_after() + Duration::from_secs(3600));

        holder
            .ensure_fresh(&http(), &server.uri(), &AuthToken::Legacy("API-TOK".into()))
            .await
            .expect("re-mint succeeds");

        // The holder now carries the re-minted leaf (NOT the original).
        assert_eq!(
            holder.leaf_pem(),
            new_leaf,
            "holder updated to the new leaf"
        );
        assert_ne!(holder.leaf_pem(), original_leaf, "leaf changed");
        // The re-mint CSR carried the SAME public key as the holder's key (key REUSE — the mutation
        // killer: a fresh-key impl would capture a different SPKI).
        let caps = captured.lock().unwrap();
        assert_eq!(caps.len(), 1, "exactly one re-mint CSR observed");
        assert_eq!(
            caps[0], original_key_spki,
            "the re-mint reused the stored ephemeral key (same public key)"
        );
        // `expect(1)` on the mock verifies on drop that the endpoint was hit exactly once.
    }

    /// FRESH → no re-mint: a far-future leaf with the real clock is not stale, so `ensure_fresh`
    /// does NOT hit the mint endpoint (`expect(0)`) and the holder is unchanged.
    #[tokio::test]
    async fn ensure_fresh_does_not_remint_when_fresh() {
        let cert = fresh_session_cert("original");
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        // expect(0): the endpoint must NOT be hit.
        let (server, _) = mint_server(&cert.key_pem, captured.clone(), 0).await;

        let mut holder = holder_from(&cert);
        let original_leaf = holder.leaf_pem().to_string();
        // Real clock (now_override=None) vs rcgen's far-future NotAfter → fresh.

        holder
            .ensure_fresh(&http(), &server.uri(), &AuthToken::Legacy("API-TOK".into()))
            .await
            .expect("no re-mint, builds parts from the existing leaf");

        assert_eq!(
            holder.leaf_pem(),
            original_leaf,
            "leaf unchanged (no re-mint)"
        );
        assert!(captured.lock().unwrap().is_empty(), "no CSR was POSTed");
        // `expect(0)` verifies on drop the endpoint was never hit.
    }

    /// Re-mint that gets a 401 (api-session expired) PROPAGATES the error (does NOT re-authenticate,
    /// does NOT hang). The holder is left unchanged (the old leaf stays). Oracle deviation: the
    /// oracle never renews; we propagate per spec §2.
    #[tokio::test]
    async fn ensure_fresh_propagates_401_on_remint() {
        let cert = fresh_session_cert("original");
        let original_leaf = cert.leaf_pem.clone();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/current-api-session/certificates"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "code": "UNAUTHORIZED", "message": "api session expired" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut holder = holder_from(&cert);
        holder.set_now(holder.not_after() + Duration::from_secs(3600));

        // ChannelTlsParts is intentionally non-Debug (it holds a key), so match instead of expect_err.
        match holder
            .ensure_fresh(&http(), &server.uri(), &AuthToken::Legacy("API-TOK".into()))
            .await
        {
            Err(EdgeError::SessionCertHttp { status: 401, .. }) => {}
            Err(other) => panic!("expected SessionCertHttp 401, got {other:?}"),
            Ok(_) => panic!("a 401 on re-mint must propagate"),
        }
        // The holder keeps the OLD leaf (the failed re-mint did not corrupt it).
        assert_eq!(
            holder.leaf_pem(),
            original_leaf,
            "old leaf retained on failure"
        );
    }

    /// CONCURRENCY: two concurrent `ensure_fresh` through ONE shared holder re-mint exactly ONCE.
    /// The `tokio::sync::Mutex` serializes them; the first re-mints + updates the holder to a
    /// far-future leaf, so the second sees a FRESH cert and does NOT re-mint (`expect(1)`).
    #[tokio::test]
    async fn concurrent_ensure_fresh_remints_once() {
        // The original leaf is EXPIRED against the REAL clock (year-2000 NotAfter), and the re-mint
        // returns a FAR-FUTURE (4096) leaf. Under one consistent real clock: task 1 re-mints → holder
        // NotAfter jumps to 4096 → task 2 sees fresh → skips. One mint. (A frozen future override
        // would also push the clock past the 4096 re-mint and spuriously double-mint — see git history.)
        let cert = stale_session_cert("original");
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (server, _new_leaf) = mint_server(&cert.key_pem, captured.clone(), 1).await;
        let uri = server.uri();

        let holder: SessionCertHolder = Arc::new(tokio::sync::Mutex::new(holder_from(&cert)));

        let h1 = holder.clone();
        let h2 = holder.clone();
        let uri1 = uri.clone();
        let uri2 = uri.clone();
        let t1 = tokio::spawn(async move {
            let http = http();
            let mut g = h1.lock().await;
            g.ensure_fresh(&http, &uri1, &AuthToken::Legacy("API-TOK".into()))
                .await
                .map(|_| ())
        });
        let t2 = tokio::spawn(async move {
            let http = http();
            let mut g = h2.lock().await;
            g.ensure_fresh(&http, &uri2, &AuthToken::Legacy("API-TOK".into()))
                .await
                .map(|_| ())
        });
        t1.await.unwrap().expect("ensure 1 ok");
        t2.await.unwrap().expect("ensure 2 ok");

        // Exactly ONE re-mint CSR observed (the Mutex serialized; the 2nd saw the fresh far-future
        // leaf and skipped). `expect(1)` on the mock also verifies this on drop.
        assert_eq!(
            captured.lock().unwrap().len(),
            1,
            "the tokio Mutex must dedup concurrent ensures to a single re-mint"
        );
    }

    /// `is_stale` boundary: a cert whose NotAfter is exactly `now + RENEW_BUFFER` is stale (>=), and
    /// one comfortably beyond it is fresh. Pins the threshold semantics (RENEW_BUFFER + the `>=`).
    #[tokio::test]
    async fn is_stale_uses_renew_buffer_threshold() {
        let cert = fresh_session_cert("original");
        let mut holder = holder_from(&cert);
        let na = holder.not_after();

        // now = NotAfter - RENEW_BUFFER exactly → now + BUFFER == NotAfter → stale (>=).
        holder.set_now(na - RENEW_BUFFER);
        assert!(holder.is_stale(), "at exactly the buffer boundary → stale");

        // now = NotAfter - RENEW_BUFFER - 1h → fresh (well before the threshold).
        holder.set_now(na - RENEW_BUFFER - Duration::from_secs(3600));
        assert!(!holder.is_stale(), "an hour before the threshold → fresh");
    }
}
