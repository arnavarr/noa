//! PKCE (RFC 7636) y la aleatoriedad del flujo: `verifier`/`challenge`, `state` y `nonce`.
//! (F6 tramo 4: movido verbatim del monolito de `edge/oidc`.)

use base64::Engine;
use sha2::{Digest, Sha256};

/// PKCE parameters (RFC 7636). `verifier` = base64url(32 random bytes); `challenge` =
/// base64url(sha256(verifier)); method is always `S256`. Oracle `newPkceParameters`
/// (`clients_shared.go:810-827`).
///
/// Manual `Debug` REDACTS the `verifier` (the PKCE secret proving possession of the auth code) — a
/// derived `Debug` would leak it via `{:?}`. The `challenge` is the public SHA-256 sent in the
/// authorize URL, so it is shown.
#[derive(Clone)]
pub(super) struct Pkce {
    pub(super) verifier: String,
    pub(super) challenge: String,
}

impl std::fmt::Debug for Pkce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkce")
            .field("verifier", &"<redacted>")
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// base64url WITHOUT padding (the OAuth/PKCE URL-safe encoding). Oracle `base64URLEncodeNoPadding`
/// (`clients_shared.go:848`). Same engine `enroll::token` uses for JWT payloads.
pub(super) fn b64url_nopad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Fill `buf` with OS random bytes. Reuses the crate-wide `getrandom` (same as the channel marker);
/// not a crypto provider, ring-free.
fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS RNG failed");
}

/// Generate fresh PKCE params: a 32-byte random verifier, the SHA-256 challenge. Oracle
/// `newPkceParameters` (`clients_shared.go:816-824`): `verifier = b64url(rand 32)`,
/// `challenge = b64url(sha256(verifier))`.
pub(super) fn new_pkce() -> Pkce {
    let mut raw = [0u8; 32];
    random_bytes(&mut raw);
    let verifier = b64url_nopad(&raw);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = b64url_nopad(&digest);
    Pkce {
        verifier,
        challenge,
    }
}

/// A random `state` (CSRF, 16 bytes) — oracle `generateRandomState` (`:830`).
pub(super) fn new_state() -> String {
    let mut raw = [0u8; 16];
    random_bytes(&mut raw);
    b64url_nopad(&raw)
}

/// A random `nonce` (binds the request to the id_token, 32 bytes) — oracle `generateNonce` (`:837`).
pub(super) fn new_nonce() -> String {
    let mut raw = [0u8; 32];
    random_bytes(&mut raw);
    b64url_nopad(&raw)
}
