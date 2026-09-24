//! Tests de `pkce` (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`).

use sha2::{Digest, Sha256};

use super::pkce::*;

/// PKCE: the verifier is base64url(32 bytes) → 43 chars (no padding); the challenge =
/// base64url(sha256(verifier)) → 43 chars; method is implicitly S256. Two calls differ (random).
#[test]
fn pkce_verifier_and_challenge_are_well_formed() {
    let p = new_pkce();
    assert_eq!(p.verifier.len(), 43, "b64url(32 bytes) no pad = 43 chars");
    assert_eq!(p.challenge.len(), 43, "b64url(sha256=32 bytes) no pad = 43");
    assert!(!p.verifier.contains('='), "no padding");
    assert!(!p.challenge.contains('='), "no padding");
    assert!(
        !p.verifier.contains('+') && !p.verifier.contains('/'),
        "url-safe"
    );
    // The challenge is the SHA-256 of the verifier (deterministic given the verifier).
    let expect = b64url_nopad(&Sha256::digest(p.verifier.as_bytes()));
    assert_eq!(p.challenge, expect, "challenge = b64url(sha256(verifier))");
    assert_ne!(new_pkce().verifier, new_pkce().verifier, "random per call");
}
