//! e2e crypto for the edge data path: a thin wrapper over `dryoc` (libsodium-compatible
//! crypto_kx + crypto_secretstream_xchacha20poly1305). Isolates the crate so it stays
//! swappable. Oracle: openziti/secretstream (kx/kx.go + stream.go), verified byte-exact.

use dryoc::dryocstream::{DryocStream, Header, Pull, Push, Tag};
use dryoc::kx::{KeyPair as DKeyPair, PublicKey, Session};
use dryoc::types::ByteArray;
use thiserror::Error;

/// Stream header size (xchacha20poly1305 nonce-extension), == libsodium HEADERBYTES.
pub const STREAM_HEADER_BYTES: usize = 24;
/// Per-frame ciphertext overhead (1 tag byte + 16-byte poly1305 MAC), == libsodium ABYTES.
pub const ABYTES: usize = 17;

/// A 32-byte session/stream key (crate-agnostic; the wrapper hides dryoc's key types).
pub type SessionKey = [u8; 32];

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key exchange failed: {0}")]
    KeyExchange(String),
    #[error("secretstream failed: {0}")]
    Stream(String),
}

/// An X25519 keypair for the edge key exchange (`crypto_kx`).
pub struct KeyPair(DKeyPair);

impl KeyPair {
    /// Generate a fresh ephemeral keypair (random secret + scalarmult_base). The host only
    /// ever sees our public key, so the generation method is free — only the derivation and
    /// the public key on the wire must match the oracle.
    #[must_use]
    pub fn generate() -> Self {
        Self(DKeyPair::generate())
    }

    /// Our raw 32-byte X25519 public key (goes in the Connect `PublicKey` header).
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        *self.0.public_key.as_array()
    }

    /// Derive `(rx, tx)` from our keypair and the host's public key. Byte-identical to the
    /// Go `ClientSessionKeys`: rx = BLAKE2b-512(q ‖ our_pk ‖ host_pk)[..32], tx = [32..].
    pub fn client_session_keys(
        &self,
        host_pk: &[u8; 32],
    ) -> Result<(SessionKey, SessionKey), CryptoError> {
        let peer = PublicKey::from(*host_pk);
        let session = Session::new_client_with_defaults(&self.0, &peer)
            .map_err(|e| CryptoError::KeyExchange(e.to_string()))?;
        let (rx, tx) = session.into_parts();
        Ok((*rx.as_array(), *tx.as_array()))
    }

    /// Host-side mirror of `client_session_keys`: derive `(rx, tx)` from our keypair and the
    /// dialer's public key. Byte-identical to Go `ServerSessionKeys`. Used by the host accept
    /// path (`server_crypto_setup`) and by the in-crate duplex tests. kx invariant:
    /// `server_rx == client_tx`, `server_tx == client_rx`.
    pub(crate) fn server_session_keys(
        &self,
        client_pk: &[u8; 32],
    ) -> Result<(SessionKey, SessionKey), CryptoError> {
        let peer = PublicKey::from(*client_pk);
        let session = Session::new_server_with_defaults(&self.0, &peer)
            .map_err(|e| CryptoError::KeyExchange(e.to_string()))?;
        let (rx, tx) = session.into_parts();
        Ok((*rx.as_array(), *tx.as_array()))
    }

    /// Build a keypair from a known 32-byte secret key (deterministic test vectors only).
    #[cfg(test)]
    pub(crate) fn from_secret_key_for_test(sk: &[u8; 32]) -> Self {
        use dryoc::kx::SecretKey;
        Self(DKeyPair::from_secret_key(SecretKey::from(*sk)))
    }
}

/// Outbound secretstream (encrypt). Owns the push-stream state; a single writer.
pub struct Encryptor(DryocStream<Push>);

impl Encryptor {
    /// Create from the tx session key. Returns the encryptor and the 24-byte stream header
    /// (which the caller sends as the FIRST Data frame).
    #[must_use]
    pub fn new(tx: &SessionKey) -> (Self, [u8; STREAM_HEADER_BYTES]) {
        let (stream, header): (DryocStream<Push>, Header) = DryocStream::init_push(tx);
        (Self(stream), *header.as_array())
    }

    /// Encrypt one message with tag `Message` (the only tag the SDK uses).
    pub fn push(&mut self, plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.0
            .push_to_vec(&plain.to_vec(), None, Tag::MESSAGE)
            .map_err(|e| CryptoError::Stream(e.to_string()))
    }
}

/// Inbound secretstream (decrypt). Built lazily from the first inbound 24-byte frame.
pub struct Decryptor(DryocStream<Pull>);

impl Decryptor {
    /// Create from the rx session key and the host's 24-byte stream header.
    #[must_use]
    pub fn new(rx: &SessionKey, header: &[u8; STREAM_HEADER_BYTES]) -> Self {
        let h = Header::from(*header);
        Self(DryocStream::init_pull(rx, &h))
    }

    /// Decrypt one frame, returning the plaintext (the tag is ignored, matching `ziti/edge/conn.go` Read).
    pub fn pull(&mut self, cipher: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (plain, _tag) = self
            .0
            .pull_to_vec(&cipher.to_vec(), None)
            .map_err(|e| CryptoError::Stream(e.to_string()))?;
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn a32(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    fn vectors() -> serde_json::Value {
        let raw = include_str!("../../tests/fixtures/slice5_go_vectors.json");
        serde_json::from_str(raw).unwrap()
    }

    #[test]
    fn client_session_keys_match_go_vectors() {
        let v = vectors();
        let client_sk = a32(v["client_sk_hex"].as_str().unwrap());
        let server_pk = a32(v["server_pk_hex"].as_str().unwrap());
        let exp_rx = a32(v["client_rx_hex"].as_str().unwrap());
        let exp_tx = a32(v["client_tx_hex"].as_str().unwrap());

        // Build our keypair from the Go client secret key (deterministic vector).
        let kp = KeyPair::from_secret_key_for_test(&client_sk);
        let (rx, tx) = kp.client_session_keys(&server_pk).unwrap();
        assert_eq!(rx, exp_rx, "kx rx must match Go ClientSessionKeys");
        assert_eq!(tx, exp_tx, "kx tx must match Go ClientSessionKeys");
    }

    #[test]
    fn decryptor_pulls_go_secretstream_frames_in_order() {
        let v = vectors();
        let key = a32(v["stream_key_hex"].as_str().unwrap());
        let header: [u8; STREAM_HEADER_BYTES] = unhex(v["stream_header_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let plaintexts: Vec<String> = v["plaintexts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().to_string())
            .collect();
        let ciphers: Vec<Vec<u8>> = v["ciphers_hex"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| unhex(c.as_str().unwrap()))
            .collect();

        let mut dec = Decryptor::new(&key, &header);
        for (i, c) in ciphers.iter().enumerate() {
            let plain = dec.pull(c).unwrap();
            assert_eq!(
                plain,
                plaintexts[i].as_bytes(),
                "frame {i} decrypts to Go plaintext"
            );
        }
    }

    #[test]
    fn encryptor_decryptor_round_trip_and_abytes() {
        let kp = KeyPair::generate();
        let peer = KeyPair::generate();
        let (_rx, tx) = kp.client_session_keys(&peer.public_key()).unwrap();
        let (srx, _stx) = peer.server_session_keys(&kp.public_key()).unwrap();
        assert_eq!(tx, srx, "kx invariant: our tx == peer rx");

        let (mut enc, header) = Encryptor::new(&tx);
        assert_eq!(header.len(), STREAM_HEADER_BYTES);
        let msg = b"round-trip-payload";
        let cipher = enc.push(msg).unwrap();
        assert_eq!(cipher.len(), msg.len() + ABYTES, "ABYTES overhead");

        // Peer decrypts with its rx (== our tx) and our header.
        let mut dec = Decryptor::new(&srx, &header);
        assert_eq!(dec.pull(&cipher).unwrap(), msg);
        assert_ne!(&cipher[..], &msg[..], "ciphertext differs from plaintext");
    }

    #[test]
    fn decryptor_rejects_tampered_ciphertext() {
        let key = [0x55u8; 32];
        let (mut enc, header) = Encryptor::new(&key);
        let cipher = enc.push(b"authentic-message").unwrap();

        // A flipped byte in the ciphertext (here, the trailing MAC region) must fail to decrypt.
        let mut bad = cipher.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        let mut dec = Decryptor::new(&key, &header);
        assert!(
            dec.pull(&bad).is_err(),
            "tampered ciphertext must be rejected"
        );

        // Sanity: a fresh decryptor over the SAME key+header pulls the authentic frame.
        let mut dec_ok = Decryptor::new(&key, &header);
        assert_eq!(dec_ok.pull(&cipher).unwrap(), b"authentic-message");
    }
}
