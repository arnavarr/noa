//! Per-connection read/write: `impl Debug/EdgeConn`, `impl EdgeReadHalf`, `impl EdgeWriteHalf`, and
//! the host-side `server_crypto_setup`. Split out of the monolithic `edge/data` module (F6 tramo 1b).
//! **DV-11-SC CERRADA aquí:** `read` pone la bandera compartida `sent_fin` en la rama `CT_STATE_CLOSED`
//! (NO en la de FIN ni la de rx-cerrada), `close_write`/`close` también la ponen, y `write` la consulta
//! al tope y falla con `WriteAfterClose` ANTES de serializar — porta el `sentFIN` del oráculo
//! (`ziti/edge/network/conn.go`), simétrico en los dos gemelos UDP.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

use crate::channel::connect::write_message;
use crate::channel::message::Message;
use crate::edge::crypto::{Decryptor, Encryptor, STREAM_HEADER_BYTES};
use crate::edge::dial::{
    CRYPTO_METHOD_LIBSODIUM, CT_DATA, CT_STATE_CLOSED, FLAG_FIN, HDR_CRYPTO_METHOD, HDR_FLAGS,
    HDR_PUBLIC_KEY, build_data, build_state_closed,
};
use crate::edge::error::EdgeError;

use super::wire::header_u32;
use super::{ChannelState, ConnCrypto, EdgeConn, EdgeReadHalf, EdgeWriteHalf, ReadCrypto};

impl std::fmt::Debug for EdgeConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeConn")
            .field("conn_id", &self.writer.conn_id)
            .field("circuit_id", &self.circuit_id)
            .field("source_identity", &self.source_identity)
            .field("first_write", &self.writer.first_write)
            .field("read_eof", &self.reader.read_eof)
            .finish_non_exhaustive()
    }
}

impl EdgeConn {
    pub(crate) fn new(
        conn_id: u32,
        circuit_id: Option<String>,
        source_identity: Option<String>,
        rx: mpsc::Receiver<Message>,
        state: Arc<ChannelState>,
        crypto: Option<ConnCrypto>,
    ) -> Self {
        // Split the all-or-nothing ConnCrypto across the two halves: `sender` -> write,
        // `decryptor`+`rx_key` -> read. Plaintext (None) -> both halves plaintext. The invariant
        // "both encrypted or both plaintext" is preserved by construction (one ConnCrypto in).
        let (read_crypto, sender) = match crypto {
            None => (None, None),
            Some(cc) => (
                Some(ReadCrypto {
                    decryptor: cc.decryptor,
                    rx_key: cc.rx_key,
                }),
                Some(cc.sender),
            ),
        };
        // With crypto, the tx stream header was already sent as the first physical Data frame
        // (in dial), so user writes are no longer "first" (no MULTIPART flag).
        // `sender.is_none() == crypto.is_none()`, so this preserves the prior `first_write`.
        let first_write = sender.is_none();
        // The oracle's `sentFIN` (conn.go:111-113): ONE flag shared by both halves (this is the ONLY
        // construction site). The read half stores it on an inbound StateClosed; write consults it.
        let sent_fin = Arc::new(AtomicBool::new(false));
        Self {
            circuit_id,
            source_identity,
            reader: EdgeReadHalf {
                conn_id,
                rx,
                read_eof: false,
                crypto: read_crypto,
                sent_fin: Arc::clone(&sent_fin),
            },
            writer: EdgeWriteHalf {
                conn_id,
                state,
                first_write,
                sender,
                sent_fin,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        conn_id: u32,
        rx: mpsc::Receiver<Message>,
        state: Arc<ChannelState>,
    ) -> Self {
        Self::new(conn_id, None, None, rx, state, None)
    }

    /// The client-allocated connection id.
    #[must_use]
    pub fn conn_id(&self) -> u32 {
        self.writer.conn_id
    }

    /// The circuit id from `StateConnected` (header 1026), if any.
    #[must_use]
    pub fn circuit_id(&self) -> Option<&str> {
        self.circuit_id.as_deref()
    }

    /// The dialer's identity NAME from the inbound Connect's `CallerId` header (host side),
    /// or `None` if the dial carried no CallerId. Oracle: `ziti/edge/network/hosting_conn.go:298,307`.
    #[must_use]
    pub fn source_identity(&self) -> Option<&str> {
        self.source_identity.as_deref()
    }

    /// Send application bytes as a Data frame (first frame advertises MULTIPART).
    ///
    /// # Errors
    /// `EdgeError::Channel` if the write fails.
    /// `EdgeError::Crypto` if encryption fails.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), EdgeError> {
        self.writer.write(data).await
    }

    /// Half-close the WRITE side: send one empty `Data` frame carrying the `FIN` flag, telling the
    /// peer that no more application bytes will follow on this direction. The peer's read side maps
    /// an inbound `Data` with `FIN` to EOF (see [`EdgeConn::read`], which sets `read_eof`). Does NOT
    /// touch the read side and does NOT deregister the conn from the mux — read can keep draining
    /// the other direction (true half-close). IDEMPOTENT: a `sent_fin` compare-and-set sends the
    /// FIN at most once (a 2nd call is a silent no-op), mirroring the oracle's `sentFIN` CAS.
    ///
    /// Takes `&self` (the FIN is a one-shot latch, no mutable conn state changes) so a splice's
    /// per-direction task can half-close without owning the connection mutably.
    ///
    /// Oracle: `edgeConn.CloseWrite` (`ziti/edge/network/conn.go:242-256`): on the first call it
    /// sends an empty Data with `FlagsHeader = edge.FIN`, idempotent via a `sentFIN` CAS.
    ///
    /// # Errors
    /// `EdgeError::Channel` if writing the FIN frame fails.
    pub async fn close_write(&self) -> Result<(), EdgeError> {
        self.writer.close_write().await
    }

    /// Split this connection into its read and write halves so a tunneler splice can read one
    /// direction while writing the other CONCURRENTLY (the field sets are disjoint, so `&mut`
    /// borrows of each half don't conflict). The caller MUST keep the owning `EdgeChannel` alive
    /// for the duration (it drives the rx-loop that feeds [`EdgeReadHalf`]); see
    /// [`crate::edge::conn::ServiceConn::into_parts`], which returns the channel alongside the
    /// halves. The connection metadata (`circuit_id`/`source_identity`) is dropped — the splice
    /// does not need it.
    #[must_use]
    pub fn into_split(self) -> (EdgeReadHalf, EdgeWriteHalf) {
        (self.reader, self.writer)
    }

    /// Read the next chunk of application bytes, or `None` at EOF (FIN/StateClosed or
    /// the channel closed). In-order FIFO; no MULTIPART_MSG reassembly (router sends
    /// plain Data, verified live).
    ///
    /// # Errors
    /// `EdgeError::Crypto` if decryption fails.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, EdgeError> {
        self.reader.read().await
    }

    /// Close the connection: send StateClosed and deregister from the mux.
    ///
    /// # Errors
    /// `EdgeError::Channel` if the close write fails.
    pub async fn close(&mut self) -> Result<(), EdgeError> {
        self.writer.close().await
    }
}

impl EdgeReadHalf {
    /// The client-allocated connection id (same as the write half and the parent `EdgeConn`).
    #[must_use]
    pub fn conn_id(&self) -> u32 {
        self.conn_id
    }

    /// Read the next chunk of application bytes, or `None` at EOF (FIN/StateClosed or the channel
    /// closed). In-order FIFO; no MULTIPART_MSG reassembly (router sends plain Data, verified live).
    /// The returned value is byte-identical to the pre-split `EdgeConn::read`; the ONLY added effect
    /// is DV-11-SC: on a `StateClosed` (conn dead) it also sets the shared `sent_fin` so a subsequent
    /// `write` fails — the discriminant vs a FIN (half-close), which does NOT set it.
    ///
    /// # Errors
    /// `EdgeError::Crypto` if decryption fails.
    pub async fn read(&mut self) -> Result<Option<Vec<u8>>, EdgeError> {
        if self.read_eof {
            return Ok(None);
        }
        loop {
            match self.rx.recv().await {
                None => {
                    self.read_eof = true;
                    return Ok(None);
                }
                Some(msg) if msg.content_type == CT_DATA => {
                    let fin = header_u32(&msg, HDR_FLAGS).unwrap_or(0) & FLAG_FIN != 0;
                    if fin {
                        self.read_eof = true;
                    }
                    match &mut self.crypto {
                        None => {
                            if !msg.body.is_empty() {
                                return Ok(Some(msg.body));
                            }
                            if self.read_eof {
                                return Ok(None);
                            }
                        }
                        Some(cc) if cc.rx_key.is_some() => {
                            // First inbound Data = the host's 24-byte stream header.
                            if msg.body.len() != STREAM_HEADER_BYTES {
                                return Err(EdgeError::Crypto(format!(
                                    "stream header must be {STREAM_HEADER_BYTES} bytes, got {}",
                                    msg.body.len()
                                )));
                            }
                            let header: [u8; STREAM_HEADER_BYTES] =
                                msg.body.as_slice().try_into().unwrap();
                            let rx_key = cc.rx_key.take().unwrap();
                            cc.decryptor = Some(Decryptor::new(&rx_key, &header));
                            if self.read_eof {
                                return Ok(None);
                            }
                            // consume the header frame; loop for the next
                        }
                        Some(cc) => {
                            if msg.body.is_empty() {
                                if self.read_eof {
                                    return Ok(None);
                                }
                                continue;
                            }
                            if msg.body.len() < crate::edge::crypto::ABYTES {
                                return Err(EdgeError::Crypto(format!(
                                    "encrypted frame too short: {} < {}",
                                    msg.body.len(),
                                    crate::edge::crypto::ABYTES
                                )));
                            }
                            let dec = cc.decryptor.as_mut().expect("decryptor set after header");
                            let plain = dec
                                .pull(&msg.body)
                                .map_err(|e| EdgeError::Crypto(e.to_string()))?;
                            if !plain.is_empty() {
                                return Ok(Some(plain));
                            }
                            if self.read_eof {
                                return Ok(None);
                            }
                        }
                    }
                }
                Some(msg) if msg.content_type == CT_STATE_CLOSED => {
                    self.read_eof = true;
                    // Discriminant: a StateClosed (the conn is DEAD) sets `sent_fin` so the write half
                    // fails a subsequent write — the oracle's `sentFIN.Store(true)` in `AcceptMessage`'s
                    // StateClosed arm (conn.go:361) and in `close(false)` (conn.go:862, reached from
                    // the non-xgress Read StateClosed path :777-779). A FIN (below) and an rx-hangup
                    // (above) do NOT set it (oracle sets only `readFIN` there, :761/:751).
                    self.sent_fin.store(true, Ordering::Release);
                    return Ok(None);
                }
                Some(_) => {}
            }
        }
    }
}

impl EdgeWriteHalf {
    /// The client-allocated connection id (same as the read half and the parent `EdgeConn`).
    #[must_use]
    pub fn conn_id(&self) -> u32 {
        self.conn_id
    }

    /// Send application bytes as a Data frame (first frame advertises MULTIPART).
    ///
    /// Fails FAST if the write side is closed: an inbound `StateClosed` (seen by the read half, which
    /// shares `sent_fin`), our own `close_write`, or our own `close` all set the shared `sent_fin`
    /// flag, and this consults it BEFORE serializing / taking the channel mutex — so a dead conn emits
    /// ZERO bytes on the shared wire (the drain arm of each UDP relay twin aborts on this error).
    /// Mirrors the oracle, whose `Write` consults `sentFIN` first (`conn.go:216-220`).
    ///
    /// # Errors
    /// [`EdgeError::WriteAfterClose`] if the write side is closed (`sent_fin` set).
    /// `EdgeError::Channel` if the write fails. `EdgeError::Crypto` if encryption fails.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), EdgeError> {
        // Oracle conn.go:215-221: consult `sentFIN` first and fail before touching the wire.
        if self.sent_fin.load(Ordering::Acquire) {
            return Err(EdgeError::WriteAfterClose);
        }
        let body = match &mut self.sender {
            Some(enc) => enc
                .push(data)
                .map_err(|e| EdgeError::Crypto(e.to_string()))?,
            None => data.to_vec(),
        };
        let mut msg = build_data(self.conn_id, &body, self.first_write);
        self.first_write = false;
        msg.sequence = self.state.next_seq();
        let mut w = self.state.write.lock().await;
        write_message(&mut *w, &msg).await.map_err(EdgeError::from)
    }

    /// Half-close the WRITE side: send one empty `Data` frame carrying the `FIN` flag, telling the
    /// peer that no more application bytes will follow on this direction. IDEMPOTENT via a
    /// `sent_fin` compare-and-set. Takes `&self` so a splice's per-direction task can half-close
    /// without owning the half mutably. Oracle: `edgeConn.CloseWrite` (`conn.go:242-256`).
    ///
    /// # Errors
    /// `EdgeError::Channel` if writing the FIN frame fails.
    pub async fn close_write(&self) -> Result<(), EdgeError> {
        // CAS: only the first caller proceeds to send the FIN; later calls are no-ops.
        if self
            .sent_fin
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        // Empty Data frame with the FIN flag (not MULTIPART): `build_data(.., first=false)` gives an
        // empty-body Data with NO flags, then we set FIN explicitly. Oracle conn.go:248 sends an
        // empty Data with FlagsHeader=edge.FIN.
        let mut msg = build_data(self.conn_id, &[], false);
        msg.headers
            .insert(HDR_FLAGS, FLAG_FIN.to_le_bytes().to_vec());
        msg.sequence = self.state.next_seq();
        let mut w = self.state.write.lock().await;
        write_message(&mut *w, &msg).await.map_err(EdgeError::from)
    }

    /// Close the connection: send StateClosed and deregister from the mux. Takes `&self` (the only
    /// mutation is removing the conn-id from the shared mux, behind its own lock) so the splice can
    /// do the single full-close after its `join!`. Behaviour mirrors the pre-split `EdgeConn::close`.
    ///
    /// Also sets the shared `sent_fin` flag (the oracle's THIRD `sentFIN` setter, `close():862`) so a
    /// write after our own `close()` fails with [`EdgeError::WriteAfterClose`] instead of racing a
    /// frame onto a torn-down conn-id. The StateClosed itself goes via `write_message` (not `write`),
    /// so setting the flag does NOT block the close frame.
    ///
    /// # Errors
    /// `EdgeError::Channel` if the close write fails.
    pub async fn close(&self) -> Result<(), EdgeError> {
        // Third setter, parity with the oracle's `close()` (conn.go:862). The `readFIN` side (:861)
        // is out of scope: it is post-local-close read state (the read half does not share read_eof),
        // with no effect on the wire (spec §3.1.6).
        self.sent_fin.store(true, Ordering::Release);
        let mut msg = build_state_closed(self.conn_id);
        msg.sequence = self.state.next_seq();
        {
            let mut w = self.state.write.lock().await;
            write_message(&mut *w, &msg).await?;
        }
        self.state.conns.lock().unwrap().remove(&self.conn_id);
        Ok(())
    }
}

/// Set up the host (server) side of e2e crypto for one accepted child — the inverted mirror of
/// the client's `establish_client_crypto`. Pure: no wire IO. The caller writes the returned
/// 24-byte stream header AFTER the DialSuccess (oracle `dialSucceeded`). Returns `Ok(None)` for
/// a plaintext child — either the service is not encrypted (`keypair` is `None`) or the dialer
/// sent no `PublicKey` (oracle `hosting_conn.go:370-372`: warn + plaintext, NOT a reject).
/// Oracle: `establishServerCrypto` (`ziti/edge/network/conn.go:698`).
///
/// # Errors
/// - `EdgeError::UnsupportedCrypto` if the dialer's `CryptoMethod` is not libsodium.
/// - `EdgeError::Crypto` if the dialer's public key is malformed or the key exchange fails.
pub(crate) fn server_crypto_setup(
    conn_id: u32,
    keypair: Option<&crate::edge::crypto::KeyPair>,
    dial: &Message,
) -> Result<Option<(ConnCrypto, [u8; STREAM_HEADER_BYTES])>, EdgeError> {
    let Some(keypair) = keypair else {
        return Ok(None); // plaintext service
    };
    let Some(client_pk_raw) = dial.headers.get(&HDR_PUBLIC_KEY) else {
        // Silent downgrade: encrypted bind but the dialer advertised no key. Plaintext child,
        // NOT a reject (oracle hosting_conn.go:371 Warnf). The child conn-id rides the warn so
        // the operator knows WHICH connection downgraded (oracle :371 is `newConnLogger`,
        // connId = the child id).
        tracing::warn!(
            conn_id,
            "client did not send its key. connection is not end-to-end encrypted"
        );
        return Ok(None); // dialer sent no key -> plaintext child (oracle :370-372)
    };
    let method = dial
        .headers
        .get(&HDR_CRYPTO_METHOD)
        .and_then(|v| v.first().copied())
        .unwrap_or(CRYPTO_METHOD_LIBSODIUM);
    if method != CRYPTO_METHOD_LIBSODIUM {
        return Err(EdgeError::UnsupportedCrypto);
    }
    let client_pk: [u8; 32] = client_pk_raw.as_slice().try_into().map_err(|_| {
        EdgeError::Crypto(format!(
            "dialer public key must be 32 bytes, got {}",
            client_pk_raw.len()
        ))
    })?;
    let (rx, tx) = keypair
        .server_session_keys(&client_pk)
        .map_err(|e| EdgeError::Crypto(e.to_string()))?;
    let (sender, tx_header) = Encryptor::new(&tx);
    Ok(Some((
        ConnCrypto {
            sender,
            decryptor: None,
            rx_key: Some(rx),
        },
        tx_header,
    )))
}
