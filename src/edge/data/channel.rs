//! `impl EdgeChannel` (build/dial/bind/accept/close) + `impl Drop for EdgeChannel`. Split out of the
//! monolithic `edge/data` module (F6 tramo 1b), byte-identical. Owns the rx-loop + latency-probe task
//! spawn and the accept path.

use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::channel::connect::write_message;
use crate::channel::message::Message;
use crate::edge::bind::{
    CT_DIAL, HDR_ROUTER_PROVIDED_CONN_ID, build_bind, build_unbind, classify_bind_reply,
};
use crate::edge::dial::{
    CRYPTO_METHOD_LIBSODIUM, CT_STATE_CLOSED, HDR_CIRCUIT_ID, HDR_CRYPTO_METHOD, HDR_PUBLIC_KEY,
    build_connect, build_data, classify_dial_reply, new_marker,
};
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;

use super::rxloop::rx_loop;
use super::wire::{header_u32, run_latency_probe};
use super::{
    BoxRead, BoxWrite, ChannelState, ConnCrypto, EdgeChannel, EdgeConn, LATENCY_CHECK_INTERVAL,
    LATENCY_CHECK_TIMEOUT, PendingAccept, server_crypto_setup,
};

impl EdgeChannel {
    /// Build from already-split stream halves and spawn the rx-loop + the latency probe. `open_channel`
    /// boxes the real TLS halves and passes the Hello/Result headers; tests pass empty. Uses the
    /// production probe cadence (30s/10s); the probe's sleep-before-first-probe keeps it dormant for the
    /// first interval, so fast unit tests never see a probe frame.
    #[must_use]
    pub(crate) fn from_halves(
        read: BoxRead,
        write: BoxWrite,
        result_headers: std::collections::BTreeMap<i32, Vec<u8>>,
    ) -> Self {
        Self::from_halves_with_probe(
            read,
            write,
            result_headers,
            LATENCY_CHECK_INTERVAL,
            LATENCY_CHECK_TIMEOUT,
        )
    }

    /// Like [`Self::from_halves`] but with an explicit probe interval/timeout. Production calls
    /// [`Self::from_halves`] (30s/10s); the hang-reproduction tests inject short values so the death
    /// detector fires within the test budget.
    #[must_use]
    pub(crate) fn from_halves_with_probe(
        read: BoxRead,
        write: BoxWrite,
        result_headers: std::collections::BTreeMap<i32, Vec<u8>>,
        probe_interval: Duration,
        probe_timeout: Duration,
    ) -> Self {
        let state = Arc::new(ChannelState::new(write));
        let rx_task = tokio::spawn(rx_loop(read, state.clone()));
        let probe_task = tokio::spawn(run_latency_probe(
            state.clone(),
            probe_interval,
            probe_timeout,
        ));
        Self {
            state,
            rx_task: Some(rx_task),
            probe_task: Some(probe_task),
            result_headers,
        }
    }

    /// Router id from the channel `Result` (header `Id`=8), if any. Slice-3 API.
    #[must_use]
    pub fn router_id(&self) -> Option<String> {
        self.result_headers
            .get(&crate::channel::message::HDR_ID)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    /// Router hello version from the channel `Result` (header `HelloVersion`=4). Slice-3 API.
    #[must_use]
    pub fn hello_version(&self) -> Option<String> {
        self.result_headers
            .get(&crate::channel::message::HDR_HELLO_VERSION)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    /// A `Weak` handle to this channel's shared state, for the live-channel registry (OIDC-2). The
    /// registry holds `Weak`s so a channel kept alive by a live `ServiceConn`/`ServiceBinding` upgrades
    /// during a token push and a dropped one prunes — the channel's `Drop` need not deregister.
    #[must_use]
    pub(crate) fn state_weak(&self) -> Weak<ChannelState> {
        Arc::downgrade(&self.state)
    }

    /// Whether this channel is still usable for new dials. The router connection pool uses this for
    /// LAZY eviction — the faithful mirror of the oracle's get-time `!IsClosed()` check
    /// (`ziti.go:1749`): a channel that has been torn down (router conn dropped, TLS broke, or the
    /// latency probe declared it dead) is never handed back out, it is re-dialed.
    ///
    /// The authoritative liveness signal is `state.closed`, the single teardown flag set by
    /// [`ChannelState::mark_closed`] on EVERY death path: the rx-loop's own EOF/error exit, `close`,
    /// `Drop`, AND the latency probe's death-close. `state.closed` is exactly the oracle's `IsClosed()`.
    /// We must consult it (not only the `rx_task` JoinHandle) because the latency probe's two death
    /// paths — read-idle timeout (a black-hole router) and a wedged probe send (`WriteError`) — call
    /// `mark_closed()` WITHOUT aborting `rx_task`: the rx-loop is left parked on `read_message` (a
    /// black-hole transport never EOFs), so its JoinHandle would report STILL-RUNNING even though the
    /// channel is dead. A `rx_task`-only check would then wrongly re-hand-out a probe-killed channel.
    /// (The probe-released HOL-stall case DOES finish `rx_task` — `close_notify` wakes the
    /// dispatch-parked loop so it returns — so the two predicates only diverge on the black-hole/write
    /// surface; `state.closed` covers both.) On the black-hole death path the parked `rx_task` (and the
    /// read half it owns) is reaped by `Drop` when the pool LAZILY evicts the entry and the last `Arc`
    /// drops — a linger bounded by the next pool get (or `EdgeClient` drop), not a leak; the probe task
    /// itself has already returned. The oracle reaps more promptly via an eager `OnClose` removal from
    /// `routerConnections` (ziti.go:683-691); porting that eager removal is a named follow-up (the
    /// scoring slice keeps only the get-time lazy eviction, ziti.go:1749).
    ///
    /// The `rx_task` arm is kept as belt-and-suspenders: a PANICKED rx-loop would not reach its final
    /// `mark_closed`, leaving `closed` false, but its JoinHandle reports finished. The AND can only fire
    /// the `rx_task` arm when the loop is genuinely gone, so it never false-negatives a live channel.
    /// A `None` task (already taken in a partial move) counts as dead. `is_finished()` is the
    /// JoinHandle's terminal-state probe (stable since Rust 1.62).
    #[must_use]
    pub(crate) fn is_alive(&self) -> bool {
        !self.state.is_closed() && self.rx_task.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Seed the latency accumulator with this channel's handshake RTT (`connectTime`). Called by
    /// `open_channel_to` after the channel is built, BEFORE it is pooled, so a pooled channel always
    /// has at least one sample (the connectTime seed) when `pool_get_alive` scores it. Mirrors the
    /// oracle's `h.Update(int64(connectTime))` at `Upsert` (`ziti.go:1888`). Thin delegate to
    /// [`ChannelState::record_latency`].
    pub(crate) fn seed_latency(&self, connect_nanos: u64) {
        self.state.record_latency(connect_nanos);
    }

    /// Mean recorded latency (nanoseconds) — the router-pool scoring key. Thin delegate to
    /// [`ChannelState::mean_latency_nanos`]. `u64::MAX` for an unsampled channel.
    #[must_use]
    pub(crate) fn mean_latency_nanos(&self) -> u64 {
        self.state.mean_latency_nanos()
    }

    /// Number of latency samples recorded (test/diagnostic). Thin delegate to
    /// [`ChannelState::latency_sample_count`].
    #[must_use]
    pub(crate) fn latency_sample_count(&self) -> u64 {
        self.state.latency_sample_count()
    }

    /// Push a rotated api-session token to this channel's router (`UpdateToken`, ct 60803), awaiting
    /// the `UpdateTokenSuccess`/`UpdateTokenFailure` reply within `timeout`. Thin delegate to
    /// [`ChannelState::update_token`]. Test-only: production pushes via the live-channel registry, which
    /// upgrades a `Weak<ChannelState>` and calls [`ChannelState::update_token`] directly; this delegate
    /// exists so the duplex unit tests + the OIDC-2 live test can drive a push against a whole channel.
    ///
    /// # Errors
    /// See [`ChannelState::update_token`].
    #[cfg(test)]
    pub(crate) async fn update_token(
        &self,
        new_token: &str,
        timeout: Duration,
    ) -> Result<(), EdgeError> {
        self.state.update_token(new_token, timeout).await
    }

    /// Dial a service: allocate conn-id+seq, register the conn's queue and a reply
    /// waiter BEFORE sending (avoids the StateConnected-before-registration race), send
    /// the Connect, await the reply, return a live `EdgeConn`.
    ///
    /// `caller_id`, when `Some(non-empty)`, is sent as the Connect's `CallerId` (1008)
    /// so the host sees who dialed. `app_data`, when `Some`, is sent as the Connect's `AppData`
    /// (1011) — opaque bytes the host reads to drive a dynamic dial target (tunneler forwarding).
    ///
    /// # Errors
    /// - `EdgeError::DialRejected` if the router replies `StateClosed`.
    /// - `EdgeError::ChannelClosed` if the channel closes before a reply.
    /// - `EdgeError::Channel` on a frame/IO error or an unexpected content type.
    /// - `EdgeError::Crypto` / `EdgeError::UnsupportedCrypto` on handshake failure.
    pub async fn dial(
        &self,
        detail: &SessionDetail,
        encryption_required: bool,
        caller_id: Option<&str>,
        app_data: Option<&[u8]>,
    ) -> Result<EdgeConn, EdgeError> {
        let conn_id = self.state.next_conn_id();
        let seq = self.state.next_seq();
        // Fast-fail on an already-closed channel (mirrors `register_conn`'s C5 guard): a pooled channel
        // can die between `pool_get_alive` handing it out and this dial. `register_conn` already no-ops
        // under `closed`, but the reply-waiter insert below is NOT guarded — inserted after
        // `mark_closed`'s one-shot map-clear, nothing would ever clear it, so `reply_rx` would park the
        // full connect-timeout instead of failing fast. (A close racing AFTER this check is the bounded
        // TOCTOU the connect-timeout backstops.)
        if self.state.is_closed() {
            return Err(EdgeError::ChannelClosed);
        }
        let (data_tx, data_rx) = mpsc::channel(4);
        self.state.register_conn(conn_id, data_tx);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.state.waiters.lock().unwrap().insert(seq, reply_tx);

        // When the service requires encryption, generate a keypair and advertise our public key.
        let keypair = encryption_required.then(crate::edge::crypto::KeyPair::generate);
        let pubkey = keypair
            .as_ref()
            .map(crate::edge::crypto::KeyPair::public_key);

        let mut connect = build_connect(
            conn_id,
            &detail.token,
            &new_marker(),
            pubkey.as_ref(),
            caller_id,
            app_data,
        );
        connect.sequence = seq;
        let send = {
            let mut w = self.state.write.lock().await;
            write_message(&mut *w, &connect).await
        };
        if let Err(e) = send {
            // A transport write error means the channel itself is broken (a LOGICAL dial reject arrives
            // as a StateClosed/DialFailed reply, never as a write error). Mirror the oracle txer's
            // defer-`channel.Close()`: tear the channel down via `mark_closed` so the pool evicts it on
            // the next get (`is_alive`→false) instead of re-handing-out a write-broken channel for ~one
            // probe interval. `mark_closed` clears all conn/waiter maps (this conn + seq included) and
            // EOFs every sibling — faithful, since siblings on a write-broken transport cannot progress.
            self.state.mark_closed();
            return Err(e.into());
        }

        let Ok(reply) = reply_rx.await else {
            self.state.conns.lock().unwrap().remove(&conn_id);
            return Err(EdgeError::ChannelClosed);
        };
        match classify_dial_reply(reply) {
            Ok(state_connected) => {
                let circuit_id = state_connected
                    .headers
                    .get(&HDR_CIRCUIT_ID)
                    .map(|v| String::from_utf8_lossy(v).into_owned());
                let crypto = match self
                    .establish_client_crypto(conn_id, keypair.as_ref(), &state_connected)
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        self.state.conns.lock().unwrap().remove(&conn_id);
                        return Err(e);
                    }
                };
                Ok(EdgeConn::new(
                    conn_id,
                    circuit_id,
                    None,
                    data_rx,
                    self.state.clone(),
                    crypto,
                ))
            }
            Err(e) => {
                self.state.conns.lock().unwrap().remove(&conn_id);
                Err(e)
            }
        }
    }

    /// After StateConnected, set up the client crypto if requested: read the host's public key
    /// from the reply, do the key exchange, build the encryptor, and write our 24-byte stream
    /// header as the first Data frame. Returns `None` (plaintext) if `keypair` is `None` or the
    /// host did not provide a public key (mirrors `ziti/edge/network/conn.go:621-623`). Oracle: establishClientCrypto.
    async fn establish_client_crypto(
        &self,
        conn_id: u32,
        keypair: Option<&crate::edge::crypto::KeyPair>,
        reply: &Message,
    ) -> Result<Option<ConnCrypto>, EdgeError> {
        let Some(keypair) = keypair else {
            return Ok(None); // plaintext dial
        };
        let Some(host_pk_raw) = reply.headers.get(&HDR_PUBLIC_KEY) else {
            // Silent downgrade: we advertised a key but the host did not negotiate crypto. Fall
            // back to plaintext (oracle conn.go:622 logger.Warn).
            tracing::warn!(conn_id, "connection is not end-to-end-encrypted");
            return Ok(None);
        };
        let method = reply
            .headers
            .get(&HDR_CRYPTO_METHOD)
            .and_then(|v| v.first().copied())
            .unwrap_or(CRYPTO_METHOD_LIBSODIUM);
        if method != CRYPTO_METHOD_LIBSODIUM {
            return Err(EdgeError::UnsupportedCrypto);
        }
        let host_pk: [u8; 32] = host_pk_raw.as_slice().try_into().map_err(|_| {
            EdgeError::Crypto(format!(
                "host public key must be 32 bytes, got {}",
                host_pk_raw.len()
            ))
        })?;
        let (rx, tx) = keypair
            .client_session_keys(&host_pk)
            .map_err(|e| EdgeError::Crypto(e.to_string()))?;
        let (sender, tx_header) = crate::edge::crypto::Encryptor::new(&tx);

        // Send our stream header as the FIRST Data frame (first=true => MULTIPART flag).
        let mut hdr_msg = build_data(conn_id, &tx_header, true);
        hdr_msg.sequence = self.state.next_seq();
        {
            let mut w = self.state.write.lock().await;
            write_message(&mut *w, &hdr_msg).await?;
        }
        // Oracle conn.go:620 `logger.Debug("client tx encryption setup done")` (byte-exact,
        // DEBUG). The success counterpart to the downgrade warn above; emitted only once the
        // encryptor is built AND the stream header is on the wire. Purely additive.
        tracing::debug!(conn_id, "client tx encryption setup done");
        Ok(Some(ConnCrypto {
            sender,
            decryptor: None,
            rx_key: Some(rx),
        }))
    }

    /// Close the channel: shut down the write half, abort the rx-loop and the latency probe, and mark
    /// the channel closed (`mark_closed` clears the waiter/conn/bind maps — dropping the senders wakes
    /// any parked `dial`/`read` — AND fires `close_notify`, releasing a dispatch-stalled rx-loop). We
    /// abort rather than await the tasks — the router may not EOF promptly after our close, and
    /// `#[tokio::test]` has no timeout, so an unconditional await could hang.
    ///
    /// # Errors
    /// Infallible today; returns `Result` for forward compatibility.
    pub async fn close(mut self) -> Result<(), EdgeError> {
        {
            let mut w = self.state.write.lock().await;
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut *w).await;
        }
        if let Some(t) = self.rx_task.take() {
            t.abort();
        }
        if let Some(t) = self.probe_task.take() {
            t.abort();
        }
        self.state.mark_closed();
        Ok(())
    }

    /// Send a Bind and await the sequence-correlated reply (reuses the dial reply-waiter).
    /// Registers the bind's accept queue BEFORE sending (a Dial may arrive immediately after
    /// the StateConnected reply; unregistered => dropped) and returns its receiver alongside
    /// the allocated bind conn-id. Accepts an optional `pubkey` (7b-2: advertise host key for
    /// encrypted services). Oracle:
    /// `edgeHostConn.listen` (hosting_conn.go:455).
    ///
    /// # Errors
    /// - `EdgeError::BindRejected` if the router replies `StateClosed`.
    /// - `EdgeError::ChannelClosed` if the channel closes before a reply.
    /// - `EdgeError::Channel` on a frame/IO error or an unexpected content type.
    pub(crate) async fn send_bind(
        &self,
        token: &str,
        listener_id: &str,
        pubkey: Option<&[u8; 32]>,
    ) -> Result<(u32, mpsc::Receiver<Message>), EdgeError> {
        let conn_id = self.state.next_conn_id();
        let seq = self.state.next_seq();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.state.waiters.lock().unwrap().insert(seq, reply_tx);

        // Register the accept queue before sending (race-free, like dial registers its conn).
        let (bind_tx, bind_rx) = mpsc::channel(4);
        self.state.register_bind(conn_id, bind_tx);

        let mut bind = build_bind(conn_id, token, listener_id, pubkey);
        bind.sequence = seq;
        let send = {
            let mut w = self.state.write.lock().await;
            write_message(&mut *w, &bind).await
        };
        if let Err(e) = send {
            self.state.waiters.lock().unwrap().remove(&seq);
            self.state.binds.lock().unwrap().remove(&conn_id);
            return Err(e.into());
        }

        let Ok(reply) = reply_rx.await else {
            self.state.binds.lock().unwrap().remove(&conn_id);
            return Err(EdgeError::ChannelClosed);
        };
        match classify_bind_reply(reply) {
            Ok(()) => Ok((conn_id, bind_rx)),
            Err(e) => {
                self.state.binds.lock().unwrap().remove(&conn_id);
                Err(e)
            }
        }
    }

    /// Send an Unbind frame (best-effort teardown notification; the oracle sends it
    /// fire-and-forget). Oracle: `NewUnbindMsg` (messages.go:363) + `edgeHostConn.unbind`.
    ///
    /// # Errors
    /// `EdgeError::Channel` if the write fails.
    pub(crate) async fn send_unbind(&self, conn_id: u32, token: &str) -> Result<(), EdgeError> {
        let mut msg = build_unbind(conn_id, token);
        msg.sequence = self.state.next_seq();
        let mut w = self.state.write.lock().await;
        write_message(&mut *w, &msg).await.map_err(EdgeError::from)
    }

    /// Accept the next inbound dial on a bind queue, returning a [`PendingAccept`] that is validated +
    /// registered + crypto-computed but NOT yet acknowledged (NO DialSuccess on the wire). The caller
    /// dials its target and then calls [`PendingAccept::complete_success`] (reachable) or
    /// [`PendingAccept::complete_failed`] (unreachable) — the faithful accept-then-dial order (oracle
    /// `ManualStart=true`, hosting.go:421: DialSuccess only on `CompleteAcceptSuccess`, after the
    /// target dial). Loops past dials we reject (bad token / crypto failure) — each rejected dial gets
    /// a `DialFailed` reply and the listener keeps accepting (one bad dial does not kill the
    /// listener). A `Dial` whose `RouterProvidedConnId` is absent or not 4 bytes long is NOT a
    /// rejection: the child id is GENERATED with the oracle's clamped allocator
    /// ([`ChannelState::next_conn_id`]), exactly like `hosting_conn.go:290-296`. The child is
    /// registered in the mux here (the dialer sends
    /// no Data until it sees the DialSuccess that `complete_success` writes). Oracle:
    /// `newChildConnection` (`ziti/edge/network/hosting_conn.go:268`).
    ///
    /// # Errors
    /// - `EdgeError::ListenerClosed` if the router closes the bind (`StateClosed`) or the
    ///   channel dies (the bind queue is dropped).
    // O5 (observability): a span scopes the accept so the O1/O2 host logs (invalid-token warn,
    // crypto-fail error, downgrade warn) inherit `bind_conn_id`. SECURITY: `token` (the session JWT)
    // and `keypair` (private key material) MUST be skipped — never record a secret as a span field.
    // `bind_rx` (no Debug) skipped too; only `bind_conn_id` is recorded.
    #[tracing::instrument(skip(self, token, keypair, bind_rx), level = "debug")]
    pub(crate) async fn accept_pending(
        &self,
        bind_conn_id: u32,
        token: &str,
        keypair: Option<&crate::edge::crypto::KeyPair>,
        bind_rx: &mut mpsc::Receiver<Message>,
    ) -> Result<PendingAccept, EdgeError> {
        loop {
            let Some(msg) = bind_rx.recv().await else {
                return Err(EdgeError::ListenerClosed);
            };
            if msg.content_type == CT_STATE_CLOSED {
                return Err(EdgeError::ListenerClosed);
            }
            if msg.content_type != CT_DIAL {
                continue; // ignore anything else routed to the bind queue
            }
            let dial_seq = msg.sequence;
            if msg.body != token.as_bytes() {
                // Oracle hosting_conn.go:279 `logger.Warn("invalid token")` (logger carries the
                // bind connId). Purely additive — precedes the unchanged DialFailed reject.
                tracing::warn!(bind_conn_id, "invalid token");
                self.state
                    .send_dial_failed(bind_conn_id, dial_seq, "invalid token")
                    .await;
                continue;
            }
            // The child's conn-id: the router's when the Dial carries a READABLE `RouterProvidedConnId`
            // (header 1012, exactly 4 bytes — `GetUint32Header` treats absent and len!=4 alike), OURS
            // otherwise. Oracle `newChildConnection` (hosting_conn.go:288-296), whose three `Debugf`
            // are ported with their STATIC literal byte-exact and the value as a FIELD.
            tracing::debug!(
                bind_conn_id,
                "listener found. checking for router provided connection id"
            );
            let (child_id, router_provided) =
                if let Some(id) = header_u32(&msg, HDR_ROUTER_PROVIDED_CONN_ID) {
                    tracing::debug!(
                        bind_conn_id,
                        child_id = id,
                        "using router provided connection id"
                    );
                    (id, true)
                } else {
                    let id = self.state.next_conn_id();
                    tracing::debug!(
                        bind_conn_id,
                        child_id = id,
                        "listener found. generating id for new connection"
                    );
                    (id, false)
                };
            let circuit_id = msg
                .headers
                .get(&HDR_CIRCUIT_ID)
                .map(|v| String::from_utf8_lossy(v).into_owned());
            let source_identity = msg
                .headers
                .get(&crate::edge::dial::HDR_CALLER_ID)
                .map(|v| String::from_utf8_lossy(v).into_owned());
            // T4b-1: the inbound dial's AppData (header 1011), opaque bytes the forwarding host reads to
            // resolve a dynamic dial target. The router relays it verbatim from the dialer's Connect.
            // Oracle: the child's `appData` field is copied from `Headers[AppDataHeader]`
            // (`hosting_conn.go:309`), read via `GetAppData()` (`conn.go:887`).
            let app_data = msg.headers.get(&crate::edge::dial::HDR_APPDATA).cloned();

            // Register the child's inbound queue BEFORE replying (data-before-registration race).
            let (data_tx, data_rx) = mpsc::channel(4);
            self.state.register_conn(child_id, data_tx);

            // Server crypto is computed here (no wire IO — the stream-header is sent later, in
            // `complete_success`, after the caller's target dial succeeds). A kx/method failure is a
            // PRE-target reject: DialFailed + keep accepting (oracle cleanupAndReportError,
            // hosting_conn.go:358-373). The `match` captures the EdgeError so the ERROR log carries the
            // diagnostic the fixed-reason wire DialFailed discards.
            let crypto_setup = match server_crypto_setup(child_id, keypair, &msg) {
                Ok(setup) => setup,
                Err(e) => {
                    // Oracle hosting_conn.go:367 cleanupAndReportError("failed to establish crypto
                    // session", err) -> logger.WithError(err).Error(desc). The wire reason stays fixed.
                    tracing::error!(bind_conn_id, child_id, error = %e, "failed to establish crypto session");
                    self.state.conns.lock().unwrap().remove(&child_id);
                    self.state
                        .send_dial_failed(
                            bind_conn_id,
                            dial_seq,
                            "failed to establish crypto session",
                        )
                        .await;
                    continue;
                }
            };

            return Ok(PendingAccept {
                state: self.state.clone(),
                bind_conn_id,
                child_id,
                router_provided,
                dial_seq,
                data_rx,
                circuit_id,
                source_identity,
                app_data,
                crypto_setup,
            });
        }
    }

    /// Accept the next inbound dial AND immediately acknowledge it (DialSuccess + crypto header),
    /// returning a live `EdgeConn`. The eager-ack convenience for non-forwarding hosts (in-process
    /// echo, bind-serve) whose target is implicit — exactly `accept_pending` then `complete_success`.
    /// Forwarding hosts (`tunnel::host`) instead use `accept_pending` + dial-target +
    /// `complete_success`/`complete_failed` (the faithful accept-then-dial split), so an unreachable
    /// target yields a DialFailed rather than an eager success-then-close.
    ///
    /// # Errors
    /// - `EdgeError::ListenerClosed` if the listener is closed (router `StateClosed` / channel death).
    /// - `EdgeError::Channel` if writing the `DialSuccess` or the stream header fails.
    /// - `EdgeError::AcceptStartFailed` if the child's conn-id was GENERATED by us and the router's
    ///   `StateConnected` does not arrive within [`PendingAccept::complete_success`]'s 5s budget, or
    ///   arrives with an unexpected content type.
    pub(crate) async fn accept_next(
        &self,
        bind_conn_id: u32,
        token: &str,
        keypair: Option<&crate::edge::crypto::KeyPair>,
        bind_rx: &mut mpsc::Receiver<Message>,
    ) -> Result<EdgeConn, EdgeError> {
        self.accept_pending(bind_conn_id, token, keypair, bind_rx)
            .await?
            .complete_success()
            .await
    }
}

impl Drop for EdgeChannel {
    fn drop(&mut self) {
        if let Some(t) = self.rx_task.take() {
            t.abort();
        }
        if let Some(t) = self.probe_task.take() {
            t.abort();
        }
        // Abort cancels the rx-loop and probe before their own cleanup can run, so mark the channel
        // closed here: `mark_closed` clears the maps (dropping the senders wakes every parked
        // read()/accept/dial — a binding dropped without close() would otherwise hang its accepted
        // children forever) and fires `close_notify`.
        self.state.mark_closed();
    }
}
