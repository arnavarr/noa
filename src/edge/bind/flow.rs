//! The client-side bind flow: `EdgeClient::bind` / `bind_with_timeout` / `bind_inner` — resolve the
//! service, create a Bind session, open the channel and send the Bind (confirmed by
//! `StateConnected`), all bounded by one outer `tokio::time::timeout`. Oracle: sdk-golang
//! `ziti/ziti.go` (`ListenWithOptions`/`listenSession`, establishment bounded by
//! `WaitForN(options.ConnectTimeout)` at `:2253`).

use super::{DEFAULT_BIND_TIMEOUT, ServiceBinding, new_listener_id};
use crate::edge::client::EdgeClient;
use crate::edge::data::EdgeChannel;
use crate::edge::error::EdgeError;
use crate::edge::model::{SessionDetail, SessionType};
use std::time::Duration;

impl EdgeClient {
    /// Register this identity as a host of `service_name` with the default [`DEFAULT_BIND_TIMEOUT`]
    /// (60s, the oracle's `ListenOptions.ConnectTimeout` default). See
    /// [`EdgeClient::bind_with_timeout`] for the full flow and timeout semantics. Requires a prior
    /// `authenticate()`. Oracle: `ziti.go` `ListenWithOptions`/`listenSession` + `hosting_conn.go`
    /// `listen`.
    ///
    /// Behaviour change since the bind-timeout slice: a previously unbounded `bind()` now fails with
    /// [`EdgeError::BindTimedOut`] after 60s instead of hanging forever on a black-holed router —
    /// faithful to the oracle (which bounds listener establishment by `ConnectTimeout`, the bind-side
    /// sibling of slice 10b's connect-timeout).
    ///
    /// # Errors
    /// Same as [`EdgeClient::bind_with_timeout`].
    pub async fn bind(&self, service_name: &str) -> Result<ServiceBinding, EdgeError> {
        self.bind_with_timeout(service_name, DEFAULT_BIND_TIMEOUT)
            .await
    }

    /// Register this identity as a host of `service_name` with an explicit bind-timeout budget,
    /// end-to-end: resolve the service, create a Bind session, open the channel, and send the Bind
    /// (confirmed by a `StateConnected` reply) — advertising the host's crypto pubkey when the
    /// service is `encryptionRequired`. 7a-onward is host registration; `accept()` serves inbound
    /// dials. Requires a prior `authenticate()`.
    ///
    /// The whole flow is bounded by `timeout` (the oracle bounds listener establishment by
    /// `ListenOptions.ConnectTimeout`, `ziti.go:2253`): on expiry the in-flight future is dropped —
    /// cancel-safe, as the drop tears down any partial channel via `EdgeChannel`'s `Drop` (which
    /// aborts its rx-loop) — and `bind` returns [`EdgeError::BindTimedOut`]. Mirrors how Go exposes
    /// `ListenOptions.ConnectTimeout`. Unlike `connect`, the Bind session is NOT cached (the oracle
    /// keeps Bind sessions per-listener), so there is no session-creation backoff to thread (the
    /// bind-side backoff is deferred per `CLAUDE.md`); this is a single outer `tokio::time::timeout`.
    ///
    /// # Errors
    /// - `EdgeError::BindTimedOut` if the flow does not complete within `timeout`.
    /// - `EdgeError::NotAuthenticated` if `authenticate()` has not been called.
    /// - `EdgeError::ServiceNotFound` if no service matches `service_name`.
    /// - `EdgeError::ServicesHttp`/`SessionHttp` for REST failures (a service this identity
    ///   cannot Bind is rejected by the controller at session creation).
    /// - `EdgeError::NoTlsEdgeRouter`/`ChannelTls`/`Channel`/`BindRejected`/`ChannelClosed`.
    pub async fn bind_with_timeout(
        &self,
        service_name: &str,
        timeout: Duration,
    ) -> Result<ServiceBinding, EdgeError> {
        // `bind` keeps the first-router `open_channel` (its path is `listenerManager`, not the
        // connect race of slice 10c), and is NOT pooled (conscious deviation: the oracle shares the
        // pool across dial+bind). `bind_inner` is unchanged — it just gets the opener injected here,
        // exactly as `connect_with_timeout` injects `open_or_reuse_pooled_channel` (the pool slice).
        let binding = self
            .bind_inner(service_name, timeout, async |detail| {
                self.open_channel(detail).await
            })
            .await?;
        // OIDC-2: register the bind's channel so an OIDC refresh can push the rotated Bearer to it —
        // the long-lived idle binding that would otherwise orphan its router token is exactly the case
        // OIDC-2 protects. `bind` uses first-router `open_channel` (no race), so the kept channel is the
        // only one opened; registering after success is winner-only by construction.
        self.register_live_channel(binding.channel_weak());
        Ok(binding)
    }

    /// `bind` with the channel-creation step injected, so tests can drive the full
    /// resolve → create → open → send-Bind → StateConnected flow over a fake router (a duplex-backed
    /// channel) without a live edge router — and the timeout-trigger test can inject a router that
    /// never replies. Production passes `self.open_channel` (first-router).
    ///
    /// `timeout` bounds the WHOLE flow via an outer `tokio::time::timeout`, mirroring the oracle's
    /// `WaitForN(options.ConnectTimeout)` bound on listener establishment (`ziti.go:2253`). On expiry
    /// the in-flight future is dropped — cancel-safe (any partial `EdgeChannel` is torn down by its
    /// `Drop`, which aborts the rx-loop; no `std::sync::Mutex` guard ever crosses an await — the
    /// api-session token lock is synchronous, and the `updb` session-cert re-mint lock is a
    /// `tokio::sync::Mutex`, which a dropped future releases cleanly — so a mid-flight drop cannot
    /// poison anything).
    ///
    /// `pub(super)` (= `pub(in crate::edge::bind)`) is the same visibility bump the 5 `ServiceBinding`
    /// fields need (spec §5.1a), for the same reason: in the monolith this method was private to
    /// `edge::bind` and therefore visible to its descendant `mod tests`; after the F6 tramo 10 split
    /// `tests_flow.rs` is a SIBLING of `flow.rs`, so a bare-private `bind_inner` would be unreachable
    /// from it. Syntax, not scope: `edge::bind` + descendants before and after — `edge::data`,
    /// `tunnel::host` and the rest of the crate still cannot call it.
    pub(super) async fn bind_inner(
        &self,
        service_name: &str,
        timeout: Duration,
        open_channel: impl AsyncFn(&SessionDetail) -> Result<EdgeChannel, EdgeError>,
    ) -> Result<ServiceBinding, EdgeError> {
        let flow = async {
            let _ = self.token().ok_or(EdgeError::NotAuthenticated)?;
            let services = self.list_services().await?;
            // Reuse slice 6's exact/case-sensitive resolver; read the encryption flag + id before the
            // create_session await (no borrow of `services` crosses it).
            let service = crate::edge::conn::resolve_service(&services, service_name)?;
            let service_id = service.id.clone();
            let encryption_required = service.encryption_required;
            let detail = self.create_session(&service_id, SessionType::Bind).await?;
            let channel = open_channel(&detail).await?;
            // For an encryptionRequired service, generate the host keypair and advertise its public
            // key in the Bind; the per-child server crypto (accept) derives session keys against it.
            let keypair = encryption_required.then(crate::edge::crypto::KeyPair::generate);
            let pubkey = keypair
                .as_ref()
                .map(crate::edge::crypto::KeyPair::public_key);
            let (conn_id, bind_rx) = channel
                .send_bind(&detail.token, &new_listener_id(), pubkey.as_ref())
                .await?;
            Ok::<_, EdgeError>(ServiceBinding {
                conn_id,
                token: detail.token,
                channel,
                bind_rx,
                keypair,
            })
        };
        match tokio::time::timeout(timeout, flow).await {
            Ok(result) => result,
            Err(_elapsed) => Err(EdgeError::BindTimedOut {
                service: service_name.to_string(),
                timeout,
            }),
        }
    }
}
