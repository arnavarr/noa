//! Host mode FORWARDING (T4b-1): the accept loop whose dial target is resolved DYNAMICALLY
//! per inbound dial from its `AppData` against the service's `host.v1` config.
//!
//! (F6 tramo 9: movido verbatim del monolito de `tunnel/host`.)

use std::time::Duration;

use crate::edge::bind::ServiceBinding;
use crate::edge::data::PendingAccept;
use crate::edge::error::EdgeError;
use crate::edge::model::HostV1Config;
use crate::tunnel::resolve::{
    AddressTranslationPrefix, build_address_translations, check_deferred_config, get_dial_timeout,
    resolve_target, translate_address,
};

use super::HOST_DIAL_TIMEOUT;
use super::dial::handle_host_conn;

/// Run a FORWARDING host-TCP listener (T4b-1): for each inbound dial, resolve a DYNAMIC dial target
/// from the dial's `AppData` (header 1011, `dst_*`) against the service's `host.v1` config (`cfg`)
/// rather than a fixed target, then dial it and splice (exactly like [`run_tcp_host`](super::run_tcp_host) from there).
///
/// `cfg` is the service's parsed `host.v1` (from [`crate::edge::model::Service::host_v1_config`]). Three
/// things are resolved ONCE at startup, mirroring the oracle's once-per-`newHostingContext` setup
/// (`hosting.go`): the last deferred config-level capability (`allowedSourceAddresses`, T4b-2d-2) is
/// CHECKED ([`crate::tunnel::resolve::check_deferred_config`]); the per-service dial timeout (T4b-2c
/// `connectTimeout`/`connectTimeoutSeconds`) is RESOLVED ([`crate::tunnel::resolve::get_dial_timeout`],
/// `hosting.go:144`); and the address translations (T4b-2d-1 `forwardAddressTranslations`) are BUILT
/// ([`crate::tunnel::resolve::build_address_translations`], `hosting.go:70-101`). A deferred capability, a
/// non-positive/unparseable timeout, or an unparseable translation `from`/`to` is a clean startup error
/// here (no per-dial loop to skip, so the [`crate::edge::model::Service::host_v1_config`] log-and-skip is
/// the caller's responsibility per the T5 poller pattern; the single `noa host-forward` subcommand
/// surfaces it).
///
/// Per inbound dial: resolve the target ([`crate::tunnel::resolve::resolve_target`]); on a resolution
/// reject (disallowed/malformed appData, or a deferred per-dial case) send `complete_failed(reason)` (the
/// byte-exact oracle reason where dialer-observable) and KEEP ACCEPTING (oracle's `continue`,
/// `provider.go:145,156`). A resolved non-`tcp` protocol is also rejected loudly (this host dials TCP;
/// a udp service must use the UDP path). On a reachable target, apply `forwardAddressTranslations`
/// ([`crate::tunnel::resolve::translate_address`]) and splice as in T2.
///
/// # Errors
/// - [`EdgeError::HostForwardConfig`] at startup if `cfg` requires a deferred capability, sets a bad
///   timeout, or carries an unparseable `forwardAddressTranslations` `from`/`to`.
/// - The [`EdgeError`] from `accept_pending` (typically [`EdgeError::ListenerClosed`]) when the
///   listener is torn down; the loop otherwise never returns.
pub async fn run_tcp_host_forwarding(
    mut binding: ServiceBinding,
    cfg: HostV1Config,
) -> Result<(), EdgeError> {
    // Startup guard: config-level deferred capabilities fail loud here, not silently ignored.
    check_deferred_config(&cfg).map_err(EdgeError::HostForwardConfig)?;
    // Resolve the per-service dial timeout ONCE at startup (oracle: `dialTimeout` is computed once in
    // `newHostingContext`, hosting.go:144). An invalid/non-positive `connectTimeout` fails loud here.
    let dial_timeout =
        get_dial_timeout(&cfg, HOST_DIAL_TIMEOUT).map_err(EdgeError::HostForwardConfig)?;
    // Build the address translations ONCE at startup (T4b-2d-1; oracle: `addrTranslations` is built once
    // in `newHostingContext`, hosting.go:70-101). A bad `from`/`to` fails loud here (the oracle's
    // `return nil` = the service is not hosted).
    let translations = build_address_translations(&cfg).map_err(EdgeError::HostForwardConfig)?;
    let cfg = std::rc::Rc::new(cfg);
    let translations = std::rc::Rc::new(translations);
    loop {
        let pending = binding.accept_pending().await?;
        let cfg = cfg.clone();
        let translations = translations.clone();
        tokio::task::spawn_local(async move {
            handle_host_forward_conn(pending, &cfg, &translations, dial_timeout).await;
        });
    }
}

/// Resolve the inbound dial's appData target against `cfg`, then dial it as a local TCP socket and
/// splice (T4b-1). On a resolution reject (or a resolved non-`tcp` protocol) send `complete_failed` so
/// the dialer's `connect()` fails with the reason; on a reachable target acknowledge + splice exactly
/// like [`handle_host_conn`]. A per-dial reject does NOT abort the accept loop (the caller keeps
/// accepting), mirroring the oracle's `continue` (`provider.go:145,156`). `dial_timeout` is the
/// per-service timeout resolved once at startup (T4b-2c). A per-dial `source_addr` (T4b-2d-2), already
/// parsed by [`crate::tunnel::resolve::resolve_target`] into `target.source_bind` (a malformed value
/// rejected loudly here as a DialFailed reason), binds the dial's local end via [`handle_host_conn`].
pub(super) async fn handle_host_forward_conn(
    pending: PendingAccept,
    cfg: &HostV1Config,
    translations: &[AddressTranslationPrefix],
    dial_timeout: Duration,
) {
    let target = match resolve_target(cfg, pending.app_data()) {
        Ok(t) => t,
        Err(reason) => {
            tracing::warn!(
                reason,
                "host: appData did not resolve a target; sending DialFailed"
            );
            pending.complete_failed(&reason).await;
            return;
        }
    };
    // This forwarding host dials TCP. A resolved non-tcp protocol is rejected loudly — never silently
    // TCP-dialing a udp target (the UDP forwarding path is a separate slice). Since T4b-2b, the resolved
    // protocol may come from the appData `dst_protocol` (a `forwardProtocol` service that allows udp), so
    // this guard is now ALSO the enforcement point for a faithfully-resolved udp protocol — a CONSCIOUS,
    // dialer-observable deviation (the oracle's `dialAddress` would udp-dial it; `hosting.go:206`).
    if target.protocol != "tcp" {
        let reason = format!(
            "host appData forwarding: protocol '{}' requires the UDP host path; this forwarding host dials TCP only",
            target.protocol
        );
        tracing::warn!(
            reason,
            "host: non-tcp resolved protocol; sending DialFailed"
        );
        pending.complete_failed(&reason).await;
        return;
    }
    // Apply forwardAddressTranslations (T4b-2d-1): renumber the RESOLVED (allow-list-checked) address
    // onto the configured `to` network before dialing — the oracle's `Dial` dials
    // `translateAddress(GetAddress(...))` (hosting.go:402-415). The translated target is dialed directly
    // (NOT re-validated against `allowedAddresses`). With no translations configured this is a no-op
    // (returns the address unchanged). A real `dst_hostname` (non-IP) is never translated.
    let dial_address = translate_address(&target.address, translations);
    let socket_addr = format!("{dial_address}:{}", target.port);
    // From here the dynamic target behaves exactly like T2's fixed target (with the resolved timeout),
    // plus the per-dial `source_addr` bind (T4b-2d-2): the resolver parsed it into `target.source_bind`
    // (a malformed value already rejected loudly above), and the host binds the dial's local end to it.
    handle_host_conn(pending, socket_addr, target.source_bind, dial_timeout).await;
}
