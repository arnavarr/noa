use crate::edge::model::HostV1Config;

// ----- Deferred-capability reject reasons (T4b-2). Distinct, clear, NOT byte-matched to an oracle
// validation error (the oracle WOULD have handled these — they are our deferred capability, named so a
// dialer/operator sees a real reason instead of a silent wrong-dial). -----

/// A `host.v1` `allowedSourceAddresses` config (host-side source-address routes) is a deferred T4b-2d-3
/// capability: it `router.AddLocalAddress`es the configured source IPs onto `lo` (an OS-level netlink/root
/// operation) so a NON-local per-dial `source_addr` becomes bindable. The per-dial `source_addr` bind
/// itself is supported as of T4b-2d-2 ([`parse_source_bind`](crate::tunnel::resolve::target::parse_source_bind)); only this route-provisioning step is
/// deferred. Oracle: `GetAllowedSourceAddressRoutes` (`service.go:333-344`) + `OnClose`
/// (`hosting.go:272-281`, `router.RemoveLocalAddress`/`AddLocalAddress`).
pub const DEFERRED_SOURCE_ADDR_CONFIG: &str =
    "host appData forwarding: a host.v1 allowedSourceAddresses is not yet supported (T4b-2d-3)";
/// Guard the deferred `host.v1` capabilities that are config-level (not driven by appData). Called by the
/// host BEFORE the per-dial resolve so a misconfigured service fails loudly at the source rather than
/// silently ignoring the option. Returns the byte-distinct deferred reason; `Ok(())` when the config uses
/// no deferred capability.
///
/// As of T4b-2d-1 `forwardAddressTranslations` is NO LONGER deferred — it is built (and parse-validated)
/// at startup by [`build_address_translations`](crate::tunnel::resolve::build_address_translations) and applied per-dial by [`translate_address`](crate::tunnel::resolve::translate_address). As of
/// T4b-2d-2 the per-dial `source_addr` SOCKET BIND is supported ([`parse_source_bind`](crate::tunnel::resolve::target::parse_source_bind) +
/// [`crate::tunnel::host`]); the ONLY remaining config-level deferral is `allowedSourceAddresses` (the
/// host-side source-address ROUTE setup that `router.AddLocalAddress`es non-local source IPs onto `lo`, an
/// OS-level netlink/root operation; T4b-2d-3). As of T4b-2c, `connectTimeout`/`connectTimeoutSeconds` is
/// likewise resolved by [`get_dial_timeout`](crate::tunnel::resolve::get_dial_timeout) at startup, not here. Oracle:
/// `GetAllowedSourceAddressRoutes`/`OnClose` (`service.go:333-344`, `hosting.go:272-281`).
///
/// # Errors
/// Returns a deferred-capability reason when the config requires a not-yet-supported feature.
pub fn check_deferred_config(cfg: &HostV1Config) -> Result<(), String> {
    if !cfg.allowed_source_addresses.is_empty() {
        return Err(DEFERRED_SOURCE_ADDR_CONFIG.to_string());
    }
    Ok(())
}
