use crate::edge::model::AddressTranslation;

use super::deferred::{DEFERRED_SOURCE_ADDR_CONFIG, check_deferred_config};
use super::testsupport::{fwd_ip_cfg, listen_opts};
use super::translate::build_address_translations;

/// `connectTimeout` is no longer a DEFERRED capability (T4b-2c resolves it); `check_deferred_config`
/// must PASS a config that only sets a connectTimeout — the startup guard now only covers translations
/// and allowedSourceAddresses. (Regression: a stale connectTimeout branch in `check_deferred_config`
/// would make this RED.)
#[test]
fn connect_timeout_config_is_no_longer_a_deferred_capability() {
    let mut cfg = fwd_ip_cfg();
    cfg.listen_options = Some(listen_opts(Some("10s"), None));
    assert!(check_deferred_config(&cfg).is_ok());
    cfg.listen_options = Some(listen_opts(None, Some(10)));
    assert!(check_deferred_config(&cfg).is_ok());
}
/// T4b-2d-1: `forwardAddressTranslations` is NO LONGER a deferred config capability — it is built by
/// [`build_address_translations`] and applied by [`translate_address`]. `check_deferred_config` must
/// now PASS a config carrying translations (a regression that re-added the translations branch would
/// make this RED). The startup guard still rejects `allowedSourceAddresses` (the next test).
#[test]
fn address_translations_config_is_no_longer_a_deferred_capability() {
    let mut cfg = fwd_ip_cfg();
    cfg.forward_address_translations = vec![AddressTranslation {
        from: "1.2.3.0".to_string(),
        to: "4.5.6.0".to_string(),
        prefix_length: 24,
    }];
    assert!(check_deferred_config(&cfg).is_ok());
    // And it BUILDS (parses) rather than rejecting.
    assert_eq!(build_address_translations(&cfg).unwrap().len(), 1);
}
#[test]
fn check_deferred_config_passes_for_plain_forward_ip_config() {
    assert!(check_deferred_config(&fwd_ip_cfg()).is_ok());
}
/// A config-level non-empty `allowedSourceAddresses` (host-side source-address ROUTE setup) is still
/// rejected loudly at startup via `check_deferred_config` (deferred T4b-2d-3 — the per-dial bind is
/// supported, but provisioning a non-local source IP onto `lo` is OS-level route setup). Oracle:
/// `GetAllowedSourceAddressRoutes` (service.go:333-344).
#[test]
fn allowed_source_addresses_config_is_rejected_loudly() {
    let mut cfg = fwd_ip_cfg();
    cfg.allowed_source_addresses = vec!["10.0.0.0/8".to_string()];
    assert_eq!(
        check_deferred_config(&cfg).unwrap_err(),
        DEFERRED_SOURCE_ADDR_CONFIG
    );
}
