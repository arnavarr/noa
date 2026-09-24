use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use crate::edge::dial::{
    APPDATA_KEY_HOSTNAME, APPDATA_KEY_IP, APPDATA_KEY_PORT, APPDATA_KEY_PROTOCOL,
};
use crate::edge::model::HostV1Config;

use super::allowed::{MatchValue, parse_allowed_addresses};

/// `GetProtocol` (T4b-2b): when `forwardProtocol`, read `dst_protocol` from the appData and validate it
/// against `allowedProtocols`; otherwise return the fixed `protocol`. Faithful port of the oracle
/// (`service.go:271-282`): `getValue(dst_protocol)` FIRST (an absent key rejects byte-exact via
/// `getValue`), then a CASE-SENSITIVE membership test (`stringz.Contains`, exact `==`, NO
/// `strings.ToLower` — unlike the address matchers), rejecting a non-member with
/// `"protocol '%s' is not in allowed protocols"`. The resolved protocol is dialer-observable (it
/// drives whether the host's TCP-only path accepts the dial — see the host-level deviation below).
///
/// NON-STRING `dst_protocol` (documented carried deviation): a present-but-non-string value inherits the
/// pre-existing `parse_app_data` drop, so `get_value` reports the absent-key reason
/// (`"dst_protocol required but not provided"`) instead of the oracle's distinct `getValue` non-string
/// branch (`"... required and present but not a string ..."`, `service.go:264-266`). Both REJECT
/// (fail-loud, NEVER an over-permit); reachable only from a non-conformant dialer (`build_app_data`
/// always emits strings).
///
/// CONSCIOUS DEVIATION (named, NOT a faithful reject — the oracle has no such error): the resolver is
/// protocol-agnostic and faithfully resolves `udp` when allowed, but [`crate::tunnel::run_tcp_host_forwarding`]
/// dials TCP only, so a resolved non-`tcp` protocol is rejected at the HOST (not here). The oracle's
/// `dialAddress` (`hosting.go:206`) WOULD udp-dial it, so this is a dialer-observable divergence (DialFailed
/// vs a real udp dial) — our deferred capability (the UDP host path), kept fail-loud.
pub(super) fn get_protocol(
    cfg: &HostV1Config,
    options: &BTreeMap<String, String>,
) -> Result<String, String> {
    if !cfg.forward_protocol {
        return Ok(cfg.protocol.clone());
    }
    let protocol = get_value(options, APPDATA_KEY_PROTOCOL)?;
    if cfg.allowed_protocols.iter().any(|p| p == &protocol) {
        return Ok(protocol);
    }
    Err(format!("protocol '{protocol}' is not in allowed protocols"))
}

/// `GetAddress` (T4b-2a): the `forwardAddress` path with the full `allowedAddress` matcher
/// type-dispatch. The oracle tries `dst_hostname` FIRST (string-matched against the matchers); only when
/// `dst_hostname` is ABSENT does it fall back to `dst_ip` (IP-parsed, matched). A present-but-unmatched
/// `dst_hostname` does NOT fall back — it rejects. The allow-list is parsed LENIENTLY into all three
/// matcher kinds; the inbound value's TYPE (`String` vs `net.IP`) decides which can match (the CRUX:
/// `cidrAddress` matches only an IP, `hostnameAddress`/`domainAddress` only a string). Oracle:
/// `service.go:285-308` (`GetAddress`) + `:234-249` (`GetAllowedAddresses`, lenient) + `:176-215` (the
/// `.Allows` type-dispatch + `makeAllowedAddress`).
pub(super) fn get_address(
    cfg: &HostV1Config,
    options: &BTreeMap<String, String>,
) -> Result<String, String> {
    if !cfg.forward_address {
        // Fixed address (not forwarding): resolved directly.
        return Ok(cfg.address.clone());
    }

    // Lenient allow-list → every kind of matcher (mirrors `GetAllowedAddresses` append-on-ok).
    let allowed = parse_allowed_addresses(&cfg.allowed_addresses);

    // Oracle precedence: `dst_hostname` FIRST. `getValue(dst_hostname)` succeeds iff the key is present
    // with a string value (a non-string value was dropped by `parse_app_data`, surfacing here as absent
    // — matching the oracle, whose not-a-string `getValue` error ALSO falls to the `dst_ip` branch).
    if let Some(hostname) = options.get(APPDATA_KEY_HOSTNAME) {
        // String-matched: only `hostnameAddress`/`domainAddress` can match a string; a `cidrAddress`
        // returns false. NO fallback to `dst_ip` on a no-match (oracle `service.go:290-295,308`).
        if allowed.iter().any(|a| a.allows(&MatchValue::Str(hostname))) {
            return Ok(hostname.clone());
        }
        return Err(format!("address '{hostname}' is not in allowed addresses"));
    }

    // `dst_hostname` absent → `dst_ip` (IP-parsed, matched). `getValue` errors if absent → byte-exact.
    let address = get_value(options, APPDATA_KEY_IP)?;
    // The oracle does `net.ParseIP(address)`; a non-IP yields a nil IP that no `cidrAddress` `.Contains`,
    // so the loop falls through to "address is not in allowed addresses". We mirror that: an unparseable
    // `dst_ip` is simply not-allowed (same observable error), not a distinct parse error. IP-matched:
    // only a `cidrAddress` can match a `net.IP`; a `hostnameAddress`/`domainAddress` returns false.
    let ip_allowed = IpAddr::from_str(&address)
        .ok()
        .is_some_and(|ip| allowed.iter().any(|a| a.allows(&MatchValue::Ip(ip))));
    if ip_allowed {
        return Ok(address);
    }
    Err(format!("address '{address}' is not in allowed addresses"))
}

/// `GetPort`: T4b-1 supports the `forwardPort` path (`dst_port` validated against `allowedPortRanges`)
/// and the fixed-port path. Oracle: `service.go:313-331`.
pub(super) fn get_port(
    cfg: &HostV1Config,
    options: &BTreeMap<String, String>,
) -> Result<u16, String> {
    if !cfg.forward_port {
        return Ok(cfg.port);
    }
    let port_str = get_value(options, APPDATA_KEY_PORT)?;
    // Oracle `strconv.Atoi(portStr)` then `uint16(port)`; we parse straight to u16.
    //
    // CONSCIOUS DEVIATION #1 — reason TRUNCATION (reachable in principle from a non-conformant dialer,
    // always fail-loud): on a non-numeric value the oracle returns `errors.Wrapf(err, "invalid
    // destination port %v", portStr)`, which is the PREFIX `"invalid destination port <portStr>"`
    // FOLLOWED by Go's wrapped `strconv.Atoi` text (`: strconv.Atoi: parsing "<portStr>": invalid
    // syntax`). We emit only the `errors.Wrapf` PREFIX — a CONSCIOUS truncation, NOT byte-exact with the
    // full wrapped string. We do not hardcode Go's internal `strconv` error text: it is brittle and the
    // path is reachable only from a non-conformant dialer (a conformant dialer / `build_app_data` emits a
    // numeric `dst_port`); the dial is still rejected loudly either way.
    //
    // CONSCIOUS DEVIATION #2 — out-of-range narrowing (same reachability): the oracle Atoi-s to `int`
    // then `uint16(port)`-WRAPS (a `dst_port` like "65537" wraps to 1 and may pass the range check),
    // whereas our `u16::parse` REJECTS an out-of-`u16`-range value with the same prefix reason. We reject
    // rather than wrap — strictly safer. Matches model.rs's documented `Port int`→`u16` narrowing stance.
    let port: u16 = port_str
        .parse()
        .map_err(|_| format!("invalid destination port {port_str}"))?;
    for range in &cfg.allowed_port_ranges {
        if port >= range.low && port <= range.high {
            return Ok(port);
        }
    }
    Err(format!("port {port} is not in allowed port ranges"))
}

/// Read a required string value from the appData map, byte-exact to the oracle's `getValue`
/// "required but not provided" error (the value type is already a string here — see `parse_app_data`).
/// Oracle: `service.go:255-262`.
fn get_value(options: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    options
        .get(key)
        .cloned()
        .ok_or_else(|| format!("{key} required but not provided"))
}
