use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use crate::edge::dial::APPDATA_KEY_SOURCE_ADDR;
use crate::edge::model::HostV1Config;

use super::hostcfg::{get_address, get_port, get_protocol};

/// The dynamic dial target resolved from an inbound dial's appData against the service's `host.v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// The dial protocol (`tcp`/`udp`) — fixed `host.v1.protocol`, or (T4b-2b) the appData `dst_protocol`
    /// validated against `allowedProtocols` when `forwardProtocol`. The host dials TCP only.
    pub protocol: String,
    /// The dial address: an IP (via `dst_ip`) or, since T4b-2a, a hostname (via `dst_hostname`).
    pub address: String,
    /// The dial port.
    pub port: u16,
    /// (T4b-2d-2) The local address to bind the OUTBOUND dial's source to (`net.Dialer{LocalAddr}`), from
    /// the appData `source_addr` key. `None` when absent/empty (the common case → a default-source dial).
    /// The host applies it at dial time ([`crate::tunnel::host`]); the resolver only parses it (a bad value
    /// rejected loudly via [`resolve_target`]). The oracle reads it UNCONDITIONALLY in `dialAddress` — it
    /// is the local end of the host's own dial, never checked against an allow-list (see [`parse_source_bind`]).
    pub source_bind: Option<SocketAddr>,
}

impl ResolvedTarget {
    /// `address:port`, the string a TCP dialer connects to (oracle `dialAddress`'s `xAddress+":"+port`).
    #[must_use]
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// Resolve the dial target from `app_data` (the inbound Connect's `AppData` bytes) against `cfg` (the
/// service's `host.v1`). Returns the oracle reason string on rejection (byte-exact except `get_port`'s
/// truncated non-numeric reason; the reason becomes the host's `complete_failed` → DialFailed body,
/// dialer-observable).
///
/// Oracle order (`hosting.go` `Dial`, `:388-409`): `GetProtocol` → `GetAddress` → `GetPort`, then
/// `dialAddress`. We follow the same order so the FIRST failing check wins (matching which error the
/// dialer sees).
///
/// # Errors
/// Returns the rejection reason string (byte-exact to the oracle where dialer-observable, except the
/// `get_port` non-numeric-port truncation) when the appData is malformed, a deferred T4b-2 capability
/// is required, or a value is not allowed.
pub fn resolve_target(
    cfg: &HostV1Config,
    app_data: Option<&[u8]>,
) -> Result<ResolvedTarget, String> {
    let options = parse_app_data(app_data)?;
    let protocol = get_protocol(cfg, &options)?;
    let address = get_address(cfg, &options)?;
    let port = get_port(cfg, &options)?;
    // T4b-2d-2: a per-dial `source_addr` asks the host to bind the LOCAL end of its outbound dial to a
    // specific IP/port (`net.Dialer{LocalAddr}`). Parsed LAST so an address/port reject wins precedence —
    // the oracle reads `source_addr` in `dialAddress`, run after `Get*`/`translateAddress`
    // (`hosting.go:388-409`). EMPTY/absent `source_addr` is a no-op (`None`), mirroring the oracle's
    // `if sourceAddr != ""` gate (`hosting.go:215`); a present one is parsed by [`parse_source_bind`] into
    // the bind `SocketAddr` (a malformed value rejects loudly → DialFailed). The bind itself happens at
    // dial time in [`crate::tunnel::host`]. Oracle: `dialAddress` (`hosting.go:212-245`) keyed on
    // `SourceAddrKey="source_addr"` (`const.go:8`).
    let source_bind = match options
        .get(APPDATA_KEY_SOURCE_ADDR)
        .filter(|s| !s.is_empty())
    {
        Some(s) => Some(parse_source_bind(s)?),
        None => None,
    };
    Ok(ResolvedTarget {
        protocol,
        address,
        port,
        source_bind,
    })
}

/// Parse a per-dial `source_addr` (the appData value the host binds the OUTBOUND dial's local end to)
/// into the bind [`SocketAddr`], a faithful port of the oracle's parse inside `dialAddress`
/// (`hosting.go:212-245`): `strings.Split(sourceAddr, ":")`, and ONLY when there are EXACTLY 2 segments is
/// the second parsed as a port (`strconv.Atoi`); otherwise the whole string is the IP and the port is 0.
///
/// FIDELITY — the naive `:` split is byte-faithful (NOT `split_once`): a bare IPv6 source (`::1` → 3
/// segments, `fe80::1:53` → 4) is therefore NOT split — the whole string is the IP, port 0 — so a port
/// cannot be attached to an unbracketed IPv6 source, exactly as the oracle.
///
/// CONSCIOUS DEVIATIONS (named, safe-direction, reachable only from an unusual `dialOptions.sourceIp`
/// template, never the values a normal intercept emits; the source bind is the LOCAL end of the host's own
/// dial — NOT an allow-list — so a stricter parse can NEVER over-permit a destination, unlike the
/// `dst_ip`/`allowedAddresses` path; no Go-vs-Rust differential is needed):
/// 1. **Unparseable / empty source IP.** The oracle does `net.ParseIP(sourceIp)`, which returns `nil` for
///    a non-IP; `net.TCPAddr{IP: nil, Port: p}` then WILDCARD-binds (any local IP, port `p`). The one
///    oracle-meaningful input this refuses is the empty-IP `:port` form (`":8080"` → 2 segments, IP `""`,
///    port 8080 → oracle binds `0.0.0.0:8080`); we reject it loudly with `IpAddr::from_str` rather than
///    wildcard-bind. Safe-direction: a refused bind → DialFailed, never a wrong dial.
/// 2. **Non-numeric / out-of-`u16` port.** On `Atoi` failure the oracle hits a BUG — `errors.Wrapf(err,
///    ...)` is called with the OUTER (nil) `err`, so `Wrapf` returns `nil` and `dialAddress` returns
///    `(nil, false, nil)` (a nil conn with NO error). We do NOT replicate that nil-conn bug: a bad port
///    rejects loudly with the oracle's `errors.Wrapf` PREFIX `"failed to parse port '<seg>'"`. An
///    out-of-`u16` port (`":99999"`) — which the oracle would wrap to `uint16(99999)` = 34463 and bind —
///    is likewise rejected (same stance as `get_port`'s out-of-range narrowing).
///
/// # Errors
/// Returns a clear reject reason (the host turns it into the dialer-observable DialFailed body) when the
/// port segment is non-numeric/out-of-range or the IP is unparseable.
pub(crate) fn parse_source_bind(s: &str) -> Result<SocketAddr, String> {
    let segments: Vec<&str> = s.split(':').collect();
    let (ip_str, port) = if segments.len() == 2 {
        let port = segments[1]
            .parse::<u16>()
            .map_err(|_| format!("failed to parse port '{}'", segments[1]))?;
        (segments[0], port)
    } else {
        (s, 0u16)
    };
    let ip = IpAddr::from_str(ip_str).map_err(|_| format!("invalid source_addr IP '{ip_str}'"))?;
    Ok(SocketAddr::new(ip, port))
}

/// Parse the appData bytes as the oracle's `AppDataToMap`: an empty/absent appData is an empty map;
/// otherwise JSON object. The oracle decodes to `map[string]interface{}`, then `getValue` asserts each
/// read value is a `string`. We keep ONLY string values. Oracle: `provider.go:74` `AppDataToMap`.
///
/// CONSCIOUS DEVIATION (reachable in principle from a non-conformant dialer, always fail-loud; named
/// not silent): for a key whose value is present-but-NON-string, the oracle's `getValue` returns a
/// DISTINCT reason `"%v required and present but not a string. ..."` (`service.go:259-260`); we drop the
/// non-string value here, so on read it surfaces as the absent-key reason `"%v required but not
/// provided"` instead. This is NOT byte-equivalent, but it only diverges for a malformed (non-conformant)
/// dialer — `GetAppInfo`/[`crate::edge::dial::build_app_data`] always emit string values, and we never
/// read a non-`dst_*` key — and the value is never silently mis-resolved: a dropped non-string `dst_*`
/// key surfaces as its absent-key reject, and a dropped non-string `source_addr` is treated as absent
/// (no source-bind requested), so the dial is never silently pointed at the wrong target. (T4b-2 may
/// restore the exact non-string-vs-absent distinction.)
fn parse_app_data(app_data: Option<&[u8]>) -> Result<BTreeMap<String, String>, String> {
    let Some(bytes) = app_data.filter(|b| !b.is_empty()) else {
        return Ok(BTreeMap::new());
    };
    // Oracle: `json.Unmarshal(appData, &result)` into a `map[string]interface{}`. A non-object or
    // malformed appData is an error the oracle routes through `CompleteAcceptFailed` (provider.go:145).
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid appData: {e}"))?;
    let serde_json::Value::Object(obj) = value else {
        return Err("invalid appData: not a JSON object".to_string());
    };
    let mut map = BTreeMap::new();
    for (k, v) in obj {
        if let serde_json::Value::String(s) = v {
            map.insert(k, s);
        }
    }
    Ok(map)
}
