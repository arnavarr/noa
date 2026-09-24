use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// One parsed allow-list matcher, mirroring the oracle's `allowedAddress` interface and its three
/// implementations (`cidrAddress`/`hostnameAddress`/`domainAddress`, `service.go:168-200`). The
/// `Hostname`/`Domain` strings are stored already lowercased (`makeAllowedAddress` lowercases, `:207,:214`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AllowedAddress {
    /// `cidrAddress` — matches ONLY a `net.IP` contained in the network (`service.go:176-181`).
    Cidr(IpNet),
    /// `hostnameAddress` — matches ONLY a string equal (case-insensitive) to the hostname (`:187-190`).
    Hostname(String),
    /// `domainAddress` — matches ONLY a string: `*` matches any, `*.suffix` matches the suffix or the
    /// apex (`:196-200`). The stored string keeps the leading `*`/`*.` form.
    Domain(String),
}

/// The inbound value being matched, modelling the oracle's `addr interface{}` (`service.go:169`). The
/// CRUX: `Allows` type-dispatches on `addr.(net.IP)` / `addr.(string)`, so the value's variant — not its
/// textual content — decides which matcher kind can match.
pub(super) enum MatchValue<'a> {
    /// A `dst_ip`, IP-parsed (oracle `net.ParseIP` → `net.IP`).
    Ip(IpAddr),
    /// A `dst_hostname`, the raw string (oracle passes the string verbatim).
    Str(&'a str),
}

impl AllowedAddress {
    /// Faithful port of the three `.Allows(addr interface{})` methods (`service.go:176-200`): the
    /// type-dispatch is the cross-variant arms returning `false` (a `cidrAddress` never matches a
    /// string; a `hostnameAddress`/`domainAddress` never matches an IP).
    pub(super) fn allows(&self, value: &MatchValue) -> bool {
        match (self, value) {
            (AllowedAddress::Cidr(net), MatchValue::Ip(ip)) => net.contains(ip),
            (AllowedAddress::Hostname(h), MatchValue::Str(s)) => fold_lower(s) == *h,
            (AllowedAddress::Domain(d), MatchValue::Str(s)) => domain_allows(d, s),
            // Cross-type: the oracle's `addr.(net.IP)`/`addr.(string)` assertions fail → false.
            _ => false,
        }
    }
}

/// Lowercase RUNE-WISE (`char::to_lowercase`) to mirror Go's `strings.ToLower` (a per-rune simple
/// mapping). Rust's `str::to_lowercase` applies CONTEXT-sensitive Unicode folding — a word-final `Σ`
/// becomes `ς`, not `σ` — which OVER-PERMITS vs Go: an allow-list `"ΟΔΟΣ"` (`str::to_lowercase` →
/// `"οδος"`) would then match a `dst_hostname` `"οδος"` the oracle (`"οδοσ" != "οδος"`) denies. Per-rune
/// folding drops the final-sigma rule (`'Σ'.to_lowercase()` → `'σ'`), matching Go. A residual full-vs-
/// simple gap remains for a few code points (e.g. `İ` → `i̇` here, 2 runes, vs `i` in Go) but that is the
/// SAFE under-permit direction and unreachable by a real LDH/punycode DNS name. Oracle: `strings.ToLower`
/// at `service.go:189,198,207,214`.
fn fold_lower(s: &str) -> String {
    s.chars().flat_map(char::to_lowercase).collect()
}

/// `domainAddress.Allows` (`service.go:196-200`): `*` matches any host; `*.suffix` matches a host that
/// ends with `.suffix` (the `domain[1:]` suffix) OR equals the apex `suffix` (the `domain[2:]` apex).
/// `domain` is already lowercased and validated as `*` or `*.<suffix>` by [`make_allowed_address`], so
/// the byte slices `domain[1..]`/`domain[2..]` are always valid for the `*.<suffix>` form.
fn domain_allows(domain: &str, host: &str) -> bool {
    if domain == "*" {
        return true; // oracle: `self.domain == "*"` (short-circuits before `domain[2:]`).
    }
    let host = fold_lower(host);
    host.ends_with(&domain[1..]) || host.as_str() == &domain[2..]
}

/// Parse the `allowedAddresses` allow-list into matchers. LENIENT per-entry, faithfully mirroring the
/// oracle's `GetAllowedAddresses` (`service.go:234-249`: append-on-ok / `log.Warn`-on-err, NEVER fatal);
/// an unparseable entry is dropped (the oracle's `log.Warn` is an operational log, not behavior).
pub(super) fn parse_allowed_addresses(entries: &[String]) -> Vec<AllowedAddress> {
    entries
        .iter()
        .filter_map(|e| make_allowed_address(e))
        .collect()
}

/// Port of the oracle's `makeAllowedAddress` (`service.go:202-215`), order-faithful: a `*`/`*.` domain
/// first, then a CIDR (`GetCidr`), else a hostname. Returns `None` where the oracle would `log.Warn`-drop
/// the entry (an invalid `*…` domain) or would build an IP-only `cidrAddress` we cannot reproduce
/// faithfully as a string-unmatchable matcher (an IPv6 zone-id — see below).
///
/// FIDELITY — non-CIDR fallback to `Hostname` (the T4b-2a refinement over T4b-1's drop): when the CIDR
/// parse fails, the oracle builds a `hostnameAddress` (string-matchable), NOT a drop. T4b-1 dropped
/// non-CIDR entries because only IP matching existed; now `dst_hostname` string-matching makes the
/// difference OBSERVABLE, so we faithfully PROMOTE a non-CIDR entry to `Hostname` — INCLUDING a
/// leading-zero CIDR-looking string (`010.0.0.0/8`, `::ffff:010.0.0.1/120`), which Go `netip` also
/// rejects so the oracle treats it as a hostname. The strict-address guard in [`parse_ip_or_cidr`] keeps
/// every such entry OUT of `Cidr`, so a `dst_ip` still never matches it (no over-permit on the IP path).
///
/// FIDELITY — zone-id DROP guard: Go `netip` ACCEPTS an IPv6 zone-id (`fe80::1%eth0`) → the oracle
/// builds a `cidrAddress` (IP-only, string-UNmatchable), but [`parse_ip_or_cidr`] (via strict
/// `IpAddr::from_str`) REJECTS the `%`. Promoting it to `Hostname` would make `dst_hostname="fe80::1%eth0"`
/// match where the oracle returns not-allowed — an over-permit on the destination allow-list. We
/// therefore DROP every `%`-bearing entry whose CIDR parse failed. For the netip-ACCEPTS forms
/// (`fe80::1%eth0`) the drop is faithful on the string path (no-match == the oracle's
/// `cidrAddress`-vs-string) and a safe UNDER-permit on the IP path; for the netip-REJECTS `%` forms
/// (`1.2.3.4%eth0`, bare `%`, where the oracle would build a string-matchable `hostnameAddress`) the
/// drop is a further safe UNDER-permit. Either way it never widens the allow-list, and `%` is not a legal
/// DNS hostname character so it never drops a genuine hostname.
fn make_allowed_address(addr: &str) -> Option<AllowedAddress> {
    // Empty entry: the oracle's `addr[0]` panics; we drop it (unreachable via a real config, and a
    // panic is never the intended behavior). A safe deviation in the never-reached direction.
    let first = *addr.as_bytes().first()?;
    if first == b'*' {
        // Domain form (oracle `:203-208`): `*` alone, or `*.<≥1 char>`; anything else is an invalid
        // domain the oracle errors on → `GetAllowedAddresses` `log.Warn`-drops it.
        if addr.len() != 1 && (addr.len() < 3 || addr.as_bytes()[1] != b'.') {
            return None;
        }
        return Some(AllowedAddress::Domain(fold_lower(addr)));
    }
    if let Some(net) = parse_ip_or_cidr(addr) {
        return Some(AllowedAddress::Cidr(net));
    }
    // CIDR parse failed → the oracle builds a hostnameAddress, UNLESS the entry bears an IPv6 zone-id
    // `%` (drop it — see the zone-id doc above: dropping is a safe under-permit in every `%` case,
    // whereas promoting a netip-accepted `%` to `Hostname` would over-permit a string match).
    if addr.contains('%') {
        return None;
    }
    Some(AllowedAddress::Hostname(fold_lower(addr)))
}

/// Parse `"ip"` (→ host route /32 or /128) or `"ip/prefix"` (→ network), mirroring the oracle's
/// `GetCidr` (`tunnel/utils/ipcalc.go:25-32`: `netip.ParseAddr` then `netip.ParsePrefix`): a bare
/// address first, then a prefix. The returned `IpNet` keeps host bits verbatim (like the oracle's
/// `net.IPNet{IP: pfx.Addr().AsSlice(), Mask: CIDRMask(...)}`); masking happens at `.contains()` time.
///
/// FIDELITY — the load-bearing security guards (the over-permit class caught 3× in T4b + the
/// leading-SIGN 4th instance):
///
///  1. **Bits-token guard, byte-exact to `netip.ParsePrefix`.** `netip` REJECTS a multi-char
///     prefix-length token whose first byte is not `'1'..='9'` — both a leading-ZERO (`/00`, `/08`) AND
///     a leading-SIGN (`/+8`, `/-8`) — as "bad bits" (`strconv.Atoi`, like `u8::from_str`, would accept
///     both). The guard above is a byte-exact mirror. A single `0` (`/0`) is legitimate and kept.
///  2. **Strict ADDRESS parse via `IpAddr::from_str`.** `netip` REJECTS a leading-zero IPv4 octet
///     ANYWHERE — pure-v4 (`010.0.0.0`) AND embedded in a v4-mapped / v4-compatible / NAT64 IPv6
///     (`::ffff:010.0.0.1`, `64:ff9b::010.0.0.1`, `::00.0.0.1`). The `ipnet` crate's `IpNet::from_str`
///     is LENIENT (it normalizes `010`→`10`), so feeding it the whole string would WIDEN the
///     destination allow-list vs the oracle — an over-permit on a security boundary. We instead split
///     off the prefix and parse the ADDRESS with strict `std::net::IpAddr::from_str`, whose acceptance
///     set equals `netip.ParseAddr`'s. When `GetCidr` fails the oracle builds a string matcher that
///     never matches a `net.IP`, so a rejected entry correctly DENIES the IP path.
///  3. **V4-mapped network unmapping (mirrors `net.IPNet.Contains`'s `To4()`).** Go's `Contains` runs
///     `To4()` on the network number, so a `::ffff:a.b.c.d` network is a PURE V4 network (matches v4
///     under the low-32-bits mask, never genuine v6). [`unmap_v4_mapped`] reproduces this; keeping it as
///     a v6 `IpNet` over-permits genuine v6. DIRECTION HONESTY: this is the ONE guard here that is NOT
///     "strictly more restrictive" — closing the genuine-v6 over-permit is INSEPARABLE from representing
///     the network as Go's V4 net, which also WIDENS the v4 case vs prior Rust (`::ffff:1.2.3.4/120` now
///     matches `dst_ip=1.2.3.4` where the v6 net cross-family-DENIED). That widening is faithful to Go
///     and a necessary consequence of the fix, NOT a free-standing permissiveness add. (Guards 1+2 and
///     the leading-zero rejections ARE strictly more restrictive.)
///
/// Other CONSCIOUS, SAFE-direction deviations (stricter than the oracle, all named not silent — they
/// DROP an entry rather than over-accept): an IPv6 zone-id entry (`fe80::1%eth0`, which `netip` accepts)
/// and an empty `""` entry fail `IpAddr::from_str` here and are dropped (the zone-id drop is handled in
/// [`make_allowed_address`]). None widen the allow-list.
///
/// RESIDUAL, ORTHOGONAL (pre-existing, NOT a network-parse issue → NOT closed here): a v4-mapped IPv6
/// *destination* LITERAL (a probe `::ffff:1.2.3.4`, not the network) diverges from Go because Go's
/// `Contains` also `To4()`-normalizes the PROBE while our callers parse the probe with `IpAddr::from_str`
/// (kept v6). This is BIDIRECTIONAL: under-permit against a v4 net (Go matches it as v4, we don't),
/// over-permit against a genuine-v6 / v4-compatible / NAT64 / `::/0` net (we match it as v6, Go's
/// length-check rejects). REACHABILITY: datapath-unreachable for the intercept resolver (netstack yields
/// canonical V4/V6 destinations, never `::ffff:` literals — verified via `InterceptStack::accept`); on
/// the shared host-side path it requires a NON-conformant dialer (a conformant dialer / `build_app_data`
/// emits a canonical `dst_ip`) AND an unusual v6-net config. DEFERRED, not closed here: the only
/// Go-faithful close is to `To4`-normalize the probe, which is PURE widening — it closes NO over-permit
/// on the canonical datapath (every residual over-permit needs a non-canonical v4-mapped probe), so
/// deferring it keeps this change as tight as possible. (Contrast guard #3 above: the network unmap's
/// v4-widening is INSEPARABLE from closing a genuine over-permit, so it is not deferrable.)
///
/// REUSED by the intercept resolver (`crate::tunnel::intercept::resolve`, slice (B)) to build the
/// `intercept.v1` `addresses`/`allowedSourceAddresses` CIDR matchers — the SAME `utils.GetCidr` the
/// interceptor uses (`tunnel/intercept/iputils.go` `getInterceptIP`). Hence `pub(crate)`: the security
/// frontier shares ONE hardened parse, never a parallel one that could reintroduce the over-permit class.
pub(crate) fn parse_ip_or_cidr(s: &str) -> Option<IpNet> {
    let (addr, bits) = s.split_once('/').map_or((s, None), |(a, b)| (a, Some(b)));
    // BITS GUARD — byte-exact mirror of `netip.ParsePrefix` (`$(GOROOT)/src/net/netip/netip.go:1385`,
    // its comment: "strconv.Atoi accepts a leading sign and leading zeroes, but we don't want that"):
    // reject a MULTI-char bits token whose first byte is NOT `'1'..='9'`. `u8::from_str` (like Go's
    // `strconv.Atoi`) accepts a leading SIGN (`"+8"`→8, `"+0"`→0) AND leading ZEROES (`"08"`→8); `netip`
    // rejects BOTH as "bad bits after slash". A single-char token (`/8`, `/0`, or a lone `/+`) is left
    // to `u8::from_str`, which already accepts the digit and rejects `+`/non-digits. This closes the
    // leading-SIGN over-permit (e.g. `10.0.0.0/+8` → a whole `/8` in Rust, no entry in the oracle) — the
    // 4th instance of the leading-zero/v4-mapped over-permit class caught 3× in T4b.
    if bits.is_some_and(|b| b.len() > 1 && !(b'1'..=b'9').contains(&b.as_bytes()[0])) {
        return None;
    }
    // STRICT address parse (matches `netip.ParseAddr`, modulo `%` handled in `make_allowed_address`):
    // rejects a leading-zero IPv4 octet pure OR embedded in a v4-mapped/NAT64 IPv6, so a leading-zero
    // v4-embedded CIDR can never become a `Cidr` (over-permit). A legitimate expanded v4-mapped IPv6
    // (`0:0:0:0:0:ffff:1.2.3.4`) is NOT demoted to a string matcher by a textual leading `0` — it parses
    // here and is unmapped to a faithful V4 `Cidr` below (see `unmap_v4_mapped`).
    let ip = IpAddr::from_str(addr).ok()?;
    let prefix: u8 = match bits {
        None => {
            if ip.is_ipv4() {
                32
            } else {
                128
            }
        } // bare address → host route (/32 or /128)
        Some(b) => b.parse::<u8>().ok()?,
    };
    // V4-MAPPED NORMALIZATION — mirror Go's `net.IPNet.Contains`, which runs `ip.To4()` on BOTH the
    // network number and the probe (`$(GOROOT)/src/net/ip.go` `Contains`/`networkNumberAndMask`): a
    // `::ffff:a.b.c.d` network behaves as a PURE V4 network — it matches a v4 destination under the
    // low-32-bits mask (Go's `mask[12:]` = `max(0, prefix-96)` leading ones) and matches NO genuine v6
    // destination (the `len(ip) != len(nn)` length check rejects v6 after To4). Keeping it as a v6
    // `IpNet` OVER-PERMITS genuine v6 (a short-prefix `::ffff:.../n` shares its zero high bits with much
    // of v6 space — empirically `::ffff:1.2.3.4/64` matched `::1` in Rust where Go denies). We UNMAP the
    // v4-mapped address to v4 and reinterpret the prefix as `prefix-96` (clamped), reproducing Go's
    // collapsed v4-side mask. ONLY v4-MAPPED (`::ffff:0:0/96`) is normalized — NOT v4-compatible
    // (`::a.b.c.d`) or NAT64 (`64:ff9b::a.b.c.d`), exactly like Go's `To4` (which returns nil for those).
    let (ip, prefix) = unmap_v4_mapped(ip, prefix);
    IpNet::new(ip, prefix).ok()
}

/// Mirror Go's `To4()` normalization for a v4-MAPPED IPv6 network (`::ffff:a.b.c.d`): unmap to the
/// embedded v4 address and reinterpret the 128-bit `prefix` as the v4-side `max(0, prefix-96)` (the
/// leading 1-bits of the low 32 bits of the 128-bit mask — Go's `mask[12:]`). A non-v4-mapped address is
/// returned unchanged. ONLY v4-mapped (`Ipv6Addr::to_ipv4_mapped`, byte-identical to Go `To4`'s mapped
/// check: first 10 bytes 0, bytes 10-11 `0xff`) is normalized — v4-COMPATIBLE/NAT64 stay v6, since Go's
/// `To4` returns nil for them.
fn unmap_v4_mapped(ip: IpAddr, prefix: u8) -> (IpAddr, u8) {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return (IpAddr::V4(v4), prefix.saturating_sub(96));
    }
    (ip, prefix)
}
