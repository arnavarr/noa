use std::net::IpAddr;
use std::str::FromStr;

use crate::edge::model::HostV1Config;

// ----- T4b-2d-1: forwardAddressTranslations (`translateAddress` + the CIDR→CIDR renumber). -----

/// One built address translation: the parsed `from`/`to` IPs and the shared prefix length, mirroring the
/// oracle's `addrTranslation{fromPrefix, toPrefix}` built ONCE in `newHostingContext`
/// (`hosting.go:82-99`, both prefixes from the SAME `cfgX.PrefixLength`). The slice
/// [`build_address_translations`] returns is pre-sorted longest-prefix-first so the FIRST containing
/// `from` is the best match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressTranslationPrefix {
    from: IpAddr,
    to: IpAddr,
    /// The shared prefix length (the oracle builds `from`/`to` prefixes from the same `PrefixLength`).
    /// Kept as-is (NOT range-validated here): the oracle's `netip.PrefixFrom` does not fail on an
    /// out-of-range length — it builds an INVALID prefix whose `Contains` is always false, so the
    /// translation is silently INERT (the service is still hosted). See [`prefix_contains`]. (As a `u8` this
    /// also means a schema-out-of-range `prefixLength > 255` serde-rejects at config parse → fail-closed,
    /// while 33..=255 stays inert in both implementations via the `bits <= 32` / `<= 128` gate.)
    bits: u8,
}

/// Build the host's address translations from `cfg`, a faithful port of the `addrTranslation` slice the
/// oracle's `newHostingContext` constructs (`hosting.go:70-101`). Computed ONCE at host startup (NOT
/// per-dial), mirroring the oracle.
///
/// Returns an EMPTY vec when the config does NOT forward the address (the oracle only builds translations
/// under `if config.ForwardAddress`, `hosting.go:76`) or sets no translations — so a `forwardAddress:false`
/// config carrying a stray `forwardAddressTranslations` is IGNORED, not rejected (faithful: the oracle
/// never looks at them). Otherwise each `from`/`to` is parsed with the strict `netip.ParseAddr` equivalent
/// (`std::net::IpAddr::from_str`, whose accept-set equals `netip.ParseAddr`'s — the leading-zero / v4-mapped
/// strictness the arc established in T4b-2a; note Go `netip.ParseAddr` ACCEPTS a zone id like `fe80::1%eth0`
/// while `IpAddr::from_str` rejects it, so a zoned `from`/`to` makes us Err → the service is NOT hosted, vs
/// the oracle stripping the zone and hosting: fail-closed, safe-direction, and schema-unreachable since the
/// host.v1 `format:ipv6` rejects zones — same stance as T4b-2a) and the list is sorted by prefix length DESC
/// (`slices.SortFunc`, `hosting.go:77-80`). The sort is STABLE (Rust); Go's `SortFunc` is UNSTABLE. Two
/// DISTINCT unmasked `from` literals can collapse to the SAME masked network at the shared prefix length
/// (e.g. `107.153.242.62/2` and `86.153.30.86/2` both mask to `64.0.0.0/2`), so an input CAN be contained by
/// two equal-length translations — but this is still spec-equivalent: Go's unstable `SortFunc` leaves the
/// equal-key tie order UNSPECIFIED, so Rust's deterministic input-order pick is always a valid oracle
/// outcome; and `to` is operator-authored, never re-validated against the allow-list in either
/// implementation, so the tie selects only among operator-intended targets (no allow-list escape).
///
/// # Errors
/// Returns an operator-facing startup reason when a `from`/`to` fails to parse, mirroring the oracle's
/// `log.Errorf(...) + return nil` (the hosting context is NOT created → the service is NOT hosted,
/// `hosting.go:84-94`). This is a startup (not dialer-observable) failure, so the reason is a clear custom
/// message close to the oracle's log text (same stance as [`get_dial_timeout`](crate::tunnel::resolve::get_dial_timeout)'s startup reasons), NOT a
/// byte-matched wire reason.
pub fn build_address_translations(
    cfg: &HostV1Config,
) -> Result<Vec<AddressTranslationPrefix>, String> {
    if !cfg.forward_address || cfg.forward_address_translations.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(cfg.forward_address_translations.len());
    for x in &cfg.forward_address_translations {
        let from = IpAddr::from_str(&x.from)
            .map_err(|_| format!("failed to parse 'from' address translation '{}'", x.from))?;
        let to = IpAddr::from_str(&x.to)
            .map_err(|_| format!("failed to parse 'to' address translation '{}'", x.to))?;
        out.push(AddressTranslationPrefix {
            from,
            to,
            bits: x.prefix_length,
        });
    }
    // Sort by prefix length DESC so the FIRST matching `from` is the longest-prefix (best) match.
    out.sort_by(|a, b| b.bits.cmp(&a.bits));
    Ok(out)
}

/// Apply the host's address translations to a resolved dial `address`, a faithful port of the oracle's
/// `translateAddress` (`hosting.go:374-393`): parse `address` as an IP (a NON-IP — a real `dst_hostname`
/// — is returned UNCHANGED, oracle `netip.ParseAddr` error → `return addr`); find the FIRST translation
/// whose `from` prefix contains it (the slice is pre-sorted longest-prefix-first, so this is the best
/// match); renumber the host bits onto the `to` network. No match → unchanged. NEVER errors per-dial: the
/// oracle's `translateIP` error is caught and `continue`d, never propagated — the only failure is the
/// startup parse in [`build_address_translations`].
///
/// Applied AFTER the allow-list check ([`get_address`](crate::tunnel::resolve::hostcfg::get_address)) and BEFORE the dial — the translated target is
/// dialed DIRECTLY and is NOT re-validated against `allowedAddresses` (faithful: the oracle's `Dial` dials
/// `translateAddress(GetAddress(...))` without re-checking, `hosting.go:402-415`). The operator's
/// translation config is trusted to redirect a dial OUTSIDE the allow-list.
#[must_use]
pub fn translate_address(address: &str, translations: &[AddressTranslationPrefix]) -> String {
    let Ok(ip) = IpAddr::from_str(address) else {
        return address.to_string(); // non-IP (a real hostname) → unchanged (oracle `ParseAddr` err)
    };
    for t in translations {
        // The `&&` short-circuit IS the oracle's control flow: on a `from`-Contains MISS we skip to the
        // next translation, and on the cross-family `translate_ip` `None` (the oracle's `translateIP`
        // error) we ALSO fall through to the next (oracle `continue`); only a contained, same-family
        // match returns (oracle `break`).
        if prefix_contains(t.from, t.bits, ip)
            && let Some(translated) = translate_ip(ip, t.to, t.bits)
        {
            return translated.to_string();
        }
    }
    address.to_string()
}

/// `netip.Prefix.Contains` for a `(from, bits)` prefix: `ip` is contained iff it is the SAME family as
/// `from`, `bits` is a VALID prefix length for that family (≤32 v4 / ≤128 v6 — an out-of-range `bits`
/// makes the oracle's `netip.PrefixFrom` build an INVALID prefix whose `Contains` is ALWAYS false, so the
/// translation is inert, NOT a startup error), and `ip` masked to `bits` equals `from` masked to `bits`.
/// Matches Go's `Contains` (incl. invalid-prefix→false and cross-family→false), differential-verified.
fn prefix_contains(from: IpAddr, bits: u8, ip: IpAddr) -> bool {
    match (from, ip) {
        (IpAddr::V4(f), IpAddr::V4(a)) => bits <= 32 && masked_eq(&f.octets(), &a.octets(), bits),
        (IpAddr::V6(f), IpAddr::V6(a)) => bits <= 128 && masked_eq(&f.octets(), &a.octets(), bits),
        // Cross-family: a v4 prefix never contains a v6 address and vice versa (a v4-mapped v6 literal
        // like `::ffff:10.0.0.7` parses to `IpAddr::V6` and so is NOT contained by a v4 prefix — oracle
        // `Contains` says the same: "a v6-mapped IPv6 address will not be contained in an IPv4 prefix").
        _ => false,
    }
}

/// Are the first `bits` bits of `x` and `y` equal? (`x`/`y` are same-length octet slices, `bits` already
/// validated `≤ len*8` by the caller.) The partial trailing byte is compared under a top-`rem`-bits mask.
fn masked_eq(x: &[u8], y: &[u8], bits: u8) -> bool {
    let bits = bits as usize;
    let full = bits / 8;
    if x[..full] != y[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = !(0xFFu8 >> rem); // the top `rem` bits of the partial byte
    (x[full] & mask) == (y[full] & mask)
}

/// `translateIP` (`hosting.go:310-358`): renumber `ip`'s host bits onto the `to` network (`to` masked to
/// `bits`). `ip`'s family equals `from`'s (guaranteed by [`prefix_contains`] having returned true) and
/// `bits` is in range. If `to` is a DIFFERENT family than `ip` returns `None` — a CONSCIOUS, safe-direction
/// deviation on a SCHEMA-UNREACHABLE input: the controller's `addressTranslation` schema is a `oneOf`
/// (`migration_initialize.go:297-321`) that forces `from`/`to` the SAME family (ipv4 with /0-32 OR ipv6
/// with /0-128), so a cross-family translation cannot be served. On such an input the oracle would either
/// byte-renumber across families (e.g. v4-`from`/v6-`to` → it slices the v6 `to`'s first 4 bytes), skip it
/// via its internal `Bits()` mismatch, or — for v6-`from`/v4-`to` with `bits` ≤ 32 — PANIC
/// (`ip.AsSlice()[:16]` indexing a 4-byte `to` → slice-bounds-out-of-range, a goroutine/host crash); we
/// instead skip it (the address is dialed UNCHANGED, i.e. the
/// allow-listed original — never a byte-soup target). Same family → the renumber always succeeds.
fn translate_ip(ip: IpAddr, to: IpAddr, bits: u8) -> Option<IpAddr> {
    match (ip, to) {
        (IpAddr::V4(a), IpAddr::V4(t)) => {
            Some(IpAddr::V4(renumber(a.octets(), t.octets(), bits).into()))
        }
        (IpAddr::V6(a), IpAddr::V6(t)) => {
            Some(IpAddr::V6(renumber(a.octets(), t.octets(), bits).into()))
        }
        _ => None, // cross-family (schema-unreachable): skip rather than dial a byte-soup target
    }
}

/// Renumber: `result[i] = (to[i] masked to the network) | (ip[i] host bits)`, the byte loop of the
/// oracle's `translateIP` (`hosting.go:333-345`). `to[i] & mask_byte` reproduces `toPrefix.Masked()` (the
/// `to` network with host bits zeroed); `ip[i] & !mask_byte` is `ip`'s host portion. `mask_byte` for byte
/// `i`: all-ones if the byte is fully within the prefix, a top-`bits_left`-bits mask for the partial byte
/// (`^(0xFF >> bitsLeft)` in Go), zero if the byte is fully host. Generic over `N` = 4 (v4) / 16 (v6).
fn renumber<const N: usize>(ip: [u8; N], to: [u8; N], bits: u8) -> [u8; N] {
    let bits = bits as usize;
    let mut result = [0u8; N];
    for i in 0..N {
        let mask_byte: u8 = if i * 8 < bits {
            let bits_left = bits - i * 8;
            if bits_left < 8 {
                !(0xFFu8 >> bits_left)
            } else {
                0xFF
            }
        } else {
            0
        };
        result[i] = (to[i] & mask_byte) | (ip[i] & !mask_byte);
    }
    result
}
