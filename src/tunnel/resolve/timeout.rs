use std::time::Duration;

use crate::edge::model::HostV1Config;

// ----- T4b-2c: dial-timeout resolution (`GetDialTimeout` + the Go-duration parse). -----

/// Resolve the host's per-dial timeout from the service's `host.v1`, a faithful port of the oracle's
/// `GetDialTimeout` (`service.go:222-232`): `connectTimeout` (a Go-duration string) takes precedence over
/// `connectTimeoutSeconds` (whole seconds); when `listenOptions` is absent or neither is set, the host's
/// no-config `default` is used (the oracle passes `5 * time.Second`, [`HOST_DIAL_TIMEOUT`](crate::tunnel::host::HOST_DIAL_TIMEOUT), at
/// `hosting.go:144`). Computed ONCE at host startup (the oracle computes `dialTimeout` once in
/// `newHostingContext`), not per-dial.
///
/// PRECEDENCE (mutation-killer surface): a present `connectTimeout` is used EVEN IF it is malformed — the
/// oracle never reaches `connectTimeoutSeconds` once `ConnectTimeout != nil`, and a malformed string fails
/// the WHOLE `mapstructure` config decode (`service.go:391,397`) so the service is never hosted. We mirror
/// that: a present-but-unparseable `connectTimeout` is a hard `Err`, NOT a silent fall-through to
/// `connectTimeoutSeconds` or the default.
///
/// CONSCIOUS DEVIATIONS (named, safe-direction, reachable only from an unusual config — not the values a
/// `ziti edge` host.v1 normally carries):
/// 1. **Where the parse-failure surfaces.** The oracle parses `connectTimeout` at config DECODE (in
///    `GetConfigOfType`); our serde keeps the raw string ([`crate::edge::model::HostV1ListenOptions`]) and
///    we parse here, at host startup. Both outcomes are identical and observable: a malformed value means
///    the service is NOT hosted (the oracle's decode error vs our startup `Err`). This is an operator-
///    facing startup error, NOT a dialer-observable DialFailed, so the reason string is a CLEAR custom
///    message, not byte-matched to Go's `"time: invalid duration ..."` (same stance as `get_port`'s
///    truncated reason).
/// 2. **Non-positive resolved timeout → fail loud.** Go's `net.Dialer{Timeout}` treats a `Timeout <= 0`
///    as "no timeout" (an unbounded dial), but `tokio::time::timeout(Duration::ZERO, ...)` fires
///    IMMEDIATELY (the opposite), and an unbounded host dial would defeat the hang-protection invariant
///    T2/T4a rely on. So a resolved `"0s"` / `"-5s"` / `connectTimeoutSeconds: 0` is rejected loudly (the
///    host refuses to serve) rather than passed through — a conscious, safe-direction deviation reachable
///    only from a deliberately-degenerate config.
/// 3. **Integer-overflow handling (stricter than Go — a conscious improvement, NOT a faithful match).**
///    Go's `time.ParseDuration` accumulates with a WRAPPING `uint64 d += v` then post-checks `d > 1<<63`,
///    so a degenerate multi-term string whose nanosecond sum wraps modulo `2^64` is ACCEPTED by Go
///    (`"…808ns…808ns5s"`: two exactly-`2^63`-ns terms wrap the accumulator to 0, then `5s` → Go = 5s,
///    service hosted). Our [`parse_go_duration`] uses `checked_add`, which REJECTS the `2^64` wrap → we are
///    STRICTLY stricter / fail-closed (the host refuses to serve where Go would host with a wrapped value).
///    Reachable only from a hand-crafted ~43-char string of two ~292-year terms that no `ziti edge` host.v1
///    emits; NEVER an over-permit (a full differential vs `go time.ParseDuration` found zero
///    Rust-accepts-Go-rejects and zero value-mismatches on the realistic surface). We deliberately do NOT
///    mirror Go's overflow wraparound — replicating it would host a service for a nonsensical wrapped
///    timeout; rejecting it is the safe-direction improvement (same stance as the stricter-than-oracle
///    `iss` URL validation).
///
/// # Errors
/// Returns a clear startup reason when `connectTimeout` is unparseable or the resolved timeout is not a
/// positive duration. The reason is wrapped by [`crate::edge::error::EdgeError::HostForwardConfig`].
pub fn get_dial_timeout(cfg: &HostV1Config, default: Duration) -> Result<Duration, String> {
    let Some(opts) = &cfg.listen_options else {
        return Ok(default);
    };
    if let Some(ct) = &opts.connect_timeout {
        // connectTimeout (the Go-duration string) WINS; a malformed value does NOT fall back.
        let nanos = parse_go_duration(ct)
            .ok_or_else(|| format!("invalid host.v1 connectTimeout '{ct}'"))?;
        return positive_duration_from_nanos(nanos)
            .ok_or_else(|| format!("host.v1 connectTimeout '{ct}' must be a positive duration"));
    }
    if let Some(secs) = opts.connect_timeout_seconds {
        if secs == 0 {
            return Err(
                "host.v1 connectTimeoutSeconds must be a positive number of seconds".to_string(),
            );
        }
        return Ok(Duration::from_secs(u64::from(secs)));
    }
    Ok(default)
}

/// A resolved Go-duration (signed nanoseconds) → a positive `std::time::Duration`, or `None` for a
/// non-positive value (see [`get_dial_timeout`] deviation #2).
fn positive_duration_from_nanos(nanos: i64) -> Option<Duration> {
    // `try_from` rejects negatives; the `> 0` filter rejects zero. Both → None (non-positive).
    u64::try_from(nanos)
        .ok()
        .filter(|&n| n > 0)
        .map(Duration::from_nanos)
}

/// Faithful port of Go's `time.ParseDuration` (`time/format.go`), returning the duration in SIGNED
/// nanoseconds (Go's `time.Duration` is an `int64` ns count) or `None` on any parse error (Go returns an
/// error for: empty input, a missing/unknown unit, a bare number without a unit other than `"0"`, or
/// arithmetic overflow). Grammar: `[-+]?([0-9]*(\.[0-9]*)?<unit>)+`, units `ns`/`us`/`µs`/`μs`/`ms`/
/// `s`/`m`/`h`, with the special case that `"0"` alone is a valid zero.
///
/// FIDELITY: the load-bearing surface is the grammar ACCEPT/REJECT set (and thus the precedence/default
/// behavior of [`get_dial_timeout`]). It is differential-tested against `go time.ParseDuration` and matches
/// over the entire realistic input surface (zero Rust-accepts-Go-rejects, zero accepted-value mismatches);
/// the SOLE divergence is integer-overflow handling — deviation #3 on [`get_dial_timeout`] — where Go's
/// wrapping accumulator accepts a degenerate `2^64`-wrap string our `checked_add` rejects (fail-closed,
/// unreachable from a real config). Leading zeros in a NUMBER are accepted (`"01s"` → 1s) — unlike the IP
/// allow-list, this is NOT a security boundary, so the leading-zero strictness applied to CIDR octets
/// does not apply here. The fractional-nanosecond arithmetic mirrors Go's `float64` path (`1.5h`); it is
/// low-stakes for a dial timeout, and any residual ULP-level divergence is harmless.
///
/// The single-character bindings (`s`/`d`/`v`/`f`/`c`) mirror Go's `time/format.go` for verifiability.
#[allow(clippy::many_single_char_names)]
pub(super) fn parse_go_duration(s: &str) -> Option<i64> {
    let mut s = s;
    let mut d: u64 = 0;
    let mut neg = false;

    // Consume an optional leading sign.
    if let Some(&c) = s.as_bytes().first()
        && (c == b'-' || c == b'+')
    {
        neg = c == b'-';
        s = &s[1..];
    }
    // Special case: a lone "0" (after the sign) is a valid zero with no unit.
    if s == "0" {
        return Some(0);
    }
    if s.is_empty() {
        return None;
    }
    while !s.is_empty() {
        // The next character must be a digit or '.'.
        let b0 = s.as_bytes()[0];
        if b0 != b'.' && !b0.is_ascii_digit() {
            return None;
        }
        // Consume the integer part.
        let pl = s.len();
        let (v, rest) = leading_int(s)?;
        s = rest;
        let pre = pl != s.len();

        // Consume an optional fractional part.
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if !s.is_empty() && s.as_bytes()[0] == b'.' {
            s = &s[1..];
            let pl = s.len();
            let (nf, nscale, rest) = leading_fraction(s);
            f = nf;
            scale = nscale;
            s = rest;
            post = pl != s.len();
        }
        if !pre && !post {
            return None; // no digits at all (e.g. ".s")
        }

        // Consume the unit (run of non-digit, non-'.' bytes).
        let bytes = s.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'.' || c.is_ascii_digit() {
                break;
            }
            i += 1;
        }
        if i == 0 {
            return None; // missing unit
        }
        let unit = unit_nanos(&s[..i])?; // unknown unit → None
        s = &s[i..];

        // v *= unit, with Go's overflow checks (against 1<<63).
        if v > (1u64 << 63) / unit {
            return None;
        }
        let mut v = v * unit;
        if f > 0 {
            v += fraction_nanos(f, unit, scale);
            if v > (1u64 << 63) {
                return None;
            }
        }
        d = d.checked_add(v)?;
        if d > (1u64 << 63) {
            return None;
        }
    }
    if neg {
        // Go returns `-Duration(d)`; d may be exactly 1<<63 → i64::MIN. Avoid the negation overflow.
        return Some(if d == (1u64 << 63) {
            i64::MIN
        } else {
            -d.cast_signed()
        });
    }
    if d > (1u64 << 63) - 1 {
        return None;
    }
    Some(d.cast_signed())
}

/// Go's fractional term `uint64(float64(f) * (float64(unit) / scale))` (`time/format.go`). The casts
/// faithfully mirror Go's `float64` arithmetic for sub-unit fractions: `f` and `unit` are bounded well
/// within `f64`'s exact-integer range for any realistic duration, and the product is non-negative by
/// construction, so the truncating `as u64` reproduces Go's behavior.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn fraction_nanos(f: u64, unit: u64, scale: f64) -> u64 {
    (f as f64 * (unit as f64 / scale)) as u64
}

/// Go's `leadingInt`: consume a run of digits into a `u64`, with Go's overflow guards (against `1<<63`).
/// Returns `None` on overflow (Go's `errLeadingInt`, which `ParseDuration` maps to a generic error).
fn leading_int(s: &str) -> Option<(u64, &str)> {
    let bytes = s.as_bytes();
    let mut x: u64 = 0;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if !c.is_ascii_digit() {
            break;
        }
        if x > (1u64 << 63) / 10 {
            return None;
        }
        x = x * 10 + u64::from(c - b'0');
        if x > (1u64 << 63) {
            return None;
        }
        i += 1;
    }
    Some((x, &s[i..]))
}

/// Go's `leadingFraction`: consume a run of digits as the fractional part, tracking `scale` (10^digits)
/// and saturating (Go's `overflow` flag) past `1<<63` rather than erroring — extra fraction digits are
/// dropped, never an error. Single-char bindings (`x`/`c`/`y`/`i`) mirror Go's `time/format.go`.
#[allow(clippy::many_single_char_names)]
fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let bytes = s.as_bytes();
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if !c.is_ascii_digit() {
            break;
        }
        i += 1;
        if overflow {
            continue;
        }
        if x > ((1u64 << 63) - 1) / 10 {
            overflow = true;
            continue;
        }
        let y = x * 10 + u64::from(c - b'0');
        if y > (1u64 << 63) {
            overflow = true;
            continue;
        }
        x = y;
        scale *= 10.0;
    }
    (x, scale, &s[i..])
}

/// Go's `unitMap` (`time/format.go`): the nanosecond value of each duration unit, including BOTH micro
/// symbols (`µs` U+00B5 and `μs` U+03BC) and the ASCII `us`. Returns `None` for an unknown unit.
fn unit_nanos(u: &str) -> Option<u64> {
    match u {
        "ns" => Some(1),
        "us" | "µs" | "μs" => Some(1_000),
        "ms" => Some(1_000_000),
        "s" => Some(1_000_000_000),
        "m" => Some(60_000_000_000),
        "h" => Some(3_600_000_000_000),
        _ => None,
    }
}
