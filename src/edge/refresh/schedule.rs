//! Scheduling puro del refresh proactivo: `RefreshIntervals`/`PROD_INTERVALS` (las constantes
//! pineadas del oráculo) y las fns puras `parse_expires_at`/`next_sleep`.
//! (F6 tramo 7: movido verbatim del monolito de `edge/refresh`.)

use std::time::{Duration, SystemTime};

/// Production refresh intervals (the oracle's pinned constants, `ziti.go:1026`/`:1057`/`:1054`):
/// lead = 10 s BEFORE `expiresAt`; default = 30 s when expiry is unknown; retry = 5 s on error.
/// Injectable so tests drive the loop in milliseconds (mirrors `session_cert_renew`'s clock
/// injection); production passes [`PROD_INTERVALS`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct RefreshIntervals {
    /// How long before `expiresAt` to refresh. Oracle: `expiresAt - 10s` (`ziti.go:1029`).
    pub lead: Duration,
    /// Sleep when the api-session expiry is unknown. Oracle: `now + 30s` (`ziti.go:1026`).
    pub default: Duration,
    /// Reschedule after a refresh error (or a `None` token). Oracle: `now + 5s` (`ziti.go:1045`/`:1054`).
    pub retry: Duration,
}

/// The oracle's pinned timing: 10 s lead, 30 s default, 5 s retry.
pub(crate) const PROD_INTERVALS: RefreshIntervals = RefreshIntervals {
    lead: Duration::from_secs(10),
    default: Duration::from_secs(30),
    retry: Duration::from_secs(5),
};

/// Parse the controller's RFC3339 `expiresAt` to a `SystemTime`. Best-effort: an unparseable or empty
/// value yields `None`, which the timer treats as "expiry unknown" → the DEFAULT sleep, faithful to
/// the oracle's nil-`GetExpiresAt()` default (`ziti.go:1026`). `time` is a 0-new-crate direct dep
/// (already transitive via rcgen/jsonwebtoken).
pub(crate) fn parse_expires_at(s: &str) -> Option<SystemTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(SystemTime::from)
}

/// The sleep until the next refresh, given the current api-session expiry and `now`. PURE (testable
/// without a real wait): `Some(exp)` → `saturating(exp - lead - now)` (≥0; if already within the lead
/// window, fire immediately, i.e. `Duration::ZERO`); `None` → `default`. Mirrors the oracle's
/// `refreshAt = expiresAt - 10s` (then `time.Until(refreshAt)`), with the 30 s default for nil expiry.
pub(crate) fn next_sleep(
    expires_at: Option<SystemTime>,
    now: SystemTime,
    intervals: &RefreshIntervals,
) -> Duration {
    match expires_at {
        // `exp - lead`, then the remaining time until that instant. Both subtractions saturate to
        // ZERO (fire now) rather than underflow, covering an already-past or imminent expiry.
        Some(exp) => exp
            .checked_sub(intervals.lead)
            .and_then(|deadline| deadline.duration_since(now).ok())
            .unwrap_or(Duration::ZERO),
        None => intervals.default,
    }
}
