//! Los knobs de timing del session-refresh: `SessionRefreshIntervals` y la const de producción
//! `PROD_SESSION_INTERVALS` (paridad DV-A5 con el oráculo, `options.go:17,19`).
//! (F6 tramo 8: movido verbatim del monolito de `edge/session_refresh`.)

use std::time::Duration;

/// The session-refresh timing knobs (the oracle's post-clamp/post-default values). Injectable so tests
/// drive the loop in milliseconds (mirrors [`crate::edge::service_refresh::ServiceRefreshIntervals`]);
/// production passes [`PROD_SESSION_INTERVALS`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionRefreshIntervals {
    /// The base refresh period. Oracle: `SessionRefreshInterval` defaulted to
    /// `DefaultSessionRefreshInterval` (1 h, `options.go:17`) and clamped to `>= MinRefreshInterval`
    /// (1 s, `ziti.go:1015-1019`). We expose no interval knob, so [`PROD_SESSION_INTERVALS`] bakes the
    /// post-clamp value (1 h > 1 s, so the clamp never binds).
    pub interval: Duration,
    /// The ± jitter fraction, capped at 0.5 (`jitter := min(options.RefreshJitter, 0.5)`,
    /// `ziti.go:1021`). Production default `DefaultRefreshJitter` = 0.1 (`options.go:19`).
    pub jitter: f64,
}

/// The oracle's pinned production timing: a 1-hour interval, ±10% jitter.
pub(crate) const PROD_SESSION_INTERVALS: SessionRefreshIntervals = SessionRefreshIntervals {
    interval: Duration::from_secs(60 * 60),
    jitter: 0.1,
};
