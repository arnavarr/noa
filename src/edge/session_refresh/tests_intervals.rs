//! Test de los knobs de timing (TB0: paridad de `PROD_SESSION_INTERVALS` con los defaults del
//! oráculo).
//! (F6 tramo 8: movidos verbatim del monolito de `edge/session_refresh`.)

use super::*;

use std::time::Duration;

// ───────────────────────── TB0: pure ─────────────────────────

/// TB0: the production session-refresh intervals equal the oracle's defaults (`options.go:17,19`).
#[test]
fn prod_session_intervals_match_oracle_defaults() {
    assert_eq!(
        PROD_SESSION_INTERVALS.interval,
        Duration::from_secs(3600),
        "DefaultSessionRefreshInterval = time.Hour (options.go:17)"
    );
    assert!(
        (PROD_SESSION_INTERVALS.jitter - 0.1).abs() < f64::EPSILON,
        "DefaultRefreshJitter = 0.1 (options.go:19)"
    );
}
