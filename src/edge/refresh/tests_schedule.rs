//! Tests del scheduling puro (`parse_expires_at`, `next_sleep`).
//! (F6 tramo 7: movidos verbatim del monolito de `edge/refresh`.)

use super::*;

use std::time::{Duration, SystemTime};

fn intervals() -> RefreshIntervals {
    RefreshIntervals {
        lead: Duration::from_secs(10),
        default: Duration::from_secs(30),
        retry: Duration::from_secs(5),
    }
}

/// Valid RFC3339 → Some; garbage / empty → None (best-effort, → the timer's DEFAULT sleep).
#[test]
fn parse_expires_at_handles_valid_and_garbage() {
    assert!(parse_expires_at("2026-06-17T12:00:00Z").is_some());
    assert!(parse_expires_at("2026-06-17T12:00:00.500Z").is_some());
    assert!(parse_expires_at("not-a-date").is_none());
    assert!(parse_expires_at("").is_none());
    // A bare host:port (the lenient kind Go's time.Parse would also reject) → None.
    assert!(parse_expires_at("12:00:00").is_none());
}

/// Scheduling (the oracle's `refreshAt = expiresAt - 10s`, then `time.Until`): expiry known and
/// comfortably ahead → `exp - lead - now`; expiry unknown → DEFAULT; expiry already past or within
/// the lead window → ZERO (fire immediately, no underflow).
#[test]
fn next_sleep_schedules_lead_before_expiry() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let iv = intervals();

    // Expiry 100s ahead → sleep 100 - 10 = 90s.
    let exp = now + Duration::from_secs(100);
    assert_eq!(
        next_sleep(Some(exp), now, &iv),
        Duration::from_secs(90),
        "exp - lead - now"
    );

    // Expiry unknown → DEFAULT (30s).
    assert_eq!(next_sleep(None, now, &iv), Duration::from_secs(30));

    // Expiry within the lead window (5s ahead, lead 10s) → fire NOW (ZERO), no underflow.
    let near = now + Duration::from_secs(5);
    assert_eq!(next_sleep(Some(near), now, &iv), Duration::ZERO);

    // Expiry already in the past → fire NOW (ZERO), no underflow.
    let past = now - Duration::from_secs(60);
    assert_eq!(next_sleep(Some(past), now, &iv), Duration::ZERO);
}
