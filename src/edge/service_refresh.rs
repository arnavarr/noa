//! Background service-refresh timer — the svc-refresh arm of the oracle's `runRefreshes`.
//!
//! T5 (svc-poller), slice T5-2b. The oracle's `runRefreshes` (`sdk-golang` v1.7.0 `ziti/ziti.go:1002`)
//! is ONE goroutine with a `select` over THREE independent timers (api-session refresh, service
//! refresh, session refresh). The api-session arm is ported as the proactive-refresh timer
//! ([`crate::edge::refresh::run_refreshes`]). This module ports the SERVICE-refresh arm
//! (`ziti.go:1067-1078`) as a SIBLING background task: the three arms fire on independent timers, so
//! splitting them into separate tasks is observably equivalent and keeps the blast radius off the
//! live-validated api-session timer. The task shares the SAME `Arc`s (token, the [`ServiceWatcher`],
//! `dial_sessions`, `last_service_update`) as the rest of [`crate::edge::client::EdgeClient`].
//!
//! # What it does
//! Every ~`RefreshInterval` (5 min, jittered ±10%) it runs the cheap update-check-gated refresh (the
//! free core of [`crate::edge::client::EdgeClient::poll_services_if_changed`]): `GET
//! /current-api-session/service-updates` and, only if the controller reports a change, `GET /services`
//! then a diff → fire the Added/Changed/Removed listeners and evict dial sessions for removed services. This
//! keeps an IDLE long-lived client's local service cache fresh (an idle client never polls on its own,
//! so without this its cache would go stale).
//!
//! # Conscious deviations (documented, safe-direction)
//! 1. **Opt-in vs auto-start (FORM deviation).** The oracle starts the svc-refresh arm unconditionally
//!    inside `runRefreshes`. We expose it as an explicit
//!    [`start_service_polling`](crate::edge::client::EdgeClient::start_service_polling)`(config_types)`:
//!    a library cannot guess the `configTypes` a consumer wants, and polling every 5 min for a client
//!    that never reads services is waste. Same observable once opted in; same class as T5-1's unified
//!    callback form deviation.
//! 2. **No api-session liveness within the tick (SCOPE/SIMPLICITY + safe-direction — NOT Send-forced).**
//!    The oracle's `refreshServices(false,false)` calls `ensureApiSession()` first AND re-auths on a
//!    401 `GetServices`. Our tick does NEITHER: it uses the free [`do_list_services`] (no reactive
//!    reauth-retry) and, on ANY non-unavailable error, logs + retries next tick. Reactive reauth in a
//!    spawned task IS possible — the proactive timer does exactly that via the free `do_reauthenticate`
//!    (this is NOT a Send limitation; only `with_reauth_retry`'s `AsyncFn` closure is non-Send). We omit
//!    it for SCOPE/SIMPLICITY because the svc timer's real target — an idle long-lived client — has its
//!    api-session kept fresh by the ALWAYS-ON proactive timer ([`run_refreshes`](crate::edge::refresh::run_refreshes)), so the tick reads a
//!    valid token every cycle and never 401s in steady state. Recovery bound (the TRUE worst case): a
//!    transient (scheduled-expiry) 401 self-heals within ≤ one jittered interval via the proactive
//!    timer's pre-emptive re-auth. A HARD server-side-revocation 401 (admin revoke / posture failure /
//!    controller restart of a still-locally-VALID session) is NOT caught reactively here — the oracle
//!    DOES catch it (its reactive 401 re-auth inside `refreshServices`, `ziti.go:892`/`:921`, self-heals
//!    within ≤1 svc interval), whereas ours stays stale until the PROACTIVE timer's next wake
//!    (`expiresAt − 10s`, up to ~one api-session window — 3-6× the svc interval, NOT one svc interval).
//!    Even then it is NEVER a PERMANENT miss (the legacy proactive re-auth self-heals it) and never a
//!    crash, but it IS observably NOISIER than the oracle on such a 401 (one extra fetch + an `error!`
//!    emitted twice) — so safe-direction, NOT strictly "same observable". The svc tick takes NO
//!    `reauth_lock` and writes NO token, so it can neither deadlock nor contend with the proactive
//!    timer's re-auth — both write `dial_sessions` only under its `std::sync::Mutex` (monotone removal:
//!    `clear` ⊇ `remove`, remove-of-absent is a no-op), end-state-consistent.
//!
//! # Send
//! Spawned with `tokio::spawn` (a library must not impose a `LocalSet` on its consumer), so the task
//! body is `Send`: it uses ONLY free `async fn`s over the shared `Arc`s and NEVER `with_reauth_retry`
//! (whose `AsyncFn` closure is non-Send). No `std::sync` guard crosses an `.await`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::edge::auth_token::AuthToken;
use crate::edge::client::{
    check_service_list_update_free, do_list_services, store_and_process_free,
};
use crate::edge::error::EdgeError;
use crate::edge::model::SessionDetail;
use crate::edge::refresh::read_token;
use crate::edge::services::{ServiceEvent, ServiceWatcher};

/// The svc-refresh timing knobs (the oracle's post-clamp/post-default values). Injectable so tests
/// drive the loop in milliseconds (mirrors [`crate::edge::refresh::RefreshIntervals`]); production
/// passes [`PROD_SERVICE_INTERVALS`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServiceRefreshIntervals {
    /// The base refresh period. Oracle: `RefreshInterval` defaulted to `DefaultServiceRefreshInterval`
    /// (5 min, `options.go:16`) and clamped to `>= MinRefreshInterval` (1 s) (`ziti.go:1006-1011`). We
    /// expose no interval knob, so [`PROD_SERVICE_INTERVALS`] bakes the post-clamp value.
    pub interval: Duration,
    /// The ± jitter fraction, capped at 0.5 (`jitter := min(options.RefreshJitter, 0.5)`,
    /// `ziti.go:1022`). Production default `DefaultRefreshJitter` = 0.1 (`options.go:19`).
    pub jitter: f64,
}

/// The oracle's pinned production timing: a 5-minute interval, ±10% jitter.
pub(crate) const PROD_SERVICE_INTERVALS: ServiceRefreshIntervals = ServiceRefreshIntervals {
    interval: Duration::from_secs(5 * 60),
    jitter: 0.1,
};

/// The `5*time.Second` floor of the oracle's ControllerUnavailable backoff (`ziti.go:1072`).
const BACKOFF_FLOOR: Duration = Duration::from_secs(5);
/// The `2*time.Minute` cap of the oracle's ControllerUnavailable backoff (`ziti.go:1071`).
const BACKOFF_CAP: Duration = Duration::from_secs(2 * 60);

/// A jittered refresh period: uniform in `[base·(1−jitter), base·(1+jitter)]`. `frac` is the random
/// draw (the oracle's `rand.Float64()` is `[0, 1)`; the production source [`rand_fraction`] may round
/// up to the CLOSED `[0, 1]`, benign — `frac=1.0` yields the exact upper endpoint `base·(1+jitter)`),
/// INJECTED so the bounds are unit-testable without a real RNG. Byte-faithful port of `jitteredDuration`
/// (`ziti.go:991-998`): `jitter <= 0 → base`; else `minD + frac·2·delta` with `delta = base·jitter`,
/// `minD = base − delta`.
#[must_use]
pub(crate) fn jittered_duration(base: Duration, jitter: f64, frac: f64) -> Duration {
    if jitter <= 0.0 {
        return base;
    }
    #[allow(clippy::cast_precision_loss)]
    let base_ns = base.as_nanos() as f64;
    let delta = base_ns * jitter;
    let min_d = base_ns - delta;
    // Go's `time.Duration(float64)` truncates toward zero; for `jitter ∈ (0, 0.5]` and `frac ∈ [0, 1]`
    // the value is `>= base·0.5 > 0`, so `.max(0.0)` is belt-and-suspenders, not load-bearing.
    let ns = (min_d + frac * 2.0 * delta).max(0.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Duration::from_nanos(ns as u64)
}

/// The ControllerUnavailable retry delay, uniform in `[5s, retryMax)` with
/// `retryMax = min(2min, interval/2)`. `frac` is the random draw in `[0, 1]` (see [`rand_fraction`];
/// `frac=1.0` yields exactly `retryMax`, the closed upper endpoint — finite + safe), INJECTED for
/// testability. Oracle (`ziti.go:1071-1073`):
/// ```text
/// retryMax  = min(2*time.Minute, svcRefreshInterval/2)
/// retryDelay = 5*time.Second + rand.Int63n(int64(retryMax - 5*time.Second))
/// ```
///
/// VALUE-faithful to Go with one harmless rounding deviation: `span.mul_f64(frac)` rounds to NEAREST
/// whereas Go's `int64(...)` truncates toward zero, so the Rust delay is up to +1ns at ~4% of draws —
/// never negative, never below the 5s floor, safe-direction (a hair longer backoff). We do NOT switch to
/// integer math: that would match a stand-in, not Go's real `rand.Int63n`, for no behavioral gain.
///
/// CONSCIOUS DEVIATION (panic-guard, safe-direction): the oracle's `rand.Int63n(n)` PANICS for
/// `n <= 0`, which happens when `retryMax <= 5s`, i.e. `svcRefreshInterval <= 10s` — reachable only via
/// a sub-10s interval, never the 5-min production value. We instead return the `5s` floor (the lower
/// endpoint of the oracle's intended `[5s, retryMax]` range when the span collapses), so a small
/// interval degrades gracefully instead of aborting the timer task.
#[must_use]
pub(crate) fn backoff_delay(interval: Duration, frac: f64) -> Duration {
    let retry_max = (interval / 2).min(BACKOFF_CAP);
    let span = retry_max.saturating_sub(BACKOFF_FLOOR);
    if span.is_zero() {
        return BACKOFF_FLOOR; // oracle would panic here (interval <= 10s)
    }
    BACKOFF_FLOOR + span.mul_f64(frac)
}

/// A random fraction in `[0, 1]` for jitter/backoff, from the OS RNG (`getrandom`, an existing dep — 0
/// new crates, no `ring`). NB the range is the CLOSED `[0, 1]`, not `[0, 1)` like Go's `rand.Float64()`:
/// `u64::MAX / 2^64` rounds UP to exactly `1.0` in f64 (`p ≈ 1e-16`), which is benign everywhere it is
/// used (`frac=1.0` → the exact upper interval endpoint, a finite delay, no panic/overflow). On the
/// (vanishingly unlikely) RNG failure we fall back to `0.5` (the distribution centre → the un-jittered
/// base interval) rather than unwrapping, so an RNG hiccup can NEVER abort the spawned timer task (a
/// propagated error / `.expect()` would). The `u64 → f64` precision loss (a uniform draw quantized to
/// f64) is intended — this is jitter, not a value that must round-trip.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn rand_fraction() -> f64 {
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_err() {
        return 0.5;
    }
    // u64 / 2^64 ∈ [0, 1).
    (u64::from_le_bytes(buf) as f64) / 18_446_744_073_709_551_616.0
}

/// One service-refresh cycle: the free, `Send` sibling of
/// [`EdgeClient::poll_services_if_changed`](crate::edge::client::EdgeClient::poll_services_if_changed).
/// Reads the CURRENT token (fresh each cycle, so a concurrent proactive rotation is picked up), runs
/// the update-check, and only on a reported change fetches + diffs via the extracted free cores. Mirrors
/// the same 503/other-error policy; the ONE intentional difference is the fetch: this uses the free
/// [`do_list_services`] (no reactive reauth-retry), vs the `&self` method's
/// `list_services_with_config_types` (see module deviation #2).
///
/// # Errors
/// [`EdgeError::ControllerUnavailable`] on a 503 update-check (the caller backs off);
/// [`EdgeError::NotAuthenticated`] if the token is `None` (transient — retry next tick); otherwise the
/// fetch's error (a 401 here simply errors, since the free fetch does not reauth-retry).
async fn service_refresh_tick(
    http: &reqwest::Client,
    base_url: &str,
    token: &Arc<RwLock<Option<AuthToken>>>,
    last_service_update: &Mutex<Option<i128>>,
    services: &ServiceWatcher,
    dial_sessions: &Mutex<HashMap<String, SessionDetail>>,
    config_types: &[String],
) -> Result<Vec<ServiceEvent>, EdgeError> {
    let token_val = read_token(token).ok_or(EdgeError::NotAuthenticated)?;
    let (check_needed, new_ts) = match check_service_list_update_free(
        http,
        base_url,
        &token_val,
        last_service_update,
    )
    .await
    {
        Ok(pair) => pair,
        // 503 → controller unavailable: WARN here (the oracle puts the warn in `refreshServices`,
        // `ziti.go:890`, NOT the svc-timer arm) and signal the caller to back off. The
        // `| ControllerUnavailable` half is forward-defense (today the free check only yields
        // `ServiceUpdatesHttp`/`...Response`/`NotAuthenticated`).
        Err(
            EdgeError::ServiceUpdatesHttp { status: 503, .. } | EdgeError::ControllerUnavailable,
        ) => {
            tracing::warn!("controller unavailable checking for service updates, will retry");
            return Err(EdgeError::ControllerUnavailable);
        }
        // Any OTHER check error → fetch anyway (mirrors the oracle's `else`-arm `checkService=true`,
        // `ziti.go:902`; and `poll_services_if_changed`'s collapsed arm). NB: the rationale is NOT
        // "the fetch reauth-retries" — the free `do_list_services` does not; we fetch to mirror
        // checkService=true, and a fetch failure just propagates → the timer retries next tick.
        Err(other) => {
            tracing::error!(error = %other, "failed to check if service list update is available");
            (true, None)
        }
    };
    if !check_needed {
        return Ok(Vec::new());
    }
    let fetched = do_list_services(http, base_url, &token_val, config_types).await?;
    Ok(store_and_process_free(
        last_service_update,
        services,
        dial_sessions,
        &fetched,
        new_ts,
    ))
}

/// The background svc-refresh timer task (sibling of [`super::refresh::run_refreshes`]). Ports the svc-refresh arm of
/// `runRefreshes` (`ziti.go:1067-1078`): arm the timer for one jittered interval (so there is NO
/// immediate initial poll, faithful to the oracle arming `svcRefreshTimer` before the loop), then loop —
/// run the tick; on [`EdgeError::ControllerUnavailable`] reschedule on the SHORTER backoff and continue
/// (skipping the normal re-arm); on any other error log + reschedule on the normal jittered interval; on
/// success reschedule on the normal jittered interval. Cancelled by
/// [`EdgeClient`](crate::edge::client::EdgeClient)'s `Drop` aborting the `JoinHandle`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_service_refreshes(
    http: reqwest::Client,
    base_url: String,
    token: Arc<RwLock<Option<AuthToken>>>,
    last_service_update: Arc<Mutex<Option<i128>>>,
    services: Arc<ServiceWatcher>,
    dial_sessions: Arc<Mutex<HashMap<String, SessionDetail>>>,
    config_types: Vec<String>,
    intervals: ServiceRefreshIntervals,
) {
    // The oracle arms `svcRefreshTimer` BEFORE the loop (`ziti.go:1024`) → the FIRST tick is one
    // jittered interval out (no immediate poll).
    let mut next = jittered_duration(intervals.interval, intervals.jitter, rand_fraction());
    loop {
        tokio::time::sleep(next).await;
        match service_refresh_tick(
            &http,
            &base_url,
            &token,
            &last_service_update,
            &services,
            &dial_sessions,
            &config_types,
        )
        .await
        {
            Err(EdgeError::ControllerUnavailable) => {
                // Oracle: shorter backoff, `continue` (does NOT re-arm the normal timer this round).
                next = backoff_delay(intervals.interval, rand_fraction());
                continue;
            }
            Err(e) => {
                // Oracle: `log.WithError(err).Error("failed to load service updates")` (`ziti.go:1076`),
                // then fall through to the normal re-arm. Retriable next tick, NOT fatal.
                tracing::error!(error = %e, "failed to load service updates");
            }
            Ok(_events) => {}
        }
        next = jittered_duration(intervals.interval, intervals.jitter, rand_fraction());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    // ───────────────────────── pure: jittered_duration ─────────────────────────

    /// `jitter <= 0` returns the base unchanged (oracle's early return, `ziti.go:992-994`).
    #[test]
    fn jittered_duration_zero_jitter_is_base() {
        let base = Duration::from_secs(300);
        assert_eq!(jittered_duration(base, 0.0, 0.0), base);
        assert_eq!(jittered_duration(base, 0.0, 0.9999), base);
        assert_eq!(
            jittered_duration(base, -0.1, 0.5),
            base,
            "negative jitter → base"
        );
    }

    /// The bounds: `frac=0` → `base·(1−jitter)`, `frac→1` → `base·(1+jitter)`, `frac=0.5` → `base`.
    #[test]
    fn jittered_duration_spans_the_jitter_window() {
        let base = Duration::from_secs(300); // 5 min
        let j = 0.1;
        // frac = 0 → minD = base·0.9 = 270s.
        assert_eq!(jittered_duration(base, j, 0.0), Duration::from_secs(270));
        // frac = 0.5 → centre = base = 300s.
        assert_eq!(jittered_duration(base, j, 0.5), base);
        // frac → 1 → ~base·1.1 = ~330s (frac is in [0,1), so just under the upper bound).
        let high = jittered_duration(base, j, 0.999_999);
        assert!(
            high > Duration::from_secs(329) && high <= Duration::from_secs(330),
            "near-upper bound ~330s, got {high:?}"
        );
        // Every draw stays within [270s, 330s].
        for &f in &[0.0, 0.25, 0.5, 0.75, 0.99] {
            let d = jittered_duration(base, j, f);
            assert!(
                d >= Duration::from_secs(270) && d <= Duration::from_secs(330),
                "frac {f} → {d:?} out of [270s,330s]"
            );
        }
    }

    /// The jitter cap is 0.5 (`min(opt, 0.5)`); at jitter=0.5 the window is `[base/2, 3·base/2]` and
    /// never underflows.
    #[test]
    fn jittered_duration_half_jitter_lower_bound_is_base_over_two() {
        let base = Duration::from_secs(300);
        assert_eq!(jittered_duration(base, 0.5, 0.0), Duration::from_secs(150));
        assert_eq!(jittered_duration(base, 0.5, 0.5), base);
    }

    // ───────────────────────── pure: backoff_delay ─────────────────────────

    /// Production interval (5 min): `retryMax = min(2min, 2.5min) = 2min`; delay ∈ `[5s, 2min)`.
    #[test]
    fn backoff_delay_production_spans_5s_to_2min() {
        let iv = Duration::from_secs(300);
        assert_eq!(
            backoff_delay(iv, 0.0),
            BACKOFF_FLOOR,
            "frac=0 → the 5s floor"
        );
        // frac=0.5 → 5s + 0.5·(120s−5s) = 5s + 57.5s = 62.5s.
        assert_eq!(backoff_delay(iv, 0.5), Duration::from_millis(62_500));
        // frac→1 → just under 2min.
        let high = backoff_delay(iv, 0.999_999);
        assert!(
            high > Duration::from_secs(119) && high < Duration::from_secs(120),
            "near-cap ~120s, got {high:?}"
        );
    }

    /// The 2-minute cap binds for large intervals: a 1-hour interval would give `interval/2 = 30min`,
    /// but `retryMax` is capped at 2 min, so the delay still tops out just under 2 min.
    #[test]
    fn backoff_delay_caps_retry_max_at_two_minutes() {
        let iv = Duration::from_secs(60 * 60); // 1h
        assert_eq!(backoff_delay(iv, 0.0), BACKOFF_FLOOR);
        let high = backoff_delay(iv, 0.999_999);
        assert!(
            high < Duration::from_secs(120),
            "capped at 2min, got {high:?}"
        );
    }

    /// PANIC-GUARD deviation: an interval `<= 10s` makes `retryMax <= 5s` → the oracle's
    /// `rand.Int63n(<=0)` would PANIC; we return the 5s floor instead (fail-safe, never aborts the
    /// task). A `wrapping`/unguarded port would either panic or underflow here.
    #[test]
    fn backoff_delay_small_interval_is_fail_safe_not_panic() {
        // interval/2 = 5s → span = 0 → floor.
        assert_eq!(backoff_delay(Duration::from_secs(10), 0.9), BACKOFF_FLOOR);
        // interval/2 = 4s < 5s → saturating_sub → 0 → floor (oracle would compute a NEGATIVE arg).
        assert_eq!(backoff_delay(Duration::from_secs(8), 0.5), BACKOFF_FLOOR);
        assert_eq!(backoff_delay(Duration::from_secs(1), 0.99), BACKOFF_FLOOR);
    }

    // ───────────────────────── timer (wiremock) ─────────────────────────

    /// A `/services` responder that counts hits and serves one service.
    struct CountingServices(Arc<AtomicUsize>);
    impl Respond for CountingServices {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            self.0.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_string(
                r#"{"data":[{"id":"s1","name":"alpha","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
            )
        }
    }

    fn tiny(interval_ms: u64) -> ServiceRefreshIntervals {
        ServiceRefreshIntervals {
            interval: Duration::from_millis(interval_ms),
            jitter: 0.0, // deterministic period for the window math
        }
    }

    fn legacy_token(tok: &str) -> Arc<RwLock<Option<AuthToken>>> {
        Arc::new(RwLock::new(Some(AuthToken::Legacy(tok.to_string()))))
    }

    /// The timer DRIVES the update-check-gated refresh: over a window it polls `/service-updates`
    /// repeatedly and, because the controller reports a CHANGING `lastChangeAt`, re-fetches `/services`
    /// each time → the listener fires. Pins that the spawned timer actually runs the tick (≥1) and is
    /// NOT a hot-loop (bounded by the interval). MUTATION: dropping the `sleep(next)` → the fetch count
    /// explodes past the bound; never calling the tick → 0 fetches.
    #[tokio::test]
    async fn timer_drives_gated_refresh_over_a_window() {
        // A monotonically-changing lastChangeAt → every check reports "changed" → a fetch each tick.
        struct Changing(Arc<AtomicUsize>);
        impl Respond for Changing {
            fn respond(&self, _req: &Request) -> ResponseTemplate {
                let n = self.0.fetch_add(1, Ordering::SeqCst);
                let secs = 10 + n; // distinct instant each call
                ResponseTemplate::new(200).set_body_string(format!(
                    r#"{{"data":{{"lastChangeAt":"2026-06-26T12:00:{secs:02}.000Z"}},"meta":{{}}}}"#
                ))
            }
        }
        crate::enroll::trust::ensure_crypto_provider();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/edge/client/v1/current-api-session/service-updates"))
            .respond_with(Changing(Arc::new(AtomicUsize::new(0))))
            .mount(&server)
            .await;
        let fetches = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/edge/client/v1/services"))
            .respond_with(CountingServices(fetches.clone()))
            .mount(&server)
            .await;

        let base = format!("{}/edge/client/v1", server.uri());
        let watcher = Arc::new(ServiceWatcher::new());
        let events = Arc::new(AtomicUsize::new(0));
        let events_cb = events.clone();
        watcher.add(Arc::new(move |_ev: &ServiceEvent| {
            events_cb.fetch_add(1, Ordering::SeqCst);
        }));
        let handle = tokio::spawn(run_service_refreshes(
            reqwest::Client::new(),
            base,
            legacy_token("T0"),
            Arc::new(Mutex::new(None)),
            watcher,
            Arc::new(Mutex::new(HashMap::new())),
            vec![],
            tiny(8), // ~8ms period
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
        handle.abort();

        let n = fetches.load(Ordering::SeqCst);
        assert!(n >= 1, "the timer ran the tick at least once");
        assert!(
            n < 60,
            "bounded by the ~8ms period, not a hot-loop: {n} fetches"
        );
        assert!(
            events.load(Ordering::SeqCst) >= 1,
            "the first changed poll fired the Added listener"
        );
    }

    /// On a `503` update-check the tick returns `ControllerUnavailable` and the timer BACKS OFF (it does
    /// NOT fetch `/services`, and does not hot-loop). With a small interval the backoff floor (5s) keeps
    /// the check count tiny over the window; `/services` is `expect(0)`.
    #[tokio::test]
    async fn timer_backs_off_on_controller_unavailable() {
        struct Unavailable(Arc<AtomicUsize>);
        impl Respond for Unavailable {
            fn respond(&self, _req: &Request) -> ResponseTemplate {
                self.0.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(503).set_body_string("unavailable")
            }
        }
        crate::enroll::trust::ensure_crypto_provider();
        let server = MockServer::start().await;
        let checks = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/edge/client/v1/current-api-session/service-updates"))
            .respond_with(Unavailable(checks.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/edge/client/v1/services"))
            .respond_with(ResponseTemplate::new(200).set_body_string("SHOULD-NOT-FETCH"))
            .expect(0)
            .mount(&server)
            .await;

        let base = format!("{}/edge/client/v1", server.uri());
        let handle = tokio::spawn(run_service_refreshes(
            reqwest::Client::new(),
            base,
            legacy_token("T0"),
            Arc::new(Mutex::new(None)),
            Arc::new(ServiceWatcher::new()),
            Arc::new(Mutex::new(HashMap::new())),
            vec![],
            tiny(8),
        ));
        // First tick at ~8ms → 503 → backoff floor 5s. Over a 60ms window only the FIRST check fires;
        // the backoff (5s) parks the rest.
        tokio::time::sleep(Duration::from_millis(60)).await;
        handle.abort();

        let n = checks.load(Ordering::SeqCst);
        assert!(n >= 1, "the timer checked at least once");
        assert!(
            n <= 3,
            "503 → 5s backoff parks further checks (no hot-loop): {n} checks in 60ms"
        );
        // `/services` expect(0) verified on drop: a 503 check never fetches.
    }

    /// A non-503 check error (here a 500) → "fetch anyway"; if the fetch THEN errors (500), the tick
    /// returns `Err`, the timer logs "failed to load service updates" and re-arms on the NORMAL jittered
    /// interval (it does NOT back off, and does NOT crash). Over the window the check fires repeatedly
    /// (bounded by the interval, not the 5s backoff). MUTATION: routing a non-503 error into the backoff
    /// arm would slash the count to ~1 (5s park); a panic-on-error would stop after the first.
    #[tokio::test]
    async fn timer_retries_next_tick_on_non_unavailable_error() {
        struct Err500(Arc<AtomicUsize>);
        impl Respond for Err500 {
            fn respond(&self, _req: &Request) -> ResponseTemplate {
                self.0.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(500).set_body_string("boom")
            }
        }
        crate::enroll::trust::ensure_crypto_provider();
        let server = MockServer::start().await;
        let checks = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/edge/client/v1/current-api-session/service-updates"))
            .respond_with(Err500(checks.clone()))
            .mount(&server)
            .await;
        // "fetch anyway" then the fetch ALSO 500s → tick Err → re-arm normal.
        Mock::given(method("GET"))
            .and(path("/edge/client/v1/services"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let base = format!("{}/edge/client/v1", server.uri());
        let handle = tokio::spawn(run_service_refreshes(
            reqwest::Client::new(),
            base,
            legacy_token("T0"),
            Arc::new(Mutex::new(None)),
            Arc::new(ServiceWatcher::new()),
            Arc::new(Mutex::new(HashMap::new())),
            vec![],
            tiny(8),
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
        handle.abort();

        let n = checks.load(Ordering::SeqCst);
        // Re-armed on the ~8ms interval (NOT the 5s backoff) → several checks over 60ms.
        assert!(
            n >= 2,
            "a non-503 error re-arms on the normal interval, not a 5s backoff: {n}"
        );
        assert!(n < 60, "still bounded by the interval, not a hot-loop: {n}");
    }
}
