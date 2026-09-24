//! El loop del timer (`run_session_refreshes`): arma el sleep jittered ANTES del primer tick
//! (`ziti.go:1024`) y re-arma tras cada tick, sin manejo de error ni backoff (`:1082-1083`).
//! (F6 tramo 8: movido verbatim del monolito de `edge/session_refresh`.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::edge::auth_token::AuthToken;
use crate::edge::model::SessionDetail;
use crate::edge::service_refresh::{jittered_duration, rand_fraction};

use super::{SessionRefreshIntervals, session_refresh_tick};

/// The background session-refresh timer task (sibling of `run_refreshes`/`run_service_refreshes`).
/// Ports the session-refresh arm of `runRefreshes` (`ziti.go:1080-1083`): arm the timer for one
/// jittered interval (so there is NO immediate initial poll, faithful to the oracle arming
/// `sessionRefreshTimer` BEFORE the loop, `:1024`), then loop — run the tick, re-arm on the normal
/// jittered interval. The session arm has NO error handling and NO backoff (`refreshSessions` returns
/// nothing). Cancelled by [`crate::edge::client::EdgeClient`]'s `Drop` aborting the `JoinHandle`.
pub(crate) async fn run_session_refreshes(
    http: reqwest::Client,
    base_url: String,
    token: Arc<RwLock<Option<AuthToken>>>,
    dial_sessions: Arc<Mutex<HashMap<String, SessionDetail>>>,
    intervals: SessionRefreshIntervals,
) {
    // The oracle arms `sessionRefreshTimer` BEFORE the loop (`ziti.go:1024`) → the FIRST tick is one
    // jittered interval out (no immediate poll).
    let mut next = jittered_duration(intervals.interval, intervals.jitter, rand_fraction());
    loop {
        tokio::time::sleep(next).await;
        session_refresh_tick(&http, &base_url, &token, &dial_sessions).await;
        // No error handling, no backoff (the session arm has neither, `ziti.go:1082-1083`).
        next = jittered_duration(intervals.interval, intervals.jitter, rand_fraction());
    }
}
