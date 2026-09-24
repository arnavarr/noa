use super::{EdgeClient, PAGE_LIMIT, apply_access_header, parse_error_envelope};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::edge::auth_token::AuthToken;
use crate::edge::error::EdgeError;
use crate::edge::model::{Envelope, Paginated, Service, SessionDetail};
use crate::edge::service_refresh::{
    PROD_SERVICE_INTERVALS, ServiceRefreshIntervals, run_service_refreshes,
};
use crate::edge::services::{ServiceEvent, ServiceListenerId};

/// GET the service list, following pagination. Sends the api-session auth header (`zt-session` for
/// legacy, `Authorization: Bearer` for OIDC) via [`apply_access_header`]. When `config_types` is
/// non-empty, each requested type is sent as a repeated `configTypes` query param so the controller
/// populates each service's `config` map for those types (the tunneler reads `host.v1` this way);
/// an empty slice sends NO `configTypes` param, leaving the wire byte-identical to before T4b-0 (so
/// connect/bind/list flows are unchanged). Oracle: ziti/client.go GetServices (limit 500,
/// offset += 500 until offset >= totalCount) + `:394` (`params.ConfigTypes = self.ConfigTypes`).
pub async fn do_list_services(
    client: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
    config_types: &[String],
) -> Result<Vec<Service>, EdgeError> {
    let mut out = Vec::new();
    let mut offset: i64 = 0;
    let url = format!("{base_url}/services");
    loop {
        // limit + offset, then a repeated `configTypes=<type>` for each requested type (in order).
        // reqwest form-encodes the values (serde_urlencoded); an empty `config_types` adds nothing.
        let mut query: Vec<(&str, String)> = vec![
            ("limit", PAGE_LIMIT.to_string()),
            ("offset", offset.to_string()),
        ];
        for ct in config_types {
            query.push(("configTypes", ct.clone()));
        }
        let resp = apply_access_header(client.get(&url).query(&query), token)
            .send()
            .await
            .map_err(|e| EdgeError::ServicesResponse(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| EdgeError::ServicesResponse(e.to_string()))?;
        if !status.is_success() {
            let (code, message) = parse_error_envelope(&text);
            return Err(EdgeError::ServicesHttp {
                status: status.as_u16(),
                code,
                message,
            });
        }
        let page: Paginated<Service> = serde_json::from_str(&text)
            .map_err(|e| EdgeError::ServicesResponse(format!("json: {e}")))?;
        let total = page.meta.pagination.total_count;
        out.extend(page.data);
        offset += PAGE_LIMIT;
        if offset >= total {
            break;
        }
    }
    Ok(out)
}

/// The `{ "lastChangeAt": <date-time> }` payload of `/current-api-session/service-updates`. Oracle
/// model: `CurrentAPISessionServiceUpdateList` (edge-api `rest_model`), whose `lastChangeAt` is
/// `validate.Required` (date-time) — so a valid response always carries it.
#[derive(Debug, serde::Deserialize)]
struct ServiceUpdates {
    #[serde(rename = "lastChangeAt")]
    last_change_at: String,
}

/// Parse an RFC3339 timestamp to its UTC instant in nanoseconds since the Unix epoch. INSTANT-based:
/// matches the oracle's `strfmt.DateTime.Equal` → `time.Time.Equal` (compares the absolute instant,
/// NOT the wall-clock+offset representation). Two timestamps that denote the same moment in different
/// offsets compare equal, exactly as the oracle's gate does. `None` on an unparseable value.
pub(crate) fn parse_last_change_at(s: &str) -> Option<i128> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(time::OffsetDateTime::unix_timestamp_nanos)
}

/// `GET {base_url}/current-api-session/service-updates` → the controller's `lastChangeAt` instant
/// (UTC ns since the Unix epoch). Sends the api-session auth header via [`apply_access_header`]
/// (`zt-session` for legacy, `Authorization: Bearer` for OIDC — so an OIDC session checks updates too).
/// A 503 is the controller's `ListServiceUpdatesServiceUnavailable`; the refresh path maps it to
/// [`EdgeError::ControllerUnavailable`]. This is a PURE check — it does NOT re-authenticate (faithful
/// to `IsServiceListUpdateAvailable`, which returns the error and lets `refreshServices` decide).
///
/// Oracle: the `ListServiceUpdates` REST call (`/current-api-session/service-updates`,
/// `current_api_session_client.go:641`) read by `IsServiceListUpdateAvailable` (`ziti/client.go:148`).
///
/// # Errors
/// [`EdgeError::ServiceUpdatesResponse`] on transport / an unparseable or missing `lastChangeAt`;
/// [`EdgeError::ServiceUpdatesHttp`] on a non-2xx (e.g. 503 unavailable, 401 expired session).
pub(crate) async fn do_service_updates_get(
    client: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
) -> Result<i128, EdgeError> {
    let url = format!("{base_url}/current-api-session/service-updates");
    let resp = apply_access_header(client.get(&url), token)
        .send()
        .await
        .map_err(|e| EdgeError::ServiceUpdatesResponse(e.to_string()))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| EdgeError::ServiceUpdatesResponse(e.to_string()))?;
    if !status.is_success() {
        let (code, message) = parse_error_envelope(&text);
        return Err(EdgeError::ServiceUpdatesHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }
    let env: Envelope<ServiceUpdates> = serde_json::from_str(&text)
        .map_err(|e| EdgeError::ServiceUpdatesResponse(format!("json: {e}")))?;
    parse_last_change_at(&env.data.last_change_at).ok_or_else(|| {
        EdgeError::ServiceUpdatesResponse(format!(
            "unparseable lastChangeAt: {:?}",
            env.data.last_change_at
        ))
    })
}

/// The free, `Send` core of [`EdgeClient::check_service_list_update`]: `GET /service-updates` and
/// compare its `lastChangeAt` instant against the stored last-seen one. Returns `(check_needed,
/// new_instant)` — `new_instant` is always `Some` on success (the field is required). Extracted so the
/// background svc-refresh timer ([`crate::edge::service_refresh`]) can reuse it WITHOUT borrowing
/// `&self` or pulling in the non-Send `with_reauth_retry`. The `std::sync::Mutex` guard is dropped
/// before the `.await` returns (it never crosses one). Oracle: `IsServiceListUpdateAvailable`
/// (`ziti/client.go:148`).
pub(crate) async fn check_service_list_update_free(
    http: &reqwest::Client,
    base_url: &str,
    token: &AuthToken,
    last_service_update: &Mutex<Option<i128>>,
) -> Result<(bool, Option<i128>), EdgeError> {
    let new_ts = do_service_updates_get(http, base_url, token).await?;
    let check_needed = {
        let stored = *last_service_update
            .lock()
            .expect("last_service_update mutex poisoned");
        // `nil || !Equal`: no prior instant → check; else check iff the instants differ.
        stored != Some(new_ts)
    };
    Ok((check_needed, Some(new_ts)))
}

/// The free core of [`EdgeClient::store_and_process`]: store `new_ts` as the last-seen service-update
/// instant, diff + fan out the events against the [`ServiceWatcher`](crate::edge::services::ServiceWatcher)
/// cache, and evict cached dial sessions for `Removed` services (oracle `deleteServiceSessions`).
/// Extracted so the background svc-refresh timer reuses the exact same cache/eviction bookkeeping. No
/// `.await` is held across either `std::sync::Mutex` guard. Oracle: `CtrlClt.lastServiceUpdate = ...;
/// processServiceUpdates(services)` (`ziti.go:930-931`).
pub(crate) fn store_and_process_free(
    last_service_update: &Mutex<Option<i128>>,
    services: &crate::edge::services::ServiceWatcher,
    dial_sessions: &Mutex<HashMap<String, SessionDetail>>,
    fetched: &[Service],
    new_ts: Option<i128>,
) -> Vec<ServiceEvent> {
    *last_service_update
        .lock()
        .expect("last_service_update mutex poisoned") = new_ts;
    let events = services.process(fetched);
    if events.iter().any(|e| matches!(e, ServiceEvent::Removed(_))) {
        let mut sessions = dial_sessions
            .lock()
            .expect("dial-session cache mutex poisoned");
        for ev in &events {
            if let ServiceEvent::Removed(svc) = ev {
                sessions.remove(&svc.id);
            }
        }
    }
    events
}

impl EdgeClient {
    /// Start the background service-refresh poller (OPT-IN). Spawns a sibling background task that
    /// periodically runs the update-check-gated service refresh (the free core of
    /// [`poll_services_if_changed`](Self::poll_services_if_changed)) requesting `config_types`, keeping
    /// the local service cache + registered [`add_service_listener`](Self::add_service_listener)
    /// listeners fresh for a long-lived/idle client (which otherwise never polls on its own). Idempotent
    /// (a second call is a no-op — start-once); the task is aborted on `Drop`.
    ///
    /// FORM deviation (conscious, same observable): the oracle auto-starts this arm inside
    /// `runRefreshes`. We make it explicit because a library cannot guess the `configTypes` a consumer
    /// wants, and polling every 5 min for a consumer that never reads services is waste. Same class as
    /// T5-1's unified-callback form deviation. See [`crate::edge::service_refresh`].
    ///
    /// The FIRST poll fires after one (jittered) interval — there is NO immediate initial fetch
    /// (faithful: the oracle arms `svcRefreshTimer` before the select loop). A consumer that wants the
    /// cache populated up front should call [`poll_services`](Self::poll_services) once before this.
    pub fn start_service_polling(&mut self, config_types: Vec<String>) {
        self.start_service_polling_with(config_types, PROD_SERVICE_INTERVALS);
    }

    /// [`start_service_polling`](Self::start_service_polling) with injectable intervals (tests drive the
    /// loop in milliseconds; production passes [`PROD_SERVICE_INTERVALS`]).
    pub(super) fn start_service_polling_with(
        &mut self,
        config_types: Vec<String>,
        intervals: ServiceRefreshIntervals,
    ) {
        if self.service_refresh_task.is_some() {
            return; // start-once
        }
        let task = tokio::spawn(run_service_refreshes(
            self.http.clone(),
            self.base_url.clone(),
            self.token.clone(),
            self.last_service_update.clone(),
            self.services.clone(),
            self.dial_sessions.clone(),
            config_types,
            intervals,
        ));
        self.service_refresh_task = Some(task);
    }

    /// List the identity's services. Requires a prior `authenticate()`. A 401 (expired api-session)
    /// triggers a reactive re-auth + retry-once (slice reauth-401; oracle `refreshServices` →
    /// `GetServices` on `ListServicesUnauthorized`, `ziti.go:916-927`).
    pub async fn list_services(&self) -> Result<Vec<Service>, EdgeError> {
        self.with_reauth_retry(async |token| {
            do_list_services(&self.http, &self.base_url, &token, &[]).await
        })
        .await
    }

    /// List the identity's services, requesting the given typed `config_types` (e.g. `["host.v1"]`) so
    /// each returned [`Service`]'s `config` map is populated for those types. The tunneler host (T4b-1)
    /// calls this to read a service's `host.v1` config via [`Service::host_v1_config`]. Like
    /// [`list_services`](Self::list_services), a 401 (expired api-session) triggers a reactive re-auth +
    /// retry-once. With an empty `config_types` this is wire-identical to `list_services`. Oracle:
    /// `ziti/client.go:394` (`params.ConfigTypes = self.ConfigTypes`).
    ///
    /// # Errors
    /// Same as [`list_services`](Self::list_services) (`ServicesHttp`/`ServicesResponse`/`NotAuthenticated`).
    pub async fn list_services_with_config_types(
        &self,
        config_types: &[String],
    ) -> Result<Vec<Service>, EdgeError> {
        self.with_reauth_retry(async |token| {
            do_list_services(&self.http, &self.base_url, &token, config_types).await
        })
        .await
    }

    /// Register a listener invoked once per service change (Added/Changed/Removed) detected by a
    /// subsequent [`poll_services`](Self::poll_services). Returns an id to deregister it via
    /// [`remove_service_listener`](Self::remove_service_listener). Multiple listeners may be
    /// registered; each receives every event. The callback must be `Send + Sync` (a future background
    /// svc-refresh timer, T5-2, fans out from a spawned task). Oracle: the `AddServiceAddedListener`/
    /// `...Changed...`/`...Removed...` registration methods (`ziti/ziti.go:351-415`), unified into one
    /// typed callback receiving a [`ServiceEvent`] (the `serviceCB`/`OnServiceUpdate` shape; see the
    /// [`services`](crate::edge::services) module docs for the conscious form deviation).
    pub fn add_service_listener(
        &self,
        listener: Arc<dyn Fn(&ServiceEvent) + Send + Sync>,
    ) -> ServiceListenerId {
        self.services.add(listener)
    }

    /// Deregister a service-event listener previously added with
    /// [`add_service_listener`](Self::add_service_listener), returning whether one was removed.
    /// Oracle: the remove-fn returned by `AddServiceAddedListener` (`ziti.go:368`).
    #[must_use]
    pub fn remove_service_listener(&self, id: ServiceListenerId) -> bool {
        self.services.remove(id)
    }

    /// Fetch the identity's services and reconcile them against the local cache, returning the
    /// Added/Changed/Removed [`ServiceEvent`]s and firing every registered listener (see
    /// [`add_service_listener`](Self::add_service_listener)). The FIRST poll reports every service as
    /// `Added` (the cache starts empty). A `Removed` service additionally evicts its cached dial
    /// session (the oracle's `deleteServiceSessions`, `ziti.go:712`/`:2141`; this SDK caches only Dial
    /// sessions, so there is no Bind entry to evict — faithful, as Bind sessions are not cached).
    ///
    /// Requires a prior `authenticate`; a 401 (expired api-session) triggers the reactive re-auth +
    /// retry-once inherited from [`list_services_with_config_types`](Self::list_services_with_config_types).
    /// Pass the typed `config_types` (e.g. `["host.v1".into()]`) you want populated in each
    /// [`Service`]'s `config` map — they participate in change detection ([`service_details_equal`](crate::edge::services::service_details_equal)
    /// compares `config`); pass `&[]` for a plain service set.
    ///
    /// Ports `RefreshServices` (forceRefresh, `ziti.go:867`) + the diff of `processServiceUpdates`
    /// (`:694`). The background svc-refresh timer (the `runRefreshes` svc arm) is deferred to T5-2b;
    /// the conditional, update-check-gated variant lands as
    /// [`poll_services_if_changed`](Self::poll_services_if_changed) (T5-2a).
    ///
    /// A forced poll RESETS the last-seen service-update instant to `None` (faithful to the oracle: in
    /// `refreshServices` the function-local `lastServiceUpdate` is never assigned in the force branch,
    /// so `CtrlClt.lastServiceUpdate = nil`, `ziti.go:930`), guaranteeing the next
    /// [`poll_services_if_changed`](Self::poll_services_if_changed)/timer check fetches once.
    ///
    /// # Errors
    /// Same as [`list_services_with_config_types`](Self::list_services_with_config_types)
    /// (`ServicesHttp`/`ServicesResponse`/`NotAuthenticated`).
    pub async fn poll_services(
        &self,
        config_types: &[String],
    ) -> Result<Vec<ServiceEvent>, EdgeError> {
        let fetched = self.list_services_with_config_types(config_types).await?;
        // Force path → store nil (the oracle's force branch leaves `lastServiceUpdate` unassigned).
        Ok(self.store_and_process(&fetched, None))
    }

    /// Seed the [`ServiceWatcher`](crate::edge::services::ServiceWatcher) cache with an
    /// already-fetched service list, so a subsequent [`poll_services_if_changed`](Self::poll_services_if_changed)
    /// diffs against the CURRENT set (only real deltas fire) instead of an empty cache (which would
    /// re-emit every service as `Added`). Mirrors the oracle's post-`Authenticate` `context.services`
    /// cache being warm before `runRefreshes` starts ticking (`ziti.go`). The all-`Added` events from
    /// seeding an empty cache are discarded (no listener is registered at this point). Does NOT set the
    /// last-service-update instant, so the first timer tick's update-check still fetches once, then
    /// diffs against this seeded cache → no spurious events; a benign extra fetch, no re-emit.
    ///
    /// The intercept subcommand builds its resolver from the same fetched list, then primes here so its
    /// live svc-poll arm sees only genuine changes.
    pub fn prime_service_cache(&self, services: &[Service]) {
        let _ = self.services.process(services);
    }

    /// Reconcile a freshly-fetched service list against the cache: store `new_ts` as the last-seen
    /// service-update instant, diff + fan out the events, and evict cached dial sessions for `Removed`
    /// services. The shared tail of [`poll_services`](Self::poll_services) (force, `new_ts = None`) and
    /// [`poll_services_if_changed`](Self::poll_services_if_changed) (the checked timestamp). Mirrors the
    /// oracle's `CtrlClt.lastServiceUpdate = lastServiceUpdate; processServiceUpdates(services)`
    /// (`ziti.go:930-931`) — the store happens BEFORE the diff. No `.await` is held across either
    /// `std::sync::Mutex` guard.
    fn store_and_process(&self, fetched: &[Service], new_ts: Option<i128>) -> Vec<ServiceEvent> {
        store_and_process_free(
            &self.last_service_update,
            &self.services,
            &self.dial_sessions,
            fetched,
            new_ts,
        )
    }

    /// Ask the controller whether the identity's service list has changed since this client last saw
    /// it: `GET /current-api-session/service-updates` and compare its `lastChangeAt` instant against the
    /// stored last-seen one. `Ok(true)` when no prior instant is stored OR the controller's differs;
    /// `Ok(false)` when they match (no refresh needed). A PURE check — it does NOT mutate the stored
    /// instant and does NOT re-authenticate (faithful to the oracle's `IsServiceListUpdateAvailable`,
    /// which returns `(true, nil, err)` on error and lets `refreshServices` decide).
    ///
    /// Oracle: `CtrlClient.IsServiceListUpdateAvailable` (`ziti/client.go:148`):
    /// `self.lastServiceUpdate == nil || !resp.LastChangeAt.Equal(*self.lastServiceUpdate)`.
    ///
    /// # Errors
    /// [`EdgeError::ServiceUpdatesHttp`] (incl. 503 unavailable / 401 expired) or
    /// [`EdgeError::ServiceUpdatesResponse`] from the GET; [`EdgeError::NotAuthenticated`] with no token.
    pub async fn is_service_list_update_available(&self) -> Result<bool, EdgeError> {
        Ok(self.check_service_list_update().await?.0)
    }

    /// The `(check_needed, new_instant)` pair behind [`is_service_list_update_available`](Self::is_service_list_update_available).
    /// `new_instant` is the controller's `lastChangeAt` (always `Some` on success — the field is
    /// required) so the fetch path can store the very instant the check observed (the oracle threads the
    /// SAME `lastServiceUpdate` from the check into `CtrlClt.lastServiceUpdate`, `ziti.go:893`/`:929`).
    /// Reads the stored instant under a short `std::sync::Mutex` guard dropped BEFORE the `.await`.
    async fn check_service_list_update(&self) -> Result<(bool, Option<i128>), EdgeError> {
        let token = self.auth_token().ok_or(EdgeError::NotAuthenticated)?;
        check_service_list_update_free(
            &self.http,
            &self.base_url,
            &token,
            &self.last_service_update,
        )
        .await
    }

    /// The update-check-gated service refresh: only fetch + diff when the controller reports a change.
    /// First `GET /current-api-session/service-updates`; if its `lastChangeAt` matches the last-seen
    /// instant, return no events WITHOUT fetching; otherwise fetch the service list, store the checked
    /// instant, and emit the Added/Changed/Removed events (firing listeners + evicting dial sessions for
    /// `Removed`, exactly like [`poll_services`](Self::poll_services)). This is the cheap poll the
    /// background svc-refresh timer (T5-2b) drives.
    ///
    /// Faithful port of `refreshServices(forceRefresh=false)` (`ziti.go:871`):
    /// * a 503 update-check (`ListServiceUpdatesServiceUnavailable`) → [`EdgeError::ControllerUnavailable`]
    ///   (the oracle returns `ErrControllerUnavailable`, `ziti.go:891`, which the timer treats as retriable);
    /// * any OTHER check error (incl. a 401 expired session) → fetch anyway. The oracle handles errors
    ///   PER-ARM (`ziti.go:889-903`): on the `else` arm it logs + `checkService = true`; on a 401 it
    ///   re-authenticates and re-checks. We COLLAPSE both into "fetch anyway", because the fetch
    ///   ([`list_services_with_config_types`](Self::list_services_with_config_types)) already carries the
    ///   reactive 401 re-auth + retry-once. CONSCIOUS DEVIATION (safe-direction, never a missed change),
    ///   precise about the two controller-reachable 401 sub-cases that make the observable NOT identical:
    ///   * 401 → re-auth SUCCEEDS → re-check reports UNCHANGED: the oracle sets `checkService = false`
    ///     (`ziti.go:896-897`) so the `if checkService || forceRefresh` gate (`:907`) is false → it does
    ///     ZERO fetches; we instead fetch once AND store nil, so the NEXT poll also fetches before
    ///     re-pinning the instant — up to two `GetServices` where the oracle does none. Bounded extra
    ///     control-plane load, NEVER a missed change.
    ///   * 401 → re-auth FAILS: the oracle logs + `return nil` (`ziti.go:894`→`:934`, i.e. `Ok` with no
    ///     fetch); we instead fetch (which itself reauth-retries) and propagate any fetch error as `Err`.
    ///     Fail-loud where the oracle is silent — a conscious safe-direction divergence.
    ///
    /// # Errors
    /// [`EdgeError::ControllerUnavailable`] on a 503 update-check; otherwise as
    /// [`poll_services`](Self::poll_services) (the fetch's errors propagate).
    pub async fn poll_services_if_changed(
        &self,
        config_types: &[String],
    ) -> Result<Vec<ServiceEvent>, EdgeError> {
        let (check_needed, new_ts) = match self.check_service_list_update().await {
            Ok(pair) => pair,
            // 503 → controller unavailable (retriable for the timer). Oracle: `ErrControllerUnavailable`
            // after the WARN (`ziti.go:890-891`). The `| ControllerUnavailable` half is forward-defense
            // for T5-2b (today `check_service_list_update` only yields `ServiceUpdatesHttp`/`...Response`/
            // `NotAuthenticated`, so it is structurally unreachable here).
            Err(
                EdgeError::ServiceUpdatesHttp { status: 503, .. }
                | EdgeError::ControllerUnavailable,
            ) => {
                tracing::warn!("controller unavailable checking for service updates, will retry");
                return Err(EdgeError::ControllerUnavailable);
            }
            // Any other check error (401/transport/parse) → fetch anyway (the fetch reauth-retries).
            // Mirror the oracle's `else`-arm log (`ziti.go:903`) instead of dropping the error silently
            // (the O1–O5 observability discipline): the collapsed arm subsumes the 401 path too.
            Err(other) => {
                tracing::error!(error = %other, "failed to check if service list update is available");
                (true, None)
            }
        };
        if !check_needed {
            return Ok(Vec::new());
        }
        let fetched = self.list_services_with_config_types(config_types).await?;
        Ok(self.store_and_process(&fetched, new_ts))
    }
}
