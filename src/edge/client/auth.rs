use super::{
    EdgeClient, MfaCodeProvider, controller_supports_oidc, expires_in_to_rfc3339, oidc_base,
    parse_error_envelope,
};

use crate::edge::auth_token::{ApiSessionType, AuthToken};
use crate::edge::error::EdgeError;
use crate::edge::model::{ApiSession, Envelope};
use crate::edge::oidc::OidcGrant;
use crate::edge::reauth::is_unauthorized;
use crate::edge::refresh::{do_oidc_session_refresh, do_reauthenticate, do_refresh_get};

/// Apply the api-session's control-plane auth header to a request builder, dispatched on the token
/// mode: legacy → `zt-session: <uuid>`; OIDC → `authorization: Bearer <jwt>`. The SINGLE place the
/// header fork lives (oracle `GetAccessHeader()`, `edge-apis/api_session.go:186`/`:330`), so every
/// control-plane call site routes through it instead of a hand-edited `.header("zt-session", …)`.
pub(crate) fn apply_access_header(
    req: reqwest::RequestBuilder,
    token: &AuthToken,
) -> reqwest::RequestBuilder {
    let (name, value) = token.access_header();
    req.header(name, value)
}

/// POST the legacy authentication for `method` (`cert`/`password`) with `body` and return the API
/// session. The shared core of [`do_authenticate`] (cert) and [`do_authenticate_password`] (updb):
/// `POST {base_url}/authenticate?method={method}` → status-to-`AuthHttp` → `Envelope<ApiSession>`
/// parse → the MFA gate. The caller's `client` carries any client identity (mTLS for cert; none for
/// password). Oracle: edge-apis `legacyAuth` (token in `data.token`) → `authenticate()` authQuery check
/// (`ziti.go:1175`).
///
/// **MFA gate (`authQueries` non-empty).** This is the SINGLE place a legacy partial session is
/// detected, so satisfying MFA here completes it for ALL three legacy entry points (`authenticate`,
/// `from_updb`, `do_reauthenticate`) from ONE implementation — the load-bearing invariant. With an
/// `mfa_provider` it satisfies the challenge ([`satisfy_legacy_mfa`]); without one it returns the
/// generic [`EdgeError::MfaRequired`] (BYTE-IDENTICAL to before this slice — the no-provider fallback,
/// faithful to the oracle's "no MFA TOTP code providers" warn, `ziti.go:1413`).
pub(crate) async fn legacy_authenticate(
    client: &reqwest::Client,
    base_url: &str,
    method: &str,
    body: &str,
    mfa_provider: Option<&MfaCodeProvider>,
) -> Result<ApiSession, EdgeError> {
    let url = format!("{base_url}/authenticate?method={method}");
    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| EdgeError::AuthResponse(e.to_string()))?;

    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| EdgeError::AuthResponse(e.to_string()))?;
    if !status.is_success() {
        let (code, message) = parse_error_envelope(&text);
        return Err(EdgeError::AuthHttp {
            status: status.as_u16(),
            code,
            message,
        });
    }
    let env: Envelope<ApiSession> =
        serde_json::from_str(&text).map_err(|e| EdgeError::AuthResponse(format!("json: {e}")))?;
    if !env.data.auth_queries.is_empty() {
        return satisfy_legacy_mfa(client, base_url, env.data, mfa_provider).await;
    }
    Ok(env.data)
}

/// Satisfy a legacy MFA challenge on a PARTIAL api-session (one whose `authQueries` is non-empty),
/// then return the COMPLETED session. Faithful port of `authenticateMfa` (`ziti.go:1365-1401`):
/// 1. obtain a TOTP code from `mfa_provider` (none → [`EdgeError::MfaRequired`], the no-provider
///    fallback, byte-identical to before this slice);
/// 2. `submit_mfa_code` → `POST /authenticate/mfa {code}` with `zt-session: <partial token>`;
/// 3. re-fetch the api-session ([`do_refresh_get`], the oracle's `Refresh()` `:1370`) to (a) CONFIRM
///    `authQueries` is now empty (termination, `:1396`) and (b) capture the post-MFA `expiresAt`.
///
/// **The 3rd `updateTokenOnAllErs` site (`:1388`) is a LEGACY no-op here.** A legacy session's
/// `RequiresRouterTokenUpdate()` is `false` (`api_session.go:169`), so the oracle's post-MFA push
/// reaches the gate and pushes NOTHING. `legacy_authenticate` has no live-channel registry (it is a
/// free function); the callers that DO (`EdgeClient`) push only on OIDC rotation
/// ([`crate::edge::refresh::push_token_to_live_channels`], gated identically). So the legacy MFA path
/// reaches the gate, whose faithful legacy verdict is "push nothing". The live test cannot observe a
/// push (gate); its value is MFA-auth → connect round-trip.
///
/// **TRIPWIRE — OIDC mid-session MFA push is DEFERRED (not delivered).** The site only does real work
/// for an OIDC session re-verifying MFA mid-session. The oracle SCAFFOLDS that path (`ziti.go:1376-1386`,
/// `RequiresRouterTokenUpdate()`=true `api_session.go:294`) but GATES it behind a nil stub:
/// `ApiSessionOidc.GetAuthQueries()` is `//todo; return nil` (`api_session.go:383`), so an OIDC session
/// carries NO `authQueries` in v1.7.0 — deferred in the ORACLE TOO. It would be `authenticateMfa` →
/// `/authenticate/mfa` → push the rotated Bearer.
/// In this SDK OIDC MFA is login-only (`/oidc/login/totp`, MFA-1); an OIDC session NEVER enters
/// `legacy_authenticate`/`satisfy_legacy_mfa` (its re-auth is the token-exchange grant, not the legacy
/// auth). So the non-vacuous case of the 3rd site is NOT delivered — a future OIDC-mid-session-MFA
/// slice must wire `push_token_to_live_channels` after the OIDC `/authenticate/mfa` submit.
///
/// CONSCIOUS DEVIATION: single-submit. The oracle is event-driven and may re-emit `EventMfaTotpCode`;
/// we are synchronous, so a still-pending session after one submit is [`EdgeError::MfaRequired`]. The
/// OIDC branch of `authenticateMfa` (`CreateTotpToken`/posture `SetTotpToken`, `:1376-1386`) is OUT OF
/// SCOPE (posture-token subsystem absent). NOTE: the `mfa_provider` runs while `reauth_lock` is held
/// on the re-auth/timer path (the OIDC-3 dedup pattern), so it must be NON-BLOCKING for background use
/// — a slow/interactive provider would stall control-plane ops on a 401. UNLIKE the oracle's off-stack
/// non-blocking emit-and-return, ours invokes `provider()` INLINE under `reauth_lock`.
async fn satisfy_legacy_mfa(
    client: &reqwest::Client,
    base_url: &str,
    partial: ApiSession,
    mfa_provider: Option<&MfaCodeProvider>,
) -> Result<ApiSession, EdgeError> {
    let provider = mfa_provider.ok_or(EdgeError::MfaRequired)?;
    let code = provider().map_err(|e| EdgeError::TotpProvider(e.to_string()))?;
    submit_mfa_code(client, base_url, &partial.token, &code).await?;
    // The oracle's `Refresh()` (`ziti.go:1370`): re-fetch over the SAME (now-upgraded) legacy token.
    let refreshed = do_refresh_get(client, base_url, &AuthToken::Legacy(partial.token)).await?;
    if !refreshed.auth_queries.is_empty() {
        // Still partial after one submit → unsatisfiable for our synchronous, single-submit flow.
        return Err(EdgeError::MfaRequired);
    }
    Ok(refreshed)
}

/// Submit a TOTP `code` to `POST {base_url}/authenticate/mfa` with the partial api-session's
/// `zt-session: <token>` header (`AuthenticateMFA`, `client.go:180-191`). 200 → Ok; 400 →
/// [`EdgeError::TotpCodeRejected`] (the controller's `MFA_INVALID_TOKEN`, probed live); any other
/// non-2xx → [`EdgeError::AuthHttp`]. The TOTP code lives in the REQUEST body (never logged).
async fn submit_mfa_code(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    code: &str,
) -> Result<(), EdgeError> {
    let url = format!("{base_url}/authenticate/mfa");
    let body = serde_json::json!({ "code": code }).to_string();
    let resp = client
        .post(&url)
        .header("zt-session", token)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| EdgeError::AuthResponse(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    if status == reqwest::StatusCode::BAD_REQUEST {
        return Err(EdgeError::TotpCodeRejected);
    }
    let text = resp.text().await.unwrap_or_default();
    let (err_code, message) = parse_error_envelope(&text);
    Err(EdgeError::AuthHttp {
        status: status.as_u16(),
        code: err_code,
        message,
    })
}

/// POST the legacy cert authentication and return the API session.
/// The mTLS client identity is carried by `client`; `base_url` is the ztAPI
/// (`https://host:port/edge/client/v1`). `body` is the JSON request body (`"{}"` works). An
/// `mfa_provider` satisfies a legacy MFA challenge if the controller returns a partial session
/// (`authQueries` non-empty); `None` → [`EdgeError::MfaRequired`] (byte-identical to before MFA support).
/// Oracle: edge-apis legacyAuth (`POST /authenticate?method=cert`, token in `data.token`).
pub async fn do_authenticate(
    client: &reqwest::Client,
    base_url: &str,
    body: &str,
    mfa_provider: Option<&MfaCodeProvider>,
) -> Result<ApiSession, EdgeError> {
    legacy_authenticate(client, base_url, "cert", body, mfa_provider).await
}

/// POST the legacy username/password authentication and return the API session. Used by the `updb`
/// path: the `client` carries NO client cert (a `updb` identity has none), and auth is by the
/// `{username, password}` body alone. `base_url` is the ztAPI. Oracle: edge-apis `legacyAuth` with
/// `AuthMethodUpdb = "password"` (`POST /authenticate?method=password`, token in `data.token`).
///
/// # Errors
/// [`EdgeError::AuthHttp`] on a non-2xx (e.g. 401 for bad credentials); [`EdgeError::AuthResponse`]
/// on transport failure or an unparseable body; [`EdgeError::MfaRequired`] if the api-session carries
/// MFA auth-queries and no `mfa_provider` is supplied (else MFA is satisfied via the provider).
pub async fn do_authenticate_password(
    client: &reqwest::Client,
    base_url: &str,
    username: &str,
    password: &str,
    mfa_provider: Option<&MfaCodeProvider>,
) -> Result<ApiSession, EdgeError> {
    // Build the body conditionally (username only if non-empty), matching the oracle (edge-api
    // `authenticate.go` `omitempty` + sdk-golang `UpdbCredentials.Payload`) and the sibling
    // `enroll::updb::request_updb`.
    let body = if username.is_empty() {
        serde_json::json!({ "password": password })
    } else {
        serde_json::json!({ "username": username, "password": password })
    }
    .to_string();
    legacy_authenticate(client, base_url, "password", &body, mfa_provider).await
}

impl EdgeClient {
    /// Authenticate (legacy cert) and store the API-session token + expiry, then spawn the proactive
    /// refresh timer (spawn-once; a second call does not re-spawn). Oracle: `Authenticate()` →
    /// `onFullAuth` → `firstAuthOnce.Do(go runRefreshes)` (`ziti.go:1066`).
    ///
    /// A legacy MFA identity returns a partial session (`authQueries` non-empty) → without a provider
    /// this is [`EdgeError::MfaRequired`]; use [`authenticate_with_totp`](Self::authenticate_with_totp).
    pub async fn authenticate(&mut self) -> Result<(), EdgeError> {
        self.authenticate_with_totp(None).await
    }

    /// [`authenticate`](Self::authenticate) for an MFA (TOTP) cert-identity: supply an owned
    /// `mfa_provider` ([`MfaCodeProvider`]) that returns a fresh TOTP code when the legacy cert auth
    /// returns a partial api-session. `authenticate()` delegates here with `None` (a legacy MFA
    /// challenge then → [`EdgeError::MfaRequired`]); a non-MFA identity is unaffected either way. The
    /// provider is STORED so a later session re-auth (slice reauth-401, which funnels through the SAME
    /// legacy cert auth) can re-satisfy MFA mid-session. Oracle: `authenticate()` → `handleAuthQuery`
    /// → `authenticateMfa` (`ziti.go:1163-1188`, `:1365`).
    ///
    /// # Errors
    /// As [`authenticate`](Self::authenticate), plus the TOTP errors
    /// ([`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]) when a provider is supplied.
    pub async fn authenticate_with_totp(
        &mut self,
        mfa_provider: Option<MfaCodeProvider>,
    ) -> Result<(), EdgeError> {
        let session =
            do_authenticate(&self.http, &self.base_url, "{}", mfa_provider.as_ref()).await?;
        self.identity_name = Some(session.identity.name);
        self.mfa_provider = mfa_provider;
        self.set_token_and_expiry(
            AuthToken::Legacy(session.token),
            session.expires_at.as_deref(),
        );
        self.spawn_refresh_timer();
        Ok(())
    }

    /// Authenticate via **OIDC** (cert grant) and store the Bearer api-session token + expiry, then
    /// spawn the proactive refresh timer. The OPT-IN sibling of [`authenticate`](Self::authenticate): the legacy
    /// constructors are unchanged; this is the explicit OIDC entry for a cert-identity (the v1.7.0
    /// default for a single-controller client is legacy — `oidcDynamicallyEnabled` defaults false,
    /// `client_edge_client.go:102`). Fails fast with [`EdgeError::OidcNotSupported`] if the controller
    /// does not advertise `OIDC_AUTH`.
    ///
    /// Drives the PKCE direct-grant flow ([`crate::edge::oidc::oidc_authenticate`]) over a dedicated
    /// NO-REDIRECT mTLS client (the same enrolment identity as `self.http`): the cert rides the mTLS
    /// transport so `/oidc/login/cert` authenticates, and — crucially — the cert-OIDC api-session is
    /// BOUND to the cert fingerprint (`z_cfs`), so subsequent control-plane calls MUST carry the cert.
    /// `self.http` is already that mTLS client, so the Bearer control-plane works. Oracle:
    /// `Authenticate()` → `oidcAuth` (`client_edge_client.go:149`, `clients_shared.go:290`).
    ///
    /// # Errors
    /// [`EdgeError::OidcNotSupported`] if the controller lacks `OIDC_AUTH`; the OIDC flow errors
    /// ([`EdgeError::OidcHttp`]/[`EdgeError::OidcResponse`]/[`EdgeError::TotpProviderRequired`]); a
    /// TLS-setup error building the no-redirect OIDC client.
    pub async fn authenticate_oidc(&mut self) -> Result<(), EdgeError> {
        self.authenticate_oidc_with_totp(None).await
    }

    /// [`authenticate_oidc`](Self::authenticate_oidc) for an MFA (TOTP) cert-identity: supply a
    /// `totp_provider` (see [`crate::edge::oidc::TotpCodeProvider`]) that returns a fresh TOTP code
    /// when the OIDC login signals `totp-required`. `authenticate_oidc()` delegates here with `None`
    /// (a `totp-required` login then → [`EdgeError::TotpProviderRequired`]); a non-MFA identity is
    /// unaffected either way. Oracle: the `TotpCodeProvider` carried by the `EdgeOidcAuthenticator`
    /// (`clients_shared.go:564`).
    ///
    /// # Errors
    /// As [`authenticate_oidc`](Self::authenticate_oidc), plus the TOTP errors
    /// ([`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]/[`EdgeError::TotpEnrollmentRequired`]).
    pub async fn authenticate_oidc_with_totp(
        &mut self,
        totp_provider: Option<&crate::edge::oidc::TotpCodeProvider<'_>>,
    ) -> Result<(), EdgeError> {
        self.authenticate_oidc_with_mfa(totp_provider, None).await
    }

    /// [`authenticate_oidc`](Self::authenticate_oidc) for a cert identity whose auth-policy REQUIRES
    /// TOTP MFA: supply BOTH a `totp_provider` (already-enrolled code) AND an `enroll_handler`
    /// (first-time enrollment; see [`crate::edge::oidc::TotpEnrollmentHandler`]). `authenticate_oidc`
    /// and `authenticate_oidc_with_totp` delegate here with `enroll_handler=None` (an enroll challenge
    /// then → [`EdgeError::TotpEnrollmentRequired`]). Additive: a non-MFA identity is unaffected.
    ///
    /// # Errors
    /// As [`authenticate_oidc`](Self::authenticate_oidc), plus the TOTP errors
    /// ([`EdgeError::TotpProviderRequired`]/[`EdgeError::TotpEnrollmentRequired`]/[`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]/[`EdgeError::TotpEnrollmentCodeRejected`]).
    pub async fn authenticate_oidc_with_mfa(
        &mut self,
        totp_provider: Option<&crate::edge::oidc::TotpCodeProvider<'_>>,
        enroll_handler: Option<&crate::edge::oidc::TotpEnrollmentHandler<'_>>,
    ) -> Result<(), EdgeError> {
        if !controller_supports_oidc(&self.http, &self.base_url).await {
            return Err(EdgeError::OidcNotSupported);
        }
        // A dedicated mTLS client with redirects disabled (the PKCE flow is stepped by hand). Same
        // enrolment identity as `self.http` (which carries the cert for the bound-session control-plane
        // calls).
        let oidc_http = crate::edge::identity_tls::oidc_mtls_client(&self.config)?;
        let tokens = crate::edge::oidc::oidc_authenticate(
            &oidc_http,
            &oidc_base(&self.base_url),
            &OidcGrant::Cert,
            totp_provider,
            enroll_handler,
        )
        .await?;
        let expires_at = expires_in_to_rfc3339(tokens.expires_in);
        self.identity_name = tokens.identity_name;
        self.set_token_and_expiry(
            AuthToken::Oidc {
                access: tokens.access,
                refresh: tokens.refresh,
            },
            // The OIDC expiry is `now + expires_in` (oracle `clients_shared.go:786`); we store it as an
            // RFC3339 string so the shared `store_token_and_expiry` parse path is reused.
            expires_at.as_deref(),
        );
        self.spawn_refresh_timer();
        Ok(())
    }

    /// Run a control-plane `op` with the current api-session token; on a 401 (the api-session
    /// expired), re-authenticate ONCE (deduped) and retry the op exactly once with the fresh token.
    /// A 1:1 mirror of the oracle's reactive on-401 pattern (`refreshServices` → `GetServices`,
    /// `ziti.go:916-927`): re-auth FAILURE ⇒ return the ORIGINAL op error (not the auth error);
    /// re-auth SUCCESS ⇒ one retry. `op` receives the token to use (the retry gets the rotated token),
    /// so the channel Hello / control-plane headers pick up the fresh token automatically.
    ///
    /// CONSCIOUS DEVIATION (spec §4): retry-once, not retry-until-budget — a persistent 401 after a
    /// successful re-auth means the fresh token is also rejected, so more retries won't help.
    ///
    /// `pub(crate)` so the connect path (`connect_inner` in `edge::conn`) can wrap its service
    /// resolution in it too (the bare `do_resolve_service` takes a raw client+token).
    pub(crate) async fn with_reauth_retry<T>(
        &self,
        op: impl AsyncFn(AuthToken) -> Result<T, EdgeError>,
    ) -> Result<T, EdgeError> {
        let token = self.auth_token().ok_or(EdgeError::NotAuthenticated)?;
        match op(token.clone()).await {
            Ok(value) => Ok(value),
            // LEGACY 401: the reactive re-auth path is `POST /authenticate`.
            Err(first)
                if is_unauthorized(&first) && token.session_type() == ApiSessionType::Legacy =>
            {
                // Re-auth failed (e.g. bad credentials → AuthHttp 401) → propagate the ORIGINAL 401,
                // not the auth error (oracle returns the original `err`). The dedup re-check compares
                // on the channel-token value the failed op carried.
                if self.reauthenticate(token.channel_token()).await.is_err() {
                    return Err(first);
                }
                let fresh = self.auth_token().ok_or(EdgeError::NotAuthenticated)?;
                op(fresh).await
            }
            // OIDC 401 (OIDC-3): the api-session is EXTENDED via the RFC 8693 token-exchange grant —
            // NOT a re-auth. The oracle's reactive arm (`RefreshApiSession`, OIDC branch) swaps tokens
            // on the SAME api-session (no `setUnauthenticated`, no cache clear). The deduped shared
            // helper rotates the token; we then retry the op ONCE with the rotated Bearer. A refresh
            // FAILURE (e.g. the refresh token itself expired) ⇒ propagate the ORIGINAL 401, mirroring
            // the legacy arm.
            Err(first)
                if is_unauthorized(&first) && token.session_type() == ApiSessionType::Oidc =>
            {
                if self
                    .oidc_session_refresh(token.channel_token())
                    .await
                    .is_err()
                {
                    return Err(first);
                }
                let fresh = self.auth_token().ok_or(EdgeError::NotAuthenticated)?;
                op(fresh).await
            }
            Err(other) => Err(other),
        }
    }

    /// Re-authenticate the api-session, DEDUPED: concurrent 401s collapse to ONE `/authenticate`.
    /// The dedup is the `reauth_lock` + a token re-check — after taking the gate, if the current
    /// token already differs from `token_used` (the one the failed op used), another op already
    /// re-authed, so skip (the retry uses the new token). Mirrors the oracle's `Authenticate()`
    /// (`authAttemptLock` + the "refreshed < 5s ago → skip" short-circuit, `ziti.go:1197-1217`); we
    /// dedup by token-identity instead of a 5s window (a conscious improvement, spec §4).
    ///
    /// On success the oracle's FULL `setUnauthenticated` is mirrored (`ziti.go:1153`+`:1156`):
    /// (1) the session-cert holder is CLEARED (the `ApiSessionCertificate = nil`): the old cert was
    /// minted under the now-stale api-session, so the next channel open re-mints under the fresh one
    /// (updb-only, `session_cert` is `Some`); and (2) the Dial-session cache is CLEARED (the
    /// `sessions.Clear()`): every cached Dial session was minted under the now-stale api-session, so
    /// leaving them would let `get_or_create_dial_session` return a stale session-token the router
    /// would reject — a wire state the oracle never emits. (Slice 9's refresh+retry-once would
    /// eventually self-heal it, but at the cost of a wasted dial + liveness probe; clearing here is
    /// the faithful fix.)
    ///
    /// This re-auth intentionally SKIPS the oracle's refresh-first probe (`Authenticate()` tries
    /// `RefreshApiSessionWithBackoff()` — a `GET /current-api-session` — before falling back to the
    /// full `POST /authenticate`, `ziti.go:1206`): for the reactive-on-401 target the api-session is
    /// already known-expired, so the refresh would 401 too and fall through anyway → the end-state is
    /// identical for our case (a conscious simplification, spec §4).
    ///
    /// `identity_name` is intentionally NOT updated: a re-auth is the SAME identity (cert or updb),
    /// so the name is invariant (spec §3.1).
    async fn reauthenticate(&self, token_used: &str) -> Result<(), EdgeError> {
        // Thin wrapper over the shared free helper (DRY with the proactive timer, which calls the SAME
        // `do_reauthenticate` on the SAME `Arc`s — so a proactive re-auth and a reactive one contend
        // on the SAME `reauth_lock` and dedup against each other). The helper holds the dedup gate +
        // the `setUnauthenticated` mirror (clear Dial cache + invalidate the updb session-cert).
        do_reauthenticate(
            &self.token,
            &self.expires_at,
            &self.reauth_lock,
            &self.dial_sessions,
            self.session_cert.as_ref(),
            &self.http,
            &self.base_url,
            &self.reauth_method,
            self.mfa_provider.as_ref(),
            token_used,
        )
        .await
    }

    /// Refresh an OIDC api-session via the RFC 8693 token-exchange grant, DEDUPED (OIDC-3). The OIDC
    /// counterpart of [`Self::reauthenticate`]: a thin wrapper over the shared free helper
    /// [`do_oidc_session_refresh`] (DRY with the proactive timer, which calls the SAME helper on the
    /// SAME `Arc`s → both contend on the SAME `reauth_lock`). Unlike `reauthenticate` it clears
    /// NOTHING (an OIDC refresh EXTENDS the same api-session — the Dial cache + the updb session-cert
    /// minted under it stay valid; the helper docs carry the full rationale). The refresh runs over
    /// `self.http` (the mTLS client for cert-OIDC, the non-mTLS token-only client for updb-OIDC — the
    /// token-exchange is a public grant, no client cert required). Called by both `with_reauth_retry`
    /// (reactive 401) and the public `refresh()`.
    pub(super) async fn oidc_session_refresh(&self, token_used: &str) -> Result<(), EdgeError> {
        do_oidc_session_refresh(
            &self.token,
            &self.expires_at,
            &self.reauth_lock,
            &self.http,
            &oidc_base(&self.base_url),
            token_used,
        )
        .await?;
        // OIDC-2: the access token just rotated → push it to every live edge-router channel. This is
        // the funnel for BOTH the reactive `with_reauth_retry` OIDC arm and the public `refresh()`
        // (both call this method), covering the oracle's reactive `RefreshApiSession` push
        // (`ziti.go:1279`). The push is gated on `RequiresRouterTokenUpdate()` inside
        // `push_token_to_live_channels` (OIDC-only) and collects per-channel failures without failing
        // the refresh.
        crate::edge::refresh::push_token_to_live_channels(&self.live_channels, &self.token).await;
        Ok(())
    }
}
