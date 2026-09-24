use super::{
    EdgeClient, ExtJwtConfig, MfaCodeProvider, controller_supports_oidc, do_authenticate_password,
    expires_in_to_rfc3339, oidc_base,
};
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, RwLock};
#[cfg(test)]
use std::time::SystemTime;

use crate::edge::auth_token::{ApiSessionType, AuthToken};
use crate::edge::error::EdgeError;
use crate::edge::identity_tls::mtls_client;
use crate::edge::oidc::OidcGrant;
use crate::edge::reauth::ReauthMethod;
use crate::edge::refresh::{
    PROD_INTERVALS, RefreshIntervals, do_refresh_get, parse_expires_at, run_refreshes,
    store_token_and_expiry,
};
use crate::edge::session_refresh::{
    PROD_SESSION_INTERVALS, SessionRefreshIntervals, run_session_refreshes,
};
use crate::enroll::identity::Config;

impl EdgeClient {
    /// Build from an enrolled identity. Does NOT authenticate yet.
    pub fn from_identity(cfg: &Config) -> Result<Self, EdgeError> {
        Ok(Self {
            base_url: cfg.zt_api.clone(),
            http: mtls_client(cfg)?,
            token: Arc::new(RwLock::new(None)),
            expires_at: Arc::new(RwLock::new(None)),
            // A cert-identity re-authenticates by mTLS cert-auth (the enrolment cert in `http`).
            reauth_method: Arc::new(ReauthMethod::Cert),
            // No MFA provider by default; `authenticate_with_totp` sets it for an MFA cert-identity.
            mfa_provider: None,
            reauth_lock: Arc::new(tokio::sync::Mutex::new(())),
            identity_name: None,
            config: cfg.clone(),
            dial_sessions: Arc::new(Mutex::new(HashMap::new())),
            // Cert-identity: the channel mTLS reads `config` directly (no renewal — its leaf is the
            // enrolment cert, not a short-lived session-cert). Byte-identical to before this slice.
            session_cert: None,
            // Not authenticated yet → no timer until `authenticate()` spawns it (spawn-once).
            refresh_task: None,
            live_channels: Arc::new(Mutex::new(Vec::new())),
            channel_pool: Arc::new(Mutex::new(HashMap::new())),
            tls_opens: Arc::new(AtomicUsize::new(0)),
            services: Arc::new(crate::edge::services::ServiceWatcher::new()),
            last_service_update: Arc::new(Mutex::new(None)),
            service_refresh_task: None,
            session_refresh_task: None,
            edge_router_url_filter: None,
        })
    }

    /// Build a READY (authenticated) client for a `updb` identity, end-to-end. A `updb` identity has
    /// no enrolment cert, so it cannot do the mTLS-cert auth `from_identity`+`authenticate` use.
    /// Instead this:
    /// 1. builds a NON-mTLS http client trusting `cfg.ca` (the control plane authenticates by token,
    ///    not by client cert — the oracle's `updb` client is RootCAs-only);
    /// 2. authenticates by password (`do_authenticate_password`) → api-session token + identity name;
    /// 3. mints an ephemeral mTLS client cert for the api-session
    ///    ([`crate::edge::session_cert::acquire_api_session_cert`], the oracle's
    ///    `NewApiSessionCertificate` — used here only to authenticate the edge-router channel);
    /// 4. synthesises a [`Config`] whose `id` is `{ cert: leaf, key: ephemeral, ca: cfg.ca }`, so the
    ///    channel's mTLS (which reads `config()`) uses the session-cert with ZERO changes to the
    ///    channel.
    ///
    /// The returned client is fully authenticated: `token` and `identity_name` are set. `connect()`
    /// works immediately. The control plane keeps using the token over the non-mTLS http client; only
    /// the router channel uses the session-cert. Oracle: `client.go` `NewApiSessionCertificate`
    /// (`:327`) + `GetIdentity` (`:303`, builds the router mTLS identity from the session-cert).
    ///
    /// # Errors
    /// - [`EdgeError::TlsSetup`] if the non-mTLS client can't be built from `cfg.ca`.
    /// - [`EdgeError::AuthHttp`]/[`EdgeError::AuthResponse`]/[`EdgeError::MfaRequired`] from the
    ///   password auth.
    /// - [`EdgeError::SessionCertHttp`]/[`EdgeError::SessionCertResponse`] from the cert mint.
    pub async fn from_updb(cfg: &crate::enroll::updb::UpdbConfig) -> Result<Self, EdgeError> {
        Self::from_updb_with_totp(cfg, None).await
    }

    /// [`from_updb`](Self::from_updb) for an MFA (TOTP) `updb` identity: supply an `mfa_provider`
    /// (an owned [`MfaCodeProvider`]) that returns a fresh TOTP code when the legacy password auth
    /// returns a partial api-session (`authQueries` non-empty). `from_updb()` delegates here with
    /// `None` (a legacy MFA challenge then → [`EdgeError::MfaRequired`]); a non-MFA identity is
    /// unaffected either way. The provider is STORED so a later session re-auth (slice reauth-401) can
    /// re-satisfy MFA mid-session. Oracle: `authenticate()` → `handleAuthQuery` → `authenticateMfa`
    /// (`ziti.go:1163-1188`, `:1365`).
    ///
    /// # Errors
    /// As [`from_updb`](Self::from_updb), plus the TOTP errors
    /// ([`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]) on a supplied-provider path.
    pub async fn from_updb_with_totp(
        cfg: &crate::enroll::updb::UpdbConfig,
        mfa_provider: Option<MfaCodeProvider>,
    ) -> Result<Self, EdgeError> {
        // (a) Non-mTLS http client trusting the controller CA bundle. `cfg.ca` is RAW PEM; the
        // anchor-gating `parse_ca_pems` yields the trust-anchor DERs `verified_client` expects.
        let ca_ders = crate::enroll::trust::parse_ca_pems(&cfg.ca);
        let http = crate::enroll::trust::verified_client(&ca_ders)
            .map_err(|e| EdgeError::TlsSetup(e.to_string()))?;

        // (b) Authenticate by password → token + identity name. The stored provider satisfies a legacy
        // MFA challenge in `legacy_authenticate`; `None` keeps the pre-MFA `MfaRequired` behaviour.
        let session = do_authenticate_password(
            &http,
            &cfg.zt_api,
            &cfg.username,
            &cfg.password,
            mfa_provider.as_ref(),
        )
        .await?;

        // (c) Mint the ephemeral session-cert for the router mTLS (S1 free function — no
        // `EdgeClient` exists yet). The control-plane auth here is the LEGACY password token.
        let session_expires_at = session.expires_at.clone();
        let auth = AuthToken::Legacy(session.token);
        let cert =
            crate::edge::session_cert::acquire_api_session_cert(&http, &cfg.zt_api, &auth).await?;

        // (d) Synthesise the channel's identity Config. The THREE id values are RAW PEM (cfg.ca via
        // `ders_to_pem`, leaf/key from S1) → add EXACTLY ONE `pem:` prefix to each (the channel's
        // `pem_value` ERRORs without it). Leaf-only (faithful: oracle keeps `certs[0]`).
        let config = Config {
            zt_api: cfg.zt_api.clone(),
            zt_apis: None,
            config_types: None,
            id: crate::enroll::identity::Id {
                cert: format!("pem:{}", cert.leaf_pem),
                key: format!("pem:{}", cert.key_pem),
                ca: format!("pem:{}", cfg.ca),
            },
        };

        // (f) The renewable session-cert holder. This — not the synthetic `config` above — is the
        // SOLE channel-TLS source for `updb` (see `channel_client_config`): the holder re-mints the
        // leaf on expiry (reusing the key), a CONSCIOUS IMPROVEMENT beyond the oracle (which never
        // renews; see `edge::session_cert_renew`). `root_ders` are the same anchors `verified_client`
        // used. The `config` leaf is kept only as the immutable record of the FIRST mint (e.g. so a
        // cert-identity-shaped `config()` still reads), never as the live TLS leaf on the `Some` path.
        let holder = crate::edge::session_cert_renew::SessionCertState::new(&cert, ca_ders)?;

        // (e) A READY client: token + identity name set, synthetic config, non-mTLS http, empty cache.
        let mut client = Self {
            base_url: cfg.zt_api.clone(),
            http,
            token: Arc::new(RwLock::new(Some(auth))),
            expires_at: Arc::new(RwLock::new(
                session_expires_at.as_deref().and_then(parse_expires_at),
            )),
            // A updb client re-authenticates by password over the same non-mTLS `http`; stash the
            // credentials (the password is redacted in `ReauthMethod`'s Debug; `EdgeClient` is not
            // `Debug`). On re-auth the session-cert holder is cleared so the next channel open
            // re-mints under the fresh api-session (oracle `setUnauthenticated`).
            reauth_method: Arc::new(ReauthMethod::Updb {
                username: cfg.username.clone(),
                password: cfg.password.clone(),
            }),
            // The stored provider re-satisfies MFA on a session re-auth (reauth-401 funnels through the
            // SAME legacy password auth as construction).
            mfa_provider,
            reauth_lock: Arc::new(tokio::sync::Mutex::new(())),
            identity_name: Some(session.identity.name),
            config,
            dial_sessions: Arc::new(Mutex::new(HashMap::new())),
            session_cert: Some(std::sync::Arc::new(tokio::sync::Mutex::new(holder))),
            refresh_task: None,
            live_channels: Arc::new(Mutex::new(Vec::new())),
            channel_pool: Arc::new(Mutex::new(HashMap::new())),
            tls_opens: Arc::new(AtomicUsize::new(0)),
            services: Arc::new(crate::edge::services::ServiceWatcher::new()),
            last_service_update: Arc::new(Mutex::new(None)),
            service_refresh_task: None,
            session_refresh_task: None,
            edge_router_url_filter: None,
        };
        // (g) Spawn the proactive refresh timer (this path authenticated → spawn-once).
        client.spawn_refresh_timer();
        Ok(client)
    }

    /// Build a READY (authenticated) client for a `updb` identity via **OIDC** (password grant),
    /// end-to-end. The OPT-IN OIDC sibling of [`from_updb`](Self::from_updb): the legacy `from_updb` is unchanged; this
    /// is the explicit OIDC entry. Like `from_updb` it has no enrolment cert, so the control-plane
    /// authenticates by the Bearer token (over a non-mTLS RootCAs-only client) and the router channel
    /// uses a freshly-minted api-session cert — but the mint here authenticates with the BEARER
    /// (`Authorization: Bearer`, not `zt-session`), which the controller accepts for a Bearer-authed
    /// api-session (probed live: 201).
    ///
    /// 1. NON-mTLS no-redirect http (RootCAs of `cfg.ca`; the OIDC flow is stepped by hand).
    /// 2. fail-fast if the controller lacks `OIDC_AUTH`.
    /// 3. OIDC password PKCE flow → Bearer access token (+ refresh, + identity name from the id_token).
    /// 4. mint the api-session cert with the Bearer (S1 endpoint, Bearer-authed) → channel mTLS leaf.
    /// 5. synthetic `Config` (`{cert: leaf, key: ephemeral, ca: cfg.ca}`) for the channel; the renewable
    ///    holder is the live TLS source.
    ///
    /// # Errors
    /// [`EdgeError::TlsSetup`] (non-mTLS client); [`EdgeError::OidcNotSupported`]; the OIDC flow errors;
    /// [`EdgeError::SessionCertHttp`]/[`EdgeError::SessionCertResponse`] from the Bearer-authed mint.
    pub async fn from_updb_oidc(cfg: &crate::enroll::updb::UpdbConfig) -> Result<Self, EdgeError> {
        Self::from_updb_oidc_with_totp(cfg, None).await
    }

    /// [`from_updb_oidc`](Self::from_updb_oidc) for an MFA (TOTP) updb identity: supply a
    /// `totp_provider` (see [`crate::edge::oidc::TotpCodeProvider`]) that returns a fresh TOTP code
    /// when the OIDC login signals `totp-required`. `from_updb_oidc` delegates here with `None`.
    /// Additive: a non-MFA updb identity is unaffected either way.
    ///
    /// # Errors
    /// As [`from_updb_oidc`](Self::from_updb_oidc), plus the TOTP errors
    /// ([`EdgeError::TotpProviderRequired`]/[`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]/[`EdgeError::TotpEnrollmentRequired`]).
    pub async fn from_updb_oidc_with_totp(
        cfg: &crate::enroll::updb::UpdbConfig,
        totp_provider: Option<&crate::edge::oidc::TotpCodeProvider<'_>>,
    ) -> Result<Self, EdgeError> {
        Self::from_updb_oidc_with_mfa(cfg, totp_provider, None).await
    }

    /// [`from_updb_oidc`](Self::from_updb_oidc) for an updb identity whose auth-policy REQUIRES TOTP
    /// MFA: supply BOTH a `totp_provider` (already-enrolled code) AND an `enroll_handler` (first-time
    /// enrollment; see [`crate::edge::oidc::TotpEnrollmentHandler`]). The login leg signalling
    /// `totp-required` is routed to whichever applies by `isTotpEnrolled`. `from_updb_oidc` and
    /// `from_updb_oidc_with_totp` delegate here with `enroll_handler=None` (an enroll challenge then →
    /// [`EdgeError::TotpEnrollmentRequired`]). Additive: a non-MFA updb identity is unaffected.
    ///
    /// # Errors
    /// As [`from_updb_oidc`](Self::from_updb_oidc), plus the TOTP errors
    /// ([`EdgeError::TotpProviderRequired`]/[`EdgeError::TotpEnrollmentRequired`]/[`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]/[`EdgeError::TotpEnrollmentCodeRejected`]).
    pub async fn from_updb_oidc_with_mfa(
        cfg: &crate::enroll::updb::UpdbConfig,
        totp_provider: Option<&crate::edge::oidc::TotpCodeProvider<'_>>,
        enroll_handler: Option<&crate::edge::oidc::TotpEnrollmentHandler<'_>>,
    ) -> Result<Self, EdgeError> {
        // (a) Non-mTLS RootCAs-only client; no auto-redirect (the OIDC flow is stepped by hand; the
        // control-plane + mint calls do not redirect, so a single no-redirect client serves both).
        let ca_ders = crate::enroll::trust::parse_ca_pems(&cfg.ca);
        let http = crate::enroll::trust::verified_client_no_redirect(&ca_ders)
            .map_err(|e| EdgeError::TlsSetup(e.to_string()))?;

        // (b) Fail-fast on a non-OIDC controller.
        if !controller_supports_oidc(&http, &cfg.zt_api).await {
            return Err(EdgeError::OidcNotSupported);
        }

        // (c) OIDC password PKCE flow → Bearer tokens + identity name.
        let tokens = crate::edge::oidc::oidc_authenticate(
            &http,
            &oidc_base(&cfg.zt_api),
            &OidcGrant::Password {
                username: cfg.username.clone(),
                password: cfg.password.clone(),
            },
            totp_provider,
            enroll_handler,
        )
        .await?;

        // (d) A READY OIDC client. OIDC-3 wired the OIDC api-session refresh in: the reactive 401 arm
        // and the public `refresh()` now EXTEND the session via the RFC 8693 token-exchange grant (NOT
        // a legacy re-auth — the OIDC-defer guard routes an OIDC token to `oidc_session_refresh`).
        // `reauth_method` is kept as `Updb` for the legacy-path machinery but is never reached for an
        // OIDC token. The proactive timer (spawned inside `finish_oidc_construction`) ACTIVELY refreshes
        // an OIDC session via the same token-exchange.
        Self::finish_oidc_construction(
            http,
            &cfg.zt_api,
            &cfg.ca,
            ca_ders,
            tokens,
            ReauthMethod::Updb {
                username: cfg.username.clone(),
                password: cfg.password.clone(),
            },
        )
        .await
    }

    /// Build a READY (authenticated) client from an **external IdP JWT** (ext-jwt) via OIDC,
    /// end-to-end. The OPT-IN OIDC sibling of [`from_updb_oidc`](Self::from_updb_oidc) for the
    /// `ext-jwt` credential: the identity PRE-EXISTS in the controller (bound by `externalId` to the
    /// JWT `sub`), so there is no enrolment, no username/password and no client cert — the external JWT
    /// is presented as `Authorization: Bearer <jwt>` on the OIDC login POST
    /// (`/oidc/login/ext-jwt`). The control-plane then authenticates by the minted OIDC Bearer (over a
    /// non-mTLS RootCAs-only client) and the router channel uses a freshly-minted api-session cert
    /// (the same S1 mint `from_updb_oidc` uses, here Bearer-authed).
    ///
    /// 1. NON-mTLS no-redirect http (RootCAs of `cfg.ca`; the OIDC flow is stepped by hand).
    /// 2. fail-fast if the controller lacks `OIDC_AUTH`.
    /// 3. OIDC **ext-jwt** PKCE flow ([`OidcGrant::ExtJwt`]) → Bearer access token (+ refresh, +
    ///    identity name from the id_token).
    /// 4. mint the api-session cert with the Bearer → channel mTLS leaf.
    /// 5. synthetic `Config` for the channel; the renewable holder is the live TLS source.
    ///
    /// The returned client is fully authenticated; `connect()`/`bind()` work immediately. An OIDC
    /// session's liveness is the RFC 8693 token-exchange refresh (OIDC-3) — proactive timer + reactive
    /// on-401 + `refresh()` — so the ext-jwt session lives until its OIDC **refresh token** expires
    /// (~24h). `reauth_method` is [`ReauthMethod::ExtJwt`], a fail-loud guard that is unreachable via
    /// any current path (the OIDC dispatch routes the session to the token-exchange refresh, never to
    /// the legacy `do_reauthenticate`); it is a tripwire for a future refactor, not a live code path.
    ///
    /// # Named deferral (not a silent cliff)
    /// RE-PRESENTATION of the external JWT at the ~24h OIDC refresh-token cliff is DEFERRED. When the
    /// OIDC refresh token finally expires, the SDK would need to re-present the external JWT (a
    /// re-login), which requires a JWT-provider callback this SDK does not have yet. The oracle RECOVERS
    /// at this cliff (if the stored JWT is still valid): it re-presents the STORED JWT at a full re-auth
    /// — `JwtCredentials.AuthenticateRequest`
    /// (`credentials.go:340`) adds `"Bearer "+c.JWT`, `LoginWithJWT` (`ziti.go:657-669`) stores that
    /// credential, and `Authenticate()`→`authenticate()` (`ziti.go:1197`) re-uses it. We DEFER that
    /// re-presentation; a later slice can add the provider callback. (This deferral is SEPARATE from the
    /// [`ReauthMethod::ExtJwt`] guard above, which is about the unreachable legacy re-auth arm — not the
    /// missing re-presentation feature.)
    ///
    /// # Errors
    /// [`EdgeError::TlsSetup`] (non-mTLS client); [`EdgeError::OidcNotSupported`]; the OIDC flow errors
    /// (a 401 at login = a bad/rejected external JWT or a wrong `sub`/`aud` binding);
    /// [`EdgeError::SessionCertHttp`]/[`EdgeError::SessionCertResponse`] from the Bearer-authed mint.
    pub async fn from_ext_jwt(jwt: &str, cfg: &ExtJwtConfig) -> Result<Self, EdgeError> {
        Self::from_ext_jwt_with_totp(jwt, cfg, None).await
    }

    /// [`from_ext_jwt`](Self::from_ext_jwt) for an MFA (TOTP) ext-jwt identity: supply a
    /// `totp_provider` (see [`crate::edge::oidc::TotpCodeProvider`]) that returns a fresh TOTP code
    /// when the OIDC login signals `totp-required`. `from_ext_jwt` delegates here with `None`.
    /// Additive: a non-MFA ext-jwt identity is unaffected either way.
    ///
    /// # Errors
    /// As [`from_ext_jwt`](Self::from_ext_jwt), plus the TOTP errors
    /// ([`EdgeError::TotpProviderRequired`]/[`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]/[`EdgeError::TotpEnrollmentRequired`]).
    pub async fn from_ext_jwt_with_totp(
        jwt: &str,
        cfg: &ExtJwtConfig,
        totp_provider: Option<&crate::edge::oidc::TotpCodeProvider<'_>>,
    ) -> Result<Self, EdgeError> {
        Self::from_ext_jwt_with_mfa(jwt, cfg, totp_provider, None).await
    }

    /// [`from_ext_jwt`](Self::from_ext_jwt) for an ext-jwt identity whose auth-policy REQUIRES TOTP MFA:
    /// supply BOTH a `totp_provider` (already-enrolled code) AND an `enroll_handler` (first-time
    /// enrollment; see [`crate::edge::oidc::TotpEnrollmentHandler`]). `from_ext_jwt` and
    /// `from_ext_jwt_with_totp` delegate here with `enroll_handler=None` (an enroll challenge then →
    /// [`EdgeError::TotpEnrollmentRequired`]). Additive: a non-MFA ext-jwt identity is unaffected.
    ///
    /// # Errors
    /// As [`from_ext_jwt`](Self::from_ext_jwt), plus the TOTP errors
    /// ([`EdgeError::TotpProviderRequired`]/[`EdgeError::TotpEnrollmentRequired`]/[`EdgeError::TotpProvider`]/[`EdgeError::TotpCodeRejected`]/[`EdgeError::TotpEnrollmentCodeRejected`]).
    pub async fn from_ext_jwt_with_mfa(
        jwt: &str,
        cfg: &ExtJwtConfig,
        totp_provider: Option<&crate::edge::oidc::TotpCodeProvider<'_>>,
        enroll_handler: Option<&crate::edge::oidc::TotpEnrollmentHandler<'_>>,
    ) -> Result<Self, EdgeError> {
        // (a) Non-mTLS RootCAs-only no-redirect client (the OIDC flow is stepped by hand).
        let ca_ders = crate::enroll::trust::parse_ca_pems(&cfg.ca);
        let http = crate::enroll::trust::verified_client_no_redirect(&ca_ders)
            .map_err(|e| EdgeError::TlsSetup(e.to_string()))?;

        // (b) Fail-fast on a non-OIDC controller.
        if !controller_supports_oidc(&http, &cfg.zt_api).await {
            return Err(EdgeError::OidcNotSupported);
        }

        // (c) OIDC ext-jwt PKCE flow → Bearer tokens + identity name. The external JWT rides the login
        // POST as `Authorization: Bearer <jwt>` (see `OidcGrant::ExtJwt`).
        let tokens = crate::edge::oidc::oidc_authenticate(
            &http,
            &oidc_base(&cfg.zt_api),
            &OidcGrant::ExtJwt {
                jwt: jwt.to_string(),
            },
            totp_provider,
            enroll_handler,
        )
        .await?;

        // (d) A READY OIDC client (shared tail). `ReauthMethod::ExtJwt` is the fail-loud guard — never
        // reached for an OIDC session (its liveness is the OIDC token-exchange refresh, OIDC-3).
        Self::finish_oidc_construction(
            http,
            &cfg.zt_api,
            &cfg.ca,
            ca_ders,
            tokens,
            ReauthMethod::ExtJwt,
        )
        .await
    }

    /// Shared tail of the OIDC token-based constructors ([`from_updb_oidc`](Self::from_updb_oidc),
    /// [`from_ext_jwt`](Self::from_ext_jwt)): turn a successful OIDC PKCE flow into a READY client.
    /// Mints the api-session cert with the Bearer (S1, Bearer-authed — probed live: 201), synthesises
    /// the channel identity `Config` (leaf-only, faithful `certs[0]`), wires the renewable session-cert
    /// holder (the SOLE live channel-TLS source), and spawns the proactive refresh timer (spawn-once).
    /// The callers differ ONLY in the grant they ran and the `reauth_method` they pass (which is never
    /// reached for an OIDC session — the OIDC dispatch routes refresh to the token-exchange grant).
    async fn finish_oidc_construction(
        http: reqwest::Client,
        zt_api: &str,
        ca_pem: &str,
        ca_ders: Vec<Vec<u8>>,
        tokens: crate::edge::oidc::OidcTokens,
        reauth_method: ReauthMethod,
    ) -> Result<Self, EdgeError> {
        let auth = AuthToken::Oidc {
            access: tokens.access,
            refresh: tokens.refresh,
        };
        // Mint the ephemeral session-cert for the router mTLS, authenticated with the BEARER.
        let cert =
            crate::edge::session_cert::acquire_api_session_cert(&http, zt_api, &auth).await?;
        // Synthetic channel identity Config (leaf-only). Each id value carries EXACTLY ONE `pem:`.
        let config = Config {
            zt_api: zt_api.to_string(),
            zt_apis: None,
            config_types: None,
            id: crate::enroll::identity::Id {
                cert: format!("pem:{}", cert.leaf_pem),
                key: format!("pem:{}", cert.key_pem),
                ca: format!("pem:{ca_pem}"),
            },
        };
        let holder = crate::edge::session_cert_renew::SessionCertState::new(&cert, ca_ders)?;
        let mut client = Self {
            base_url: zt_api.to_string(),
            http,
            token: Arc::new(RwLock::new(Some(auth))),
            expires_at: Arc::new(RwLock::new(
                expires_in_to_rfc3339(tokens.expires_in)
                    .as_deref()
                    .and_then(parse_expires_at),
            )),
            reauth_method: Arc::new(reauth_method),
            // OIDC sessions satisfy MFA via the transient borrowed `TotpCodeProvider` at login (MFA-1),
            // not the stored LEGACY provider; an OIDC re-auth is the token-exchange grant, never the
            // legacy auth where this is read.
            mfa_provider: None,
            reauth_lock: Arc::new(tokio::sync::Mutex::new(())),
            identity_name: tokens.identity_name,
            config,
            dial_sessions: Arc::new(Mutex::new(HashMap::new())),
            session_cert: Some(std::sync::Arc::new(tokio::sync::Mutex::new(holder))),
            refresh_task: None,
            live_channels: Arc::new(Mutex::new(Vec::new())),
            channel_pool: Arc::new(Mutex::new(HashMap::new())),
            tls_opens: Arc::new(AtomicUsize::new(0)),
            services: Arc::new(crate::edge::services::ServiceWatcher::new()),
            last_service_update: Arc::new(Mutex::new(None)),
            service_refresh_task: None,
            session_refresh_task: None,
            edge_router_url_filter: None,
        };
        client.spawn_refresh_timer();
        Ok(client)
    }

    /// The current api-session token's CHANNEL-TOKEN VALUE (the uuid for legacy, the access-JWT for
    /// OIDC), cloned out. This is the value the channel Hello (header 1002) and the not-authenticated
    /// checks use. Interior-mutable: a reactive re-auth can swap it under `&self`. The read-lock guard
    /// is dropped at the end of the expression — it never crosses an `.await`.
    pub(crate) fn token(&self) -> Option<String> {
        self.auth_token()
            .as_ref()
            .map(|t| t.channel_token().to_string())
    }

    /// The current api-session token as the full [`AuthToken`] (the variant carries the control-plane
    /// header dispatch). Cloned out; the read-lock guard never crosses an `.await`.
    pub(crate) fn auth_token(&self) -> Option<AuthToken> {
        self.token.read().expect("token rwlock poisoned").clone()
    }

    /// The current api-session expiry (parsed `expiresAt`), or `None` if unknown. Cloned out; the
    /// read-lock guard is dropped at the end of the expression — it never crosses an `.await`.
    #[cfg(test)]
    pub(crate) fn expires_at(&self) -> Option<SystemTime> {
        *self.expires_at.read().expect("expires_at rwlock poisoned")
    }

    /// The configured re-auth method (test introspection — pins which constructor wired which method).
    #[cfg(test)]
    pub(crate) fn reauth_method(&self) -> &ReauthMethod {
        &self.reauth_method
    }

    /// Store a fresh token AND its parsed expiry together (the §4.3-class fix). Used by every
    /// session-minting path — `authenticate`/`from_updb`/`reauthenticate`/`refresh` — so the proactive
    /// timer always reads a deadline matching the live token. Synchronous writes; no guard crosses an
    /// `.await`. Delegates to the shared free helper (DRY with the timer).
    pub(crate) fn set_token_and_expiry(&self, token: AuthToken, expires_at: Option<&str>) {
        store_token_and_expiry(&self.token, &self.expires_at, token, expires_at);
    }

    /// Spawn the proactive refresh timer ONCE (mirrors the oracle's `firstAuthOnce.Do`). A no-op if
    /// already spawned (a second `authenticate()` does not re-spawn). Captures CLONES of the shared
    /// `Arc`s so the task owns its handles independently of `&self`. Always-on (faithful to the oracle,
    /// which spawns `runRefreshes` unconditionally). `with_intervals` lets tests inject tiny intervals.
    pub(super) fn spawn_refresh_timer(&mut self) {
        self.spawn_refresh_timer_with(PROD_INTERVALS);
    }

    pub(super) fn spawn_refresh_timer_with(&mut self, intervals: RefreshIntervals) {
        if self.refresh_task.is_some() {
            return; // spawn-once
        }
        let task = tokio::spawn(run_refreshes(
            self.token.clone(),
            self.expires_at.clone(),
            self.reauth_lock.clone(),
            self.dial_sessions.clone(),
            self.session_cert.clone(),
            self.http.clone(),
            self.base_url.clone(),
            self.reauth_method.clone(),
            self.mfa_provider.clone(),
            self.live_channels.clone(),
            intervals,
        ));
        self.refresh_task = Some(task);
        // D2: the session-refresh arm goes ALWAYS-ON with the api-session arm (the oracle's
        // `runRefreshes` runs all three arms in one goroutine, `ziti.go:1080-1083`). Production
        // intervals; a test that wants a fast session timer calls `spawn_session_refresh_timer_with`
        // directly.
        self.spawn_session_refresh_timer_with(PROD_SESSION_INTERVALS);
    }

    /// Spawn the ALWAYS-ON background session-refresh timer ONCE (D2). Start-once (a second call is a
    /// no-op), captures CLONES of the shared `Arc`s. [`spawn_refresh_timer_with`](Self::spawn_refresh_timer_with)
    /// calls this with [`PROD_SESSION_INTERVALS`] so it goes always-on alongside the api-session timer
    /// after the first auth; tests inject tiny intervals directly. Ports the session-refresh arm of the
    /// oracle's `runRefreshes` (`ziti.go:1080-1083`), spawned unconditionally.
    pub(super) fn spawn_session_refresh_timer_with(&mut self, intervals: SessionRefreshIntervals) {
        if self.session_refresh_task.is_some() {
            return; // start-once
        }
        let task = tokio::spawn(run_session_refreshes(
            self.http.clone(),
            self.base_url.clone(),
            self.token.clone(),
            self.dial_sessions.clone(),
            intervals,
        ));
        self.session_refresh_task = Some(task);
    }

    /// The authenticated identity's name (from the api-session), or `None` before
    /// `authenticate()`. Sent as the dial's `CallerId`. Oracle: `GetIdentityName()`
    /// (`edge-apis/api_session.go:177`); `ziti/ziti.go:1473`.
    #[must_use]
    pub fn identity_name(&self) -> Option<&str> {
        self.identity_name.as_deref()
    }

    // Now only read by tests: the channel TLS goes through `channel_client_config`, which reads
    // `self.config` directly for cert-identities (this slice's seam). Kept for test introspection.
    #[cfg(test)]
    pub(crate) fn config(&self) -> &crate::enroll::identity::Config {
        &self.config
    }

    /// The channel's mTLS `ClientConfig` + the leaf CN for the channel Hello. The single seam through
    /// which `open_channel_to` obtains its TLS, so renewal is invisible to the channel:
    ///
    /// - **cert-identity (`session_cert` = `None`):** returns `client_config(&self.config)` + the CN
    ///   of `self.config().id.cert` — the SAME calls as before this slice, so byte-identical. No
    ///   network, no renewal.
    /// - **`updb` (`session_cert` = `Some`):** locks the holder, ENSURES the session-cert is fresh
    ///   (re-minting via the S1 endpoint, REUSING the ephemeral key, if within `RENEW_BUFFER` of
    ///   `NotAfter`), then builds the `ClientConfig` from the current leaf + the controller-CA roots.
    ///   The guard is held across check→mint→store (no double-mint; dedups the 10c parallel-router
    ///   race), then released BEFORE the `ClientConfig`/TLS is built. The holder — not the synthetic
    ///   `config` — is the live TLS source, so the re-mint actually takes effect.
    ///
    /// CONSCIOUS IMPROVEMENT beyond the oracle: `EnsureApiSessionCertificate` is create-if-nil and
    /// never renews; we add expiry-driven renewal for long-lived clients (spec / README §deviation).
    ///
    /// # Errors
    /// - cert-identity: [`EdgeError::IdentityLoad`]/[`EdgeError::TlsSetup`] from `client_config`.
    /// - `updb`: the re-mint errors ([`EdgeError::SessionCertHttp`] incl. 401 on an expired
    ///   api-session, propagated; [`EdgeError::SessionCertResponse`]) + the TLS build errors.
    pub(crate) async fn channel_client_config(
        &self,
    ) -> Result<(rustls::ClientConfig, String), EdgeError> {
        match &self.session_cert {
            // Cert-identity: exactly today's calls → byte-identical config + CN, no network.
            None => {
                let cc = crate::edge::identity_tls::client_config(&self.config)?;
                let cn = crate::edge::channel::leaf_common_name_for(
                    self.config
                        .id
                        .cert
                        .strip_prefix("pem:")
                        .unwrap_or(&self.config.id.cert),
                )
                .unwrap_or_default();
                Ok((cc, cn))
            }
            // updb: ensure fresh (re-mint reusing the key if stale) under the lock, then build. A 401
            // from the re-mint (the api-session itself expired) is folded into the reactive re-auth
            // (slice reauth-401): re-auth, clear the holder, retry the ensure (which re-mints under
            // the fresh api-session). The holder guard is taken INSIDE `op` and dropped before
            // `with_reauth_retry` takes `reauth_lock`, so the reauth→holder-clear nesting never
            // deadlocks (spec §3.6). The `ClientConfig` is built lock-free, after `op` returns.
            Some(holder) => {
                let parts = self
                    .with_reauth_retry(async |token| {
                        let mut guard = holder.lock().await;
                        guard.ensure_fresh(&self.http, &self.base_url, &token).await
                    })
                    .await?;
                parts.into_config()
            }
        }
    }

    /// Test-only handle to the `updb` session-cert holder (to drive the live renewal-proof: advance
    /// the clock so the next `connect` re-mints through the production path).
    #[cfg(test)]
    pub(crate) fn session_cert_holder(
        &self,
    ) -> Option<&crate::edge::session_cert_renew::SessionCertHolder> {
        self.session_cert.as_ref()
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Mint an ephemeral mTLS client certificate for this api-session
    /// (`POST /current-api-session/certificates`). Requires a prior `authenticate()`.
    ///
    /// The oracle mints this only for credentials WITHOUT a client identity (updb, ext-jwt): in
    /// `GetIdentity` (`ziti/client.go:298-312`) credentials implementing `IdentityProvider` (cert/ott)
    /// short-circuit to the enrolment cert, and only the others fall through to
    /// `NewApiSessionCertificate` (`:327`). Our SDK mirrors this: it mints only on the `updb` path
    /// (which has no enrolment cert — see slice S2 `from_updb`); cert/ott reuse the enrolment cert.
    /// The mint is auth-method-independent: any authenticated api-session token works. This thin
    /// method is the public seam delegating to
    /// [`crate::edge::session_cert::acquire_api_session_cert`] (S2 calls the free function directly,
    /// before an `EdgeClient` exists).
    ///
    /// # Errors
    /// [`EdgeError::NotAuthenticated`] if called before `authenticate()`; otherwise the errors of
    /// [`crate::edge::session_cert::acquire_api_session_cert`].
    pub async fn acquire_session_cert(
        &self,
    ) -> Result<crate::edge::session_cert::SessionCert, EdgeError> {
        let token = self.auth_token().ok_or(EdgeError::NotAuthenticated)?;
        crate::edge::session_cert::acquire_api_session_cert(&self.http, &self.base_url, &token)
            .await
    }

    /// Extend the API session, persisting the refreshed token + expiry. Requires authentication.
    /// Dispatches by session TYPE (oracle `RefreshApiSession`, `client_edge_client.go:211`): a LEGACY
    /// session GETs `/current-api-session` (shared free helper [`do_refresh_get`], DRY with the
    /// proactive timer); an OIDC session refreshes via the RFC 8693 token-exchange grant through the
    /// shared locking helper [`do_oidc_session_refresh`](crate::edge::refresh::do_oidc_session_refresh). Oracle: `CtrlClient.Refresh`
    /// (`ziti/client.go:129`).
    ///
    /// OIDC-3 DECISION (spec §5.6): `refresh()` now DOES the OIDC refresh (it early-returned `Ok` for
    /// OIDC in OIDC-1). It is the public "extend my session now" verb; leaving it a silent no-op after
    /// OIDC-3 wired the machinery would be a surprising dead branch. **It routes through the LOCKING
    /// shared helper, NOT a bare path** — `&mut self` does NOT exclude the background refresh timer
    /// (which holds clones of the token `Arc` and runs concurrently), so the `reauth_lock` dedup is
    /// load-bearing, not stylistic (the spec §5.6 "exclusive, no dedup needed" rationale is wrong; the
    /// conclusion holds only via the locking helper).
    pub async fn refresh(&mut self) -> Result<(), EdgeError> {
        let token = self.auth_token().ok_or(EdgeError::NotAuthenticated)?;
        // OIDC: token-exchange refresh through the shared locking helper (NO degrade to Legacy — the
        // helper writes back an `AuthToken::Oidc`, preserving the Bearer control-plane header).
        if token.session_type() == ApiSessionType::Oidc {
            return self.oidc_session_refresh(token.channel_token()).await;
        }
        let session = do_refresh_get(&self.http, &self.base_url, &token).await?;
        self.identity_name = Some(session.identity.name);
        // The GET-refresh extends a LEGACY api-session. Store the refreshed token as Legacy.
        self.set_token_and_expiry(
            AuthToken::Legacy(session.token),
            session.expires_at.as_deref(),
        );
        Ok(())
    }
}
