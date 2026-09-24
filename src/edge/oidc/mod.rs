//! OIDC PKCE direct-grant authentication against an OpenZiti controller's integrated issuer.
//!
//! Faithful port of `edge-apis`'s `EdgeOidcAuthenticator.AuthenticateWithResponses`
//! (`sdk-golang` v1.7.0 `edge-apis/clients_shared.go:374-418`), MINUS TOTP (OIDC-T). The flow is
//! a standard OAuth 2.0 PKCE authorization-code grant against the controller's headless OP login
//! endpoints (`/oidc/{authorize,login/*,oauth/token}` — no external IdP, no browser):
//!
//! 1. `GET /oidc/authorize?...&code_challenge=...&code_challenge_method=S256` → 302 to
//!    `/oidc/login/{method}?authRequestID=...` (the controller picks `cert` when an mTLS client cert
//!    is presented, `password`/`username` otherwise). Capture the `authRequestID`.
//! 2. `POST /oidc/login/{cert|password}` as `application/x-www-form-urlencoded` (`id`, `username`,
//!    `password`, …) → 302 to `/oidc/authorize/callback?id=...`. (Cert: empty username/password; the
//!    client cert rides the mTLS transport.)
//! 3. `GET /oidc/authorize/callback?id=...` → 302 to `redirect_uri?code=...&state=...`.
//! 4. validate `state`; `POST /oidc/oauth/token` (`grant_type=authorization_code`, `code_verifier`,
//!    `code`, …) → 200 JSON `{access_token, id_token, expires_in, refresh_token}`. Validate the
//!    `id_token` `nonce`.
//!
//! # Step-by-step, NOT auto-redirect
//! Each request is issued by hand and the next is driven from the `Location` header. The HTTP client
//! is configured with `redirect(Policy::none())` so it never auto-follows: the final redirect targets
//! `http://localhost:8080/auth/callback` (the oracle's `DefaultOidcRedirectUri`), a NON-listening
//! sentinel — we only read its `Location` to extract the `code`. This mirrors the live cert-probe
//! exactly and sidesteps reqwest redirect-policy surprises (method/body across 302s, stop-at-prefix).
//!
//! # No signature verification (hand-rolled claim decode)
//! The client does NOT verify the JWT signature — that is the controller's job (oracle
//! `ParseUnverified`, `api_session.go:302`). We base64url-decode the `id_token` payload to read the
//! identity `name` (for the dial `CallerId`). 0 new crates: `base64`/`serde_json` are in-tree.

use crate::edge::error::EdgeError;

mod flow;
mod pkce;
mod refresh_grant;
mod token;
mod totp;
mod wire;

#[cfg(test)]
mod tests_enroll;
#[cfg(test)]
mod tests_flow;
#[cfg(test)]
mod tests_pkce;
#[cfg(test)]
mod tests_refresh_grant;
#[cfg(test)]
mod tests_token;
#[cfg(test)]
mod tests_totp;
#[cfg(test)]
mod tests_types;
#[cfg(test)]
mod tests_wire;
#[cfg(test)]
mod testsupport;

// Los 2 ÚNICOS re-exports (ambos con consumidor externo real ⇒ jamás `unused`).
pub(crate) use flow::oidc_authenticate;
pub(crate) use refresh_grant::do_oidc_refresh;

/// The fixed redirect URI baked into the controller's default OIDC config. A non-listening sentinel:
/// the controller 302s the authorization code to it and we read the `Location` — no server runs here.
/// Oracle: `DefaultOidcRedirectUri` (`clients_shared.go:47`).
pub(crate) const DEFAULT_REDIRECT_URI: &str = "http://localhost:8080/auth/callback";

/// Which OIDC login leg to drive: the OP login path segment + the mode.
///
/// Manual `Debug` REDACTS the `password` (a derived `Debug` would leak it via `{:?}`) — mirrors the
/// redaction on `ReauthMethod`/`UpdbConfig`/`SessionCert`. The same secret `ReauthMethod::Updb`
/// redacts.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum OidcGrant {
    /// `/oidc/login/cert` — the client cert rides the mTLS transport of the supplied http client;
    /// the form body's username/password are empty. Oracle `AuthMethodCert` → login segment `cert`.
    Cert,
    /// `/oidc/login/password` — username + password in the form body; no client cert.
    /// Oracle `AuthMethodUpdb = "password"`.
    Password { username: String, password: String },
    /// `/oidc/login/ext-jwt` — an external IdP JWT presented as `Authorization: Bearer <jwt>` on the
    /// login POST; empty form username/password, no client cert. Oracle `AuthMethodJwtExt = "ext-jwt"`
    /// (`edge-apis/credentials.go:26`); the Bearer header is `JwtCredentials.AuthenticateRequest`
    /// (`:340` — `request.GetHeaderParams().Add("Authorization", "Bearer "+c.JWT)`). The `jwt` is a
    /// SECRET (a Bearer token) → redacted in `Debug`.
    ExtJwt { jwt: String },
}

impl OidcGrant {
    /// The `/oidc/login/{segment}` path segment (`cert` | `password`). Oracle:
    /// `loginUri = ".../oidc/login/" + string(Credentials.Method())` (`clients_shared.go:499`).
    fn login_segment(&self) -> &'static str {
        match self {
            OidcGrant::Cert => "cert",
            OidcGrant::Password { .. } => "password",
            OidcGrant::ExtJwt { .. } => "ext-jwt",
        }
    }
}

// Manual Debug: NEVER format `password` — a derived Debug would leak it via `{:?}`. Keeps the
// username visible for diagnostics (mirrors `ReauthMethod::Updb`).
impl std::fmt::Debug for OidcGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OidcGrant::Cert => f.write_str("Cert"),
            OidcGrant::Password { username, .. } => f
                .debug_struct("Password")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            OidcGrant::ExtJwt { .. } => f
                .debug_struct("ExtJwt")
                .field("jwt", &"<redacted>")
                .finish(),
        }
    }
}

/// The OIDC tokens minted by a successful PKCE flow. `access` is the RS256 Bearer for the
/// control-plane + channel Hello; `refresh` is kept for OIDC-3's refresh-token grant; `expires_in` is
/// the access-token lifetime in seconds (the oracle deadline = `now + expires_in`,
/// `clients_shared.go:786`); `identity_name` is the `id_token` `name` claim (for the dial `CallerId`).
///
/// Manual `Debug` REDACTS `access` + `refresh` (the Bearer + refresh tokens) — a derived `Debug`
/// would leak them via `{:?}` (mirrors `AuthToken`/`SessionCert`).
#[derive(Clone)]
pub(crate) struct OidcTokens {
    pub access: String,
    pub refresh: Option<String>,
    pub expires_in: u64,
    pub identity_name: Option<String>,
}

impl std::fmt::Debug for OidcTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcTokens")
            .field("access", &"<redacted>")
            .field("refresh", &self.refresh.as_ref().map(|_| "<redacted>"))
            .field("expires_in", &self.expires_in)
            .field("identity_name", &self.identity_name)
            .finish()
    }
}

/// A caller-supplied source of a TOTP code (6–8 digit string). Invoked AT LOGIN TIME, ONLY when the
/// login leg signals `totp-required` for an already-enrolled identity. The caller holds the
/// authenticator/secret — the SDK never computes a code (faithful to the oracle, which delegates to a
/// `TotpCodeProvider` callback, `edge-apis/totp.go:54`). Returning `Err` aborts the flow WITHOUT
/// submitting a code ([`EdgeError::TotpProvider`]).
///
/// # Sync, not async (conscious deviation)
/// The oracle's `TotpCodeProvider.GetTotpCode()` returns a CHANNEL with a 30-min timeout — built for
/// a human typing a code into a UI. This SDK's consumers are machine clients (a code computed from a
/// stored secret, or fetched synchronously), so a sync closure is sufficient and avoids
/// `Send`/`Pin`/`AsyncFn` complexity: the provider is consumed DURING construction and never stored,
/// so it never crosses the refresh timer. DEFERRED (named, not silent): an async provider + the
/// 30-min collection timeout (only needed by a human-in-the-loop consumer, none exists yet).
///
/// # `+ Sync` keeps the construction futures `Send`
/// The bound is `+ Sync` so a `&TotpCodeProvider` is `Send` → the `*_with_totp` constructor futures
/// (and the unchanged `from_*`/`authenticate_oidc` that delegate with `None`) stay `Send`, i.e. a
/// downstream `tokio::spawn(async { EdgeClient::from_updb_oidc(&cfg).await })` still compiles. Without
/// `+ Sync` the `&dyn Fn` parameter would poison the construction future's `Send` auto-trait — a
/// SILENT regression of the otherwise byte-unchanged `from_*` signatures. The mild caller constraint
/// (the provider closure may not capture `Rc`/`RefCell`) is absent from the Go oracle (a conscious,
/// documented addition); a code computed from a stored secret or fetched synchronously captures only
/// `Sync` data.
pub type TotpCodeProvider<'a> = dyn Fn() -> Result<String, EdgeError> + Sync + 'a;

/// A caller-supplied source of a TOTP **enrollment** code, invoked AT LOGIN TIME when the login leg
/// signals `totp-required` for an identity that has NOT yet enrolled TOTP (`isTotpEnrolled: false`).
/// UNLIKE [`TotpCodeProvider`] (which computes a code from a PRE-SHARED secret), this handler RECEIVES
/// the controller-issued provisioning URL (`otpauth://totp/...?secret=BASE32...`, the argument), enrols
/// it (e.g. displays a QR code for a human to scan, or stores the secret for a machine client), and
/// returns the FIRST verification code computed from that NEW secret. The SDK never computes the code —
/// faithful to the oracle, which delegates to a `TotpEnrollmentProvider.GetTotpEnrollmentCode`
/// (`edge-apis/totp.go:30-33`). Returning `Err` cancels enrollment WITHOUT submitting a code
/// ([`EdgeError::TotpProvider`], mirroring the oracle's "totp enrollment cancelled: %w" path,
/// `clients_shared.go:644-646`).
///
/// # Sync, not async (same deviation as [`TotpCodeProvider`])
/// The oracle's `GetTotpEnrollmentCode` returns a CHANNEL with a 30-min timeout — built for a human
/// scanning a QR code into a UI. This SDK's consumers are machine clients (a code computed from the
/// just-provisioned secret), so a sync closure suffices: the handler is consumed DURING construction
/// and never stored, so it never crosses the refresh timer. DEFERRED (named, not silent): an async
/// handler + the 30-min collection timeout (only a human-in-the-loop consumer needs them; none exists).
///
/// # `+ Sync` keeps the construction futures `Send`
/// Same rationale as [`TotpCodeProvider`]: `+ Sync` makes a `&TotpEnrollmentHandler` `Send` so the
/// `*_with_mfa` constructor futures stay spawnable. The mild caller constraint (the closure may not
/// capture `Rc`/`RefCell`) is absent from the Go oracle (a conscious, documented addition).
pub type TotpEnrollmentHandler<'a> = dyn Fn(&str) -> Result<String, EdgeError> + Sync + 'a;

/// Per-request timeout for the token-exchange POST. Bounds THIS POST only (the refresh exchange is
/// awaited UNDER `reauth_lock`, so a black-holed token endpoint would otherwise freeze the proactive
/// refresh timer permanently AND wedge concurrent `connect()`s contending on the lock). Oracle:
/// `30*time.Second` (`edge-apis/clients_shared.go:168`, the `context.WithTimeout` wrapping the
/// token-exchange). Same per-request-timeout pattern as the session-cert mint POST
/// (`session_cert::SESSION_CERT_REQUEST_TIMEOUT`).
pub(crate) const OIDC_REFRESH_REQUEST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// The rotated tokens a successful OIDC refresh-token-exchange yields. `access` is the new Bearer;
/// `refresh` is the ROTATED refresh token (the controller returns a new value each exchange — probed
/// live; the SDK MUST write it back to slide the refresh horizon). `expires_in` is the new access
/// lifetime in seconds (the oracle deadline = `now + expires_in`, `clients_shared.go:216`).
///
/// Manual `Debug` REDACTS `access` + `refresh` (a derived `Debug` would leak the tokens via `{:?}`;
/// mirrors [`OidcTokens`]).
#[derive(Clone)]
pub(crate) struct RefreshedOidc {
    pub access: String,
    pub refresh: Option<String>,
    pub expires_in: u64,
}

impl std::fmt::Debug for RefreshedOidc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshedOidc")
            .field("access", &"<redacted>")
            .field("refresh", &self.refresh.as_ref().map(|_| "<redacted>"))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}
