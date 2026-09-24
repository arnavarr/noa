//! Reactive re-authentication of the api-session on a 401 (REACTIVE-ONLY).
//!
//! When an api-session's idle window lapses, the next control-plane call (`list_services` /
//! `create_session` / session-cert re-mint) returns 401. The oracle re-authenticates **reactively**
//! at each control-plane call site, then retries once. Two representative sites
//! (`sdk-golang` v1.7.0 `ziti/ziti.go`):
//!
//! - `refreshServices` → `GetServices` (`:916-927`): on `ListServicesUnauthorized`,
//!   `log.Info("attempting to re-authenticate")` → `Authenticate()` → retry `GetServices` ONCE
//!   (re-auth failure ⇒ return the ORIGINAL error).
//! - `createSession` (`:2065-2099`, the unit retried by `createSessionWithBackoff`): on
//!   `CreateSessionUnauthorized`/`isUnauthorizedApiError`, `Authenticate()` then `return nil, err`
//!   (the ORIGINAL error) so the backoff loop re-runs `createSession` with the now-fresh token.
//!
//! **Dedup** lives in `Authenticate()` (`:1197-1217`): `authAttemptLock.Lock()` + "if a current
//! api-session was refreshed < 5s ago, return nil" — so concurrent reactive re-auths collapse to one.
//!
//! This module holds the two PURE pieces of that pattern: [`ReauthMethod`] (how to re-authenticate,
//! stored on the `EdgeClient`) and [`is_unauthorized`] (the 401 classifier). The orchestration
//! (`with_reauth_retry`) and the dedup gate (`reauthenticate`) are methods on `EdgeClient` (they need
//! its private auth state), in [`crate::edge::client`].
//!
//! # Conscious deviations (documented in code + README)
//!
//! 1. **Proactive refresh timer deferred.** The oracle also has a PROACTIVE `runRefreshes` /
//!    `RefreshApiSessionWithBackoff` timer that refreshes ~before `expiresAt`. Omitting it leaves an
//!    EFFICIENCY gap (one 401-then-recover at the expiry boundary), NOT a correctness gap.
//! 2. **Retry-once, not retry-until-budget.** For `createSession` the oracle re-runs the backoff loop
//!    (deduped re-auth) until `MaxElapsedTime`; we retry exactly once (the `refreshServices` shape). A
//!    persistent 401 after a successful re-auth means the fresh token is also rejected — more retries
//!    won't help. (For `create_session` the surrounding slice-10a backoff still re-runs the whole
//!    reauth-retried create on a transient *5xx*, so backon's recovery shape is preserved.)
//! 3. **Re-auth clears the session-cert (FAITHFUL to the oracle).** The oracle's `setUnauthenticated`
//!    nils `ApiSessionCertificate` on re-auth; `reauthenticate` matches it (the old cert was minted
//!    under the now-stale api-session, and the mint endpoint is api-session-scoped). Updb-only.
//! 4. **Dedup by token-identity, not a 5s wall-clock window.** The oracle skips a re-auth if the last
//!    successful refresh was < 5s ago; we skip if the token already rotated away from the one the
//!    failed op used. A CONSCIOUS IMPROVEMENT (more precise: it dedups exactly the concurrent burst
//!    that observed the same stale token, with no time-based false-positive/negative).

use crate::edge::error::EdgeError;

/// How to re-authenticate the api-session reactively, stored on the [`crate::edge::client::EdgeClient`].
///
/// `self.http` is already the right transport for each: the mTLS cert client for [`ReauthMethod::Cert`]
/// (the enrolment cert), the non-mTLS client for [`ReauthMethod::Updb`] (exactly what the initial
/// password-auth in `from_updb` used).
pub(crate) enum ReauthMethod {
    /// Re-auth via legacy mTLS cert-auth (`POST /authenticate?method=cert`, body `{}`). The client
    /// identity is the enrolment cert carried by `self.http`. Used by `from_identity` clients.
    Cert,
    /// Re-auth via legacy username/password (`POST /authenticate?method=password`). Used by
    /// `from_updb` clients. The `password` is a SECRET (redacted in `Debug`).
    Updb { username: String, password: String },
    /// An ext-jwt client (`from_ext_jwt`): there is NO legacy re-auth (no password, no client cert).
    /// An ext-jwt session is always an OIDC session, so its liveness is the OIDC token-exchange refresh
    /// (OIDC-3), and the OIDC dispatch routes it AWAY from the legacy `do_reauthenticate` — so this arm
    /// is unreachable via any current path. Carries NO secret (the external JWT has no consumer here;
    /// see [`EdgeError::ExtJwtReauthUnsupported`]). A unit variant that fails LOUDLY as a tripwire if a
    /// future refactor ever wires it into `do_reauthenticate`.
    ExtJwt,
}

// Manual Debug: NEVER format `password` — a derived Debug would leak it via `{:?}`. Mirrors the
// redaction on `UpdbConfig`/`SessionCert`/`SessionCertState`. (`EdgeClient` itself is not `Debug`,
// so this is defense-in-depth for any future log/span that touches a `ReauthMethod`.)
impl std::fmt::Debug for ReauthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReauthMethod::Cert => f.write_str("Cert"),
            ReauthMethod::Updb { username, .. } => f
                .debug_struct("Updb")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            ReauthMethod::ExtJwt => f.write_str("ExtJwt"),
        }
    }
}

/// Whether an error from a control-plane op means "the api-session is no longer authorized" (HTTP
/// 401), i.e. a reactive re-auth + retry should fire. Keys on the three control-plane variants that
/// carry a status and can surface a 401 from an EXPIRED api-session:
///
/// - [`EdgeError::ServicesHttp`] — `GET /services` (oracle `ListServicesUnauthorized`).
/// - [`EdgeError::SessionHttp`] — `POST /sessions` (oracle `CreateSessionUnauthorized`).
/// - [`EdgeError::SessionCertHttp`] — `POST /current-api-session/certificates` re-mint (folds the
///   cert-remint-401 the renewal slice deferred).
///
/// NOT [`EdgeError::AuthHttp`]: that is the authenticate call itself; a 401 there means bad
/// credentials, so re-authenticating again is pointless (mirrors the oracle treating
/// `AuthenticateUnauthorized` as `backoff.Permanent`).
///
/// CONSCIOUS DEVIATION (spec §4): the oracle keys on typed `*Unauthorized`/`UnauthorizedCode`; our
/// REST layer surfaces HTTP status codes, and 401 is the faithful equivalent.
pub(crate) fn is_unauthorized(err: &EdgeError) -> bool {
    matches!(
        err,
        EdgeError::ServicesHttp { status: 401, .. }
            | EdgeError::SessionHttp { status: 401, .. }
            | EdgeError::SessionCertHttp { status: 401, .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn services_http(status: u16) -> EdgeError {
        EdgeError::ServicesHttp {
            status,
            code: "X".into(),
            message: "x".into(),
        }
    }
    fn session_http(status: u16) -> EdgeError {
        EdgeError::SessionHttp {
            status,
            code: "X".into(),
            message: "x".into(),
        }
    }
    fn session_cert_http(status: u16) -> EdgeError {
        EdgeError::SessionCertHttp {
            status,
            code: "X".into(),
            message: "x".into(),
        }
    }
    fn auth_http(status: u16) -> EdgeError {
        EdgeError::AuthHttp {
            status,
            code: "X".into(),
            message: "x".into(),
        }
    }

    /// Each control-plane 401 the reactive path must recover from is classified as unauthorized.
    /// This is the gate of the WHOLE feature: if any arm were dropped, that path's recovery would
    /// never fire in production (the matching wiremock recovery test would go RED).
    #[test]
    fn classifies_control_plane_401s_as_unauthorized() {
        assert!(is_unauthorized(&services_http(401)), "list-services 401");
        assert!(is_unauthorized(&session_http(401)), "create-session 401");
        assert!(
            is_unauthorized(&session_cert_http(401)),
            "session-cert re-mint 401"
        );
    }

    /// AuthHttp 401 (bad credentials at the authenticate call itself) is NOT unauthorized-for-retry:
    /// re-authenticating again would just fail the same way (oracle: `AuthenticateUnauthorized` is
    /// `backoff.Permanent`). This is what stops an infinite re-auth loop.
    #[test]
    fn auth_call_401_is_not_unauthorized_for_retry() {
        assert!(!is_unauthorized(&auth_http(401)));
    }

    /// Non-401 statuses on the SAME variants are not unauthorized (so they propagate without a
    /// spurious re-auth): 403/404/500 on the three control-plane variants.
    #[test]
    fn non_401_statuses_are_not_unauthorized() {
        for status in [403, 404, 408, 429, 500, 503] {
            assert!(
                !is_unauthorized(&services_http(status)),
                "services {status}"
            );
            assert!(!is_unauthorized(&session_http(status)), "session {status}");
            assert!(
                !is_unauthorized(&session_cert_http(status)),
                "session-cert {status}"
            );
        }
    }

    /// Errors with no HTTP status (transport, not-authenticated, channel) are never unauthorized.
    #[test]
    fn non_http_errors_are_not_unauthorized() {
        assert!(!is_unauthorized(&EdgeError::NotAuthenticated));
        assert!(!is_unauthorized(&EdgeError::SessionResponse(
            "reset".into()
        )));
        assert!(!is_unauthorized(&EdgeError::ServicesResponse(
            "reset".into()
        )));
    }

    /// The `Updb` re-auth method REDACTS the password in `Debug` (no secret leak via `{:?}`), while
    /// keeping the username visible for diagnostics; `Cert` renders as a bare tag.
    #[test]
    fn reauth_method_debug_redacts_password() {
        let updb = ReauthMethod::Updb {
            username: "alice".into(),
            password: "s3cr3t-pw".into(),
        };
        let s = format!("{updb:?}");
        assert!(s.contains("alice"), "username is visible: {s}");
        assert!(
            !s.contains("s3cr3t-pw"),
            "the password must NOT appear in Debug: {s}"
        );
        assert!(s.contains("<redacted>"), "password is redacted: {s}");

        assert_eq!(format!("{:?}", ReauthMethod::Cert), "Cert");
        // ExtJwt is a unit variant carrying no secret — renders as a bare tag.
        assert_eq!(format!("{:?}", ReauthMethod::ExtJwt), "ExtJwt");
    }
}
