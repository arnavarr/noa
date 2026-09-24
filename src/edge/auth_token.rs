//! The api-session token, in either authentication mode (legacy `zt-session` or OIDC `Bearer`).
//!
//! This is the FORK the OIDC arc introduces: OpenZiti supports two api-session models that differ in
//! exactly three observable ways, all keyed off the session TYPE:
//!
//! 1. **Control-plane header** — legacy sends `("zt-session", uuid)`; OIDC sends
//!    `("authorization", "Bearer " + access_token)`. Oracle: `ApiSession.GetAccessHeader()`
//!    (`edge-apis/api_session.go:186` legacy / `:330` OIDC).
//! 2. **Channel Hello token** — header `1002` carries the same BYTES `GetToken()` returns: the uuid
//!    for legacy, the access-JWT bytes for OIDC. NOT a different header — a different VALUE. Oracle:
//!    `GetToken()` (`:216`/`:375`); channel Hello `ziti/ziti.go:1795`.
//! 3. **Router-token update** — `RequiresRouterTokenUpdate()` is `false` for legacy, `true` for OIDC
//!    (`:169`/`:294`). Used by OIDC-2's `updateTokenOnAllErs`; exposed here via [`ApiSessionType`] but
//!    NOT acted on in OIDC-1 (deferred).
//!
//! The two modes COEXIST behind these accessors so the control-plane sites and the channel Hello are
//! dispatched on the token VARIANT, not bolted on top of the legacy path.

/// Which authentication mechanism established the api-session. Mirrors the oracle's `ApiSessionType`
/// (`edge-apis/api_session.go:89-99`: `legacy` | `oidc`). Drives [`AuthToken::requires_router_token_update`]
/// (the OIDC-2 gate) and the control-plane header dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiSessionType {
    /// Original Ziti auth: a uuid session token in the `zt-session` header.
    Legacy,
    /// OIDC auth: a JWT bearer token in the `authorization` header.
    Oidc,
}

/// The api-session token in its authentication mode. The single source of truth for the
/// control-plane header (`access_header`), the channel Hello bytes (`channel_token`), and the session
/// type (`session_type`). Stored behind the `EdgeClient`'s interior-mutable token `Arc` (it was
/// `Option<String>` before the OIDC arc; the OIDC arc changes the TYPE behind the same accessors, not
/// the call sites).
///
/// Manual `Debug` REDACTS the token VALUES (the legacy uuid, the OIDC Bearer + refresh) — a derived
/// `Debug` would leak them via `{:?}`. `AuthToken` is `pub` in a `pub mod`, so it is reachable by an
/// external consumer; defense-in-depth mirroring `ReauthMethod`/`SessionCert`/`OidcTokens`. The
/// variant name is kept (it is the session-type discriminator, not a secret).
#[derive(Clone, PartialEq, Eq)]
pub enum AuthToken {
    /// Legacy: the uuid session token (`zt-session`).
    Legacy(String),
    /// OIDC: the RS256 access token (`Bearer`). `refresh` is the OIDC refresh token, kept for OIDC-3's
    /// refresh-token grant (unused in OIDC-1). The client does NOT verify the JWT signature — that is
    /// the controller's job (oracle `ParseUnverified`, `api_session.go:302`).
    Oidc {
        access: String,
        refresh: Option<String>,
    },
}

// Manual Debug: NEVER format the token VALUES — a derived Debug would leak the session uuid / the
// Bearer + refresh via `{:?}`. Mirrors `ReauthMethod`/`SessionCert`/`OidcTokens`.
impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthToken::Legacy(_) => f.debug_tuple("Legacy").field(&"<redacted>").finish(),
            AuthToken::Oidc { refresh, .. } => f
                .debug_struct("Oidc")
                .field("access", &"<redacted>")
                .field("refresh", &refresh.as_ref().map(|_| "<redacted>"))
                .finish(),
        }
    }
}

impl AuthToken {
    /// The control-plane HTTP auth header name + value for this token. Legacy → `("zt-session", uuid)`;
    /// OIDC → `("authorization", "Bearer " + access)`. Oracle: `GetAccessHeader()`
    /// (`api_session.go:186`/`:330`). The name is `'static`; the value is owned (the `Bearer ` prefix
    /// allocates only for OIDC).
    pub(crate) fn access_header(&self) -> (&'static str, String) {
        match self {
            AuthToken::Legacy(uuid) => ("zt-session", uuid.clone()),
            AuthToken::Oidc { access, .. } => ("authorization", format!("Bearer {access}")),
        }
    }

    /// The bytes that go in the channel Hello header `1002` (`SessionToken`): the uuid for legacy, the
    /// access-JWT for OIDC. Same header in both modes (oracle `GetToken()`, `:216`/`:375`; Hello
    /// `ziti.go:1795`). Returned as `&str` (the caller does `.as_bytes()`).
    pub(crate) fn channel_token(&self) -> &str {
        match self {
            AuthToken::Legacy(uuid) => uuid,
            AuthToken::Oidc { access, .. } => access,
        }
    }

    /// The session type. Oracle `GetType()` (`:161`/`:286`).
    pub(crate) fn session_type(&self) -> ApiSessionType {
        match self {
            AuthToken::Legacy(_) => ApiSessionType::Legacy,
            AuthToken::Oidc { .. } => ApiSessionType::Oidc,
        }
    }

    /// The OIDC refresh token, if any (the subject token of the OIDC-3 refresh-token-exchange grant).
    /// `None` for a legacy session (no refresh token) and for an OIDC session whose refresh was absent.
    /// Oracle: `ApiSessionOidc.OidcTokens.RefreshToken` (`api_session.go:280`).
    pub(crate) fn refresh_token(&self) -> Option<&str> {
        match self {
            AuthToken::Legacy(_) => None,
            AuthToken::Oidc { refresh, .. } => refresh.as_deref(),
        }
    }

    /// Whether the token requires pushing to edge-router connections on refresh (the OIDC-2 arm).
    /// `false` for legacy, `true` for OIDC. Oracle `RequiresRouterTokenUpdate()` (`:169`/`:294`).
    /// The gate of OIDC-2's `push_token_to_live_channels` (`edge::refresh`), mirroring the oracle's
    /// `if apiSession.RequiresRouterTokenUpdate()` in `updateTokenOnAllErs` (`ziti.go:976`): a legacy
    /// refresh pushes NOTHING to the routers.
    pub(crate) fn requires_router_token_update(&self) -> bool {
        matches!(self, AuthToken::Oidc { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Legacy → `("zt-session", uuid)`; the uuid is verbatim (no prefix). Oracle `:186`.
    #[test]
    fn legacy_access_header_is_zt_session_uuid() {
        let t = AuthToken::Legacy("a-uuid-123".into());
        assert_eq!(t.access_header(), ("zt-session", "a-uuid-123".to_string()));
    }

    /// OIDC → `("authorization", "Bearer " + access)` — the `Bearer ` prefix and the verbatim access
    /// token. Oracle `:330`. (A mutation dropping the prefix would make a live control-plane call 401.)
    #[test]
    fn oidc_access_header_is_authorization_bearer() {
        let t = AuthToken::Oidc {
            access: "ey.jwt.sig".into(),
            refresh: Some("r".into()),
        };
        assert_eq!(
            t.access_header(),
            ("authorization", "Bearer ey.jwt.sig".to_string())
        );
    }

    /// The channel Hello token is the uuid for legacy and the access-JWT for OIDC (same header 1002,
    /// different value). Oracle `GetToken()` `:216`/`:375`.
    #[test]
    fn channel_token_is_uuid_or_access_jwt() {
        assert_eq!(AuthToken::Legacy("u".into()).channel_token(), "u");
        assert_eq!(
            AuthToken::Oidc {
                access: "ey.a".into(),
                refresh: None
            }
            .channel_token(),
            "ey.a"
        );
    }

    /// `session_type` discriminates the variant — the gate the proactive-refresh + reactive-reauth
    /// OIDC-defer guard branches on. Oracle `GetType()`.
    #[test]
    fn session_type_discriminates() {
        assert_eq!(
            AuthToken::Legacy("u".into()).session_type(),
            ApiSessionType::Legacy
        );
        assert_eq!(
            AuthToken::Oidc {
                access: "a".into(),
                refresh: None
            }
            .session_type(),
            ApiSessionType::Oidc
        );
    }

    /// `requires_router_token_update` is the OIDC-2 gate: false for legacy, true for OIDC. Oracle
    /// `:169`/`:294`.
    #[test]
    fn requires_router_token_update_only_for_oidc() {
        assert!(!AuthToken::Legacy("u".into()).requires_router_token_update());
        assert!(
            AuthToken::Oidc {
                access: "a".into(),
                refresh: None
            }
            .requires_router_token_update()
        );
    }

    /// `refresh_token` returns the OIDC refresh token (the refresh-grant subject) and `None` for
    /// legacy or an OIDC session with no refresh.
    #[test]
    fn refresh_token_only_for_oidc_with_refresh() {
        assert_eq!(AuthToken::Legacy("u".into()).refresh_token(), None);
        assert_eq!(
            AuthToken::Oidc {
                access: "a".into(),
                refresh: Some("ref".into())
            }
            .refresh_token(),
            Some("ref")
        );
        assert_eq!(
            AuthToken::Oidc {
                access: "a".into(),
                refresh: None
            }
            .refresh_token(),
            None
        );
    }
}
