//! Error type for the edge client. One variant per failure stage.

use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EdgeError {
    #[error("failed to load identity for mTLS: {0}")]
    IdentityLoad(String),

    #[error("failed to set up mTLS client: {0}")]
    TlsSetup(String),

    #[error("authentication failed (status {status}): {code}: {message}")]
    AuthHttp {
        status: u16,
        code: String,
        message: String,
    },

    #[error("unexpected authenticate response: {0}")]
    AuthResponse(String),

    /// The legacy auth path's api-session carries `authQueries` (a non-empty `authQueries` on the
    /// legacy `legacyAuth` response) that could NOT be satisfied: either NO `mfa_provider` was supplied
    /// to an MFA identity (the no-provider fallback — call `authenticate_with_totp`/`from_updb_with_totp`
    /// with an [`MfaCodeProvider`](crate::edge::client::MfaCodeProvider)), or — with NO provider — a
    /// non-MFA posture query is present, or the session was STILL partial after one MFA submit
    /// (the single-submit deviation — slice `feat/edge-mfa-midsession`). NOTE: WITH a provider set,
    /// `satisfy_legacy_mfa` does not discriminate by provider/`typeId`, so a non-`ziti` posture query
    /// triggers a spurious `/authenticate/mfa` submit → [`TotpCodeRejected`](Self::TotpCodeRejected) or
    /// this error (conscious deviation, spec §7.5). GENERIC by design (the legacy
    /// path mirrors the oracle's "no MFA TOTP code providers" warn, `ziti.go:1413`); the OIDC-TOTP
    /// "enrolled but no provider supplied" case is the distinct
    /// [`TotpProviderRequired`](Self::TotpProviderRequired) instead.
    #[error("authentication requires posture/MFA that cannot be satisfied")]
    MfaRequired,

    /// The OIDC login leg returned the `totp-required` header, TOTP IS enrolled, but NO TOTP-code
    /// callback was supplied — call a `*_with_totp` constructor with a
    /// [`TotpCodeProvider`](crate::edge::oidc::TotpCodeProvider). NOT returned when TOTP succeeds.
    /// Distinct from the generic legacy [`MfaRequired`](Self::MfaRequired). Oracle:
    /// `"totp is required but no totp callback was defined"` (`clients_shared.go:561`).
    #[error("totp is required but no totp code provider was supplied")]
    TotpProviderRequired,

    #[error("listing services failed (status {status}): {code}: {message}")]
    ServicesHttp {
        status: u16,
        code: String,
        message: String,
    },

    #[error("unexpected services response: {0}")]
    ServicesResponse(String),

    /// `GET /current-api-session/service-updates` returned a non-2xx status. Mirrors
    /// `ServicesHttp`/`SessionHttp`. A 503 here is the controller's `ListServiceUpdatesServiceUnavailable`
    /// → mapped to [`ControllerUnavailable`](Self::ControllerUnavailable) by the refresh path; a 401 is
    /// an expired api-session. Oracle wire: `ListServiceUpdates` read by `IsServiceListUpdateAvailable`
    /// (`ziti/client.go:148`).
    #[error("checking service updates failed (status {status}): {code}: {message}")]
    ServiceUpdatesHttp {
        status: u16,
        code: String,
        message: String,
    },

    /// Transport failure or an unparseable/missing-`lastChangeAt` body from the service-updates
    /// endpoint. Mirrors `ServicesResponse`.
    #[error("unexpected service-updates response: {0}")]
    ServiceUpdatesResponse(String),

    /// The controller is unavailable (the service-updates check returned 503,
    /// `ListServiceUpdatesServiceUnavailable`). The background svc-refresh timer (T5-2b) treats this as
    /// retriable (re-schedules with backoff) rather than a hard error. Oracle: `ErrControllerUnavailable`
    /// (`ziti/ziti.go:1000`), returned by `refreshServices` on a 503 update-check (`ziti.go:891`).
    #[error("controller unavailable")]
    ControllerUnavailable,

    #[error("creating session failed (status {status}): {code}: {message}")]
    SessionHttp {
        status: u16,
        code: String,
        message: String,
    },

    #[error("unexpected create-session response: {0}")]
    SessionResponse(String),

    /// `POST /current-api-session/certificates` returned a non-201 status. Mirrors
    /// `AuthHttp`/`SessionHttp`. The controller answers 400 `COULD_NOT_PROCESS_CSR` for a bad CSR and
    /// 401 for missing/invalid auth. Oracle wire: `NewApiSessionCertificate` (`ziti/client.go:365`).
    #[error("acquiring api-session certificate failed (status {status}): {code}: {message}")]
    SessionCertHttp {
        status: u16,
        code: String,
        message: String,
    },

    /// Transport failure or an unparseable 201 body from the api-session certificate endpoint.
    /// Mirrors `AuthResponse`/`SessionResponse`.
    #[error("unexpected api-session certificate response: {0}")]
    SessionCertResponse(String),

    /// A step of the OIDC PKCE flow (`/oidc/{authorize,login/*,oauth/token}`) returned an unexpected
    /// HTTP status. `step` names the leg (`authorize`/`login`/`callback`/`token exchange`). Mirrors
    /// `AuthHttp`/`SessionHttp`. Oracle: the per-step status checks in `clients_shared.go`
    /// (`:447`/`:533`/`:701`/`:750`).
    #[error("oidc {step} failed (status {status}): {message}")]
    OidcHttp {
        status: u16,
        step: String,
        message: String,
    },

    /// Transport failure, a missing redirect `Location`, an unparseable token body, or a
    /// state/nonce mismatch during the OIDC PKCE flow. Mirrors `AuthResponse`/`SessionResponse`.
    #[error("unexpected oidc response: {0}")]
    OidcResponse(String),

    /// The controller does not advertise the `OIDC_AUTH` capability, so an OIDC authentication was
    /// requested against a controller that cannot serve it (fail-fast before the doomed PKCE flow).
    /// Oracle gate: `CapabilitiesOIDCAUTH` (`client_edge_management.go:258`).
    #[error("controller does not advertise OIDC_AUTH capability")]
    OidcNotSupported,

    #[error("not authenticated: call authenticate() first")]
    NotAuthenticated,

    #[error("service '{0}' not found")]
    ServiceNotFound(String),

    #[error("session has no edge router with a tls protocol")]
    NoTlsEdgeRouter,

    #[error("failed to set up channel TLS to edge router: {0}")]
    ChannelTls(String),

    #[error("channel handshake failed: {0}")]
    Channel(#[from] crate::channel::error::ChannelError),

    #[error("dial rejected by router: {0}")]
    DialRejected(String),

    #[error("bind rejected by router: {0}")]
    BindRejected(String),

    /// The accept-start handshake failed for a child whose conn-id WE generated (the oracle's
    /// `!routerProvidedConnId` branch, `ziti/edge/network/conn.go:992-1003`): with a generated id the
    /// `DialSuccess` is NOT fire-and-forget — it is sent `SendForReply` with a 5s budget and the host
    /// requires a `StateConnected` back before the conn is live. Two producers, one per oracle branch:
    /// the reply never arrives (budget exhausted or the channel died — `conn.go:995`
    /// `"failed to send reply to dial request"`), or it arrives with an unexpected content type
    /// (`conn.go:1002` `"failed to receive start after dial. got %v"`). Never produced on the
    /// router-provided path, which does not wait at all (`conn.go:1004`).
    #[error("accept start failed: {0}")]
    AcceptStartFailed(String),

    /// The bind's listener is closed: the router sent `StateClosed` for the bind conn-id, or
    /// the channel died. Returned by `ServiceBinding::accept`.
    #[error("listener closed")]
    ListenerClosed,

    #[error("edge channel closed")]
    ChannelClosed,

    /// A `write` was attempted on a connection whose WRITE side is already closed: the router sent a
    /// `StateClosed` for this conn-id (the conn is dead), or our own `close_write`/`close` set the FIN
    /// latch. `EdgeWriteHalf::write` consults the shared `sent_fin` flag and returns this BEFORE
    /// serializing the frame, so NO Data reaches the wire (the drain arm of each UDP relay twin aborts
    /// on the first write error → 0 stray `Data` frames to a torn-down conn-id). Byte-exact to the
    /// oracle's `"connection closed for writes"` (`ziti/edge/network/conn.go:220`); DISTINCT from
    /// [`ChannelClosed`](Self::ChannelClosed) (the whole channel/transport died) so a caller can tell
    /// "this one conn is dead" from "the transport is dead". Oracle: `edgeConn.Write` consults
    /// `sentFIN` and fails (`conn.go:215-221`); the flag is the oracle's `sentFIN` (`conn.go:111-113`),
    /// set by an inbound `StateClosed` (`AcceptMessage` `:361`), `CloseWrite` (`:243`), and `close()`
    /// (`:862`).
    #[error("connection closed for writes")]
    WriteAfterClose,

    #[error("end-to-end crypto failure: {0}")]
    Crypto(String),

    #[error("router requested an unsupported crypto method (only libsodium is supported)")]
    UnsupportedCrypto,

    /// `connect()` did not complete within its connect-timeout budget (the whole
    /// resolve → create[+backoff] → dial → refresh → retry flow). Mirrors the oracle's
    /// `DialContextWithOptions` applying `ConnectTimeout` as a context deadline
    /// (`ziti/ziti.go:1453-1460`, default 15s at `:1450`).
    #[error("connect to service '{service}' timed out after {timeout:?}")]
    ConnectTimedOut { service: String, timeout: Duration },

    /// `bind()` did not complete within its bind-timeout budget (resolve → create Bind session →
    /// open channel → send Bind → StateConnected). Mirrors the oracle's `listenSession` bounding
    /// the listener establishment by `ListenOptions.ConnectTimeout` (`ziti/ziti.go:2253`
    /// `WaitForN(options.ConnectTimeout)`), defaulted to `time.Minute` (60s) at `:1638-1639`.
    /// Distinct default from `ConnectTimedOut` (15s): the oracle deliberately gives listen and
    /// dial different defaults.
    #[error("bind to service '{service}' timed out after {timeout:?}")]
    BindTimedOut { service: String, timeout: Duration },

    /// An ext-jwt api-session was routed to the LEGACY re-auth path (`POST /authenticate`), which it
    /// cannot do: an external-JWT credential has no username/password and no client cert. This is a
    /// defense-in-depth GUARD over the unreachable legacy arm — an ext-jwt session is always an OIDC
    /// session, so its liveness is the RFC 8693 token-exchange refresh (OIDC-3), and the OIDC dispatch
    /// in `with_reauth_retry`/`run_refreshes`/`refresh()` routes it to that refresh, never to
    /// `do_reauthenticate`. No current path reaches this arm; it fails LOUDLY only as a tripwire if a
    /// future refactor ever wires an ext-jwt `ReauthMethod` into `do_reauthenticate`.
    ///
    /// This guard's unreachability is SEPARATE from the named deferral below. The DEFERRAL is that we
    /// do not re-present the external JWT at the ~24h OIDC refresh-token cliff (when the refresh token
    /// itself expires). CONSCIOUS DEVIATION from the oracle, which RECOVERS there (if the stored JWT is
    /// still valid) by re-presenting the STORED JWT at a full re-auth:
    /// `JwtCredentials.AuthenticateRequest` (`edge-apis/credentials.go:340`)
    /// adds `"Bearer "+c.JWT`, and `LoginWithJWT` (`ziti/ziti.go:657-669`) stores that `JwtCredentials`
    /// so `Authenticate()`→`authenticate()` (`ziti/ziti.go:1197`) re-uses it. We DEFER that
    /// re-presentation: re-supplying the external JWT (re-login) needs a JWT-provider callback this SDK
    /// does not have yet (see [`crate::edge::client::EdgeClient::from_ext_jwt`]). The gap sits at the
    /// refresh-token cliff, NOT on this guard.
    #[error("ext-jwt session cannot legacy-reauthenticate; the external JWT must be re-supplied")]
    ExtJwtReauthUnsupported,

    /// Pushing a rotated api-session token to a live edge-router channel (`UpdateToken`, ct 60803)
    /// did not succeed: the router replied `UpdateTokenFailure` (60802, body = `reason`), the reply
    /// did not arrive within the 10s budget (`reason` = "timed out"), the channel closed first, or
    /// the reply carried an unexpected content type. Mirrors the oracle's `routerConn.UpdateToken`
    /// returning the failure body / a timeout / an "invalid content type" error
    /// (`ziti/edge/network/factory.go:157-178`). Collected (not propagated) by the OIDC-2 push, which
    /// keeps updating the other channels (oracle `errors.Join`, `updateTokenOnAllErs` `ziti.go:974`).
    #[error("edge-router rejected the token update: {reason}")]
    UpdateTokenFailed { reason: String },

    /// The TOTP-code callback returned an error (the caller could not supply a code: the user
    /// cancelled, the authenticator was unavailable, etc.). The flow aborts WITHOUT submitting a
    /// code. Mirrors the oracle's `fmt.Errorf("error getting totp code: %w", totpCodeResult.Err)`
    /// (`edge-apis/clients_shared.go:570`). The wrapped message is the callback's own error string.
    #[error("error getting totp code: {0}")]
    TotpProvider(String),

    /// The controller rejected the submitted TOTP code: `POST /oidc/login/totp` returned 400. The
    /// code did not verify (wrong code, expired window, or a clock skew). Faithful to the oracle's
    /// `errors.New("totp code did not verify")` (`edge-apis/clients_shared.go:597`); the message is
    /// byte-exact so callers can distinguish a bad code from other OIDC failures.
    #[error("totp code did not verify")]
    TotpCodeRejected,

    /// The identity must enrol in TOTP first (the login leg returned `totp-required` with
    /// `isTotpEnrolled: false` in its `authQueries`), but NO enrollment handler was supplied. This SDK
    /// CAN drive the inline enrollment flow (`/oidc/login/totp/enroll` + `/enroll/verify`, oracle
    /// `handleTotpEnrollment` `clients_shared.go:603-676`) when the caller supplies a
    /// [`crate::edge::oidc::TotpEnrollmentHandler`] via a `*_with_mfa` constructor; this error is the
    /// no-handler short-circuit (the flow stops BEFORE any enroll POST). Byte-exact to the oracle's
    /// no-provider error `"totp enrollment is required but no totp enrollment provider was configured"`
    /// (`clients_shared.go:609`). Distinct from [`TotpProviderRequired`](Self::TotpProviderRequired)
    /// (already-enrolled but no CODE provider): this one needs first-time enrollment.
    #[error("totp enrollment is required but no totp enrollment provider was configured")]
    TotpEnrollmentRequired,

    /// The controller rejected the TOTP code submitted to COMPLETE first-time enrollment:
    /// `POST /oidc/login/totp/enroll/verify` returned 400. The code did not verify against the
    /// just-provisioned secret (wrong code, expired window, or clock skew). Faithful to the oracle's
    /// `errors.New("totp enrollment code did not verify")` (`clients_shared.go:673`); the message is
    /// byte-exact and DISTINCT from [`TotpCodeRejected`](Self::TotpCodeRejected) (the already-enrolled
    /// submit's "totp code did not verify"), consistent with the
    /// [`TotpProviderRequired`](Self::TotpProviderRequired)/[`TotpEnrollmentRequired`](Self::TotpEnrollmentRequired)
    /// split.
    #[error("totp enrollment code did not verify")]
    TotpEnrollmentCodeRejected,

    /// A service's typed config (e.g. `host.v1`) was present but could not be parsed. Oracle: the
    /// tunneler's `parseConfig`/mapstructure decode of a `host.v1` config returns an error
    /// (`ziti/tunnel/entities/service.go:388-405`).
    #[error("service config '{config_type}' is malformed: {message}")]
    ServiceConfig {
        config_type: String,
        message: String,
    },

    /// The forwarding host's `host.v1` config could not be served at startup. This is the STARTUP guard,
    /// covering three cases: (1) a CONFIG-LEVEL capability not yet supported
    /// (`tunnel::resolve::check_deferred_config` rejects `allowedSourceAddresses`, the last deferred
    /// config capability, T4b-2d-2); (2, T4b-2c) an INVALID or non-positive `connectTimeout`/
    /// `connectTimeoutSeconds` (`tunnel::resolve::get_dial_timeout` — `connectTimeout` itself is
    /// SUPPORTED, but an unparseable Go-duration string or a non-positive resolved timeout is a clean
    /// startup error); and (3, T4b-2d-1) an unparseable `from`/`to` in `forwardAddressTranslations`
    /// (`tunnel::resolve::build_address_translations` — `forwardAddressTranslations` is now SUPPORTED, but
    /// a bad `from`/`to` is a clean startup error, mirroring the oracle's `return nil` = service not
    /// hosted). (Per-dial deferrals — `forwardProtocol` to udp, a `dst_hostname` destination, and a
    /// per-dial `source_addr` — are surfaced separately as the DialFailed reason of that dial, not as this
    /// error.) A config the host cannot honor fails loudly at startup rather than being silently ignored.
    /// Oracle: the tunneler honors all of these (`hosting.go`/`service.go`); a malformed `connectTimeout`
    /// fails the oracle's `mapstructure` config decode (`service.go:391,397`), and a bad translation
    /// `from`/`to` makes `newHostingContext` return nil (`hosting.go:84-94`) — both the equivalent of this error.
    #[error("host forwarding config not supported: {0}")]
    HostForwardConfig(String),
}

/// The EXACT reason string the controller emits for a dead dial session
/// (`InvalidSessionError.Error() = "invalid session"`, ziti@9bf62f3
/// `controller/handler_edge_ctrl/errors.go:110-112`) and the router relays VERBATIM in the DIAL path
/// (`FinishConnect` → `sendStateClosedReply(err.Error(), …)`, `listener.go:1553-1561`). The match is
/// EXACT (`==`, not `contains`): under-permit (spec DV-2). FRAGILE to the router version — confined to
/// THIS one site and pinned by a test; a follow-up (spec §9) swaps it for the typed error if the router
/// ever attaches it to the dial (as it already does in HOSTING, `hosted.go:485`).
const DIAL_INVALID_SESSION_REASON: &str = "invalid session";

impl EdgeError {
    /// True iff this is a router DIAL rejection whose reason is EXACTLY the controller's
    /// `invalid session` verdict — the ONLY discriminant available in the dial path, because the router
    /// discards the typed error there (`FinishConnect` sends only `err.Error()`, ziti@9bf62f3
    /// `listener.go:1561`; the typed error is lost, spec §1.3). Semantic mirror of what the oracle does
    /// in HOSTING with `RetryHint == RetryStartOver` (sdk-golang@4b6a087 `hosting_conn.go:177-179`).
    ///
    /// String citation: `InvalidSessionError.Error() = "invalid session"`
    /// (ziti@9bf62f3 `controller/handler_edge_ctrl/errors.go:110-112`). Match is EXACT, never
    /// `contains`: if the router ever wraps the text we degrade to today's non-recovery, never a false
    /// positive or a runaway retry (spec DV-2).
    pub(crate) fn is_dial_invalid_session(&self) -> bool {
        matches!(self, EdgeError::DialRejected(reason) if reason == DIAL_INVALID_SESSION_REASON)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_http_formats_status_and_code() {
        let e = EdgeError::AuthHttp {
            status: 401,
            code: "INVALID_AUTH".into(),
            message: "no".into(),
        };
        let s = e.to_string();
        assert!(s.contains("401") && s.contains("INVALID_AUTH"));
    }

    #[test]
    fn session_http_formats_status_and_code() {
        let e = EdgeError::SessionHttp {
            status: 404,
            code: "NOT_FOUND".into(),
            message: "service with id x not found".into(),
        };
        let s = e.to_string();
        assert!(s.contains("404") && s.contains("NOT_FOUND"), "got: {s}");
    }

    #[test]
    fn service_not_found_formats_name() {
        let e = EdgeError::ServiceNotFound("testsvc".into());
        assert_eq!(e.to_string(), "service 'testsvc' not found");
    }

    #[test]
    fn bind_rejected_formats_message() {
        let e = EdgeError::BindRejected("no terminators".into());
        assert_eq!(e.to_string(), "bind rejected by router: no terminators");
    }

    #[test]
    fn listener_closed_formats_message() {
        assert_eq!(EdgeError::ListenerClosed.to_string(), "listener closed");
    }

    #[test]
    fn connect_timed_out_formats_service_and_timeout() {
        let e = EdgeError::ConnectTimedOut {
            service: "testsvc".into(),
            timeout: Duration::from_secs(15),
        };
        let s = e.to_string();
        assert!(s.contains("testsvc") && s.contains("15s"), "got: {s}");
    }

    #[test]
    fn totp_code_rejected_is_byte_exact_to_oracle() {
        // Oracle `clients_shared.go:597`: errors.New("totp code did not verify"). Byte-exact so a
        // caller can distinguish a bad code from any other OIDC failure.
        assert_eq!(
            EdgeError::TotpCodeRejected.to_string(),
            "totp code did not verify"
        );
    }

    #[test]
    fn totp_provider_wraps_callback_error() {
        let e = EdgeError::TotpProvider("authenticator unavailable".into());
        assert_eq!(
            e.to_string(),
            "error getting totp code: authenticator unavailable"
        );
    }

    #[test]
    fn totp_enrollment_required_is_the_no_handler_message() {
        // Now the no-handler short-circuit (the enrollment flow IS supported when a handler is given).
        // Byte-exact to the oracle's `TotpEnrollmentProvider == nil` error (`clients_shared.go:609`).
        let s = EdgeError::TotpEnrollmentRequired.to_string();
        assert_eq!(
            s,
            "totp enrollment is required but no totp enrollment provider was configured"
        );
    }

    #[test]
    fn totp_enrollment_code_rejected_is_distinct_from_code_rejected() {
        // The enroll-verify 400 has a DISTINCT oracle message from the already-enrolled submit's 400.
        let s = EdgeError::TotpEnrollmentCodeRejected.to_string();
        assert_eq!(s, "totp enrollment code did not verify");
        assert_ne!(
            s,
            EdgeError::TotpCodeRejected.to_string(),
            "enroll-verify rejection is distinct from the already-enrolled submit rejection"
        );
    }

    #[test]
    fn mfa_required_is_generic_for_the_legacy_posture_path() {
        // The legacy producer (`legacy_authenticate`, non-empty posture/MFA authQueries) has NO
        // "TOTP provider" concept — its message stays GENERIC. MUTATION: a TOTP-specific message
        // (the pre-fix wording) would misfire on the legacy path → this RED.
        let s = EdgeError::MfaRequired.to_string();
        assert_eq!(
            s,
            "authentication requires posture/MFA that cannot be satisfied"
        );
        assert!(
            !s.contains("provider"),
            "the legacy path has no provider concept: {s}"
        );
    }

    #[test]
    fn totp_provider_required_names_the_missing_provider() {
        // The OIDC-TOTP producer (`handle_totp_secondary_auth`, enrolled but no callback) names the
        // missing TOTP code provider so the caller knows to use a `*_with_totp` constructor.
        let s = EdgeError::TotpProviderRequired.to_string();
        assert_eq!(s, "totp is required but no totp code provider was supplied");
    }

    #[test]
    fn ext_jwt_reauth_unsupported_formats_clearly() {
        let s = EdgeError::ExtJwtReauthUnsupported.to_string();
        assert!(
            s.contains("ext-jwt") && s.contains("re-supplied"),
            "the message names ext-jwt and the re-supply requirement: {s}"
        );
    }

    #[test]
    fn bind_timed_out_formats_service_and_timeout() {
        let e = EdgeError::BindTimedOut {
            service: "bindsvc".into(),
            timeout: Duration::from_secs(60),
        };
        let s = e.to_string();
        assert!(s.contains("bindsvc") && s.contains("60s"), "got: {s}");
    }

    // ----- D3: is_dial_invalid_session (the ONLY string discriminant, spec §6.1) -----

    /// T1 (GWT-1): a `DialRejected` whose reason is EXACTLY the controller's `invalid session` verdict
    /// (`errors.go:110-112`) matches. Pins the exact string + its citation.
    #[test]
    fn dial_rejected_invalid_session_matches_exact_reason() {
        let err = EdgeError::DialRejected("invalid session".into());
        assert!(
            err.is_dial_invalid_session(),
            "the router's verbatim `invalid session` body must match the predicate"
        );
    }

    /// T2 (GWT-2): another rejection reason, and the OZ-oracle-style WRAPPED form
    /// (`dial failed: invalid session`, `conn.go:585`), are both NOT invalid-session. Pins `==`, not
    /// `contains` (under-permit, DV-2): a wrapped string must degrade to non-recovery, never a false
    /// positive.
    #[test]
    fn dial_rejected_other_or_wrapped_reason_is_not_invalid_session() {
        assert!(
            !EdgeError::DialRejected("no terminators".into()).is_dial_invalid_session(),
            "an unrelated rejection is not invalid-session"
        );
        assert!(
            !EdgeError::DialRejected("dial failed: invalid session".into())
                .is_dial_invalid_session(),
            "a WRAPPED reason must NOT match (== not contains, DV-2 under-permit)"
        );
    }

    /// T3 (GWT-3): a non-`DialRejected` variant is never invalid-session, even one that could
    /// coincidentally carry the substring elsewhere. Pins "only the `DialRejected` variant".
    #[test]
    fn non_dial_rejected_error_is_not_invalid_session() {
        assert!(
            !EdgeError::SessionHttp {
                status: 404,
                code: "NOT_FOUND".into(),
                message: "invalid session".into(),
            }
            .is_dial_invalid_session(),
            "a SessionHttp error is not a dial invalid-session, even with the substring in its message"
        );
        assert!(
            !EdgeError::NotAuthenticated.is_dial_invalid_session(),
            "an unrelated variant is not invalid-session"
        );
    }
}
