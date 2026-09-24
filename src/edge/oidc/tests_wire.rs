//! Tests de `wire` (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`).

use super::pkce::Pkce;
use super::wire::*;

/// The authorize URL carries every flow param: client_id=native, response_type=code, the S256
/// challenge, the fixed redirect_uri, state, nonce, scope. Oracle `:685-694`.
#[test]
fn authorize_url_has_all_pkce_and_flow_params() {
    let pkce = Pkce {
        verifier: "VER".into(),
        challenge: "CHAL".into(),
    };
    let u = authorize_url("https://h:1280", &pkce, "ST8", "NON5");
    assert!(u.starts_with("https://h:1280/oidc/authorize?"), "{u}");
    assert!(u.contains("client_id=native"), "{u}");
    assert!(u.contains("response_type=code"), "{u}");
    assert!(u.contains("code_challenge=CHAL"), "{u}");
    assert!(u.contains("code_challenge_method=S256"), "{u}");
    assert!(u.contains("state=ST8"), "{u}");
    assert!(u.contains("nonce=NON5"), "{u}");
    // scope is "openid offline_access" url-encoded (space → +).
    assert!(u.contains("scope=openid+offline_access"), "{u}");
    assert!(
        u.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauth%2Fcallback"),
        "redirect_uri is the encoded sentinel: {u}"
    );
}

/// `extract_auth_request_id` reads the `authRequestID` query value from a relative or absolute
/// Location, stopping at `&`/`#`; absent/empty → None.
#[test]
fn extract_auth_request_id_reads_query() {
    assert_eq!(
        extract_auth_request_id("/oidc/login/cert?authRequestID=abc-123"),
        Some("abc-123".to_string())
    );
    assert_eq!(
        extract_auth_request_id("https://h/oidc/login/username?authRequestID=xy&foo=1"),
        Some("xy".to_string())
    );
    assert_eq!(extract_auth_request_id("/oidc/login/cert"), None);
    assert_eq!(extract_auth_request_id("?authRequestID="), None);
}

/// `extract_code` reads `code` and enforces the `state` match; a state mismatch or a missing code
/// errors (CSRF protection, oracle `:463`).
#[test]
fn extract_code_validates_state_and_reads_code() {
    let loc = "http://localhost:8080/auth/callback?code=THE_CODE&state=S1";
    assert_eq!(extract_code(loc, "S1").unwrap(), "THE_CODE");
    // wrong state → error
    assert!(
        extract_code(loc, "OTHER").is_err(),
        "state mismatch rejected"
    );
    // no code → error
    let nocode = "http://localhost:8080/auth/callback?state=S1";
    assert!(extract_code(nocode, "S1").is_err(), "missing code rejected");
}

/// `absolutize` leaves absolute URLs and prefixes relative ones with the base.
#[test]
fn absolutize_handles_relative_and_absolute() {
    assert_eq!(
        absolutize("https://h:1280", "/oidc/authorize/callback?id=x"),
        "https://h:1280/oidc/authorize/callback?id=x"
    );
    assert_eq!(
        absolutize("https://h:1280", "https://h:1280/other"),
        "https://h:1280/other"
    );
}
