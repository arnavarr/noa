//! Tests del vocabulario de `oidc` (F6 tramo 4: movidos verbatim del monolito de `edge/oidc`).

use super::*;

/// The login segment is `cert` for Cert, `password` for Password, `ext-jwt` for ExtJwt. Oracle
/// `AuthMethodCert`/`AuthMethodUpdb`/`AuthMethodJwtExt` (`credentials.go:23-26`).
#[test]
fn login_segment_maps_grant() {
    assert_eq!(OidcGrant::Cert.login_segment(), "cert");
    assert_eq!(
        OidcGrant::Password {
            username: "u".into(),
            password: "p".into()
        }
        .login_segment(),
        "password"
    );
    assert_eq!(
        OidcGrant::ExtJwt { jwt: "ey.x".into() }.login_segment(),
        "ext-jwt"
    );
}

/// `OidcGrant::ExtJwt`'s `Debug` REDACTS the JWT (a Bearer secret) — no leak via `{:?}`.
#[test]
fn ext_jwt_grant_debug_redacts_the_jwt() {
    let g = OidcGrant::ExtJwt {
        jwt: "ey.SECRET-JWT.sig".into(),
    };
    let s = format!("{g:?}");
    assert!(
        !s.contains("SECRET-JWT"),
        "the JWT must NOT appear in Debug: {s}"
    );
    assert!(s.contains("<redacted>"), "the JWT is redacted: {s}");
}
