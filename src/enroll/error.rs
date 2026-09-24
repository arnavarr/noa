//! Error type for the enrolment flow. One variant per failure stage.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnrollError {
    #[error("invalid enrolment token: {0}")]
    InvalidToken(String),

    #[error("JWT signature verification failed: {0}")]
    JwtSignature(String),

    #[error("TLS bootstrap to issuer failed: {0}")]
    BootstrapTls(String),

    #[error("failed to fetch CA bundle: {0}")]
    CaFetch(String),

    #[error("failed to parse PKCS7 CA bundle: {0}")]
    Pkcs7Parse(String),

    #[error("CA pool is empty after enrolment trust setup")]
    EmptyCaPool,

    #[error("key generation failed: {0}")]
    KeyGen(String),

    #[error("CSR construction failed: {0}")]
    CsrBuild(String),

    #[error("enrolment request failed (status {status}): {code}: {message}")]
    EnrollHttp {
        status: u16,
        code: String,
        message: String,
    },

    #[error("unexpected enrolment response: {0}")]
    EnrollResponse(String),

    #[error("failed to write identity: {0}")]
    IdentityWrite(String),

    // CLI key-algorithm parse (slice E3-keyalg). Byte-exact oracle message: KeyAlgVar.Set
    // (key_alg_var.go:34) `errors.New("invalid option -- must specify either 'EC' or 'RSA'")`.
    #[error("invalid option -- must specify either 'EC' or 'RSA'")]
    InvalidKeyAlg,

    // ottca / dispatch (slice E2). Oracle: enroll.go switch default (:250) + enrollCA (:444-475).
    #[error("enrollment method '{0}' is not supported")]
    UnsupportedMethod(String),

    // updb (slice E4a): `updb` IS supported, but via `enroll_updb` (it needs username+password, which
    // the JWT does not carry). Specific + actionable, NOT a generic "unsupported" lie.
    #[error("updb enrolment requires credentials — use enroll_updb(jwt, username, password)")]
    UpdbRequiresCredentials,

    #[error("ottca enrolment requires a pre-existing client identity (cert + key)")]
    MissingClientIdentity,

    #[error("the provided identity has already been enrolled")]
    AlreadyEnrolled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_error_formats_with_status_and_code() {
        let e = EnrollError::EnrollHttp {
            status: 404,
            code: "NOT_FOUND".into(),
            message: "no".into(),
        };
        assert!(e.to_string().contains("404") && e.to_string().contains("NOT_FOUND"));
    }
}
