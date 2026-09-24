//! La respuesta del token endpoint: la forma JSON cruda, las claims del `id_token` (decodificadas
//! SIN verificar la firma) y el parseo a `OidcTokens` con el check de `nonce`.
//! (F6 tramo 4: movido verbatim del monolito de `edge/oidc`.)

use base64::Engine;
use serde::Deserialize;

use crate::edge::error::EdgeError;

use super::OidcTokens;

/// The raw `/oidc/oauth/token` 200 JSON shape we consume. Oracle
/// `exchangeAuthorizationCodeForTokens` (`clients_shared.go:761-790`).
///
/// Manual `Debug` REDACTS `access_token` + `refresh_token` (a derived `Debug` would leak them via
/// `{:?}`). The token-exchange refresh now writes a ROTATED refresh token through this shape, so the
/// redaction is load-bearing (latent — never logged today, but it mirrors the
/// [`OidcTokens`]/[`RefreshedOidc`](super::RefreshedOidc) convention so a future
/// `tracing::debug!(?tr)` cannot leak).
#[derive(Deserialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    #[serde(default)]
    pub(super) refresh_token: Option<String>,
    #[serde(default)]
    pub(super) expires_in: u64,
    #[serde(default)]
    id_token: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            // The id_token is a (public) JWT the controller signs; not a bearer secret like the
            // access/refresh tokens, but kept opaque here for brevity.
            .field("id_token", &self.id_token.as_ref().map(|_| "<jwt>"))
            .finish()
    }
}

/// The id_token claims we read (unverified): the identity `name` and the `nonce` (to validate the
/// flow). Oracle `IDTokenClaims` (`name` at `api_session.go:322`; nonce check `clients_shared.go:477`).
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// Decode a JWT's payload claims WITHOUT verifying the signature (oracle `ParseUnverified`,
/// `api_session.go:302`). Same base64url-payload decode `enroll::token::parse` uses. Returns the
/// parsed claims, or an error if the token is malformed.
fn decode_id_token_claims(jwt: &str) -> Result<IdTokenClaims, EdgeError> {
    let payload_b64 = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| EdgeError::OidcResponse("id_token is not a JWT".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| EdgeError::OidcResponse(format!("id_token base64: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| EdgeError::OidcResponse(format!("id_token json: {e}")))
}

/// Parse the token-endpoint 200 body into [`OidcTokens`], validating the id_token nonce against the
/// flow nonce (oracle `:477`). The identity name comes from the id_token `name` claim.
///
/// The nonce check is UNCONDITIONAL, faithful to the oracle `finishOAuthFlow`
/// (`clients_shared.go:477`): `tokens.IDTokenClaims.Nonce != verificationParams.Nonce`. The Go
/// `IDTokenClaims` is never nil there, so a missing/empty id_token nonce decodes to `""` and never
/// matches the non-empty flow nonce → the oracle errors. We mirror that exactly: an ABSENT id_token
/// (or an id_token whose `nonce` claim ≠ the flow nonce) is rejected. With `scope=openid` the
/// controller ALWAYS returns an id_token carrying the nonce we sent, so the live flow passes.
pub(super) fn parse_token_response(
    body: &str,
    expected_nonce: &str,
) -> Result<OidcTokens, EdgeError> {
    let tr: TokenResponse = serde_json::from_str(body)
        .map_err(|e| EdgeError::OidcResponse(format!("token response json: {e}")))?;
    // An absent id_token is the oracle's nil/zero-value `IDTokenClaims` (Nonce == "") → it never
    // matches the non-empty flow nonce, so the oracle errors. Require the id_token present.
    let idt = tr
        .id_token
        .as_deref()
        .ok_or_else(|| EdgeError::OidcResponse("nonce mismatch in id_token".into()))?;
    let claims = decode_id_token_claims(idt)?;
    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err(EdgeError::OidcResponse("nonce mismatch in id_token".into()));
    }
    let identity_name = claims.name;
    Ok(OidcTokens {
        access: tr.access_token,
        refresh: tr.refresh_token.filter(|r| !r.is_empty()),
        expires_in: tr.expires_in,
        identity_name,
    })
}
