//! Service resolution: exact-name match, the shared resolve half of a dial, and the no-cache
//! Dial-session one-shot. (F6 tramo 5: movido verbatim del monolito de `edge/conn`.)

use crate::edge::client::{do_create_session, do_list_services};
use crate::edge::error::EdgeError;
use crate::edge::model::{Service, SessionDetail, SessionType};

/// Find the service whose name matches `name` exactly (case-sensitive, like Go's
/// `context.services` map keyed by name). Oracle: `ziti/ziti.go` `GetService` (:1948).
///
/// # Errors
/// `EdgeError::ServiceNotFound` if no service has that exact name.
pub(crate) fn resolve_service<'a>(
    services: &'a [Service],
    name: &str,
) -> Result<&'a Service, EdgeError> {
    services
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| EdgeError::ServiceNotFound(name.to_string()))
}

/// Resolve a service by name to its id + `encryption_required` flag (list + exact-name match).
/// The shared first half of a dial: `connect()` then caches-or-creates the session itself (slice 9),
/// while `do_resolve_dial_session` creates a fresh one. Oracle: `ziti.go` `GetService` (:1466).
///
/// # Errors
/// - `EdgeError::ServicesHttp`/`ServicesResponse` if listing services fails.
/// - `EdgeError::ServiceNotFound` if no service matches `name`.
pub(crate) async fn do_resolve_service(
    client: &reqwest::Client,
    base_url: &str,
    token: &crate::edge::auth_token::AuthToken,
    name: &str,
) -> Result<(String, bool), EdgeError> {
    // connect/bind resolve services without typed configs (they ignore service config) → pass `&[]`,
    // keeping the service-list wire byte-identical to before T4b-0.
    let services = do_list_services(client, base_url, token, &[]).await?;
    let svc = resolve_service(&services, name)?;
    Ok((svc.id.clone(), svc.encryption_required))
}

/// Resolve a service by name and create a fresh Dial session for it (NO cache). Returns the
/// session detail plus the service's `encryption_required` flag (read from the `Service`, NOT
/// passed by the caller). `connect()` no longer uses this — it goes through the Dial-session cache
/// (slice 9) — but it stays as a back-compat one-shot exercised by the REST tests. Oracle: `ziti.go`
/// `DialContextWithOptions` (resolve + create on a cold cache).
///
/// # Errors
/// - `EdgeError::ServicesHttp`/`ServicesResponse` if listing services fails.
/// - `EdgeError::ServiceNotFound` if no service matches `name`.
/// - `EdgeError::SessionHttp`/`SessionResponse` if session creation fails — this is where a
///   not-dialable / no-permission service surfaces, exactly as Go relies on the controller.
pub async fn do_resolve_dial_session(
    client: &reqwest::Client,
    base_url: &str,
    token: &crate::edge::auth_token::AuthToken,
    name: &str,
) -> Result<(SessionDetail, bool), EdgeError> {
    let (service_id, encryption_required) =
        do_resolve_service(client, base_url, token, name).await?;
    let detail = do_create_session(client, base_url, token, &service_id, SessionType::Dial).await?;
    Ok((detail, encryption_required))
}
