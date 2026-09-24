//! `intercept.v1` config parse + dial-timeout + allowed-source derivation (F6 tramo 2b troceo).
//! Movido verbatim del monolito de `intercept/resolve`; ver `docs/superpowers/specs/2026-07-15-f6-tramo2-troceo-resolve-design.md` §2.2.

use std::time::Duration;

use ipnet::IpNet;
use serde::Deserialize;

use crate::edge::conn::DEFAULT_CONNECT_TIMEOUT;
use crate::edge::error::EdgeError;
use crate::edge::model::{PortRange, Service};
use crate::tunnel::resolve::parse_ip_or_cidr;

use super::{INTERCEPT_DIAL_TIMEOUT, INTERCEPT_V1_CONFIG_TYPE};

/// El config `intercept.v1` de un servicio: qué destinos `(addresses × protocols × portRanges)` se
/// interceptan hacia este servicio, con qué timeout de dial y desde qué orígenes. Deserializado con el
/// conjunto de campos completo (camelCase, todos con default), espejo de
/// `tunnel/entities/service.go:360-371` `InterceptV1Config` + el esquema del controller
/// (`migration_initialize.go:529-590`). `sourceIp`/`dialOptions.identity` se PARSEAN pero su efecto
/// está diferido (ver el doc del módulo, diferidos #2/#3).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct InterceptV1Config {
    /// Protocolos interceptados (`["tcp","udp"]`). Requerido por el esquema; match case-sensitive.
    pub protocols: Vec<String>,
    /// Direcciones interceptadas (IP / CIDR / hostname / `*.dominio`). Requerido por el esquema. Solo
    /// las IP/CIDR construyen entrada IP-match HOY; hostname/wildcard → DNS (M3, diferido #1).
    pub addresses: Vec<String>,
    /// Rangos de puerto interceptados `[{low,high}]`. Requerido por el esquema. REUSA
    /// [`crate::edge::model::PortRange`] (mismo `{low,high}` que `host.v1`).
    pub port_ranges: Vec<PortRange>,
    /// Opciones de dial (`connectTimeoutSeconds` → timeout; `identity` → instanceId, diferido #3).
    pub dial_options: Option<DialOptions>,
    /// Plantilla de IP de origen a falsear en el host (diferido #2: motor de plantillas).
    pub source_ip: Option<String>,
    /// Whitelist de IPs/CIDRs de ORIGEN que pueden interceptarse; vacío = cualquier origen (ver el doc
    /// del módulo y [`InterceptEntry::source_allowed`](crate::tunnel::intercept::resolve::InterceptEntry::source_allowed)). Aplicarla es load-bearing (ignorarla = over-permit).
    pub allowed_source_addresses: Vec<String>,
}

/// `dialOptions` del `intercept.v1`. Oráculo: `tunnel/entities/service.go:350-353` `DialOptions`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct DialOptions {
    /// Segundos de timeout de dial; sobreescribe el default de 5s. `0` → 15s (normalización `<1` del
    /// SDK, ver [`dial_timeout_for`]). Tipado `u32` (esquema: `integer` 0..=`MaxInt32`).
    pub connect_timeout_seconds: Option<u32>,
    /// Plantilla de identidad del terminador a dial-ear (diferido #3: requiere un header de Connect nuevo).
    pub identity: Option<String>,
}

/// Parsea el `intercept.v1` de un servicio, si está presente. Espejo de
/// [`crate::edge::model::Service::host_v1_config`]. Devuelve `None` cuando el servicio no tiene
/// `intercept.v1` en su `config` (p.ej. la api-session no pidió ese config-type), `Some(cfg)` cuando
/// está y es válido, y `Err` cuando está presente pero malformado.
///
/// # Errors
/// [`EdgeError::ServiceConfig`] si `config["intercept.v1"]` está presente pero no deserializa.
pub fn intercept_v1_config(svc: &Service) -> Result<Option<InterceptV1Config>, EdgeError> {
    let Some(value) = svc.config.get(INTERCEPT_V1_CONFIG_TYPE) else {
        return Ok(None);
    };
    serde_json::from_value::<InterceptV1Config>(value.clone())
        .map(Some)
        .map_err(|e| EdgeError::ServiceConfig {
            config_type: INTERCEPT_V1_CONFIG_TYPE.to_string(),
            message: e.to_string(),
        })
}

/// El timeout de dial efectivo de un `intercept.v1`, espejo de `addService` (`svcpoll.go:184,196-198`)
/// + la normalización `<1→15s` del SDK (`ziti.go:1449`):
///  - sin `dialOptions` o sin `connectTimeoutSeconds` → 5s ([`INTERCEPT_DIAL_TIMEOUT`], nunca
///    normalizado porque 5 ≥ 1);
///  - `connectTimeoutSeconds = 0` → `svc.DialTimeout = 0` → el SDK lo normaliza `<1 → 15s`
///    ([`DEFAULT_CONNECT_TIMEOUT`]); además `Duration::ZERO` haría disparar `tokio::time::timeout` de
///    inmediato, así que el mapeo a 15s es a la vez fiel y correcto;
///  - `connectTimeoutSeconds = N ≥ 1` → `N` segundos (N ≥ 1 → sin normalización).
///
/// DISCREPANCIA esquema-vs-código (nombrada, no un bug): la DESCRIPCIÓN del esquema del controller dice
/// "defaults to 15 if dialOptions are defined but connectTimeoutSeconds is not specified"
/// (`migration_initialize.go:564`). El CÓDIGO del tunneler — el oráculo de RUNTIME — NO hace eso:
/// `addService` (`svcpoll.go:196-198`) solo sobreescribe los 5s cuando `ConnectTimeoutSeconds != nil`,
/// así que `dialOptions` presente SIN `connectTimeoutSeconds` deja 5s. Espejamos el CÓDIGO (los 5s), no
/// el doc-string del esquema (los 15s) — la fidelidad es al comportamiento observable, no a la prosa.
pub(super) fn dial_timeout_for(cfg: &InterceptV1Config) -> Duration {
    match cfg
        .dial_options
        .as_ref()
        .and_then(|o| o.connect_timeout_seconds)
    {
        Some(0) => DEFAULT_CONNECT_TIMEOUT, // svc.DialTimeout=0 → SDK <1→15s (ziti.go:1449)
        Some(secs) => Duration::from_secs(u64::from(secs)),
        None => INTERCEPT_DIAL_TIMEOUT, // svcpoll.go:184 (5s, nunca normalizado)
    }
}

/// Construye el set de CIDRs de origen permitidos a partir de `allowedSourceAddresses`.
///  - lista VACÍA (no fijada) → `None` = SIN restricción (el default del oráculo: "all ips can be
///    intercepted if this is not set");
///  - lista NO vacía → `Some(cidrs)`: se parsea cada entrada con [`parse_ip_or_cidr`] (la misma
///    primitiva endurecida); las hostname/wildcard se DESCARTAN — follow-up nombrado PROPIO
///    ("`build_allowed_sources` `*`/`*.` imprecisión", origen como hostname/dominio), ABIERTO y
///    distinto del dispatch de DESTINO (#6, cerrado en `0211810`). El gate se
///    keyea en que la lista ORIGINAL sea no-vacía, NO en el set parseado: un `allowedSourceAddresses`
///    de SOLO-hostnames parsea a `[]` y debe casar CON NINGÚN origen (UNDER-permit seguro), JAMÁS
///    convertirse en "permitir cualquiera" (eso sería convertir una restricción en un over-permit).
pub(super) fn build_allowed_sources(entries: &[String]) -> Option<Vec<IpNet>> {
    if entries.is_empty() {
        return None; // sin restricción
    }
    // Restringido: la lista era no-vacía → SIEMPRE Some, aunque todas las entradas se descarten (→
    // casa con ningún origen, no con todos).
    Some(
        entries
            .iter()
            .filter(|s| !s.starts_with('*')) // wildcard de dominio → DNS (M3)
            .filter_map(|s| parse_ip_or_cidr(s)) // hostname (GetCidr falla) → DNS (M3)
            .collect(),
    )
}
