//! Serde models for the edge client REST API. Oracle: edge-api rest_model/*.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// Deserialize a field the controller may send as an explicit JSON `null` (e.g. a service
/// with no `configs`) into `T::default()`. `#[serde(default)]` alone only covers a MISSING
/// key, not an explicit `null`. Oracle: the edge `/services` response sends `"configs": null`
/// for a service with no config instances.
fn null_to_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// `{ "data": T }` envelope (single object).
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope<T> {
    pub data: T,
}

/// `{ "data": [T], "meta": { "pagination": {...} } }` envelope (list).
#[derive(Debug, Clone, Deserialize)]
pub struct Paginated<T> {
    pub data: Vec<T>,
    pub meta: Meta,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    pub pagination: Pagination,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pagination {
    #[serde(rename = "totalCount")]
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
}

/// The legacy API session detail (`/authenticate` response data).
#[derive(Debug, Clone, Deserialize)]
pub struct ApiSession {
    pub token: String,
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<String>,
    #[serde(rename = "authQueries", default)]
    pub auth_queries: Vec<serde_json::Value>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub identity: IdentityRef,
}

/// The identity referenced by an api-session (`data.identity`). Only `name` is needed:
/// Go's legacy `GetIdentityName()` returns `Detail.Identity.Name`. Oracle:
/// rest_model `CurrentAPISessionDetail.Identity`; `edge-apis/api_session.go:177-179`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IdentityRef {
    #[serde(default)]
    pub name: String,
}

/// A service visible to the identity (`/services` response items).
#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    pub id: String,
    pub name: String,
    #[serde(rename = "encryptionRequired", default)]
    pub encryption_required: bool,
    #[serde(default, deserialize_with = "null_to_default")]
    pub permissions: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub config: serde_json::Map<String, serde_json::Value>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub configs: Vec<String>,
}

impl Service {
    /// Parse this service's `host.v1` typed config, if present. Returns `None` when the service has
    /// no `host.v1` config in its `config` map (e.g. the api-session did not request the `host.v1`
    /// config type — see [`crate::edge::client::EdgeClient::list_services_with_config_types`] — or the
    /// service simply has no host.v1), `Some(cfg)` when present and well-formed, and an error when a
    /// `host.v1` entry is present but malformed. The returned config carries data only; the tunneler
    /// host (T4b-1) adds the resolver that uses it. Oracle: `ziti/tunnel/entities/service.go`
    /// `HostV1Config` (decoded via mapstructure from `service.Configs["host.v1"]`, :388-405).
    ///
    /// # Errors
    /// [`crate::edge::error::EdgeError::ServiceConfig`] if `config["host.v1"]` is present but does not
    /// deserialize into a [`HostV1Config`].
    pub fn host_v1_config(&self) -> Result<Option<HostV1Config>, crate::edge::error::EdgeError> {
        let Some(value) = self.config.get(HOST_V1_CONFIG_TYPE) else {
            return Ok(None);
        };
        serde_json::from_value::<HostV1Config>(value.clone())
            .map(Some)
            .map_err(|e| crate::edge::error::EdgeError::ServiceConfig {
                config_type: HOST_V1_CONFIG_TYPE.to_string(),
                message: e.to_string(),
            })
    }
}

/// The `host.v1` config type name (the key under `Service.config`). Oracle: `HostConfigV1 = "host.v1"`
/// (`ziti/tunnel/entities/service.go:27`).
pub const HOST_V1_CONFIG_TYPE: &str = "host.v1";

/// A service's `host.v1` config: how a hosting identity dials the backing target for inbound dials.
/// Deserialized with the FULL field set (camelCase, every field defaulted) so the T4b-1/T4b-2
/// resolver slices need no struct change — T4b-0 only PARSES it; nothing resolves a target yet.
/// Oracle: `ziti/tunnel/entities/service.go:112-132` `HostV1Config` + the controller host.v1 JSON
/// schema (`ziti/controller/db/migration_initialize.go`). `proxy`/`portChecks`/`httpChecks` are
/// intentionally not declared (serde ignores unknown keys) — out of T4b scope, named not silent.
///
/// Two CONSCIOUS deviations from the oracle's decoder, both bounded by the controller's create-time
/// host.v1 JSON schema (canonical camelCase keys, `additionalProperties:false`, concrete field types
/// 0..=65535 ports etc.) so they are unreachable for any config the controller actually serves:
/// (1) serde is case-SENSITIVE (exact camelCase) where the oracle's `mapstructure` folds case
///     (`service.go:386-401`, no field tags) — a non-canonical key would silently default here, but the
///     schema rejects such keys at create-time; (2) `port: u16` narrows the oracle's `Port int`, and a
///     present-but-`null` field/config is fail-loud `Err` (container `default` fills MISSING keys only,
///     not JSON `null`) where the oracle yields a zero-value config — both impossible under the schema.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct HostV1Config {
    /// The fixed dial protocol (`tcp`/`udp`) when not forwarding the protocol.
    pub protocol: String,
    /// When true, dial the protocol from the inbound appData (`dst_protocol`) instead of `protocol`.
    pub forward_protocol: bool,
    /// The protocols a forwarded dial may use (the allow-list when `forward_protocol`).
    pub allowed_protocols: Vec<String>,
    /// The fixed dial address (host/IP) when not forwarding the address.
    pub address: String,
    /// When true, dial the address from the inbound appData (`dst_ip`/`dst_hostname`).
    pub forward_address: bool,
    /// CIDR→CIDR translations applied to a forwarded address (T4b-2).
    pub forward_address_translations: Vec<AddressTranslation>,
    /// The addresses (IP/CIDR/hostname/wildcard) a forwarded dial may reach (the allow-list).
    pub allowed_addresses: Vec<String>,
    /// The fixed dial port when not forwarding the port.
    pub port: u16,
    /// When true, dial the port from the inbound appData (`dst_port`) instead of `port`.
    pub forward_port: bool,
    /// The port ranges a forwarded dial may reach (the allow-list when `forward_port`).
    pub allowed_port_ranges: Vec<PortRange>,
    /// The source addresses a forwarded dial may bind (T4b-2).
    pub allowed_source_addresses: Vec<String>,
    /// Listen/dial options (e.g. `connectTimeout`, applied by `GetDialTimeout`); T4b-2.
    pub listen_options: Option<HostV1ListenOptions>,
}

/// An inclusive port range `[low, high]`. Oracle: `ziti/tunnel/entities/service.go:355` `PortRange`
/// + the controller schema's `portRange` (`low`/`high`, each a 0-65535 `portNumber`).
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub low: u16,
    pub high: u16,
}

/// A CIDR→CIDR address translation (host bits preserved). T4b-2. Oracle:
/// `ziti/tunnel/entities/service.go:88` `AddressTranslation` + the controller schema's
/// `addressTranslation` (`from`/`to`/`prefixLength`).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct AddressTranslation {
    pub from: String,
    pub to: String,
    pub prefix_length: u8,
}

/// `host.v1` listen options. Only the fields the tunneler dial path reads are declared (the dial
/// timeout, T4b-2 `GetDialTimeout`); the rest (cost/precedence/identity/...) are ignored. Oracle:
/// `ziti/tunnel/entities/service.go:78` `HostV1ListenOptions` + `GetDialTimeout` (:222-232).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct HostV1ListenOptions {
    /// A dial timeout in whole seconds (lower precedence than `connect_timeout`).
    ///
    /// Typed `u32` (the oracle's field is `*int` = int64): both ends are STRICTER than Go, fail-closed at
    /// serde, in the safe direction. A NEGATIVE value (Go: `time.Second * negative` < 0 → unbounded dial)
    /// and a value `> u32::MAX` (Go: `time.Second * secs` silently overflows int64 to a negative `Duration`
    /// at `secs ≥ 9_223_372_037` → unbounded dial) both fail to deserialize here — we refuse to host rather
    /// than dial unbounded. Neither is a real `ziti edge` host.v1 value.
    pub connect_timeout_seconds: Option<u32>,
    /// A Go-duration string dial timeout (e.g. `"5s"`); takes precedence over `connect_timeout_seconds`.
    /// Kept as the raw string here; parsing is deferred to T4b-2 (`GetDialTimeout`).
    pub connect_timeout: Option<String>,
}

/// Session type for a dial/bind request. Oracle: rest_model `DialBind` (case-sensitive wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionType {
    #[serde(rename = "Dial")]
    Dial,
    #[serde(rename = "Bind")]
    Bind,
}

/// The create-session request body. Oracle: edge-api rest_model `SessionCreate`.
#[derive(Debug, Clone, Serialize)]
pub struct SessionCreate {
    #[serde(rename = "serviceId")]
    pub service_id: String,
    #[serde(rename = "type")]
    pub session_type: SessionType,
}

/// One edge router serving a session. Oracle: rest_model `SessionEdgeRouter`
/// (only the fields slice 2 needs; scoring fields and legacy `urls` are ignored).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SessionEdgeRouter {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(rename = "supportedProtocols", default)]
    pub supported_protocols: BTreeMap<String, String>,
}

/// The `{"data":{"edgeRouters":[…]}}` body of `ListServiceEdgeRouters`
/// (`GET /services/{id}/edge-routers`) — the fetch the oracle's `GetSessionFromJwt` issues to refresh
/// a JWT session's edge-router set (`ziti/client.go:264`). Only `edgeRouters` is needed: the D2
/// session-refresh reconstructs the refreshed [`SessionDetail`] by swapping just this field (spec
/// DV-A2). Extra fields (the service's own attributes) are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServiceEdgeRouterList {
    #[serde(rename = "edgeRouters", default)]
    pub edge_routers: Vec<SessionEdgeRouter>,
}

/// A created session (`POST /sessions` response data). Oracle: rest_model `SessionDetail`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionDetail {
    pub id: String,
    pub token: String,
    #[serde(rename = "serviceId")]
    pub service_id: String,
    #[serde(rename = "type")]
    pub session_type: SessionType,
    #[serde(rename = "apiSessionId", default)]
    pub api_session_id: String,
    #[serde(rename = "identityId", default)]
    pub identity_id: String,
    #[serde(rename = "edgeRouters", default)]
    pub edge_routers: Vec<SessionEdgeRouter>,
}

/// Rewrite `proto://host:port` to `proto:host:port` in each value, keeping all entries.
/// Oracle: `ziti/client.go` `sanitizeSessionUrls` (`strings.Replace(url, "://", ":", 1)`).
/// Deviation (slice 2): we do NOT drop entries that fail address parsing; transport-address
/// validation is deferred to slice 3. See spec §5.1.
#[must_use]
pub fn sanitize_supported_protocols(
    protocols: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    protocols
        .iter()
        .map(|(k, v)| (k.clone(), v.replacen("://", ":", 1)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_api_session_ignoring_extra_fields() {
        // Trimmed from a real `/authenticate?method=cert` 200 response.
        let json = r#"{
            "data": {
                "id": "abc", "token": "bbc15cb5-5b93-4bf8-9b1e-000000000000",
                "expiresAt": "2026-06-17T12:00:00Z", "authQueries": [],
                "identity": {"id": "id1", "name": "auth-probe"}, "configTypes": []
            },
            "meta": {}
        }"#;
        let env: Envelope<ApiSession> = serde_json::from_str(json).unwrap();
        assert_eq!(env.data.token, "bbc15cb5-5b93-4bf8-9b1e-000000000000");
        assert!(env.data.auth_queries.is_empty());
        assert_eq!(env.data.identity.name, "auth-probe");
    }

    #[test]
    fn api_session_parses_identity_name() {
        let json = r#"{"data":{"id":"a","token":"t","authQueries":[],
            "identity":{"id":"id1","name":"alice"}},"meta":{}}"#;
        let env: Envelope<ApiSession> = serde_json::from_str(json).unwrap();
        assert_eq!(env.data.identity.name, "alice");
    }

    #[test]
    fn api_session_identity_name_defaults_when_absent_or_null() {
        // Absent `identity` key -> default (empty name).
        let absent = r#"{"data":{"token":"t","authQueries":[]},"meta":{}}"#;
        let a: Envelope<ApiSession> = serde_json::from_str(absent).unwrap();
        assert_eq!(a.data.identity.name, "");
        // Explicit `"identity": null` -> default (the house null_to_default pattern).
        let null = r#"{"data":{"token":"t","authQueries":[],"identity":null},"meta":{}}"#;
        let n: Envelope<ApiSession> = serde_json::from_str(null).unwrap();
        assert_eq!(n.data.identity.name, "");
    }

    #[test]
    fn deserializes_service_list_with_pagination() {
        // Trimmed from a real `/services` 200 response (service `testsvc`).
        let json = r#"{
            "data": [
                {"id": "svc1", "name": "testsvc", "encryptionRequired": true,
                 "permissions": ["Dial"], "config": {}, "configs": ["cfg1"],
                 "postureQueries": [], "createdAt": "..."}
            ],
            "meta": { "pagination": { "limit": 500, "offset": 0, "totalCount": 1 } }
        }"#;
        let page: Paginated<Service> = serde_json::from_str(json).unwrap();
        assert_eq!(page.meta.pagination.total_count, 1);
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].name, "testsvc");
        assert!(page.data[0].encryption_required);
        assert_eq!(page.data[0].permissions, vec!["Dial".to_string()]);
        assert_eq!(page.data[0].configs, vec!["cfg1".to_string()]);
    }

    #[test]
    fn deserializes_empty_service_list() {
        let json =
            r#"{"data": [], "meta": {"pagination": {"limit":500,"offset":0,"totalCount":0}}}"#;
        let page: Paginated<Service> = serde_json::from_str(json).unwrap();
        assert!(page.data.is_empty());
        assert_eq!(page.meta.pagination.total_count, 0);
    }

    #[test]
    fn session_type_serializes_to_wire_values() {
        assert_eq!(
            serde_json::to_string(&SessionType::Dial).unwrap(),
            "\"Dial\""
        );
        assert_eq!(
            serde_json::to_string(&SessionType::Bind).unwrap(),
            "\"Bind\""
        );
        let st: SessionType = serde_json::from_str("\"Dial\"").unwrap();
        assert_eq!(st, SessionType::Dial);
    }

    #[test]
    fn sanitize_replaces_scheme_separator_keeping_all_entries() {
        use std::collections::BTreeMap;
        let mut m = BTreeMap::new();
        m.insert("tls".to_string(), "tls://localhost:3022".to_string());
        m.insert("wss".to_string(), "wss://router.example:443".to_string());
        let out = sanitize_supported_protocols(&m);
        assert_eq!(out.get("tls").unwrap(), "tls:localhost:3022");
        assert_eq!(out.get("wss").unwrap(), "wss:router.example:443");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn sanitize_is_idempotent_and_leaves_unschemed_untouched() {
        use std::collections::BTreeMap;
        let mut m = BTreeMap::new();
        m.insert("tls".to_string(), "tls:already:rewritten".to_string());
        let once = sanitize_supported_protocols(&m);
        let twice = sanitize_supported_protocols(&once);
        assert_eq!(once, twice);
        assert_eq!(once.get("tls").unwrap(), "tls:already:rewritten");
    }

    #[test]
    fn deserializes_real_session_detail_fixture() {
        let json = include_str!("../../tests/fixtures/session_create_201.json");
        let env: Envelope<SessionDetail> = serde_json::from_str(json).unwrap();
        let d = env.data;
        assert!(!d.token.is_empty());
        assert_eq!(d.service_id, "4wN0IlApM5DhJcmWstU9FE");
        assert_eq!(d.session_type, SessionType::Dial);
        assert_eq!(d.edge_routers.len(), 1);
        let er = &d.edge_routers[0];
        assert_eq!(er.name, "er1");
        assert_eq!(
            er.supported_protocols.get("tls").unwrap(),
            "tls://localhost:3022"
        );
    }

    // ───────────────────────── T4b-0: host.v1 config parse ─────────────────────────

    fn svc_with_config(name: &str, config_json: &str) -> Service {
        let config: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(config_json).unwrap();
        Service {
            id: "id".into(),
            name: name.into(),
            encryption_required: false,
            permissions: vec![],
            config,
            configs: vec![],
        }
    }

    #[test]
    fn host_v1_fixed_address_shape_parses_with_forward_flags_false() {
        // The shape served for testsvc-noenc's `noenc-host` (a FIXED address/port host).
        let svc = svc_with_config(
            "testsvc-noenc",
            r#"{"host.v1":{"address":"localhost","port":19009,"protocol":"tcp"}}"#,
        );
        let cfg = svc.host_v1_config().unwrap().expect("host.v1 present");
        assert_eq!(cfg.address, "localhost");
        assert_eq!(cfg.port, 19009);
        assert_eq!(cfg.protocol, "tcp");
        // No forward flags in a fixed host → all false, allow-lists empty.
        assert!(!cfg.forward_address && !cfg.forward_port && !cfg.forward_protocol);
        assert!(cfg.allowed_addresses.is_empty() && cfg.allowed_port_ranges.is_empty());
    }

    #[test]
    fn host_v1_forward_address_shape_parses_allow_lists() {
        // The shape T4b-1 needs (a dynamic forwardAddress host with allow-lists). Mirrors the spike
        // config exactly: forwardAddress + flat CIDR allow-list + forwardPort + a port range.
        let svc = svc_with_config(
            "dyn",
            r#"{"host.v1":{"protocol":"tcp","forwardAddress":true,
                "allowedAddresses":["127.0.0.1/32"],"forwardPort":true,
                "allowedPortRanges":[{"low":19000,"high":19100}]}}"#,
        );
        let cfg = svc.host_v1_config().unwrap().expect("host.v1 present");
        assert!(cfg.forward_address, "forwardAddress parsed (camelCase)");
        assert!(cfg.forward_port, "forwardPort parsed");
        assert_eq!(cfg.protocol, "tcp");
        assert_eq!(cfg.allowed_addresses, vec!["127.0.0.1/32".to_string()]);
        assert_eq!(
            cfg.allowed_port_ranges,
            vec![PortRange {
                low: 19000,
                high: 19100
            }]
        );
        // A forwardAddress host has no fixed address/port.
        assert!(cfg.address.is_empty() && cfg.port == 0);
    }

    #[test]
    fn host_v1_full_field_set_tolerated() {
        // The full field set (so T4b-2 needs no struct change): translations, listenOptions,
        // allowedProtocols, allowedSourceAddresses, forwardProtocol — plus an UNKNOWN key (proxy)
        // that serde must ignore.
        let svc = svc_with_config(
            "full",
            r#"{"host.v1":{
                "forwardProtocol":true,"allowedProtocols":["tcp","udp"],
                "forwardAddress":true,"allowedAddresses":["10.0.0.0/8"],
                "forwardAddressTranslations":[{"from":"1.2.3.0","to":"4.5.6.0","prefixLength":24}],
                "forwardPort":true,"allowedPortRanges":[{"low":1,"high":65535}],
                "allowedSourceAddresses":["192.168.0.0/16"],
                "listenOptions":{"connectTimeoutSeconds":7,"connectTimeout":"5s","cost":10},
                "proxy":{"address":"p:1","type":"http"}}}"#,
        );
        let cfg = svc.host_v1_config().unwrap().expect("host.v1 present");
        assert!(cfg.forward_protocol);
        assert_eq!(cfg.allowed_protocols, vec!["tcp", "udp"]);
        assert_eq!(
            cfg.forward_address_translations,
            vec![AddressTranslation {
                from: "1.2.3.0".into(),
                to: "4.5.6.0".into(),
                prefix_length: 24,
            }]
        );
        assert_eq!(
            cfg.allowed_source_addresses,
            vec!["192.168.0.0/16".to_string()]
        );
        let lo = cfg.listen_options.expect("listenOptions parsed");
        assert_eq!(lo.connect_timeout_seconds, Some(7));
        assert_eq!(lo.connect_timeout.as_deref(), Some("5s"));
    }

    #[test]
    fn host_v1_config_is_none_when_absent() {
        // A service whose config has only intercept.v1 (or nothing) → None for host.v1.
        let svc = svc_with_config(
            "i",
            r#"{"intercept.v1":{"addresses":["test.ziti"],"portRanges":[{"low":80,"high":80}],"protocols":["tcp"]}}"#,
        );
        assert!(svc.host_v1_config().unwrap().is_none());
        let empty = svc_with_config("e", "{}");
        assert!(empty.host_v1_config().unwrap().is_none());
    }

    #[test]
    fn host_v1_config_present_but_null_is_fail_loud() {
        // CONSCIOUS deviation (documented on HostV1Config): a present-but-`null` host.v1 is a
        // fail-loud ServiceConfig error here (serde cannot build a struct from JSON null), whereas the
        // oracle's mapstructure would yield a zero-value config. Unreachable through the controller's
        // schema (host.v1 must be a typed object), but pinned so the stricter behaviour is intentional.
        let svc = svc_with_config("nullcfg", r#"{"host.v1":null}"#);
        let err = svc.host_v1_config().unwrap_err();
        assert!(
            matches!(&err, crate::edge::error::EdgeError::ServiceConfig { config_type, .. } if config_type == "host.v1"),
            "present-but-null host.v1 is fail-loud, not a silent zero-value: {err:?}"
        );
    }

    #[test]
    fn host_v1_config_errors_when_malformed() {
        // A host.v1 present but with a type-wrong field (port as a string the schema forbids) →
        // fail-loud ServiceConfig error, not a silent None.
        let svc = svc_with_config("bad", r#"{"host.v1":{"port":"not-a-number"}}"#);
        let err = svc.host_v1_config().unwrap_err();
        assert!(
            matches!(&err, crate::edge::error::EdgeError::ServiceConfig { config_type, .. } if config_type == "host.v1"),
            "got: {err:?}"
        );
    }

    #[test]
    fn deserializes_service_with_null_collection_fields() {
        // A bind-only service (e.g. `bindsvc`) returns `"configs": null` (no config instances).
        // `#[serde(default)]` alone rejects an explicit null; null_to_default maps it to empty.
        let json = r#"{"id":"b","name":"bindsvc","encryptionRequired":false,
            "permissions":["Bind","Dial"],"config":{},"configs":null,"roleAttributes":null}"#;
        let svc: Service = serde_json::from_str(json).unwrap();
        assert_eq!(svc.name, "bindsvc");
        assert!(svc.configs.is_empty());
        assert_eq!(
            svc.permissions,
            vec!["Bind".to_string(), "Dial".to_string()]
        );
        // Defensive: tolerate explicit null on every collection field.
        let json2 = r#"{"id":"c","name":"x","permissions":null,"config":null,"configs":null}"#;
        let svc2: Service = serde_json::from_str(json2).unwrap();
        assert!(svc2.permissions.is_empty() && svc2.configs.is_empty() && svc2.config.is_empty());
    }
}
