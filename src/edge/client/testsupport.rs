//! Shared test fixtures for the split `client` test modules.
//!
//! This module is a re-export hub for the sibling `tests_*` modules, so it deliberately
//! re-exports names some of them do not each use.
#![allow(unused_imports)]

pub(crate) use super::auth::*;
pub(crate) use super::construct::*;
pub(crate) use super::oidc_glue::*;
pub(crate) use super::pool::*;
pub(crate) use super::services::*;
pub(crate) use super::sessions::*;
pub(crate) use super::sessions_probe::*;
pub(crate) use super::*;

pub(crate) use std::collections::HashMap;
pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};
pub(crate) use std::sync::{Arc, Mutex, RwLock, Weak};
pub(crate) use std::time::{Duration, SystemTime};

pub(crate) use backon::{ExponentialBuilder, Retryable};

pub(crate) use crate::edge::auth_token::{ApiSessionType, AuthToken};
pub(crate) use crate::edge::error::EdgeError;
pub(crate) use crate::edge::identity_tls::mtls_client;
pub(crate) use crate::edge::model::{
    ApiSession, Envelope, Paginated, Service, ServiceEdgeRouterList, SessionCreate, SessionDetail,
    SessionEdgeRouter, SessionType, sanitize_supported_protocols,
};
pub(crate) use crate::edge::oidc::OidcGrant;
pub(crate) use crate::edge::reauth::{ReauthMethod, is_unauthorized};
pub(crate) use crate::edge::refresh::{
    PROD_INTERVALS, RefreshIntervals, do_oidc_session_refresh, do_reauthenticate, do_refresh_get,
    parse_expires_at, run_refreshes, store_token_and_expiry,
};
pub(crate) use crate::edge::service_refresh::{
    PROD_SERVICE_INTERVALS, ServiceRefreshIntervals, run_service_refreshes,
};
pub(crate) use crate::edge::services::{ServiceEvent, ServiceListenerId};
pub(crate) use crate::edge::session_refresh::{
    PROD_SESSION_INTERVALS, SessionRefreshIntervals, run_session_refreshes,
};
pub(crate) use crate::enroll::identity::Config;

pub(crate) use tracing_test::traced_test;
pub(crate) use wiremock::matchers::{body_json, header, method, path, query_param};
pub(crate) use wiremock::{Mock, MockServer, ResponseTemplate};

pub(crate) const TEST_TOTAL: Duration = Duration::from_secs(15);
pub(crate) const FAR_EXPIRY: &str = "2099-01-01T00:00:00Z";

impl EdgeClient {
    pub(crate) fn from_identity_for_test() -> Self {
        Self::for_test_inner("http://127.0.0.1:1/edge/client/v1", None, None)
    }

    /// A test client wired to a wiremock `base_url` with an api-session token already set, so the
    /// stateful paths (`connect_inner`, the Dial-session cache, `refresh_session`) can be exercised
    /// over HTTP without a real controller.
    pub(crate) fn for_test_with(base_url: &str, token: &str) -> Self {
        Self::for_test_inner(base_url, Some(token), Some("tester"))
    }

    /// Like [`Self::for_test_with`], but carrying a REAL rcgen cert identity (a CA-signed leaf plus its
    /// self-signed CA) so `channel_client_config()` BUILDS OFFLINE (`for_test_with`'s identity is empty ⇒ it fails with
    /// `IdentityLoad` before any router is dialed). Needed by the slice-4b guard tests in
    /// `edge::channel`: their discriminant is that the connect fan-out actually REACHES
    /// `parse_tls_address`, so an unparseable REFRESHED router address NAMES itself in the surfaced
    /// error — which is what tells "refreshed and used the fresh edge-routers" apart from
    /// "never refreshed" (`NoTlsEdgeRouter`). Still NO network: the config is built from PEM in memory.
    pub(crate) fn for_test_with_cert_identity(base_url: &str, token: &str) -> Self {
        // `EdgeClient` implements `Drop`, so struct-update syntax (`..for_test_inner(..)`) cannot move
        // out of it — assign the field instead.
        let mut client = Self::for_test_inner(base_url, Some(token), Some("tester"));
        client.config = cert_identity_config();
        client
    }

    /// A test client whose api-session is an OIDC (Bearer) session. `refresh` carries the OIDC refresh
    /// token (the token-exchange subject) — `Some` for the OIDC-3 refresh-path tests (the helper
    /// actually exchanges), `None` for the cannot-refresh / park case. (Before OIDC-3 this was always
    /// `None`; the refresh-bearing form is REQUIRED for the converted reactive/proactive/refresh()
    /// tests, else the helper hits the no-refresh branch and false-greens by parking instead of
    /// exchanging.)
    pub(crate) fn for_test_with_oidc(base_url: &str, access: &str, refresh: Option<&str>) -> Self {
        let c = Self::for_test_inner(base_url, None, Some("tester"));
        *c.token.write().unwrap() = Some(AuthToken::Oidc {
            access: access.to_string(),
            refresh: refresh.map(str::to_string),
        });
        c
    }

    fn for_test_inner(base_url: &str, token: Option<&str>, identity_name: Option<&str>) -> Self {
        crate::enroll::trust::ensure_crypto_provider();
        Self {
            base_url: base_url.to_string(),
            http: reqwest::Client::new(),
            token: Arc::new(RwLock::new(token.map(|t| AuthToken::Legacy(t.to_string())))),
            expires_at: Arc::new(RwLock::new(None)),
            // Test ctor → Cert (spec §3.2); the wiremock re-auth tests that need it mount
            // `/authenticate?method=cert`. `from_updb` tests build via `from_updb` (→ `Updb`).
            reauth_method: Arc::new(ReauthMethod::Cert),
            // No MFA provider by default in test ctor; a test that exercises the legacy MFA re-auth
            // path sets `c.mfa_provider` directly after construction.
            mfa_provider: None,
            reauth_lock: Arc::new(tokio::sync::Mutex::new(())),
            identity_name: identity_name.map(str::to_string),
            config: crate::enroll::identity::Config {
                zt_api: base_url.to_string(),
                zt_apis: None,
                config_types: None,
                id: crate::enroll::identity::Id {
                    key: String::new(),
                    cert: String::new(),
                    ca: String::new(),
                },
            },
            dial_sessions: Arc::new(Mutex::new(HashMap::new())),
            session_cert: None,
            // Tests that need the timer build it explicitly (a tiny-interval injected variant); the
            // default test client has no live timer (no spawn-once → no background HTTP churn).
            refresh_task: None,
            live_channels: Arc::new(Mutex::new(Vec::new())),
            channel_pool: Arc::new(Mutex::new(HashMap::new())),
            tls_opens: Arc::new(AtomicUsize::new(0)),
            services: Arc::new(crate::edge::services::ServiceWatcher::new()),
            last_service_update: Arc::new(Mutex::new(None)),
            service_refresh_task: None,
            session_refresh_task: None,
            edge_router_url_filter: None,
        }
    }
}

pub(crate) fn dial_detail(service_id: &str, token: &str) -> SessionDetail {
    SessionDetail {
        id: "sess".into(),
        token: token.into(),
        service_id: service_id.into(),
        session_type: SessionType::Dial,
        api_session_id: String::new(),
        identity_id: String::new(),
        edge_routers: vec![],
    }
}

pub(crate) fn dial_detail_ers(service_id: &str, token: &str, er_name: &str) -> SessionDetail {
    SessionDetail {
        edge_routers: vec![SessionEdgeRouter {
            name: er_name.into(),
            ..Default::default()
        }],
        ..dial_detail(service_id, token)
    }
}

pub(crate) fn dial_detail_id_ers(
    service_id: &str,
    id: &str,
    token: &str,
    er_name: &str,
) -> SessionDetail {
    SessionDetail {
        id: id.into(),
        ..dial_detail_ers(service_id, token, er_name)
    }
}

pub(crate) fn er_names(session: &SessionDetail) -> Vec<String> {
    session
        .edge_routers
        .iter()
        .map(|e| e.name.clone())
        .collect()
}

pub(crate) fn fast_backoff() -> ExponentialBuilder {
    ExponentialBuilder::default()
        .with_min_delay(Duration::from_micros(1))
        .with_max_delay(Duration::from_micros(10))
        .with_total_delay(Some(Duration::from_secs(5)))
        .without_max_times()
}

pub(crate) fn session_http(status: u16) -> EdgeError {
    EdgeError::SessionHttp {
        status,
        code: "X".into(),
        message: "x".into(),
    }
}

pub(crate) fn alive_detail_body() -> &'static str {
    r#"{"data":{"id":"sess","token":"opaque-x","serviceId":"svc-1","type":"Dial","edgeRouters":[{"name":"er_new","supportedProtocols":{"tls":"tls://router:443"}}]},"meta":{}}"#
}

pub(crate) fn ephemeral_leaf() -> String {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["apiSession".to_string()]).unwrap();
    params.self_signed(&kp).unwrap().pem()
}

pub(crate) async fn mount_updb_flow(
    server: &MockServer,
    leaf: &str,
    inter: &str,
    auth_status: u16,
    cert_expect: u64,
) {
    // Password auth.
    let auth_body = if auth_status == 200 {
        serde_json::json!({
            "data": { "id": "s", "token": "updb-tok", "authQueries": [],
                      "identity": { "name": "updbuser" } },
            "meta": {}
        })
    } else {
        serde_json::json!({ "error": { "code": "INVALID_AUTH", "message": "bad" } })
    };
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "password"))
        .respond_with(ResponseTemplate::new(auth_status).set_body_json(auth_body))
        .mount(server)
        .await;
    // Cert mint (only reachable if auth succeeded). `.expect(cert_expect)` is verified on drop:
    // 0 proves the cert request is NOT made when auth fails.
    let chain = format!("{leaf}{inter}");
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/current-api-session/certificates"))
        .and(header("zt-session", "updb-tok"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "data": { "id": "cert-1", "certificate": chain, "cas": "\n<ca>" },
            "meta": {}
        })))
        .expect(cert_expect)
        .mount(server)
        .await;
}

pub(crate) fn updb_cfg(base: &str) -> crate::enroll::updb::UpdbConfig {
    crate::enroll::updb::UpdbConfig {
        // Over `http://` reqwest uses plain TCP regardless of the (dormant) RootCAs, so an empty
        // CA bundle is fine for the wiremock flow.
        zt_api: base.to_string(),
        ca: String::new(),
        username: "alice".into(),
        password: "pw".into(),
    }
}

pub(crate) fn cert_identity_config() -> crate::enroll::identity::Config {
    let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_kp).unwrap();

    let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let mut leaf_dn = rcgen::DistinguishedName::new();
    leaf_dn.push(rcgen::DnType::CommonName, "client-cn");
    let mut leaf_params = rcgen::CertificateParams::new(vec![]).unwrap();
    leaf_params.distinguished_name = leaf_dn;
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_kp);
    let leaf = leaf_params.signed_by(&leaf_kp, &issuer).unwrap();

    crate::enroll::identity::Config {
        zt_api: "https://localhost:1280/edge/client/v1".into(),
        zt_apis: None,
        config_types: None,
        id: crate::enroll::identity::Id {
            key: format!("pem:{}", leaf_kp.serialize_pem()),
            cert: format!("pem:{}{}", leaf.pem(), ca.pem()),
            ca: format!("pem:{}", ca.pem()),
        },
    }
}

pub(crate) fn p256_leaf_cn_signed(
    cn: &str,
    leaf_kp: &rcgen::KeyPair,
    ca_params: &rcgen::CertificateParams,
    ca_kp: &rcgen::KeyPair,
) -> String {
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.distinguished_name = dn;
    let issuer = rcgen::Issuer::from_params(ca_params, ca_kp);
    params.signed_by(leaf_kp, &issuer).unwrap().pem()
}

pub(crate) async fn mount_cert_reauth(server: &MockServer, new_token: &str, expect: u64) {
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/authenticate"))
        .and(query_param("method", "cert"))
        // Include `expiresAt` (the real `/authenticate` returns it) so the §4.3 requirement —
        // reauth persists token AND expiry — is exercised: a reauth test asserts
        // `expires_at().is_some()`. A far-future value keeps any spawned timer parked.
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "id": "a", "token": new_token, "expiresAt": "2099-01-01T00:00:00Z",
                      "authQueries": [], "identity": { "name": "tester" } },
            "meta": {}
        })))
        .expect(expect)
        .mount(server)
        .await;
}

pub(crate) async fn mount_refresh_get(
    server: &MockServer,
    new_token: &str,
    new_expires_at: &str,
    expect: u64,
) {
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/current-api-session"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "id": "a", "token": new_token, "expiresAt": new_expires_at,
                      "authQueries": [], "identity": { "name": "tester" } },
            "meta": {}
        })))
        .expect(expect)
        .mount(server)
        .await;
}

pub(crate) struct CountingServices(pub(crate) Arc<std::sync::atomic::AtomicUsize>);
impl wiremock::Respond for CountingServices {
    fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_string(
                r#"{"data":[{"id":"s1","name":"alpha","encryptionRequired":false,"permissions":["Dial"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
            )
    }
}
