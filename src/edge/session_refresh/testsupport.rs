//! Fixtures compartidos por los módulos de test de `edge::session_refresh`: tokens api-session,
//! sesiones Dial, bodies de mock y lectores del caché.
//! (F6 tramo 8: movidos verbatim del monolito de `edge/session_refresh`.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use crate::edge::auth_token::AuthToken;
use crate::edge::model::{SessionDetail, SessionEdgeRouter, SessionType};

pub(super) fn legacy_token(tok: &str) -> Arc<RwLock<Option<AuthToken>>> {
    Arc::new(RwLock::new(Some(AuthToken::Legacy(tok.to_string()))))
}

/// An **OIDC** api-session token (4a): the discriminant of the tick's probe is the API-SESSION type
/// (`session_router.go:220-226` — only a legacy api-session PERSISTS the session), never the session
/// token's prefix (DV-4a-3).
pub(super) fn oidc_token(tok: &str) -> Arc<RwLock<Option<AuthToken>>> {
    Arc::new(RwLock::new(Some(AuthToken::Oidc {
        access: tok.to_string(),
        refresh: None,
    })))
}

/// An OPAQUE (non-`ey`) Dial session with one edge-router named `er_name`, cached under `service_id`.
pub(super) fn opaque_session(service_id: &str, id: &str, er_name: &str) -> SessionDetail {
    SessionDetail {
        id: id.into(),
        token: "opaque-token".into(),
        service_id: service_id.into(),
        session_type: SessionType::Dial,
        api_session_id: String::new(),
        identity_id: String::new(),
        edge_routers: vec![SessionEdgeRouter {
            name: er_name.into(),
            ..Default::default()
        }],
    }
}

/// A JWT (`ey`-prefixed) Dial session — the ONLY kind a `ziti` v2 controller mints
/// (`session_router.go:191`,`:214`), hence the default fixture of every tick test.
///
/// ⚠ Since 4a its token prefix does **NOT** choose the tick's probe: the API-SESSION does (DV-4a-3).
/// Pair it with [`legacy_token`] to exercise the DURABLE probe (`GET /sessions/{id}` — the rig's real
/// combination), or with [`oidc_token`] to exercise the STATELESS one (`ListServiceEdgeRouters`,
/// `client.go:250-294`, whose controller handler never reads the session store — the WIDE window of
/// spec §1.3; evidence in the module docs, **not** `client.go:236`, which documents `GetSession`).
pub(super) fn jwt_session(service_id: &str, id: &str, er_name: &str) -> SessionDetail {
    SessionDetail {
        token: "eyJ.dial.jwt".into(),
        ..opaque_session(service_id, id, er_name)
    }
}

/// A `GET /sessions/{id}` 200 body carrying `serviceId` + a single edge-router named `er_name`.
pub(super) fn detail_body(id: &str, service_id: &str, er_name: &str) -> String {
    format!(
        r#"{{"data":{{"id":"{id}","token":"opaque-token","serviceId":"{service_id}","type":"Dial","edgeRouters":[{{"name":"{er_name}","supportedProtocols":{{"tls":"tls://router:443"}}}}]}},"meta":{{}}}}"#
    )
}

/// A `GET /services/{id}/edge-routers` 200 body with a single edge-router named `er_name`.
pub(super) fn edge_routers_body(er_name: &str) -> String {
    format!(
        r#"{{"data":{{"edgeRouters":[{{"name":"{er_name}","supportedProtocols":{{"tls":"tls://router:443"}}}}]}},"meta":{{}}}}"#
    )
}

/// The cached session's id under `service_id` (`None` if the key is absent).
pub(super) fn cached_id(
    dial: &Arc<Mutex<HashMap<String, SessionDetail>>>,
    service_id: &str,
) -> Option<String> {
    dial.lock().unwrap().get(service_id).map(|s| s.id.clone())
}

pub(super) fn seed(sessions: &[SessionDetail]) -> Arc<Mutex<HashMap<String, SessionDetail>>> {
    let mut map = HashMap::new();
    for s in sessions {
        map.insert(s.service_id.clone(), s.clone());
    }
    Arc::new(Mutex::new(map))
}

pub(super) fn cached_ers(
    dial: &Arc<Mutex<HashMap<String, SessionDetail>>>,
    service_id: &str,
) -> Vec<String> {
    dial.lock()
        .unwrap()
        .get(service_id)
        .map(|s| s.edge_routers.iter().map(|er| er.name.clone()).collect())
        .unwrap_or_default()
}
