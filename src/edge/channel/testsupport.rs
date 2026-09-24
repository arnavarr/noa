//! Helpers compartidos por los módulos de test de `edge::channel`: fixtures de sesión
//! (`er`, `detail_of`, `detail_with`) y el canal fake (`fake_channel`).
//! (F6 tramo 6: movidos verbatim del monolito de `edge/channel`.)

use std::collections::BTreeMap;

use crate::edge::data::EdgeChannel;
use crate::edge::model::{SessionDetail, SessionEdgeRouter, SessionType};

pub(super) fn er(name: &str, tls: Option<&str>) -> SessionEdgeRouter {
    let mut supported_protocols = BTreeMap::new();
    if let Some(t) = tls {
        supported_protocols.insert("tls".to_string(), t.to_string());
    }
    SessionEdgeRouter {
        name: name.to_string(),
        hostname: String::new(),
        supported_protocols,
    }
}

pub(super) fn detail_of(id: &str, token: &str, routers: Vec<SessionEdgeRouter>) -> SessionDetail {
    SessionDetail {
        id: id.into(),
        token: token.into(),
        service_id: "svc".into(),
        session_type: SessionType::Dial,
        api_session_id: String::new(),
        identity_id: String::new(),
        edge_routers: routers,
    }
}

/// The default fixture session: id `s`, OPAQUE token (`jwt-tok` does NOT start with the
/// `JWT_TOKEN_PREFIX` "ey"), service `svc`.
pub(super) fn detail_with(routers: Vec<SessionEdgeRouter>) -> SessionDetail {
    detail_of("s", "jwt-tok", routers)
}

/// A plain fake `EdgeChannel` over a duplex (no drop instrumentation).
pub(super) fn fake_channel() -> (EdgeChannel, tokio::io::DuplexStream) {
    let (client_io, router_io) = tokio::io::duplex(64);
    let (cr, cw) = tokio::io::split(client_io);
    let ch = EdgeChannel::from_halves(Box::new(cr), Box::new(cw), BTreeMap::new());
    (ch, router_io)
}
