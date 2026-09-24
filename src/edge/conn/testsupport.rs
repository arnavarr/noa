//! Fixture compartida de tests (F6 tramo 5: movida verbatim del monolito de `edge/conn`).

use crate::edge::model::{SessionDetail, SessionEdgeRouter, SessionType};

pub(super) fn detail() -> SessionDetail {
    SessionDetail {
        id: "s".into(),
        token: "jwt-tok".into(),
        service_id: "svc".into(),
        session_type: SessionType::Dial,
        api_session_id: String::new(),
        identity_id: String::new(),
        edge_routers: vec![SessionEdgeRouter::default()],
    }
}
