//! Test fixtures shared by the bind unit tests: the REST mounts `bind_inner` always hits and the
//! two duplex-backed fake routers (one that replies `StateConnected` fast, one that never replies).
//! Consumed by `tests_flow.rs`.

use crate::channel::connect::{read_message, write_message};
use crate::channel::message::Message;
use crate::edge::data::EdgeChannel;
use crate::edge::dial::CT_STATE_CONNECTED;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mount the REST steps `bind_inner` always hits: list services (one plaintext `bindsvc`,
/// id `bind-9`) and create a Bind session for it. Mirrors `conn::tests::mount_resolve_and_create`
/// but for the Bind session type and the bind service shape.
pub(super) async fn mount_bind_resolve_and_create(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/edge/client/v1/services"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"data":[{"id":"bind-9","name":"bindsvc","encryptionRequired":false,"permissions":["Bind"],"config":{},"configs":[]}],"meta":{"pagination":{"limit":500,"offset":0,"totalCount":1}}}"#,
        ))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/edge/client/v1/sessions"))
        .respond_with(ResponseTemplate::new(201).set_body_string(
            r#"{"data":{"id":"bsess","token":"bjwt-9","serviceId":"bind-9","type":"Bind","edgeRouters":[{"name":"er1","supportedProtocols":{"tls":"tls://r:3022"}}]},"meta":{}}"#,
        ))
        .mount(server)
        .await;
}

/// A duplex-backed `EdgeChannel` whose fake router replies `StateConnected` to the Bind (a fast,
/// successful bind), correlating by the Bind's sequence — so the happy-path bind completes.
pub(super) fn fast_bind_channel() -> EdgeChannel {
    let (client_io, router_io) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client_io);
    tokio::spawn(async move {
        let mut router = router_io;
        let Ok(bind) = read_message(&mut router).await else {
            return;
        };
        let mut sc = Message::new(CT_STATE_CONNECTED, vec![]);
        sc.headers.insert(1, bind.sequence.to_le_bytes().to_vec());
        let _ = write_message(&mut router, &sc).await;
        // Stay alive holding `router` so the channel doesn't see EOF while the binding lives.
        std::future::pending::<()>().await;
    });
    EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    )
}

/// A duplex-backed `EdgeChannel` whose fake router reads the Bind but NEVER replies, so the
/// bind's reply-wait hangs forever — exactly the degraded-but-listening router the bind-timeout
/// must bound. (Keeps the router task alive holding its half so the channel doesn't see EOF.)
pub(super) fn hanging_bind_channel() -> EdgeChannel {
    let (client_io, router_io) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client_io);
    tokio::spawn(async move {
        let mut router = router_io;
        let _ = read_message(&mut router).await; // consume the Bind, then hang holding `router`
        std::future::pending::<()>().await;
    });
    EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    )
}
