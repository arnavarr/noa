//! Helper compartido por los módulos de test de `edge::refresh`: `push_target`, el canal
//! duplex cuyo router fake reporta el body del `UpdateToken` recibido y responde `reply_ct`.
//! (F6 tramo 7: movidos verbatim del monolito de `edge/refresh`.)

use std::time::Duration;

use crate::channel::connect::{read_message, write_message};
use crate::channel::message::{HDR_REPLY_FOR, Message};
use crate::edge::data::{CT_UPDATE_TOKEN, EdgeChannel};

/// A duplex-backed live channel whose fake router waits briefly for an `UpdateToken`, reports its
/// BODY on a oneshot (`None` if none arrives = "not pushed"), and replies with `reply_ct`. Returns
/// the live `EdgeChannel` (the caller must keep it alive so the registry `Weak` upgrades).
pub(super) fn push_target(
    reply_ct: i32,
) -> (EdgeChannel, tokio::sync::oneshot::Receiver<Option<Vec<u8>>>) {
    let (client, mut router) = tokio::io::duplex(8192);
    let (cr, cw) = tokio::io::split(client);
    let ch = EdgeChannel::from_halves(
        Box::new(cr),
        Box::new(cw),
        std::collections::BTreeMap::new(),
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        match tokio::time::timeout(Duration::from_millis(300), read_message(&mut router)).await {
            Ok(Ok(ut)) => {
                assert_eq!(
                    ut.content_type, CT_UPDATE_TOKEN,
                    "the push is an UpdateToken"
                );
                let _ = tx.send(Some(ut.body.clone()));
                let mut reply = Message::new(reply_ct, vec![]);
                reply
                    .headers
                    .insert(HDR_REPLY_FOR, ut.sequence.to_le_bytes().to_vec());
                let _ = write_message(&mut router, &reply).await;
            }
            // No frame arrived (or EOF from a dropped channel): report "not pushed".
            _ => {
                let _ = tx.send(None);
            }
        }
    });
    (ch, rx)
}
