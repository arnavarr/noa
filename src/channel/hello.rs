//! Builders y accessors de Hello/Result. Oráculo: channel/messages.go:34-68.

use std::collections::BTreeMap;

use crate::channel::message::{CT_HELLO, HDR_RESULT_SUCCESS, HELLO_SEQUENCE, Message};

/// Construye el Hello del dialer: content-type 0, sequence -1, body = `id_token`
/// (CN del leaf, informativo), más `headers` (p.ej. `1002` = token de api-session).
#[must_use]
pub fn new_hello(id_token: &str, headers: BTreeMap<i32, Vec<u8>>) -> Message {
    Message {
        content_type: CT_HELLO,
        sequence: HELLO_SEQUENCE,
        headers,
        body: id_token.as_bytes().to_vec(),
    }
}

/// `true` si el `Result` trae `ResultSuccessHeader(2)` con primer byte `== 1`.
#[must_use]
pub fn result_success(msg: &Message) -> bool {
    msg.headers
        .get(&HDR_RESULT_SUCCESS)
        .is_some_and(|v| v.first() == Some(&1))
}

/// El mensaje de error de un `Result` (su body como texto).
#[must_use]
pub fn result_message(msg: &Message) -> String {
    String::from_utf8_lossy(&msg.body).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::message::{CT_HELLO, HELLO_SEQUENCE};

    #[test]
    fn new_hello_sets_type_seq_body() {
        let mut h = BTreeMap::new();
        h.insert(1002, b"tok".to_vec());
        let msg = new_hello("cn", h);
        assert_eq!(msg.content_type, CT_HELLO);
        assert_eq!(msg.sequence, HELLO_SEQUENCE);
        assert_eq!(msg.body, b"cn");
        assert_eq!(msg.headers.get(&1002).unwrap().as_slice(), b"tok");
    }

    #[test]
    fn result_success_reads_header() {
        let mut ok = Message::new(crate::channel::message::CT_RESULT, vec![]);
        ok.headers
            .insert(crate::channel::message::HDR_RESULT_SUCCESS, vec![1]);
        assert!(result_success(&ok));
        let mut bad = Message::new(crate::channel::message::CT_RESULT, b"denied".to_vec());
        bad.headers
            .insert(crate::channel::message::HDR_RESULT_SUCCESS, vec![0]);
        assert!(!result_success(&bad));
        assert_eq!(result_message(&bad), "denied");
    }
}
