//! Test del Hello del canal (`build_channel_hello`).
//! (F6 tramo 6: movido verbatim del monolito de `edge/channel`.)

#[test]
fn build_channel_hello_sets_token_header_and_cn_body() {
    let msg = super::build_channel_hello("api-tok-123", "LeafCN");
    assert_eq!(msg.content_type, crate::channel::message::CT_HELLO);
    assert_eq!(msg.sequence, crate::channel::message::HELLO_SEQUENCE);
    assert_eq!(msg.headers.get(&1002).unwrap().as_slice(), b"api-tok-123");
    assert_eq!(msg.body, b"LeafCN");
}
