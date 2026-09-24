//! Handshake del dialer sobre un stream async genérico. Oráculo: classic_dialer.go sendHello.
//! IO inyectable: testeado con `tokio::io::duplex`; el mTLS real solo en el `#[ignore]`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::channel::error::ChannelError;
use crate::channel::hello::{result_message, result_success};
use crate::channel::message::{CT_RESULT, DATA_SECTION_V2, Message, frame_lengths, parse_frame};

/// Lee un frame V2 completo del stream: 20 bytes de sección, luego `headers+body`.
///
/// # Errors
/// `ChannelError::Io` en error de lectura; `ChannelError::Frame` si el frame es inválido.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Message, ChannelError> {
    let mut section = [0u8; DATA_SECTION_V2];
    r.read_exact(&mut section)
        .await
        .map_err(|e| ChannelError::Io(e.to_string()))?;
    let (hlen, blen) = frame_lengths(&section)?;
    let mut rest = vec![0u8; hlen as usize + blen as usize];
    r.read_exact(&mut rest)
        .await
        .map_err(|e| ChannelError::Io(e.to_string()))?;
    let mut full = Vec::with_capacity(DATA_SECTION_V2 + rest.len());
    full.extend_from_slice(&section);
    full.extend_from_slice(&rest);
    parse_frame(&full)
}

/// Serializa y escribe un mensaje, con flush.
///
/// # Errors
/// `ChannelError::Io` en error de escritura/flush.
pub async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    msg: &Message,
) -> Result<(), ChannelError> {
    let bytes = msg.marshal_v2();
    w.write_all(&bytes)
        .await
        .map_err(|e| ChannelError::Io(e.to_string()))?;
    w.flush()
        .await
        .map_err(|e| ChannelError::Io(e.to_string()))?;
    Ok(())
}

/// Ejecuta el handshake del dialer: envía `hello`, lee un frame, exige que sea un
/// `Result(success)`. Oráculo: `classic_dialer.go:142-148`. La aceptación es por
/// `content-type == Result && ResultSuccess == true` (NO por el campo `sequence`,
/// que también vale -1 en el Result).
///
/// # Errors
/// - `ChannelError::UnexpectedContentType` si la respuesta no es un `Result`.
/// - `ChannelError::HandshakeRejected` si el `Result` trae `success == false`.
/// - Propaga `ChannelError::Io`/`Frame` de la lectura/escritura.
pub async fn connect_channel<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    hello: &Message,
) -> Result<Message, ChannelError> {
    write_message(stream, hello).await?;
    let resp = read_message(stream).await?;
    if resp.content_type != CT_RESULT {
        return Err(ChannelError::UnexpectedContentType(resp.content_type));
    }
    if !result_success(&resp) {
        return Err(ChannelError::HandshakeRejected(result_message(&resp)));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::error::ChannelError;
    use crate::channel::hello::new_hello;
    use crate::channel::message::{CT_HELLO, CT_RESULT, HDR_RESULT_SUCCESS, Message};
    use std::collections::BTreeMap;

    // Construye un Result que el "router" responde.
    fn make_result(success: bool, body: &str) -> Message {
        let mut m = Message::new(CT_RESULT, body.as_bytes().to_vec());
        m.headers
            .insert(HDR_RESULT_SUCCESS, vec![u8::from(success)]);
        m
    }

    #[tokio::test]
    async fn connect_succeeds_on_result_success() {
        let (mut client, mut router) = tokio::io::duplex(4096);
        let router_task = tokio::spawn(async move {
            let hello = read_message(&mut router).await.expect("router reads hello");
            assert_eq!(hello.content_type, CT_HELLO);
            assert_eq!(hello.headers.get(&1002).unwrap().as_slice(), b"api-tok");
            write_message(&mut router, &make_result(true, ""))
                .await
                .unwrap();
        });

        let mut headers = BTreeMap::new();
        headers.insert(1002_i32, b"api-tok".to_vec());
        let hello = new_hello("cn", headers);
        let result = connect_channel(&mut client, &hello)
            .await
            .expect("handshake ok");
        assert_eq!(result.content_type, CT_RESULT);
        router_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_rejects_on_result_failure() {
        let (mut client, mut router) = tokio::io::duplex(4096);
        let router_task = tokio::spawn(async move {
            let _ = read_message(&mut router).await.unwrap();
            write_message(&mut router, &make_result(false, "invalid token"))
                .await
                .unwrap();
        });
        let hello = new_hello("cn", BTreeMap::new());
        let err = connect_channel(&mut client, &hello).await.unwrap_err();
        assert!(matches!(err, ChannelError::HandshakeRejected(m) if m == "invalid token"));
        router_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_errors_on_unexpected_content_type() {
        let (mut client, mut router) = tokio::io::duplex(4096);
        let router_task = tokio::spawn(async move {
            let _ = read_message(&mut router).await.unwrap();
            let mut wrong = Message::new(7, vec![]); // 7 = TypeHeader, no es Result
            wrong.headers.insert(HDR_RESULT_SUCCESS, vec![1]);
            write_message(&mut router, &wrong).await.unwrap();
        });
        let hello = new_hello("cn", BTreeMap::new());
        let err = connect_channel(&mut client, &hello).await.unwrap_err();
        assert!(matches!(err, ChannelError::UnexpectedContentType(7)));
        router_task.await.unwrap();
    }
}
