//! Dial core del canal V2: mTLS + Hello/Result contra UN edge router (`dial_handshake`) y sus
//! piezas (`HDR_SESSION_TOKEN`, `leaf_common_name_for`, `build_channel_hello`).
//! (F6 tramo 6: movido verbatim del monolito de `edge/channel`.)

use std::collections::BTreeMap;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::channel::connect::connect_channel;
use crate::channel::hello::new_hello;
use crate::edge::data::EdgeChannel;
use crate::edge::error::EdgeError;

/// Header edge `SessionToken` (lleva el token de API-session en el Hello del canal).
/// Oráculo: sdk-golang edge/messages.go:85, edge_client.proto `SessionToken = 1002`.
const HDR_SESSION_TOKEN: i32 = 1002;

/// Extract the leaf CN (informational; goes in the channel Hello body) from a RAW PEM (no `pem:`
/// prefix). Used by `channel_client_config` for both the cert-identity path (CN of `config.id.cert`,
/// `pem:`-stripped at the call site) and the session-cert renewal path (the holder's raw-PEM leaf).
pub(crate) fn leaf_common_name_for(pem: &str) -> Option<String> {
    let chain = x509_cert::Certificate::load_pem_chain(pem.as_bytes()).ok()?;
    let dn = chain.first()?.tbs_certificate.subject.to_string();
    dn.split(',')
        .find_map(|p| p.trim().strip_prefix("CN=").map(str::to_string))
}

/// Build the slice-3 channel Hello: header `1002` (SessionToken) = the api-session
/// token, body = the leaf CN (informational). Oracle: ziti.go connectEdgeRouter.
pub(super) fn build_channel_hello(api_token: &str, cn: &str) -> crate::channel::message::Message {
    let mut headers = BTreeMap::new();
    headers.insert(HDR_SESSION_TOKEN, api_token.as_bytes().to_vec());
    new_hello(cn, headers)
}

/// Dial ONE edge router (`host`:`port`) over mTLS and complete the V2 channel handshake (Hello/Result),
/// returning a live [`EdgeChannel`] seeded with its connectTime. The dial CORE shared by `open_channel_to`
/// (bind, `&self`) and the connect fan-out's [`open_and_pool_router`](super::open_and_pool_router) (`'static`); takes the already-built
/// per-client `cc`/`cn`/`token` so it borrows nothing from `&EdgeClient`. Bumps `tls_opens` on the
/// completed handshake (the SOLE handshake site → the pool's reuse observable). Oracle: the dial inside
/// `connectEdgeRouter` (`ziti.go:1746-1854`).
pub(super) async fn dial_handshake(
    host: &str,
    port: u16,
    cc: Arc<rustls::ClientConfig>,
    cn: &str,
    token: &str,
    tls_opens: &std::sync::atomic::AtomicUsize,
) -> Result<EdgeChannel, EdgeError> {
    let connector = TlsConnector::from(cc);
    // connectTime clock (slice (A)): starts before the TCP connect (the config/identity is already built
    // — the oracle captures `start` AFTER `GetIdentity`), stops once the Hello/Result is in (`ziti.go:1854`).
    let connect_start = std::time::Instant::now();
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| EdgeError::ChannelTls(format!("tcp connect {host}:{port}: {e}")))?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| EdgeError::ChannelTls(format!("server name {host}: {e}")))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| EdgeError::ChannelTls(format!("tls handshake {host}: {e}")))?;
    let hello = build_channel_hello(token, cn);
    let result = connect_channel(&mut stream, &hello).await?;
    let connect_nanos = u64::try_from(connect_start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    tls_opens.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (read, write) = tokio::io::split(stream);
    let channel = EdgeChannel::from_halves(Box::new(read), Box::new(write), result.headers);
    channel.seed_latency(connect_nanos); // connectTime seed, BEFORE the channel is pooled
    Ok(channel)
}
