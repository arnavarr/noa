//! **El forward a upstream SOBRE TCP**: failover secuencial, conn por-query.

use std::net::SocketAddr;
use std::time::Duration;

use super::framing::read_tcp_dns_msg;

/// Reenvía UNA query a los upstreams SOBRE TCP: intento secuencial por servidor (connect → write
/// enmarcado → read enmarcado, todo bajo `attempt_timeout`), la primera respuesta cuyo id casa la
/// query gana. `None` = ningún upstream respondió (→ el llamante devuelve el REFUSED de fallback).
///
/// **Divergencias conscientes (spec §7.3-7.8, todas under-permit / coste-de-conns, jamás over-permit):**
///  - **failover secuencial** vs el fan-out simultáneo del oráculo UDP (`query_upstream:856-865`
///    envía a TODOS): peor caso acotado N×`attempt_timeout`; jamás una respuesta incorrecta;
///  - **conn POR QUERY** (sin el reuse cliente→upstream de RFC 7766 §6.2.1): coste de conns/latencia;
///  - **transporte TCP a upstream** (no el socket UDP): paridad de transporte — un forward que
///    volviera por UDP truncado (TC=1) provocaría livelock de cliente (§2 del spec);
///  - **respuesta >4096 → intento fallido** (cap de [`read_tcp_dns_msg`], §7.8).
pub(super) async fn forward_upstream_tcp(
    servers: &[SocketAddr],
    query: &[u8],
    attempt_timeout: Duration,
) -> Option<Vec<u8>> {
    for &server in servers {
        // connect + write + read enmarcados, TODO bajo el mismo timeout de intento.
        if let Ok(Some(resp)) =
            tokio::time::timeout(attempt_timeout, forward_one_upstream(server, query)).await
        {
            return Some(resp);
        }
        // Timeout, connect fallido, EOF/error o respuesta sobredimensionada → siguiente servidor.
    }
    None
}

/// UN intento contra un upstream TCP: conecta, escribe la query enmarcada y lee mensajes enmarcados
/// hasta que uno case el id de la query (passthrough VERBATIM de ESE mensaje). Una respuesta cuyo id
/// NO casa se descarta y se sigue leyendo la conn (espejo del descarte de espurias de `match_response`,
/// `intercept/udp/upstream.rs`: id desconocido → descarte). `None` = connect fallido, EOF/error de lectura, o respuesta
/// sobredimensionada (>[`crate::tunnel::intercept::dns_tcp::framing::DNS_TCP_MAX_MSG`]).
async fn forward_one_upstream(server: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    use tokio::io::AsyncWriteExt;
    let mut conn = tokio::net::TcpStream::connect(server).await.ok()?;
    let len = u16::try_from(query.len()).ok()?;
    conn.write_all(&len.to_be_bytes()).await.ok()?;
    conn.write_all(query).await.ok()?;
    conn.flush().await.ok()?;
    loop {
        // `Ok(None)` (EOF) o `Err` (I/O / sobredimensionado) → este servidor falló (`??` → None).
        let response = read_tcp_dns_msg(&mut conn).await.ok()??;
        // Casa por id (los 2 primeros bytes) como `match_response`; una respuesta espuria se descarta
        // y se sigue leyendo hasta el timeout envolvente (que corta el `loop`).
        if response.len() >= 2 && response[0..2] == query[0..2] {
            return Some(response);
        }
    }
}
