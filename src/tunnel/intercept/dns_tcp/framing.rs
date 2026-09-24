//! El framing **RFC 7766** (prefijo de longitud 2B big-endian, RFC 1035 §4.2.2): lee/escribe UN
//! mensaje DNS-over-TCP enmarcado. Beyond-oracle (`super`, §0): no hay bytes de C/Go que
//! fidelity-verificar aquí, hay bytes de RFC que cumplir.

use std::io;
use std::time::Duration;

/// Idle timeout de una conexión DNS-over-TCP (RFC 7766 §6.2.3: un servidor DEBERÍA cerrar las
/// conexiones ociosas tras "unos segundos"; no fija un valor). Acota tanto la espera ENTRE queries
/// como la lectura de un mensaje a medias (slow-loris: el cliente manda el prefijo de longitud y no
/// envía el cuerpo, o abre la conn y no consulta) → cerramos la conexión y liberamos la task/stream.
/// **NO corre durante el servicio de una query** (solo envuelve [`read_tcp_dns_msg`]): es la lectura
/// fiel de "idle" = sin queries pendientes (RFC 7766 §6.2.3). El tiempo en vuelo de una acción async
/// está acotado por construcción (forward ≤ N×[`crate::tunnel::intercept::udp::DNS_UPSTREAM_TIMEOUT`]; proxy ≤ dial + [`crate::tunnel::intercept::proxy_resolve::PROXY_PENDING_TIMEOUT`]).
pub(super) const DNS_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Tamaño máximo de un mensaje DNS-over-TCP aceptado. El prefijo de longitud permite 65535 (RFC 1035
/// §4.2.2), pero lo acotamos a 4096 — el mismo cap que el buffer por UDP del oráculo (`ziti_dns.c`,
/// un request >4096 desborda su heap) y que [`crate::tunnel::intercept::dns_server::handle_query`]. Las QUERIES son pequeñas (<512 B
/// típico); solo respuestas grandes justificarían TCP y este stub sirve local. Divergencia consciente
/// vs el máximo de RFC 7766: un prefijo que anuncie >`DNS_TCP_MAX_MSG` → cerramos la conexión (mensaje
/// sobredimensionado, RFC 7766 §6.2.4 + práctica estándar) en vez de reservar/leer hasta 64 KiB. El
/// MISMO cap aplica a la respuesta de un upstream sobre TCP (§7.8 del spec): una respuesta >4096 →
/// intento fallido (siguiente server / REFUSED), under-permit consciente heredado de reusar
/// [`read_tcp_dns_msg`], inalcanzable con EDNS0 típico y estrictamente mejor que el REFUSE-siempre de #4.
pub(super) const DNS_TCP_MAX_MSG: usize = 4096;

/// Escribe un mensaje DNS enmarcado (prefijo de longitud 2B BE, RFC 1035 §4.2.2 + el cuerpo).
/// `format_resp`/passthrough producen siempre ≤ el cap del buffer, muy por debajo de 65535; el guard
/// `u16::try_from` es defensivo (un prefijo no puede exceder u16 → cerrar la conn). `Err` = el
/// llamante cierra la conexión.
pub(super) async fn write_framed_response<S>(stream: &mut S, response: &[u8]) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let len = u16::try_from(response.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "respuesta DNS >65535"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(response).await?;
    stream.flush().await?;
    Ok(())
}

/// Lee un mensaje DNS-over-TCP de `stream`: prefijo de longitud (2 bytes BE, RFC 1035 §4.2.2) + esos
/// bytes. `Ok(None)` = EOF LIMPIO antes del prefijo (cierre normal entre queries, no es error);
/// `Ok(Some)` = mensaje completo; `Err` = EOF a media lectura (truncado), prefijo >[`DNS_TCP_MAX_MSG`]
/// (sobredimensionado), o error de I/O — el llamante cierra la conexión. Distingue el cierre limpio de
/// un prefijo truncado leyendo el 1er byte con `read` (0 bytes = EOF limpio) antes del `read_exact`.
pub(super) async fn read_tcp_dns_msg<S>(stream: &mut S) -> io::Result<Option<Vec<u8>>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut prefix = [0u8; 2];
    match stream.read(&mut prefix[..1]).await {
        Ok(0) => return Ok(None), // cierre LIMPIO entre queries (no hay más mensajes)
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    stream.read_exact(&mut prefix[1..]).await?; // 2º byte del prefijo (EOF aquí = truncado → Err)
    let len = u16::from_be_bytes(prefix) as usize;
    if len > DNS_TCP_MAX_MSG {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mensaje DNS-over-TCP sobredimensionado",
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?; // EOF a media lectura del cuerpo = truncado → Err
    Ok(Some(body))
}
