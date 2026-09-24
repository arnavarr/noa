//! **La completion de proxy-resolve sobre una conn overlay**: dial `RESOLVE_APP_DATA`, escribe el
//! JSON, lee chunks hasta casar el id, injerta answers, full-close. AUTOCONTENIDO (no depende de otro
//! fragmento hermano).

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::rc::Rc;
use std::time::Duration;

use crate::edge::client::EdgeClient;
use crate::edge::data::{EdgeReadHalf, EdgeWriteHalf};
use crate::tunnel::intercept::dns_server::{
    DNS_NO_ERROR, DNS_SERVFAIL, ProxyQuery, format_resp_answers,
};
use crate::tunnel::intercept::proxy_resolve::{
    PROXY_PENDING_TIMEOUT, RESOLVE_APP_DATA, parse_peer_response,
};
use crate::tunnel::intercept::resolve::InterceptResolver;

/// Sirve UN [`crate::tunnel::intercept::dns_server::DnsAction::ForwardProxy`] sobre TCP: resuelve el servicio dueño del dominio, dial-ea
/// `RESOLVE_APP_DATA` y completa vía [`complete_proxy_over_conn`], haciendo el full-close de la conn
/// overlay al terminar. Devuelve los bytes a escribir enmarcados (`Ok`) — la completion, o el SERVFAIL
/// byte-idéntico al manager UDP (State A sin servicio / dial-fail / write-fail) — o `Err(())` cuando la
/// conn del CLIENTE debe cerrarse sin responder (timeout/EOF del peer, §7.7).
///
/// **Disciplina de borrow:** el único borrow del resolver (`proxy_service`) es SÍNCRONO y muere antes
/// del dial `await`; ningún borrow cruza un await.
pub(super) async fn resolve_proxy_over_tcp(
    resolver: &Rc<RefCell<InterceptResolver>>,
    client: &Rc<EdgeClient>,
    q: &ProxyQuery,
    packet: &[u8],
    upstream_available: bool,
) -> Result<Vec<u8>, ()> {
    // El SERVFAIL de este path (State A / dial-fail / write-fail) es byte-idéntico al del manager UDP:
    // mismo `format_resp_answers(DNS_SERVFAIL, None, UNSPECIFIED, ra)`.
    let servfail = || {
        format_resp_answers(
            packet,
            q.name_strlen,
            DNS_SERVFAIL,
            None,
            Ipv4Addr::UNSPECIFIED,
            upstream_available,
        )
    };
    // El servicio dueño del dominio (síncrono; el borrow muere aquí, antes del dial).
    let service = {
        let r = resolver.borrow();
        r.proxy_service(&q.domain)
            .map(|m| (m.service.to_string(), m.dial_timeout))
    };
    // Sin servicio dueño (dominio evictado / resolver inconsistente) → SERVFAIL inmediato SIN dial
    // (espejo del quick-fail State A, `ziti_dns.c:755-756`).
    let Some((service, dial_timeout)) = service else {
        return Ok(servfail());
    };
    // Dial fallido → SERVFAIL (espejo de `on_proxy_connect` error → writes encolados fallan →
    // `on_proxy_write`); la conn del cliente SIGUE viva.
    let Ok(svc) = client
        .connect_with_appdata(&service, dial_timeout, Some(RESOLVE_APP_DATA))
        .await
    else {
        return Ok(servfail());
    };
    let (mut zr, mut zw, channel) = svc.into_parts();
    let outcome = complete_proxy_over_conn(
        &mut zr,
        &mut zw,
        q,
        packet,
        upstream_available,
        PROXY_PENDING_TIMEOUT,
    )
    .await;
    // Full-close de la conn overlay = `zw.close().await` + `drop(channel)` — el contrato EXACTO de
    // `run_proxy_conn` (`proxy_resolve/task.rs`; el channel es `Arc<EdgeChannel>` COMPARTIDO del pool, solo
    // cae nuestra referencia). Conn POR QUERY (§7.5).
    let _ = zw.close().await;
    drop(channel);
    match outcome {
        Ok(Some(response)) => Ok(response),
        // Write del JSON fallido → SERVFAIL (espejo de `WriteFailed`); conn cliente viva.
        Ok(None) => Ok(servfail()),
        // Timeout/EOF sin completion → cerrar la conn del cliente (§7.7: fail-closed, jamás inventar).
        Err(()) => Err(()),
    }
}

/// Completa UN [`crate::tunnel::intercept::dns_server::DnsAction::ForwardProxy`] sobre una conn overlay YA dial-eada: escribe el JSON del
/// request (`q.json`, emitido por `emit_dns_message_json` — bytes idénticos al path UDP), lee chunks
/// del peer hasta que uno parsea Y casa el id de la query, e injerta SOLO sus answers con
/// [`format_resp_answers`]`(DNS_NO_ERROR, answers, UNSPECIFIED, ra)` — **byte-idéntico a
/// `ProxyDns::on_event(Data)`** (mismo parser [`parse_peer_response`] + mismo serializador, cero
/// emisor/parser paralelo: la lección T4b).
///
///  - `Ok(Some(bytes))` = completion (el llamante escribe `bytes` enmarcados);
///  - `Ok(None)` = write del JSON fallido → el llamante responde SERVFAIL (espejo de `WriteFailed`);
///  - `Err(())` = timeout/EOF/error de lectura sin completion → el llamante cierra la conn del cliente
///    (§7.7). Un chunk malformado (parse → `None`) o con id ajeno se DESCARTA y se sigue leyendo
///    (espejo del drop-del-chunk del manager y del `if (req)` de `on_proxy_data`).
pub(super) async fn complete_proxy_over_conn(
    zr: &mut EdgeReadHalf,
    zw: &mut EdgeWriteHalf,
    q: &ProxyQuery,
    packet: &[u8],
    ra: bool,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, ()> {
    if zw.write(&q.json).await.is_err() {
        // Write fallido (dial caído / conn rota) → el llamante completa SERVFAIL (espejo `on_proxy_write`).
        return Ok(None);
    }
    loop {
        match tokio::time::timeout(timeout, zr.read()).await {
            Ok(Ok(Some(chunk))) => {
                // Un chunk parseable cuyo id casa completa; malformado o con id ajeno → descartar y
                // seguir leyendo (paridad con el manager: parse→None drop, o `if (req)` sin pending).
                if let Some(resp) = parse_peer_response(&chunk)
                    && resp.id == q.id
                {
                    return Ok(Some(format_resp_answers(
                        packet,
                        q.name_strlen,
                        DNS_NO_ERROR,
                        resp.answers.as_deref(),
                        Ipv4Addr::UNSPECIFIED,
                        ra,
                    )));
                }
            }
            // EOF, error de lectura o timeout sin completion → cerrar la conn del cliente (§7.7).
            Ok(Ok(None) | Err(_)) | Err(_) => return Err(()),
        }
    }
}
