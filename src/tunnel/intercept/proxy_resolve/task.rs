//! La TASK de conn de UN dominio (async, `!Send`): dial con [`RESOLVE_APP_DATA`], escribe los jobs
//! encolados, reenvía los chunks leídos al manager y muere marcando `closed`. Espejo de
//! `intercept_resolve_connect` + los callbacks `on_proxy_*`. F6 tramo 12: movido verbatim del
//! monolito de `intercept/proxy_resolve`.

use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::edge::client::EdgeClient;

use super::manager::{ProxyEvent, ProxyJob};

/// El appData del dial proxy-resolve, byte-LITERAL del oráculo (`RESOLVE_APP_DATA`,
/// `ziti_tunnel_cbs.c:725`) — distingue esta conn de un dial de datos (el host la acepta como
/// resolver en vez de abrir el forward de host.v1).
pub(crate) const RESOLVE_APP_DATA: &[u8] = br#"{"connType":"resolver"}"#;

/// La task de la conn proxy de UN dominio: dial-ea el servicio con [`RESOLVE_APP_DATA`]
/// (`intercept_resolve_connect`), escribe los jobs encolados (espejo de `ziti_write` — los que
/// llegan durante el dial esperan en el canal, como en una conn Connecting) y reenvía cada chunk
/// leído al manager ([`ProxyEvent::Data`]). Muere marcando `closed` en: dial fallido, write
/// fallido (ese job → [`ProxyEvent::WriteFailed`], espejo de `on_proxy_write` + `ziti_close`),
/// EOF/error de lectura (espejo de `on_proxy_data` con `status < 0` → `ziti_close`), o el manager
/// dropeando el handle. Al morir, TODO job aún encolado falla con `WriteFailed` (espejo de los
/// `on_proxy_write` de error de los writes en cola de una conn que cae).
pub(super) async fn run_proxy_conn(
    client: Rc<EdgeClient>,
    service: String,
    timeout: Duration,
    domain: String,
    mut jobs_rx: mpsc::UnboundedReceiver<ProxyJob>,
    events: mpsc::UnboundedSender<ProxyEvent>,
    closed: Arc<AtomicBool>,
) {
    let svc = match client
        .connect_with_appdata(&service, timeout, Some(RESOLVE_APP_DATA))
        .await
    {
        Ok(svc) => {
            tracing::info!(%domain, %service, "proxy resolve: conexión establecida"); // on_proxy_connect:686
            svc
        }
        Err(e) => {
            // on_proxy_connect con status != ZITI_OK (:689-691): la conn muere; los writes
            // encolados completan con error → SERVFAIL cada uno (via WriteFailed).
            tracing::warn!(error = %e, %domain, %service, "proxy resolve: fallo al establecer la conexión");
            closed.store(true, Ordering::Release);
            fail_queued(&mut jobs_rx, &events);
            return;
        }
    };
    let (mut zr, mut zw, channel) = svc.into_parts();
    loop {
        tokio::select! {
            job = jobs_rx.recv() => match job {
                Some(ProxyJob { id, json }) => {
                    if zw.write(&json).await.is_err() {
                        let _ = events.send(ProxyEvent::WriteFailed(id));
                        break;
                    }
                }
                None => break, // el manager dropeó el handle (evicción) → cerrar la conn
            },
            chunk = zr.read() => match chunk {
                Ok(Some(data)) => {
                    let _ = events.send(ProxyEvent::Data(data));
                }
                Ok(None) => break, // EOF del peer
                Err(e) => {
                    tracing::warn!(error = %e, %domain, "proxy resolve: conexión fallida");
                    break;
                }
            },
        }
    }
    closed.store(true, Ordering::Release);
    fail_queued(&mut jobs_rx, &events);
    // Full-close de la conn ziti (StateClosed + deregister); el CHANNEL es compartido del pool y
    // solo se dropea nuestra referencia (mismo contrato que run_vconn de M3-UDP).
    let _ = zw.close().await;
    drop(channel);
}

/// Drena los jobs que quedaron encolados en una conn muerta: cada uno completa con
/// [`ProxyEvent::WriteFailed`] (espejo de los callbacks `on_proxy_write` con error de los
/// `ziti_write` en cola cuando la conn cae).
fn fail_queued(
    rx: &mut mpsc::UnboundedReceiver<ProxyJob>,
    events: &mpsc::UnboundedSender<ProxyEvent>,
) {
    rx.close();
    while let Ok(job) = rx.try_recv() {
        let _ = events.send(ProxyEvent::WriteFailed(job.id));
    }
}
