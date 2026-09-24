//! El MANAGER: dueño ÚNICO del estado (conns por-dominio + pendientes por-id), TODO
//! síncrono/no-bloqueante (el invariante HOL del loop UDP). Espejo de `domain->resolv_proxy` +
//! `ziti_dns.requests`. F6 tramo 12: movido verbatim del monolito de `intercept/proxy_resolve`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::edge::client::EdgeClient;
use crate::tunnel::intercept::dns_server::{
    DNS_NO_ERROR, DNS_SERVFAIL, ProxyQuery, format_resp_answers,
};

use super::codec::parse_peer_response;
use super::task::run_proxy_conn;

/// TTL de un request proxy en vuelo. El oráculo no tiene timeout propio: el request vive lo que su
/// cliente DNS (idle 5s, `ziti_tunneler_set_idle_timeout(io, 5000)`, `ziti_dns.c:285` — al cerrar,
/// `on_dns_close` limpia sus requests). Mismo valor, aplicado como TTL del mapa (divergencia
/// consciente nombrada, misma clase que `DNS_UPSTREAM_TIMEOUT` de M3-DNS #1).
///
/// `pub(crate)` para que el path DNS-over-TCP (#4b, `crate::tunnel::intercept::dns_tcp::proxy_conn::complete_proxy_over_conn`) acote
/// la espera de la completion del peer con el MISMO horizonte que el manager UDP: cambio de VISIBILIDAD
/// solamente (precedente `PROXY_BUF`/`DNS_UPSTREAM_TIMEOUT`).
pub(crate) const PROXY_PENDING_TIMEOUT: Duration = Duration::from_secs(5);

/// Un evento de una task de conn proxy hacia el manager (la vuelta async del modelo de callbacks
/// del oráculo, entregada por la rama `select!` del loop UDP).
#[derive(Debug)]
pub(crate) enum ProxyEvent {
    /// Un chunk de datos de la conn de un dominio: una respuesta JSON del resolver hostante
    /// (`on_proxy_data`). El manager la parsea, casa el pendiente por id, injerta y completa.
    Data(Vec<u8>),
    /// El write de un request falló — dial caído o conn rota (`on_proxy_write` con `len < 0`,
    /// `ziti_dns.c:736-741`): el manager completa ESE pendiente con SERVFAIL.
    WriteFailed(u16),
}

/// Un request hacia una conn proxy (el `proxy_dns_req_wr_s` del oráculo: el JSON a escribir + el
/// id para completar con SERVFAIL si el write falla).
pub(super) struct ProxyJob {
    pub(super) id: u16,
    pub(super) json: Vec<u8>,
}

/// El handle del manager sobre la task de conn de UN dominio (espejo de `domain->resolv_proxy`).
/// `closed` lo pone la task al morir; el manager trata un handle cerrado como ausente (evicta y
/// re-dial-ea, el estado estable del oráculo tras `proxy_domain_close_cb`).
pub(super) struct ProxyConnHandle {
    jobs_tx: mpsc::UnboundedSender<ProxyJob>,
    pub(super) closed: Arc<AtomicBool>,
    /// El servicio al que esta conn fue dial-eada. El oráculo cachea `resolv_proxy` DENTRO del
    /// `dns_domain_t`: si el dominio se deregistra (#5 eviction) y OTRO servicio re-registra el
    /// mismo sufijo, el struct NUEVO arranca con `resolv_proxy == NULL` → dial fresco al dueño
    /// ACTUAL (`ziti_dns.c:436-445` + `proxy_domain_req`). Nuestro cache va keyed por SUFIJO y
    /// sobrevive a la eviction, así que [`ProxyDns::live_handle`] valida el dueño antes de reusar:
    /// un handle de OTRO servicio se trata como ausente (evict + dial fresco) — sin esto, una query
    /// MX/SRV/TXT bajo el dominio re-reclamado se respondería por la conn del servicio RETIRADO
    /// (over-dispatch que el oráculo no comete). Residual consciente: el MISMO servicio re-añadido
    /// reusa una conn viva pre-remove donde el oráculo dial-earía fresco — mismo servicio, mismo
    /// destino overlay, jamás over-dispatch.
    pub(super) service: String,
}

/// Un request proxy en vuelo (la entrada de `ziti_dns.requests` + el `dns_req` que la completion
/// necesita): el packet ORIGINAL + su `name_strlen` (para re-formatear la respuesta con los
/// answers injertados) y a quién devolverla.
pub(super) struct ProxyPending {
    pub(super) packet: Vec<u8>,
    pub(super) name_strlen: usize,
    /// `dst` de `reply.send_to` = `(dns_ip, 53)` (la respuesta aparece VENIR de ahí).
    pub(super) server_addr: SocketAddr,
    /// `src` de `reply.send_to` = el cliente que preguntó.
    pub(super) client_addr: SocketAddr,
    pub(super) at: Instant,
}

/// El estado proxy-resolve del manager UDP (M3-DNS #2): conns por-dominio + pendientes por-id.
/// Espejo del par `domain->resolv_proxy` (cacheada, reutilizada, reseteada al morir) +
/// `ziti_dns.requests` (mux por id) del oráculo. TODAS las operaciones son síncronas/no-bloqueantes
/// (el invariante del manager); el trabajo async vive en las tasks por-dominio ([`run_proxy_conn`]).
/// Se construye junto a su receiver de eventos ([`ProxyDns::new`]): el loop UDP recibe los
/// [`ProxyEvent`]s en una rama propia del `select!` y los entrega a [`ProxyDns::on_event`].
pub(crate) struct ProxyDns {
    pub(super) conns: HashMap<String, ProxyConnHandle>,
    pub(super) pending: HashMap<u16, ProxyPending>,
    events_tx: mpsc::UnboundedSender<ProxyEvent>,
}

impl ProxyDns {
    /// El manager + el receiver de eventos (rama del `select!` del loop UDP). Separados para que el
    /// future de `recv()` no retenga un borrow del manager mientras otra rama lo muta.
    pub(crate) fn new() -> (Self, mpsc::UnboundedReceiver<ProxyEvent>) {
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        (
            Self {
                conns: HashMap::new(),
                pending: HashMap::new(),
                events_tx,
            },
            events_rx,
        )
    }

    /// Rutea un [`ProxyQuery`] (MX/SRV/TXT bajo dominio, `DnsAction::ForwardProxy`): dedup por id →
    /// asegurar la conn del dominio (dial LAZY) → encolar el write → registrar el pendiente.
    /// `service` = lo que [`crate::tunnel::intercept::resolve::InterceptResolver::proxy_service`] resolvió (el
    /// llamante lo consulta con su borrow del resolver); `None` → SERVFAIL inmediato (espejo del
    /// quick-fail State A, `ziti_dns.c:755-756` — aquí solo alcanzable si el dominio perdió sus
    /// servicios entre el match y el routing).
    ///
    /// Devuelve `Some(respuesta)` si el request completa SÍNCRONO (el SERVFAIL de arriba);
    /// `None` = completion async (registrado) o dedup-drop silencioso (espejo del "just drop new
    /// request" del oráculo, `on_dns_req:792-799` — divergencia por-camino nombrada en el doc).
    #[allow(clippy::too_many_arguments)] // el seam completo de un request: query + destino + estado RA
    pub(crate) fn handle_forward(
        &mut self,
        client: &Rc<EdgeClient>,
        service: Option<(String, Duration)>,
        q: ProxyQuery,
        packet: Vec<u8>,
        server_addr: SocketAddr,
        client_addr: SocketAddr,
        recursion_available: bool,
    ) -> Option<Vec<u8>> {
        if self.pending.contains_key(&q.id) {
            return None; // id ya en vuelo hacia el proxy → drop silencioso
        }
        let Some((service, timeout)) = service else {
            return Some(format_resp_answers(
                &packet,
                q.name_strlen,
                DNS_SERVFAIL,
                None,
                Ipv4Addr::UNSPECIFIED,
                recursion_available,
            ));
        };
        self.send_job(
            client,
            service,
            timeout,
            q.domain,
            ProxyJob {
                id: q.id,
                json: q.json,
            },
        );
        self.pending.insert(
            q.id,
            ProxyPending {
                packet,
                name_strlen: q.name_strlen,
                server_addr,
                client_addr,
                at: Instant::now(),
            },
        );
        None
    }

    /// Asegura la conn proxy de `domain` SIN encolar nada — el espejo de que `proxy_domain_req`
    /// inicia el dial para CUALQUIER tipo no-A/AAAA bajo el dominio, aunque luego responda
    /// NOT_IMPL síncrono (`ziti_dns.c:748-753` va ANTES del gate de tipo).
    pub(crate) fn ensure_conn(
        &mut self,
        client: &Rc<EdgeClient>,
        service: String,
        timeout: Duration,
        domain: String,
    ) {
        self.live_handle(client, service, timeout, domain);
    }

    /// Entrega un job a la conn viva del dominio, re-creándola si murió entre el flag `closed` y el
    /// send (la task dropea su receiver al morir): con el canal FRESCO el send no puede fallar.
    fn send_job(
        &mut self,
        client: &Rc<EdgeClient>,
        service: String,
        timeout: Duration,
        domain: String,
        job: ProxyJob,
    ) {
        let handle = self.live_handle(client, service.clone(), timeout, domain.clone());
        if let Err(mpsc::error::SendError(job)) = handle.jobs_tx.send(job) {
            self.conns.remove(&domain);
            let fresh = self.live_handle(client, service, timeout, domain);
            let _ = fresh.jobs_tx.send(job);
        }
    }

    /// El handle vivo del dominio: uno cerrado se evicta (estado estable del oráculo tras
    /// `proxy_domain_close_cb`), uno de OTRO servicio también (el dominio cambió de dueño tras una
    /// eviction #5 + re-registro — el `dns_domain_t` NUEVO del oráculo arranca con
    /// `resolv_proxy == NULL`; ver el doc de [`ProxyConnHandle::service`]), y uno ausente se crea
    /// spawneando la task de conn (dial LAZY, `intercept_resolve_connect`). Mismo patrón
    /// evict-on-closed que `route_decision` (T3/M3-UDP).
    pub(super) fn live_handle(
        &mut self,
        client: &Rc<EdgeClient>,
        service: String,
        timeout: Duration,
        domain: String,
    ) -> &ProxyConnHandle {
        if self
            .conns
            .get(&domain)
            .is_some_and(|h| h.closed.load(Ordering::Acquire) || h.service != service)
        {
            self.conns.remove(&domain);
        }
        self.conns.entry(domain.clone()).or_insert_with(|| {
            let (jobs_tx, jobs_rx) = mpsc::unbounded_channel();
            let closed = Arc::new(AtomicBool::new(false));
            tokio::task::spawn_local(run_proxy_conn(
                Rc::clone(client),
                service.clone(),
                timeout,
                domain,
                jobs_rx,
                self.events_tx.clone(),
                Arc::clone(&closed),
            ));
            ProxyConnHandle {
                jobs_tx,
                closed,
                service,
            }
        })
    }

    /// Procesa un [`ProxyEvent`] y devuelve la respuesta a entregar `(bytes, dst, src)` — o `None`
    /// (chunk descartado, id sin pendiente, o pendiente ya expirado). Espejo de la completion del
    /// oráculo: `WriteFailed` → SERVFAIL (`on_proxy_write:736-741`); `Data` → parse + injerto de
    /// SOLO `answer` + formateo con el status DEL REQUEST (0 — el del peer se IGNORA,
    /// `on_proxy_data:704-710`) y `req->addr` nunca asignado (un answer A injertado emite 0.0.0.0).
    pub(crate) fn on_event(
        &mut self,
        ev: ProxyEvent,
        recursion_available: bool,
    ) -> Option<(Vec<u8>, SocketAddr, SocketAddr)> {
        match ev {
            ProxyEvent::WriteFailed(id) => {
                let p = self.pending.remove(&id)?;
                Some((
                    format_resp_answers(
                        &p.packet,
                        p.name_strlen,
                        DNS_SERVFAIL,
                        None,
                        Ipv4Addr::UNSPECIFIED,
                        recursion_available,
                    ),
                    p.server_addr,
                    p.client_addr,
                ))
            }
            ProxyEvent::Data(chunk) => {
                let resp = parse_peer_response(&chunk)?;
                let p = self.pending.remove(&resp.id)?;
                Some((
                    format_resp_answers(
                        &p.packet,
                        p.name_strlen,
                        DNS_NO_ERROR,
                        resp.answers.as_deref(),
                        Ipv4Addr::UNSPECIFIED,
                        recursion_available,
                    ),
                    p.server_addr,
                    p.client_addr,
                ))
            }
        }
    }

    /// Barrido del reap tick: pendientes más viejos que [`PROXY_PENDING_TIMEOUT`] (divergencia TTL
    /// nombrada) + handles de conns ya cerradas (limpieza de memoria; la evicción funcional ocurre
    /// lazy en [`Self::live_handle`]).
    pub(crate) fn evict_expired(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.at) <= PROXY_PENDING_TIMEOUT);
        self.conns.retain(|_, h| !h.closed.load(Ordering::Acquire));
    }
}
