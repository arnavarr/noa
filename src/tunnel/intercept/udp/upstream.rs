//! El forwarding a upstream DNS (M3-DNS #1) del manager UDP: envío, match por ID y eviction por TTL.
//! (F6 tramo 3a: movido verbatim del monolito de `intercept/udp`.)

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use super::{DNS_UPSTREAM_TIMEOUT, PendingUpstream, UpstreamDns};

impl UpstreamDns {
    /// Enlaza el socket local de forwarding. El oráculo bindea siempre IPv6 `[::]:0` y mapea los
    /// upstreams v4 a v4-mapeado (`ziti_dns_set_upstream:211-232,255-260`). Desviación consciente
    /// más portable: elegimos la FAMILIA del socket según los servidores (v6 `[::]:0` si ALGUNO es
    /// v6, si no v4 `0.0.0.0:0`) — así un `try_send_to` a un upstream v4 desde un socket v4 nunca
    /// depende del comportamiento dual-stack del SO (que varía). Un mix v4+v6 usa el socket v6 y solo
    /// alcanza los v6 (los v4 fallarían el send y no se registrarían — el resto sirve). `servers` NO
    /// puede estar vacío (el llamante solo construye esto con ≥1 upstream configurado).
    ///
    /// # Errors
    /// Propaga el fallo del `bind` o del `writable().await` de calentamiento del socket.
    pub(crate) async fn bind(servers: Vec<SocketAddr>) -> io::Result<Self> {
        let bind_addr = if servers.iter().any(SocketAddr::is_ipv6) {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        // Calienta la readiness de ESCRITURA del socket con el reactor ANTES del primer `forward`.
        // tokio corto-circuita `try_send_to` con `WouldBlock` cuando el registro del socket aún no
        // tiene readiness WRITABLE cacheada (un socket recién bindeado no ha sido poleado para
        // escritura todavía). El `select!` del manager SOLO espera lectura (`recv_upstream` →
        // `recv`), así que NADA calienta la escritura antes del 1er `forward`: su único `try_send_to`
        // podía dar `WouldBlock` bajo carga → `any=false` → un REFUSED espurio en la 1ª query
        // reenviada (flake ~2/17 en la suite completa; 0/N en aislamiento — es un artefacto del
        // reactor, no de la lógica). El oráculo NO sufre esto: `uv_udp_try_send` (`ziti_dns.c:857`)
        // siempre intenta el `sendmsg`. Un `writable().await` único deja la readiness WRITABLE
        // cacheada → el 1er `try_send_to` intenta el syscall como libuv (paridad observable: el 1er
        // forward tiene éxito). UDP es escribible casi de inmediato → coste despreciable, sin
        // aparcar el manager en steady-state. NO quitar este await: sin él vuelve el flake.
        socket.writable().await?;
        Ok(Self {
            socket,
            servers,
            pending: HashMap::new(),
        })
    }

    /// Reenvía `request` (verbatim) a todos los upstreams y registra el request en vuelo. Dedup por
    /// ID de los requests en vuelo HACIA UPSTREAM (`pending`): un ID ya reenviado no se reenvía otra
    /// vez (`true` sin duplicar el envío). **Divergencia consciente vs el oráculo:** el oráculo
    /// dedupa TODO request por ID al ENTRAR a `on_dns_req` (`:792-799`) contra el mapa global
    /// `ziti_dns.requests` (poblado para todos en `:821-822`, ANTES de rutar) — así una 2ª query con
    /// un ID en vuelo la DESCARTA aunque resolvería local. Nosotros solo dedupamos el camino de
    /// forward, así que una colisión de ID donde la 2ª query resuelve LOCAL (hit A/AAAA, proxy
    /// SERVFAIL/NOT_IMPL, o miss RD=0) la RESPONDEMOS (el oráculo la descarta). Es benigno/más
    /// correcto (respondemos una query legítima; un dedup global haría DESCARTAR queries locales
    /// válidas = estrictamente peor) — reframe, no cierre exacto del #3. `true` si al menos un
    /// upstream aceptó el envío (→ registrado, esperamos respuesta); `false` si NINGUNO (→ el
    /// llamante devuelve el REFUSED de fallback al cliente, espejo de `query_upstream` devolviendo
    /// `DNS_REFUSE`). Todo síncrono/no-bloqueante (`try_send_to`) — el manager nunca se aparca aquí.
    pub(super) fn forward(
        &mut self,
        request: &[u8],
        server_addr: SocketAddr,
        client_addr: SocketAddr,
    ) -> bool {
        let id = u16::from_be_bytes([request[0], request[1]]);
        if self.pending.contains_key(&id) {
            // ID ya en vuelo hacia upstream → no re-reenviar (dedup del camino de forward; ver el
            // doc de la fn para la divergencia vs el dedup global pre-routing del oráculo).
            return true;
        }
        let mut any = false;
        for server in &self.servers {
            if self.socket.try_send_to(request, *server).is_ok() {
                any = true;
            }
        }
        if any {
            self.pending.insert(
                id,
                PendingUpstream {
                    server_addr,
                    client_addr,
                    at: Instant::now(),
                },
            );
        }
        any
    }

    /// Casa una respuesta upstream por su ID contra un request en vuelo y devuelve a quién
    /// entregarla `(bytes, dst=server_addr, src=client_addr)` — passthrough VERBATIM (espejo de
    /// `on_upstream_packet:876-891`: copia la respuesta cruda y `complete_dns_req`). `None` si el ID
    /// no casa ningún pending (respuesta tardía/espuria → se descarta, como el oráculo). Consume la
    /// entrada pending (`complete_dns_req` la borra de `ziti_dns.requests`).
    pub(super) fn match_response(&mut self, response: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
        if response.len() < 2 {
            return None;
        }
        let id = u16::from_be_bytes([response[0], response[1]]);
        self.pending
            .remove(&id)
            .map(|p| (p.server_addr, p.client_addr))
    }

    /// Evicciona los requests en vuelo más viejos que [`DNS_UPSTREAM_TIMEOUT`] (barrido del reaper).
    pub(super) fn evict_expired(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.at) <= DNS_UPSTREAM_TIMEOUT);
    }
}

/// Espera la siguiente respuesta upstream, o queda `Pending` PARA SIEMPRE si no hay upstream
/// configurado (para que la rama del `select!` sea inerte sin upstream). `recv` (no `recv_from`): el
/// oráculo casa por ID y NO valida la dirección de origen (`on_upstream_packet` ignora `addr`).
pub(super) async fn recv_upstream(
    upstream: Option<&UpstreamDns>,
    buf: &mut [u8],
) -> io::Result<usize> {
    match upstream {
        Some(u) => u.socket.recv(buf).await,
        None => std::future::pending().await,
    }
}
