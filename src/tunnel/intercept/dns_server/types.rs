//! El vocabulario de wire: rcodes/qtypes/tamaños de buffer + [`DnsAction`] + [`ProxyQuery`] +
//! [`RespAnswer`]. Sin lógica, solo datos — la "vocabulary hub" que `parser`/`serializer`/`router`
//! consumen.

/// Rcodes del oráculo (`include/ziti/ziti_dns.h:24-29`). `FORMERR`/`NXDOMAIN` existen en el
/// header pero NINGÚN camino alcanzable esta rebanada los emite (FORMERR solo en el proxy
/// diferido; NXDOMAIN jamás — un miss es REFUSE), así que no se definen aquí.
pub(crate) const DNS_NO_ERROR: u8 = 0;
pub(crate) const DNS_SERVFAIL: u8 = 2;
pub(super) const DNS_NOT_IMPL: u8 = 4;
pub(super) const DNS_REFUSE: u8 = 5;

/// Tipos de query relevantes al routing (`enum ns_q_type`, `ziti_dns.c:33-39`).
pub(super) const NS_T_A: u16 = 1;
pub(super) const NS_T_MX: u16 = 15;
pub(super) const NS_T_TXT: u16 = 16;
pub(super) const NS_T_AAAA: u16 = 28;
pub(super) const NS_T_SRV: u16 = 33;

/// Longitud de la cabecera DNS (`DNS_HEADER_LEN`, `ziti_dns.c:488`).
pub(super) const DNS_HEADER_LEN: usize = 12;

/// Capacidad de los buffers de request/response del oráculo (`struct dns_req`, `ziti_dns.c:50-52`,
/// `uint8_t req[4096]` / `resp[4096]`). Gobierna DOS comportamientos espejados: el límite de
/// tamaño de un request aceptable (el oráculo desborda su heap con >4096 — aquí Drop, divergencia
/// consciente) y los guards de truncation/OPT del serializador (`resp_end`).
pub(super) const DNS_BUF: usize = 4096;

/// TTL de los registros A locales (`process_host_req`: `a->ttl = 60`, `ziti_dns.c:657`).
pub(super) const DNS_A_TTL: u32 = 60;

/// El registro OPT (EDNS0) que el oráculo anexa a TODA respuesta con sitio: nombre raíz, tipo 41,
/// UDP size 4096, TTL 0, RDLEN 0 (`DNS_OPT`, `ziti_dns.c:486`).
pub(super) const DNS_OPT: [u8; 11] = [
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// El veredicto de [`crate::tunnel::intercept::dns_server::handle_query`] sobre un datagrama dirigido al resolver embebido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// Responder con estos bytes (un mensaje DNS completo) al cliente, desde `(dns_ip, 53)`.
    Respond(Vec<u8>),
    /// Descartar sin responder (espejo del camino de parse fallido de `on_dns_req`, más las
    /// divergencias fail-closed sobre los caminos UB del oráculo — ver el doc del módulo).
    Drop,
    /// Reenviar el request ORIGINAL (verbatim, los mismos bytes del datagrama) al/los upstream DNS
    /// (M3-DNS #1): sin respuesta local, upstream configurado Y el request pedía recursión (RD=1) —
    /// espejo de `query_upstream` (`ziti_dns.c:850-868`: `avail && req->msg.recursive` →
    /// `uv_udp_try_send(req->req, req->req_len)`). El MANAGER (dueño del socket upstream) hace el
    /// envío + registra el request en vuelo; la respuesta vuelve async por ID (passthrough
    /// verbatim, `on_upstream_packet:876-891`). `on_send_failure` = la respuesta REFUSED
    /// pre-formateada (CON el bit RA: el socket upstream está activo) que el manager devuelve al
    /// cliente si NINGÚN upstream aceptó el envío — espejo de `query_upstream` devolviendo
    /// `DNS_REFUSE` → `on_dns_req`/`process_host_req` formatean y completan (`:667-672`,
    /// `:837-842`). Solo lo produce [`crate::tunnel::intercept::dns_server::handle_query`] con `upstream_available == true`.
    ForwardUpstream {
        /// Respuesta local a usar si el envío a upstream falla por completo.
        on_send_failure: Vec<u8>,
    },
    /// Resolver por el OVERLAY (M3-DNS #2): una query MX/SRV/TXT bajo un dominio wildcard
    /// interceptado, con el proxy cableado (`proxy_available == true`). El MANAGER (dueño del
    /// estado [`crate::tunnel::intercept::proxy_resolve::ProxyDns`]) asegura la conn del dominio (dial LAZY con
    /// `RESOLVE_APP_DATA`, espejo de `proxy_domain_req` → `intercept_resolve_connect`), encola el
    /// [`ProxyQuery::json`] y registra el request pendiente; la respuesta vuelve async por id
    /// (`on_proxy_data` injerta los answers) o el write fallido completa SERVFAIL
    /// (`on_proxy_write`). Ver el doc de [`crate::tunnel::intercept::proxy_resolve`].
    ForwardProxy(ProxyQuery),
    /// Responder `response` YA (síncrono) **y** asegurar la conn proxy del dominio: un tipo
    /// no-A/AAAA que el proxy nunca sirve (ni MX/SRV/TXT) bajo un dominio, con proxy cableado —
    /// el oráculo inicia la conexión ANTES del gate de tipo (`proxy_domain_req:748-753`) y luego
    /// responde `NOT_IMPL` síncrono (`:779-780`); el dial lateral se replica por fidelidad (el
    /// endpoint hostante VE llegar la conn resolver).
    RespondAndConnectProxy {
        /// La respuesta local (NOT_IMPL) a entregar ya.
        response: Vec<u8>,
        /// El dominio cuya conn proxy asegurar (vía
        /// [`crate::tunnel::intercept::resolve::InterceptResolver::proxy_service`] +
        /// [`crate::tunnel::intercept::proxy_resolve::ProxyDns::ensure_conn`]).
        domain: String,
    },
}

/// El payload de [`DnsAction::ForwardProxy`]: lo que el manager necesita para encolar el request
/// hacia la conn del dominio y completarlo después (el subconjunto del `dns_req` del oráculo que
/// cruza el seam handle_query → manager).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyQuery {
    /// El dominio casado ([`crate::tunnel::intercept::dns::DnsMatcher::matched_domain`]) — la clave de la conn cacheada
    /// (`domain->resolv_proxy`) y del servicio a dial-ear.
    pub domain: String,
    /// El id DNS del request (mux de la completion, `ziti_dns.requests`).
    pub id: u16,
    /// El `strlen` C del nombre de la query (dimensiona el eco de la pregunta al re-formatear).
    pub name_strlen: usize,
    /// El JSON compacto del request (`dns_message_to_json(&req->msg, MODEL_JSON_COMPACT)`),
    /// listo para `ziti_write` — emitido por [`crate::tunnel::intercept::proxy_resolve::emit_dns_message_json`].
    pub json: Vec<u8>,
}

/// Un registro de la sección answer a emitir (espejo del `dns_answer` del modelo del oráculo,
/// `dns_host.h` `DNS_A_MODEL`): para el camino LOCAL es el único registro A que `process_host_req`
/// sintetiza; para el camino PROXY (M3-DNS #2) son los registros injertados del JSON del resolver
/// hostante (`on_proxy_data`: `req->msg.answer = msg.answer`). Los campos numéricos son `i64` (el
/// `model_number` del oráculo es `int64_t`): la TRUNCACIÓN al escribir el cable (`SET_U16`/`SET_U32`
/// enmascaran) es parte del contrato espejado, no un accidente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RespAnswer {
    /// `a->type`: gobierna la rama del switch (1=A, 15=MX, 16=TXT, 33=SRV; el resto cae al
    /// `default` — ver el quirk en [`crate::tunnel::intercept::dns_server::format_resp_answers`]) Y los 2 bytes de tipo del cable
    /// (`SET_U16` trunca el `i64`, así que un `type` de 65537 emite `1` en el cable pero se
    /// formatea por el `default`).
    pub(crate) atype: i64,
    pub(crate) ttl: i64,
    pub(crate) priority: i64,
    pub(crate) weight: i64,
    pub(crate) port: i64,
    /// `a->data`: el texto TXT o el nombre destino MX/SRV. Las ramas A/`default` NO lo leen (el
    /// oráculo solo lo loguea). Se consume como C-string: TODO uso corta en el primer `0x00`
    /// (`strlen`/`strchr`/`memcpy` del oráculo operan sobre `char*`). El llamante del camino proxy
    /// garantiza que MX/TXT/SRV llevan data (el parser JSON rechaza fail-closed un answer de esos
    /// tipos sin él — `strlen(NULL)` sería UB del oráculo).
    pub(crate) data: String,
}
