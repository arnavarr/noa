//! El RESPONDEDOR de `ConnInspect` (ct 60798 → 60799): la contestación a la capacidad que el Bind
//! del port YA anuncia (`SupportsInspect = 1`, `src/edge/bind/wire.rs:82`) y que hasta esta
//! rebanada se descartaba en silencio en el brazo por defecto del rx-loop.
//!
//! Oráculo (`sdk-golang` v1.7.0, pin `4b6a087e92faaf94fcb027e9008bbcf45a325225`): los TRES
//! emisores — `HandleNotFoundConnInspect` (`ziti/edge/msg_mux.go:402-409`, Invalid),
//! `HandleConnInspect` (`ziti/edge/network/conn.go:303-310`, Dial) y `handleInspect`
//! (`ziti/edge/network/hosting_conn.go:192-199`, Bind) — construidos todos sobre
//! `NewConnInspectResponse` (`ziti/edge/messages.go:264-269`) y correlados con `ReplyTo`
//! (`channel/v4@v4.3.9 message.go:390-399`). Los tres son ASÍNCRONOS (`go …`), ver
//! [`spawn_conn_inspect_reply`].
//!
//! Spec: `docs/superpowers/specs/2026-08-21-qw-dg1-conninspect-design.md`.

use std::sync::Arc;

use crate::channel::connect::write_message;
use crate::channel::message::{
    HDR_REPLY_FOR, MAX_REFLECTED_HEADER, Message, REFLECTED_HEADER_BIT_MASK,
};
use crate::edge::dial::HDR_CONN_ID;

use super::ChannelState;

/// Content-type del `ConnInspectRequest`. Oráculo: `pb/edge_client_pb/edge_client.pb.go:51`
/// (`ContentType_ConnInspectRequest = 60798`).
///
/// **Visibilidad `pub(super)`, por CONSUMIDORES MEDIDOS** (RB-SDK-06; `git grep -nw` sobre `*.rs`
/// del repo): `src/edge/data/rxloop.rs` (import y guarda del brazo) y
/// `src/edge/data/tests_inspect.rs` (el cotejo contra el bloque `constants` del golden). Los dos
/// son módulos HERMANOS dentro de `edge::data`, así que `pub(super)` los alcanza y nada más. No es
/// una analogía con «las constantes de su clase»: `mod inspect` es privado, de modo que un `pub`
/// aquí no habría añadido ni un consumidor alcanzable, solo superficie.
pub(super) const CT_CONN_INSPECT_REQUEST: i32 = 60798;
/// Content-type del `ConnInspectResponse`. Oráculo: `pb/edge_client_pb/edge_client.pb.go:52`
/// (`ContentType_ConnInspectResponse = 60799`).
///
/// **Consumidores MEDIDOS:** este mismo fichero (`Message::new`) y
/// `src/edge/data/tests_inspect.rs` (cotejo contra el golden) ⇒ `pub(super)`.
pub(super) const CT_CONN_INSPECT_RESPONSE: i32 = 60799;
/// Header `ConnType` (UN byte). Oráculo: `pb/edge_client_pb/edge_client.pb.go:194`
/// (`HeaderId_ConnType = 1022`).
///
/// **Consumidores MEDIDOS:** este mismo fichero (el `insert` del paso 3) y
/// `src/edge/data/tests_inspect.rs` (cotejo contra el golden) ⇒ `pub(super)`.
pub(super) const HDR_CONN_TYPE: i32 = 1022;

/// Los cuatro valores del enum del oráculo (`ziti/edge/messages.go:611-618`).
///
/// `Unknown` (3) se porta por completitud del enum del oráculo y NO tiene productor en ninguno de
/// los dos lados: censo EJECUTADO sobre el pin (`git grep -n 'ConnTypeUnknown' -- '*.go'` = 2 hits:
/// la definición `messages.go:617` y el default del LECTOR `messages.go:631`), y en el port
/// [`classify_conn_inspect`] tiene exactamente TRES salidas. Por eso la variante lleva una
/// supresión de `dead_code` (ver el comentario del atributo) y por eso [`conn_type_byte`] cierra
/// su match con `unreachable!`.
///
/// **Visibilidad `pub(super)`, por CONSUMIDORES MEDIDOS** (RB-SDK-06): este fichero y
/// `src/edge/data/tests_inspect.rs` (`conn_type_byte_mapping_is_exact`), ambos dentro de
/// `edge::data`. Baja JUNTO a [`build_conn_inspect_response`], que lo lleva por parámetro: una
/// función más visible que el tipo de su parámetro dispara `private_interfaces`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConnType {
    Invalid,
    Dial,
    Bind,
    /// El brazo IMPOSIBLE, con su supresión de lint documentada como exige RB-SDK-06.
    ///
    /// **Cardinal MEDIDO de la superficie que silencia: 1 ítem** — esta variante y solo ella (el
    /// atributo va sobre la VARIANTE, no sobre el enum ni sobre el módulo, que apagarían el
    /// detector de toda su superficie).
    ///
    /// **Comando de re-medida** — quita el atributo y corre el lint ORDINARIO con recompilación
    /// forzada delante, porque la caché de clippy responde una invocación idéntica con salida
    /// VACÍA y un censo sobre ella mide la nada; JAMÁS `--force-warn`, que mide la ceguera del
    /// CRATE y no la atribución a ESTA supresión (RB-SDK-06 3.ª):
    /// `touch src/lib.rs && cargo clippy --all-targets --locked 2>&1 | grep -c 'never constructed'`
    /// ⇒ **1** sin el atributo, **0** con él.
    ///
    /// **`#[expect]` y no `#[allow]`, MEDIDO en las tres compilaciones del gate** (RB-SDK-06 4.ª
    /// exige medir, no heredar): sin atributo, `variant Unknown is never constructed` sale en
    /// `lib` **y** en `lib test` — la vitalidad NO cambia entre configuraciones, que es la
    /// condición bajo la que `#[expect]` daría `unfulfilled_lint_expectation` —, y con `#[expect]`
    /// los tres pasos salen rc 0: `cargo clippy --locked -- -D warnings`,
    /// `cargo clippy --all-targets --locked -- -D warnings` y
    /// `cargo clippy --all-targets --all-features --locked -- -D warnings`. Se prefiere a
    /// `#[allow]` porque se AUTO-RETIRA: en cuanto alguien construya la variante, la expectativa
    /// queda incumplida y el gate lo dice.
    ///
    /// **Consumidor y rebanada de retirada: DG-2**, que porta `UnmarshalInspectResult`
    /// (`ziti/edge/messages.go:626-641`) — el ÚNICO sitio del pin que produce `ConnTypeUnknown`,
    /// en su default `:629-631`.
    #[expect(dead_code)]
    Unknown,
}

/// Byte que viaja en el header 1022 (`PutByteHeader`, un solo byte: `channel/v4@v4.3.9
/// message.go:240-242`). Espejo de `byte(connType)` en `NewConnInspectResponse`
/// (`ziti/edge/messages.go:267`) sobre el enum de `ziti/edge/messages.go:611-618`.
///
/// El brazo `Unknown` es INALCANZABLE desde el respondedor: ninguna rama de
/// [`classify_conn_inspect`] lo produce y el oráculo tampoco (0 productores en el pin). Se cierra
/// con `unreachable!` en vez de con un byte, para que una futura cuarta salida del clasificador
/// no emita un `ConnType` inventado en silencio.
fn conn_type_byte(t: ConnType) -> u8 {
    match t {
        ConnType::Invalid => 0,
        ConnType::Dial => 1,
        ConnType::Bind => 2,
        ConnType::Unknown => unreachable!(
            "ConnType::Unknown no tiene productor: classify_conn_inspect tiene tres salidas"
        ),
    }
}

/// Clasifica el `conn_id` contra los mapas VIVOS del canal. TRES salidas.
///
/// Corre SÍNCRONO en el hilo receptor (el rx-loop), ANTES del `tokio::spawn` de
/// [`spawn_conn_inspect_reply`]: el lookup del oráculo también lo es (`mux.sinks.Get(connId)`,
/// `ziti/edge/msg_mux.go:369`, y los dos `AcceptMessage` que lo delegan —
/// `ziti/edge/network/conn.go:336-342`, `ziti/edge/network/hosting_conn.go:152-157` — se invocan
/// desde el despacho). Clasificar DENTRO de la task daría `Invalid` donde el oráculo da
/// `Dial`/`Bind` si la conn se desregistra entre el despacho y el arranque de la task.
///
/// El oráculo tiene UN mapa de sinks y el sink decide su propio tipo; el port tiene DOS
/// (`conns` y `binds`), así que necesita un desempate: **`conns` primero, `binds` después**,
/// el mismo que el rx-loop ya usa para `CT_STATE_CLOSED` (`super::rxloop`). Es la desviación
/// `D-3` del spec.
///
/// **Por qué es neutra en el dominio alcanzable — por RANGOS, y AHORA por construcción:**
/// el asignador del port ([`super::ChannelState::next_conn_id`]) ya no es un contador desnudo: es
/// el port 1:1 de `GetNextId` ([`super::channel_state::alloc_conn_id`]), que **CONSULTA los mapas
/// vivos y SALTA los ids en uso**, y **rebobina** a `minId` en cuanto el candidato sale de
/// `[minId, maxId)`. La unicidad de dos ids que ÉL reparte ya no se apoya en la monotonía (que el
/// rebobinado rompe a propósito, igual que en el oráculo) sino en algo **más fuerte**: el skip
/// consulta `conns ∪ binds` antes de devolver, así que un id vivo nunca se reparte dos veces.
///
/// Y las conn-ids de las conns HIJAS ya **no las reparte siempre el router**: las provee él cuando
/// el `Dial` trae `RouterProvidedConnId` legible, y **las generamos nosotros** cuando no
/// (`ziti/edge/network/hosting_conn.go:290-296`). El argumento se re-ancla, por tanto, en los DOS
/// RANGOS, que esta rebanada vuelve **estructurales**: el router **siembra en `[2^31, 2^32-1]`** —
/// `nextDialConnId` rebobina `idSeq` a `math.MaxUint32/2` en cuanto el contador cae por debajo
/// (openziti/ziti `9bf62f3`, `router/xgress_edge/fabric.go:198-205`, clon efímero en
/// `/tmp/zsrc/ziti`) — y el port acota los suyos por DEBAJO de
/// `maxId = (MaxUint32/2) - 1 = 2^31-2` (`ziti/edge/msg_mux.go:302`) con el MISMO clamp del
/// oráculo, que rebobina en cuanto `nextId >= maxId` (`:337-352`) ⇒ ids del port en
/// `[1, 2^31-3]` (más el `0` que sólo alcanza el envolvimiento del contador). Los dos rangos son
/// **disjuntos por construcción**, con el hueco `{2^31-2, 2^31-1}` entre ellos: ya no es un margen
/// medido de ~2^31 asignaciones, es una guarda.
pub(super) fn classify_conn_inspect(state: &ChannelState, conn_id: u32) -> ConnType {
    if state.conns.lock().unwrap().contains_key(&conn_id) {
        ConnType::Dial
    } else if state.binds.lock().unwrap().contains_key(&conn_id) {
        ConnType::Bind
    } else {
        ConnType::Invalid
    }
}

/// Construye la respuesta: los pasos 1-4 del codec, EN EL ORDEN del oráculo (RB-10, no una
/// «equivalencia razonada»). Pura — no escribe ni lee el reloj, así que se testea aislada.
///
/// 1. `NewMessage(60799, body)` deja `sequence = -1` (`channel/v4@v4.3.9 message.go:320-329`,
///    el valor de `HelloSequence`); el sequence real lo asigna el canal al enviar.
/// 2. `PutUint32Header(ConnIdHeader, connId)` (`ziti/edge/messages.go:266`).
/// 3. `PutByteHeader(ConnTypeHeader, byte(connType))` (`:267`).
/// 4. `ReplyTo(request)` (`channel/v4@v4.3.9 message.go:390-399`): el `ReplyFor` — que el oráculo
///    escribe en tiempo de marshal desde `m.replyFor` (`message.go:604-606`) — y el REFLEJO de los
///    headers del request con el predicado LITERAL del canal.
///
/// **El orden 2-3 ANTES de 4 es load-bearing**: en el oráculo el constructor corre antes de
/// `ReplyTo`, así que el reflejo *podría* sobrescribir `ConnId`/`ConnType` (`insert` pisa, igual
/// que `m.Headers[key] = value`). Con el techo sano no lo hace — ambas claves son > 255 — y ese
/// techo es load-bearing con dirección **over-permit**: un request con `1022 = 03` pisaría el
/// `ConnType` recién calculado y el peer leería `Unknown` en vez de `Dial`/`Bind`/`Invalid`.
///
/// **Visibilidad `pub(super)`, por CONSUMIDORES MEDIDOS** (RB-SDK-06): este fichero
/// (`spawn_conn_inspect_reply`) y `src/edge/data/tests_inspect.rs`
/// (`conn_type_byte_mapping_is_exact` y la mitad EMISORA de
/// `conn_inspect_decodes_every_oracle_wire_form`), ambos en `edge::data`. Baja JUNTO a
/// [`ConnType`], que viaja por parámetro: dejarla más visible que el tipo de su parámetro
/// dispararía `private_interfaces`.
pub(super) fn build_conn_inspect_response(
    conn_id: u32,
    conn_type: ConnType,
    body: Vec<u8>,
    request: &Message,
) -> Message {
    let mut msg = Message::new(CT_CONN_INSPECT_RESPONSE, body);
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    msg.headers
        .insert(HDR_CONN_TYPE, vec![conn_type_byte(conn_type)]);
    msg.headers
        .insert(HDR_REPLY_FOR, request.sequence.to_le_bytes().to_vec());
    for (&k, v) in &request.headers {
        if k & REFLECTED_HEADER_BIT_MASK != 0 && k <= MAX_REFLECTED_HEADER {
            msg.headers.insert(k, v.clone());
        }
    }
    msg
}

/// Espeja el `go …` de los tres emisores del oráculo: responde en una task PROPIA.
///
/// No es cosmético. El rx-loop del port es el hot path COMPARTIDO por todos los canales y escribir
/// exige `state.write.lock().await`: responder INLINE metería una escritura bloqueante en el bucle
/// de lectura y podría parquearlo — justo el fallo que el diseño vigente combate con el `select!`
/// contra `close_notify`. Recibe el `ConnType` **ya clasificado** (ver
/// [`classify_conn_inspect`]): solo la RESPUESTA viaja en la task.
///
/// Cuerpo de la respuesta, por desenlace:
/// - **Invalid:** el literal BYTE-EXACTO del oráculo (`fmt.Sprintf("invalid conn id [%v]", connId)`
///   con `connId` `uint32` ⇒ decimal sin signo, `ziti/edge/msg_mux.go:404`). RB-SDK-01: no se
///   traduce ni se «mejora».
/// - **Dial / Bind:** `{"id":N}`, un UNDER-REPORT declarado (`D-1` del spec): el oráculo emite
///   `getBaseState()` (9 claves, `ziti/edge/network/conn.go:277-289`) y `Inspect()` (4 + un
///   submapa `listener` de 4, `ziti/edge/network/hosting_conn.go:247-260`), cuyo estado el port no
///   tiene reunido en este punto. El campo EXACTO es el `ConnType`, que es el que el peer USA.
///
/// Un fallo de envío se loguea y se desiste, como el oráculo (`if err := … Send(…); err != nil {
/// … Error("failed to send inspect response") }`): NO se reintenta, NO se cierra el canal, NO se
/// propaga. La traza no lleva cuerpo ni token (`D-5`, RB-SDK-04).
pub(super) fn spawn_conn_inspect_reply(
    state: &Arc<ChannelState>,
    conn_id: u32,
    conn_type: ConnType,
    request: Message,
) {
    let state = state.clone();
    tokio::spawn(async move {
        let body = if matches!(conn_type, ConnType::Invalid) {
            format!("invalid conn id [{conn_id}]")
        } else {
            format!("{{\"id\":{conn_id}}}")
        };
        let mut msg = build_conn_inspect_response(conn_id, conn_type, body.into_bytes(), &request);
        // Lectura de AMBIENTE convertida en parámetro (`D-4`): UNA lectura del contador compartido
        // por respuesta emitida, inmediatamente antes del write. Espejo de
        // `s.SetSequence(self.ctx.NextSequence())` (`channel/v4@v4.3.9 senders.go:31`).
        msg.sequence = state.next_seq();
        let mut w = state.write.lock().await;
        if let Err(e) = write_message(&mut *w, &msg).await {
            tracing::warn!(conn_id, error = %e, "failed to send inspect response");
        }
    });
}
