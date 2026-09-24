//! Tests del respondedor de `ConnInspect` (rebanada `qw-dg1-conninspect`, spec
//! `docs/superpowers/specs/2026-08-21-qw-dg1-conninspect-design.md` §7).
//!
//! Dos reglas de forma que gobiernan el fichero, cada una con su ÁMBITO medido:
//!
//! 1. **Cuerpo entero envuelto en `timeout(5s)`** (RB-SDK-10) — ámbito: los **12 tests async**
//!    del fichero. Los otros dos (`conn_inspect_golden_digest_is_pinned` y
//!    `conn_type_byte_mapping_is_exact`) son `#[test]` SÍNCRONOS sin espera correlada: quedan
//!    fuera del ámbito de la regla, no la incumplen (§7.1 del spec, corregido por E-5). Acotar
//!    cada `await` por separado deja fuera el teardown (`task.await`), que cuelga igual si el
//!    rx-loop no sale por EOF. Precedente vivo: `src/edge/data/tests_channel_state.rs`
//!    (`healthy_sibling_eofs_*`).
//! 2. **Todo valor de WIRE va LITERAL en los asserts y en los frames BAJO PRUEBA que el test
//!    fabrica** (60798, 60799, 1000, 1022, 1, y los bytes 0/1/2 del `ConnType`), nunca la
//!    constante del port: usar la constante a los dos lados es una tautología y deja SIN
//!    falsador las mutaciones del censo que cambian su valor (`M-1`, `M-2`, `M-3`, `M-4`). Dos
//!    excepciones DECLARADAS: `conn_inspect_decodes_every_oracle_wire_form` compara las
//!    constantes del port contra el bloque `constants` del GOLDEN (ahí el otro lado lo pone el
//!    oráculo); y los frames AUXILIARES de sincronización (`data_frame`, el `CT_DIAL` de
//!    `conn_inspect_without_conn_id_is_dropped`) usan las constantes del port a propósito — no
//!    son el frame bajo prueba y ninguna fila del censo muta `CT_DATA`/`CT_DIAL`/`HDR_CONN_ID`.

use super::inspect::*;
use super::rxloop::rx_loop;
use super::testsupport::*;
use super::*;

use std::collections::BTreeMap;

use crate::channel::message::{
    HELLO_SEQUENCE, MAX_REFLECTED_HEADER, REFLECTED_HEADER_BIT_MASK, parse_frame,
};

/// El golden capturado EJECUTANDO el oráculo (`tests/fixtures/conninspect_goldengen`). Se lee con
/// `include_str!` como el resto del repo (`src/channel/message.rs`, `src/edge/crypto.rs`): ningún
/// test toca el disco en runtime.
const GOLDEN: &str = include_str!("../../../tests/fixtures/conninspect_golden.json");

/// sha256 del golden COMMITEADO — copia PINEADA del literal cuya sede es §3.1 del spec. Con esta
/// constante el sha vive en CUATRO sedes (§3.1, §9 paso 1, §12 y aquí): quien regenere el golden
/// (DG-2) re-pinea las cuatro, o `conn_inspect_golden_digest_is_pinned` sale ROJO (a propósito).
const GOLDEN_SHA256: &str = "c4602f44456303a90865e51deb8be2346d9229e1b3fdaf6a35542bc432292c49";

fn golden() -> serde_json::Value {
    serde_json::from_str(GOLDEN).expect("el golden es JSON válido")
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex de longitud par: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("dígito hex válido"))
        .collect()
}

/// Un `ConnInspectRequest` del peer: content-type **60798 LITERAL** y `ConnId` en el header
/// **1000 LITERAL** (4 bytes LE, como `PutUint32Header`).
fn inspect_request(conn_id: u32, sequence: i32) -> Message {
    let mut msg = Message::new(60798, vec![]);
    msg.headers.insert(1000, conn_id.to_le_bytes().to_vec());
    msg.sequence = sequence;
    msg
}

/// Un `Data` para `conn_id`: el FRAME DE SINCRONIZACIÓN de los tests de ausencia (§7.2). Enviarlo
/// DESPUÉS del frame bajo prueba y verlo llegar demuestra que el rx-loop procesó *hasta después*
/// de aquél, que es lo que convierte «no vi respuesta» en un negativo con detector acreditado.
fn data_frame(conn_id: u32, body: &[u8]) -> Message {
    let mut msg = Message::new(CT_DATA, body.to_vec());
    msg.headers
        .insert(HDR_CONN_ID, conn_id.to_le_bytes().to_vec());
    msg
}

/// Una mitad de escritura cuyo `poll_write` SIEMPRE falla (`BrokenPipe`) — el transporte muerto de
/// `T-8`. NACE aquí y no en `testsupport.rs`, que está FUERA de la lista cerrada de ficheros de la
/// rebanada (§4.1 del spec). Su gemela `BlackHoleWrite` (write eternamente `Pending`) ya vive en
/// `testsupport.rs` y se reusa tal cual en `T-11`.
struct DeadWrite;
impl tokio::io::AsyncWrite for DeadWrite {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Rig PROPIO de `T-8`/`T-11` (§7.3): el rx-loop lee de un duplex normal, pero la mitad de
/// ESCRITURA del canal es la que el test elige, no la del duplex.
///
/// ⚠ **La mitad de escritura del duplex (`cw`) se SUELTA aquí, y eso NO cierra nada.** La forma
/// anterior de este helper la DEVOLVÍA como 4.º valor «para mantenerla viva»; esa retención era
/// **INERTE**, MEDIDO sobre tokio **1.52.3** (la del `Cargo.lock`): `tokio::io::split` reparte
/// `ReadHalf`/`WriteHalf` sobre un `Arc<Inner<T>>` COMPARTIDO (`tokio-1.52.3/src/io/split.rs:18-24`
/// y `:53`) y **ninguna de las dos mitades implementa `Drop`** (`grep 'impl.*Drop'` sobre ese
/// fichero: 0 hits). El `Drop` que cierra el extremo es el del `DuplexStream`
/// (`tokio-1.52.3/src/io/util/mem.rs:175`), y solo corre cuando cae la **ÚLTIMA** referencia al
/// `Arc` — y `cr` sigue viva dentro de la task del rx-loop mientras el test dura. Retirarla evita
/// sugerir una precondición que no existe.
fn rig_with_write(
    w: BoxWrite,
) -> (
    Arc<ChannelState>,
    tokio::task::JoinHandle<()>,
    tokio::io::DuplexStream,
) {
    let (client, router) = tokio::io::duplex(8192);
    let (cr, _cw) = tokio::io::split(client);
    let state = Arc::new(ChannelState::new(w));
    let task = tokio::spawn(rx_loop(Box::new(cr), state.clone()));
    (state, task, router)
}

// ----------------------------------------------------------------------------------------------
// T-1..T-3 + T-14: los tres desenlaces (Invalid / Dial / Bind), con las DOS caras del Dial
// ----------------------------------------------------------------------------------------------

/// `T-1` (`V1-invalid-conn`, oráculo `ziti/edge/msg_mux.go:402-409`). Un `ConnId` que no está en
/// ningún mapa vivo ⇒ `ConnType = 0` y el literal BYTE-EXACTO `invalid conn id [4242]`.
#[tokio::test]
async fn conn_inspect_unknown_conn_replies_invalid() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_state, task, mut router) = rig();

        write_message(&mut router, &inspect_request(4242, 7))
            .await
            .unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        assert_eq!(resp.content_type, 60799, "ct del ConnInspectResponse");
        assert_eq!(
            resp.headers.get(&1022),
            Some(&vec![0u8]),
            "ConnType = Invalid (byte literal 0)"
        );
        assert_eq!(
            resp.body, b"invalid conn id [4242]",
            "literal byte-exacto del oráculo (msg_mux.go:404)"
        );
        assert_eq!(
            resp.headers.get(&1),
            Some(&7i32.to_le_bytes().to_vec()),
            "ReplyFor = el sequence del request"
        );
        assert_eq!(
            resp.headers.get(&1000),
            Some(&4242u32.to_le_bytes().to_vec()),
            "ConnId lo pone el constructor"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-1: el respondedor de ConnInspect no contestó al desenlace Invalid");
}

/// `T-2` (`V2-dial-conn`, oráculo `ziti/edge/network/conn.go:303-310`). Una conn HIJA viva ⇒
/// `ConnType = 1`.
///
/// Lleva además el FALSADOR de `D-3` (el desempate `conns` antes que `binds`, `M-13`): el MISMO id
/// se registra en los DOS mapas, que es el único vector que separa las dos ramas del clasificador
/// — con un id en un solo mapa, invertir el orden de consulta es un NO-OP y la fila quedaría sin
/// falsador (MEDIDO: con la forma anterior de este test, `M-13` sobrevivía 0/709). El oráculo no
/// tiene esta decisión (un solo mapa de sinks), así que el vector no contradice ninguna cita: fija
/// la desviación del port.
#[tokio::test]
async fn conn_inspect_dial_conn_replies_dial() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig();
        let (tx, _rx) = mpsc::channel(4);
        state.register_conn(7, tx);
        // Colisión DELIBERADA (el vector separador de `M-13`): el mismo id en `binds`.
        let (btx, _brx) = mpsc::channel(4);
        state.register_bind(7, btx);

        write_message(&mut router, &inspect_request(7, 11))
            .await
            .unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        assert_eq!(resp.content_type, 60799, "ct del ConnInspectResponse");
        assert_eq!(
            resp.headers.get(&1022),
            Some(&vec![1u8]),
            "ConnType = Dial (byte literal 1); con el id en AMBOS mapas, gana `conns` (D-3)"
        );
        assert_eq!(
            resp.body, b"{\"id\":7}",
            "cuerpo D-1 (UNDER-REPORT declarado)"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-2: el respondedor de ConnInspect no contestó al desenlace Dial");
}

/// `T-14`. La cara ORDINARIA del desenlace Dial: el id vive **SOLO** en `conns`, sin bind
/// homónimo. Es el mundo real (`D-3` demuestra que los dos rangos de ids son disjuntos), y `T-2`
/// no lo cubre porque su fixture es la COLISIÓN deliberada que separa las dos ramas de `M-13`.
///
/// Sin este test, la primera rama del clasificador queda sin falsador para una clase entera de
/// mutantes: MEDIDO sobre el árbol de la entrega del 2b, el mutante
/// `if conns { if binds { Dial } else { Invalid } } else if binds { Bind } else { Invalid }`
/// —que convierte «está en `conns`» en «está en LOS DOS»— sobrevivía a la suite ENTERA
/// (709 passed / 0 failed), porque el único vector de Dial que existía registraba el id en ambos
/// mapas. Con `T-14` ese mutante MUERE aquí.
#[tokio::test]
async fn conn_inspect_dial_only_conn_replies_dial() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig();
        let (tx, _rx) = mpsc::channel(4);
        state.register_conn(21, tx);
        // NINGÚN bind con ese id: es la diferencia con T-2.

        write_message(&mut router, &inspect_request(21, 13))
            .await
            .unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        assert_eq!(resp.content_type, 60799, "ct del ConnInspectResponse");
        assert_eq!(
            resp.headers.get(&1022),
            Some(&vec![1u8]),
            "ConnType = Dial (byte literal 1) con el id SOLO en `conns`"
        );
        assert_eq!(
            resp.body, b"{\"id\":21}",
            "cuerpo D-1 (UNDER-REPORT declarado)"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-14: el respondedor de ConnInspect no contestó al Dial sin bind homónimo");
}

/// `T-3` (`V3-bind-conn`, oráculo `ziti/edge/network/hosting_conn.go:192-199`). Un BIND vivo ⇒
/// `ConnType = 2`.
#[tokio::test]
async fn conn_inspect_bind_conn_replies_bind() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig();
        let (tx, _rx) = mpsc::channel(4);
        state.register_bind(9, tx);

        write_message(&mut router, &inspect_request(9, 12))
            .await
            .unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        assert_eq!(resp.content_type, 60799, "ct del ConnInspectResponse");
        assert_eq!(
            resp.headers.get(&1022),
            Some(&vec![2u8]),
            "ConnType = Bind (byte literal 2)"
        );
        assert_eq!(
            resp.body, b"{\"id\":9}",
            "cuerpo D-1 (UNDER-REPORT declarado)"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-3: el respondedor de ConnInspect no contestó al desenlace Bind");
}

// ----------------------------------------------------------------------------------------------
// T-4/T-5: el REFLEJO y su techo (`ReplyTo`, channel/v4@v4.3.9 message.go:390-399)
// ----------------------------------------------------------------------------------------------

/// El request de `V4-reflect-all-frontiers`: las 9 claves que barren las DOS caras de cada
/// frontera del predicado `key & 128 != 0 && key <= 255` (bit 7 sí/no, ≤255 sí/no, signo ±).
fn v4_request() -> Message {
    let mut msg = Message::new(60798, vec![]);
    msg.headers.insert(-129, hex("beef")); // bit 7 NO, ≤255  ⇒ no refleja (negativa)
    msg.headers.insert(-1, hex("dead")); // bit 7 SÍ, ≤255  ⇒ REFLEJA (negativa)
    msg.headers.insert(127, hex("7f")); // frontera inferior del bit 7 ⇒ no
    msg.headers.insert(128, b"uuid-128".to_vec()); // primer reflejable (el UUID real)
    msg.headers.insert(255, hex("ff")); // el TECHO exacto ⇒ REFLEJA
    msg.headers.insert(256, hex("0100")); // el único entero de la mutación `<=256`: ya falla la máscara
    msg.headers.insert(384, hex("8001")); // bit 7 SÍ y >255 ⇒ SEPARA el techo
    msg.headers.insert(1000, 4242u32.to_le_bytes().to_vec()); // ConnId REAL
    msg.headers.insert(1022, vec![3u8]); // ConnType REAL, con ConnTypeUnknown dentro
    msg.sequence = 101;
    msg
}

/// `T-4`. El conjunto ENTERO de claves de la respuesta, CON VALORES, es exactamente
/// `{-1, 1, 128, 255, 1000, 1022}`: `-1`/`128`/`255` traen el valor del request (eso es el
/// reflejo) y `1`/`1000`/`1022` los del constructor + la correlación. Se compara el mapa COMPLETO
/// y no una intersección: el port no tiene la «sonda de reflejo puro» del golden (un mensaje sin
/// headers propios), así que clasificar por intersección con el request colapsaría el `1000`, que
/// aparece en ambos porque lo pone el CONSTRUCTOR.
#[tokio::test]
async fn conn_inspect_reflects_only_headers_with_bit7_up_to_255() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_state, task, mut router) = rig();

        write_message(&mut router, &v4_request()).await.unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        let expected: BTreeMap<i32, Vec<u8>> = [
            (-1, hex("dead")),                      // reflejada: bit 7 y ≤255, NEGATIVA
            (1, 101i32.to_le_bytes().to_vec()),     // ReplyFor
            (128, b"uuid-128".to_vec()),            // reflejada
            (255, hex("ff")),                       // reflejada: el techo exacto
            (1000, 4242u32.to_le_bytes().to_vec()), // constructor
            (1022, vec![0u8]),                      // constructor: Invalid, NO el 03 del request
        ]
        .into_iter()
        .collect();
        assert_eq!(
            resp.headers, expected,
            "el conjunto de headers de la respuesta (127/-129/256/384 NO cruzan el predicado)"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-4: el respondedor de ConnInspect no contestó al vector del reflejo");
}

/// `T-5`. El techo del reflejo es load-bearing con dirección **over-permit**: el request trae
/// `1022 = 03` (`ConnTypeUnknown`) y NO puede pisar el `ConnType` que el port acaba de calcular.
///
/// ⚠ El eje `1000` COLAPSA en este vector (el request lleva el MISMO conn_id que el port
/// recalcula) ⇒ un assert sobre `headers[1000]` aquí sería TAUTOLÓGICO y se declara: el
/// discriminante del `1000` vive en `T-4` (conjunto con valores) y el de la SOBRESCRITURA en el
/// eje `1022`, que es donde los dos valores difieren.
#[tokio::test]
async fn conn_inspect_reflection_never_overwrites_conn_type() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_state, task, mut router) = rig();

        write_message(&mut router, &v4_request()).await.unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        assert_eq!(
            resp.headers.get(&1022),
            Some(&vec![0u8]),
            "el 03 del request NO pisa el ConnType calculado por el port"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-5: el respondedor de ConnInspect no contestó al vector del reflejo");
}

// ----------------------------------------------------------------------------------------------
// T-6/T-7: la correlación (ReplyFor) y el sequence propio
// ----------------------------------------------------------------------------------------------

/// `T-6` (`V6-negative-sequence`). `ReplyFor` copia el sequence del request TAL CUAL, incluido un
/// sequence NEGATIVO (`replyFor := o.sequence`, sin filtro, `message.go:391`).
#[tokio::test]
async fn conn_inspect_reply_for_carries_request_sequence() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (_state, task, mut router) = rig();

        write_message(&mut router, &inspect_request(65535, -7))
            .await
            .unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        assert_eq!(
            resp.headers.get(&1),
            Some(&(-7i32).to_le_bytes().to_vec()),
            "ReplyFor = -7 (el sequence negativo del request)"
        );
        assert_eq!(
            resp.body, b"invalid conn id [65535]",
            "el connId del literal es DECIMAL SIN SIGNO (uint32)"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-6: el respondedor de ConnInspect no contestó al vector de sequence negativo");
}

/// `T-7`. El `sequence` de la respuesta lo asigna el CANAL al enviar
/// (`s.SetSequence(self.ctx.NextSequence())`, `channel/v4@v4.3.9 senders.go:31`), nunca queda en
/// el `-1` del constructor. Forma PINADA sobre `next_seq()` = `fetch_add(1) + 1`: se lee `s0`
/// ANTES de disparar, la respuesta trae `s0 + 1`, y la llamada POSTERIOR devuelve
/// `resp.sequence + 1` — o sea, se consumió EXACTAMENTE una lectura del contador (`D-4`).
#[tokio::test]
async fn conn_inspect_reply_sequence_comes_from_next_seq() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig();
        let s0 = state.next_seq();

        write_message(&mut router, &inspect_request(4242, 7))
            .await
            .unwrap();
        let resp = read_message(&mut router).await.expect("una respuesta");

        assert_ne!(resp.sequence, -1, "no se emite el -1 del constructor");
        assert_eq!(resp.sequence, s0 + 1, "el sequence sale de next_seq()");
        assert_eq!(
            state.next_seq(),
            resp.sequence + 1,
            "la respuesta consumió EXACTAMENTE una lectura del contador"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-7: el respondedor de ConnInspect no contestó");
}

// ----------------------------------------------------------------------------------------------
// T-8/T-11: fallo de envío y liveness del rx-loop (la task propia, el `go` del oráculo)
// ----------------------------------------------------------------------------------------------

/// `T-8`. Transporte cuyo write SIEMPRE falla: el oráculo loguea y DESISTE (no reintenta, no
/// cierra el canal, no propaga) y el port hace lo mismo.
///
/// **Dos cláusulas decisivas, ninguna de ellas «no panica»** (un pánico dentro de la task solo la
/// mata, §5.6, así que es INOBSERVABLE desde fuera):
///
/// 1. **El rx-loop sigue vivo**: un `Data` posterior llega a su cola.
/// 2. **La rama «loguea y DESISTE» se OBSERVA**, con `#[traced_test]` + `logs_contain`: el port
///    recorrió el brazo de error del `write_message` y emitió la traza del oráculo
///    (`Error("failed to send inspect response")`, `ziti/edge/msg_mux.go:407`). Esto convierte en
///    FALSABLE lo que antes era una ALARMA sin falsador: borrar el `tracing::warn!` (dejar
///    `let _ = write_message(…)`) pone este test en RED. La mutación `let _ =` → `.expect()`
///    sigue sin falsador aquí (mata la task en silencio) y se declara defensa en profundidad
///    (RB-11); la que YA no lo es es la del warn.
///
/// La ventana de AUSENCIA de §7.2 se mantiene entre las dos.
#[traced_test]
#[tokio::test]
async fn conn_inspect_send_failure_never_replies_and_never_panics() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig_with_write(Box::new(DeadWrite));
        let (tx, mut rx) = mpsc::channel(4);
        state.register_conn(5, tx);

        // El frame BAJO PRUEBA primero…
        write_message(&mut router, &inspect_request(4242, 7))
            .await
            .unwrap();
        // …y el de SINCRONIZACIÓN después: verlo llegar prueba que el rx-loop procesó hasta
        // DESPUÉS del 60798 (cláusula decisiva) y ancla el orden de la ventana de ausencia.
        write_message(&mut router, &data_frame(5, b"sync"))
            .await
            .unwrap();
        let sync = rx.recv().await.expect("el rx-loop sigue despachando");
        assert_eq!(
            sync.body, b"sync",
            "el frame de sincronización llegó entero"
        );

        let late =
            tokio::time::timeout(Duration::from_millis(200), read_message(&mut router)).await;
        assert!(
            late.is_err(),
            "un write muerto no puede producir respuesta (ni pánico que tumbe el rx-loop)"
        );

        // Control POSITIVO de la rama «loguea y desiste». Se comprueba DESPUÉS de la ventana de
        // ausencia a propósito: esos 200 ms de espera ceden la runtime (current_thread) y la task
        // de respuesta ya ha sido poleada hasta su `write_message`, que falla en el primer
        // `poll_write` de `DeadWrite`. Sin esta cláusula, borrar el `tracing::warn!` no rompía
        // ningún test.
        assert!(
            logs_contain("failed to send inspect response"),
            "el fallo de envío debe dejar la traza del oráculo (msg_mux.go:407), no desistir mudo"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-8: un fallo de envío del ConnInspect no debe matar el rx-loop");
}

/// `T-11`. La respuesta va en una task PROPIA (`go conn.HandleConnInspect(msg)` y sus dos
/// gemelos). Con la escritura de la respuesta RETENIDA para siempre (`BlackHoleWrite`, `poll_write
/// → Pending`), el rx-loop **sigue despachando**.
///
/// Un respondedor INLINE tomaría `state.write.lock().await` dentro del bucle de lectura y quedaría
/// parqueado ahí: el `Data` posterior no llegaría nunca y el test moriría por el `timeout(5s)`.
/// (La forma anterior del spec — «llenar el buffer del duplex» — era insatisfacible: `rig()` abre
/// `duplex(8192)` y la respuesta pesa 75 B, así que un respondedor inline también pasaba.)
#[tokio::test]
async fn conn_inspect_reply_does_not_stall_the_rx_loop() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig_with_write(Box::new(BlackHoleWrite));
        let (tx, mut rx) = mpsc::channel(4);
        state.register_conn(5, tx);

        write_message(&mut router, &inspect_request(5, 7))
            .await
            .unwrap();
        write_message(&mut router, &data_frame(5, b"after"))
            .await
            .unwrap();

        let got = rx.recv().await.expect("el rx-loop sigue despachando");
        assert_eq!(
            got.body, b"after",
            "el Data posterior al ConnInspect llega aunque la respuesta esté retenida"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-11: una respuesta de ConnInspect retenida NO puede parquear el rx-loop");
}

// ----------------------------------------------------------------------------------------------
// T-9/T-10: equivalencia con el oráculo (el golden)
// ----------------------------------------------------------------------------------------------

/// Los vectores del golden cuyo `request` es reconstruible **sin estado**, y por tanto los únicos
/// que la mitad EMISORA de `T-9` puede cotejar. `V2`/`V3` quedan fuera con razón declarada en el
/// doc de `T-9`.
const EMITTER_VECTORS: [&str; 6] = [
    "V1-invalid-conn",
    "V2-dial-conn",
    "V3-bind-conn",
    "V4-reflect-all-frontiers",
    "V5-no-reflectable-headers",
    "V6-negative-sequence",
];

/// El PLANO OBSERVABLE pineado de un `response` del golden:
/// `(content_type, sequence, reply_for, headers, body)`. Extractor ÚNICO para las dos mitades de
/// `T-9` (la lectora y la emisora), para que no puedan divergir.
fn golden_response_plane(
    want: &serde_json::Value,
) -> (i32, i32, i32, BTreeMap<i32, Vec<u8>>, Vec<u8>) {
    let mut headers: BTreeMap<i32, Vec<u8>> = BTreeMap::new();
    for h in want["headers"].as_array().expect("headers es un array") {
        let key = i32::try_from(h["key"].as_i64().expect("key entera")).expect("key i32");
        headers.insert(key, hex(h["value_hex"].as_str().expect("value_hex")));
    }
    (
        i32::try_from(want["content_type"].as_i64().expect("ct")).expect("ct i32"),
        i32::try_from(want["sequence"].as_i64().expect("seq")).expect("seq i32"),
        i32::try_from(want["reply_for"].as_i64().expect("reply_for")).expect("i32"),
        headers,
        hex(want["body_hex"].as_str().expect("body_hex")),
    )
}

/// Rehace el `Message` del REQUEST tal como el golden lo capturó (ct + sequence + headers + body).
fn golden_request_message(req_j: &serde_json::Value) -> Message {
    let mut req = Message::new(
        i32::try_from(req_j["content_type"].as_i64().expect("ct del request")).expect("ct i32"),
        hex(req_j["body_hex"].as_str().expect("body_hex del request")),
    );
    req.sequence =
        i32::try_from(req_j["sequence"].as_i64().expect("seq del request")).expect("seq i32");
    for h in req_j["headers"].as_array().expect("headers del request") {
        let key = i32::try_from(h["key"].as_i64().expect("key entera")).expect("key i32");
        req.headers
            .insert(key, hex(h["value_hex"].as_str().expect("value_hex")));
    }
    req
}

/// El desenlace que el vector DECLARA: el byte del header 1022 de su RESPUESTA. No se re-clasifica
/// nada — se lee lo que el oráculo emitió, que es lo que hace del golden un oráculo y no un espejo.
fn golden_conn_type(want_headers: &BTreeMap<i32, Vec<u8>>, vid: &str) -> ConnType {
    match want_headers.get(&1022).map(Vec::as_slice) {
        Some([0]) => ConnType::Invalid,
        Some([1]) => ConnType::Dial,
        Some([2]) => ConnType::Bind,
        other => panic!("{vid}: ConnType inesperado en el golden: {other:?}"),
    }
}

/// El `ConnId` (header 1000 LITERAL) del request del golden.
fn golden_conn_id(req: &Message) -> u32 {
    u32::from_le_bytes(
        req.headers
            .get(&1000)
            .expect("el request del golden trae ConnId")
            .as_slice()
            .try_into()
            .expect("ConnId de 4 bytes"),
    )
}

/// El `ReplyFor` (header 1 LITERAL) de un mensaje, como `i32`.
fn reply_for_of(msg: &Message) -> Option<i32> {
    msg.headers
        .get(&1)
        .map(|v| i32::from_le_bytes(v.as_slice().try_into().expect("ReplyFor de 4 bytes")))
}

/// `T-9`. El extremo del ORÁCULO (RB-6-ampliada): los `wire_v2_forms` son bytes emitidos por
/// `channel.MarshalV2` del pin, no por el port. Se exige DECODIFICAR cada forma y obtener el plano
/// observable pineado — `content_type`, `sequence`, `reply_for`, CONJUNTO de headers y `body` —,
/// nunca EMITIR una forma concreta: el oráculo itera un mapa Go al serializar
/// (`marshalHeaders`, `message.go:635-637`) y su orden no es parte del contrato.
///
/// El test verifica además las CONSTANTES del port contra el bloque `constants` del golden: es la
/// única sede del fichero donde el otro lado de la igualdad lo pone el oráculo (y por eso la única
/// donde la constante del port puede aparecer sin ser tautología).
///
/// **Y la mitad EMISORA** (cierra el hueco de gate del paso 4: el golden se consumía SOLO en la
/// dirección lector; registro en §7.3/§12 del spec): decodificar las formas del oráculo acredita
/// el LECTOR del port, no su CONSTRUCTOR. Para los 6 vectores —todos con request reconstruible
/// **sin estado**— se rehace el request desde el golden, se toma el desenlace que el propio
/// vector DECLARA (el byte del header `1022` de su respuesta) y se llama a
/// [`build_conn_inspect_response`] con el cuerpo del golden; después se compara el **plano
/// observable EMITIDO** contra la respuesta del golden: `content_type`, `reply_for`, conjunto
/// COMPLETO de headers con valores, y `body`.
///
/// Dos límites DECLARADOS:
/// - **El `sequence` queda fuera** del cotejo: el del golden es el del contador del ORÁCULO
///   (`ctx.NextSequence()`, `senders.go:31`) y el del port lo asigna `next_seq()` al ENVIAR, que
///   es justo lo que `T-7` pinea. Compararlos exigiría sembrar el contador del port con el del
///   oráculo, que es un espejo, no una equivalencia.
/// - **En `V2`/`V3` el eje `body` es port-contra-port**: su cuerpo en el golden está SEMBRADO
///   (el generador pasa `{"id":N}`, §12 del spec), así que su assert de body no coteja al
///   oráculo — los ejes `content_type`, `1022` (el byte del `ConnType` que puso el CONSTRUCTOR
///   del oráculo), `reply_for` y el CONJUNTO de headers sí lo hacen, y son los que faltaban para
///   cotejar el constructor en los TRES desenlaces (Invalid/Dial/Bind), no solo en Invalid.
#[tokio::test]
async fn conn_inspect_decodes_every_oracle_wire_form() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let g = golden();
        let c = &g["constants"];
        assert_eq!(c["ContentTypeConnInspectRequest"], CT_CONN_INSPECT_REQUEST);
        assert_eq!(
            c["ContentTypeConnInspectResponse"],
            CT_CONN_INSPECT_RESPONSE
        );
        assert_eq!(c["ConnIdHeader"], HDR_CONN_ID);
        assert_eq!(c["ConnTypeHeader"], HDR_CONN_TYPE);
        assert_eq!(c["ReplyForHeader"], HDR_REPLY_FOR);
        assert_eq!(c["ReflectedHeaderBitMask"], REFLECTED_HEADER_BIT_MASK);
        assert_eq!(c["MaxReflectedHeader"], MAX_REFLECTED_HEADER);
        assert_eq!(c["HelloSequence"], HELLO_SEQUENCE);

        let vectors = g["vectors"].as_array().expect("vectors es un array");
        // Cardinales PINEADOS (medidos hoy sobre el golden commiteado): un extractor que
        // devolviera un subconjunto plausible dejaría este test verde sobre casi nada.
        assert_eq!(vectors.len(), 6, "los 6 vectores del golden");
        let mut forms_seen = 0usize;
        let mut emitted_seen = 0usize;

        for v in vectors {
            let vid = v["id"].as_str().expect("id del vector");
            let (want_ct, want_seq, want_reply_for, want_headers, want_body) =
                golden_response_plane(&v["response"]);

            for form in v["wire_v2_forms"].as_array().expect("wire_v2_forms") {
                let bytes = hex(form.as_str().expect("forma hex"));
                let msg = parse_frame(&bytes).expect("el port decodifica la forma del oráculo");
                assert_eq!(msg.content_type, want_ct, "{vid}: content_type");
                assert_eq!(msg.sequence, want_seq, "{vid}: sequence");
                assert_eq!(msg.body, want_body, "{vid}: body");
                assert_eq!(msg.headers, want_headers, "{vid}: conjunto de headers");
                assert_eq!(reply_for_of(&msg), Some(want_reply_for), "{vid}: ReplyFor");
                forms_seen += 1;
            }

            // ---- mitad EMISORA: el CONSTRUCTOR del port contra el mismo golden ----
            if !EMITTER_VECTORS.contains(&vid) {
                continue;
            }
            let req = golden_request_message(&v["request"]);
            let got = build_conn_inspect_response(
                golden_conn_id(&req),
                golden_conn_type(&want_headers, vid),
                want_body.clone(),
                &req,
            );
            assert_eq!(got.content_type, want_ct, "{vid}: content_type EMITIDO");
            assert_eq!(
                got.headers, want_headers,
                "{vid}: conjunto COMPLETO de headers EMITIDO (con valores)"
            );
            assert_eq!(got.body, want_body, "{vid}: body EMITIDO");
            assert_eq!(
                reply_for_of(&got),
                Some(want_reply_for),
                "{vid}: ReplyFor EMITIDO"
            );
            emitted_seen += 1;
        }
        assert_eq!(
            forms_seen, 22,
            "las 22 formas de wire capturadas del oráculo"
        );
        assert_eq!(
            emitted_seen, 6,
            "los 6 vectores del golden pasan por la mitad emisora"
        );
    })
    .await
    .expect("T-9: la decodificación del golden no puede colgarse");
}

/// `T-10`. El digest del golden COMMITEADO, pineado también aquí (RB-6: sin él, un ejecutor que no
/// logre levantar el arnés del oráculo puede volcar su PROPIO emisor al fixture y pasar el gate
/// entero — el golden dejaría de ser oráculo y pasaría a ser un espejo). Igualdad EXACTA, nunca
/// subcadena.
#[test]
fn conn_inspect_golden_digest_is_pinned() {
    use sha2::{Digest, Sha256};
    let got = Sha256::digest(GOLDEN.as_bytes());
    let got = got.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    assert_eq!(
        got, GOLDEN_SHA256,
        "el golden capturado del oráculo cambió sin declararlo"
    );
}

// ----------------------------------------------------------------------------------------------
// T-12/T-13: la guarda de conn_id y el mapeo del enum
// ----------------------------------------------------------------------------------------------

/// `T-12` (`D-2`). Un 60798 SIN header `ConnId` se descarta en la guarda que ya existía: en el
/// oráculo cae en el `Errorf` de `HandleReceive` (`msg_mux.go:365`) porque 60798 no es
/// `ContentTypeInspectRequest` (60804) — tampoco se responde. La diferencia es SOLO la traza.
#[tokio::test]
async fn conn_inspect_without_conn_id_is_dropped() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig();
        let (tx, mut rx) = mpsc::channel(4);
        state.register_bind(7, tx);

        // El frame BAJO PRUEBA: 60798 sin el header 1000.
        let mut naked = Message::new(60798, vec![]);
        naked.sequence = 7;
        write_message(&mut router, &naked).await.unwrap();
        // Frame de SINCRONIZACIÓN (§7.2), después del anterior.
        let mut dial = Message::new(CT_DIAL, b"sync".to_vec());
        dial.headers
            .insert(HDR_CONN_ID, 7u32.to_le_bytes().to_vec());
        write_message(&mut router, &dial).await.unwrap();
        let sync = rx.recv().await.expect("el rx-loop sigue despachando");
        assert_eq!(
            sync.body, b"sync",
            "el frame de sincronización llegó entero"
        );

        let late =
            tokio::time::timeout(Duration::from_millis(200), read_message(&mut router)).await;
        assert!(
            late.is_err(),
            "un ConnInspectRequest sin ConnId no puede producir respuesta"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-12: un ConnInspectRequest sin ConnId debe descartarse sin respuesta");
}

/// `T-13`. El mapeo del enum a byte, EXACTO, sobre los TRES alcanzables y con bytes literales.
/// Va **a través de** `build_conn_inspect_response` porque `conn_type_byte` es privada de
/// `inspect.rs` y este módulo es su HERMANO, no su hijo: subir su visibilidad «para poder testear»
/// sería over-permit sin call-site (RB-SDK-06).
#[test]
fn conn_type_byte_mapping_is_exact() {
    let req = Message::new(60798, vec![]);
    for (t, want) in [
        (ConnType::Invalid, 0u8),
        (ConnType::Dial, 1u8),
        (ConnType::Bind, 2u8),
    ] {
        let msg = build_conn_inspect_response(1, t, vec![], &req);
        assert_eq!(
            msg.headers.get(&1022),
            Some(&vec![want]),
            "{t:?} ⇒ byte {want} en el header 1022"
        );
    }
}

// ----------------------------------------------------------------------------------------------
// qw-wire-header-len: el respondedor NO contesta a un ConnId mal formado
// ----------------------------------------------------------------------------------------------

/// `T-3` (falsador de `C-1`, la cara del EMISOR — el observable que hizo bloqueante a `DEUDA-1`).
/// Un `60798` cuyo `ConnId` mide 5 bytes muere en la guarda de conn-id del rx-loop
/// (`rxloop.rs:43-45`), ANTES del desvío al respondedor (`:53`): el port **calla**, exactamente como
/// el oráculo. En `sdk-golang@4b6a087`, un `ConnId` no legible manda el frame al brazo `!found` de
/// `HandleReceive` (`ziti/edge/msg_mux.go:359-366`), y ese brazo desvía SOLO el `60804`
/// (`ContentTypeInspectRequest`); el desvío del `60798` vive en la rama `found`
/// (`msg_mux.go:371-372`), que un `ConnId` mal formado nunca alcanza ⇒ cae en el `Errorf` de `:365`.
///
/// El `60798` bajo prueba se arma A MANO y no con `inspect_request`: ese helper escribe 4 bytes por
/// diseño (`:60`), o sea que su vector no puebla el conjunto bajo prueba y la fila saldría NO-OP
/// (RB-SDK-09-ampliada). No se «arregla» el helper — el frame malformado vive junto a su assert.
///
/// El negativo va ACREDITADO por partida doble (RB-2): primero se comprueba que LLEGA el frame de
/// sincronización a la conn 5 (el rx-loop procesó *más allá* del frame bajo prueba) y solo entonces
/// se lee el silencio del router-side como ausencia de respuesta.
///
/// MUTACIÓN ASESINA: `v.len() >= 4` en `header_u32` ⇒ el prefijo trunca a la conn 1, que no está en
/// ningún mapa vivo, y el port EMITE un `60799` con `ConnType = Invalid (0)` y body
/// `invalid conn id [1]`.
#[tokio::test]
async fn conn_inspect_ignores_request_whose_conn_id_header_is_five_bytes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (state, task, mut router) = rig();
        let (tx, mut rx) = mpsc::channel(4);
        state.register_conn(5, tx);

        // (1) el frame BAJO PRUEBA: ct 60798 LITERAL con el ConnId (header 1000 LITERAL) de 5 bytes,
        //     prefijo LE = 1u32.
        let mut malformed = Message::new(60798, vec![]);
        malformed.headers.insert(1000, vec![1u8, 0, 0, 0, 9]);
        malformed.sequence = 7;
        write_message(&mut router, &malformed).await.unwrap();

        // (2) el frame de SINCRONIZACIÓN para la conn 5, bien formado.
        write_message(&mut router, &data_frame(5, b"sync"))
            .await
            .unwrap();

        let got = rx.recv().await.expect("el rx-loop sigue despachando");
        assert_eq!(
            got.body, b"sync",
            "lo primero que llega a la conn 5 es el frame de sincronización"
        );

        // Con el sync YA observado, el silencio del router-side es un negativo acreditado.
        let nothing =
            tokio::time::timeout(Duration::from_millis(300), read_message(&mut router)).await;
        assert!(
            nothing.is_err(),
            "un 60798 con ConnId de 5 bytes NO debe producir respuesta, pero llegó: {nothing:?}"
        );

        drop(router);
        let _ = task.await;
    })
    .await
    .expect("T-3: el rx-loop no entregó el frame de sincronización dentro del presupuesto");
}
