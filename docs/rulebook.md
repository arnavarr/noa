# Rulebook de `noa-sdk` (B1)

> Reglas de traducción/convención aprendidas de **este repo**, con origen trazable. No
> es un catálogo de estilo general: cada entrada nace de un hallazgo real de una
> rebanada y se falsa con una mutación concreta.
>
> Generado a mano por el DRIVER al adjudicar (§3.2). Un worker PROPONE una regla nueva
> vía `rulebook_proposals` en su retorno; no edita este fichero directamente.

## Sedes (puntero, no se copia)

- **Política cripto/build (D5):** `noa-sdk/CLAUDE.md` §«Política cripto/build». No se
  reescribe aquí **ni en resumen**: un resumen es una segunda sede y deriva en silencio
  (medido — el que había perdido un conyunto de la condición y quedaba más permisivo que
  la sede).
- **Dirección de las desviaciones (under-permit sí / over-permit jamás):** fila
  correspondiente de la tabla OVERRIDES de `.claude/skills/noa-next-slice/SKILL.md`.
- **Reglas de FAMILIA (RB-1, RB-2, …):** viven en
  `~/.claude/skills/slice-loop-mechanics/references/rulebook.md` y las pega el DRIVER en
  cada handoff; este fichero no las repite. Numeración `RB-SDK-NN` (no `RB-NN`)
  precisamente para no colisionar con las `RB-n` de familia.
- **Quién escribe:** el DRIVER. Un worker propone en `rulebook_proposals` del retorno;
  no edita este fichero.

## Las reglas

### RB-SDK-01: Un literal de error que cruza la frontera observable se copia BYTE-EXACTO del oráculo.

Si el original devuelve un `errors.New("…")` que el llamante puede leer (o que otro punto compara por texto), el port usa ese literal exacto y su doc-comment cita `fichero:línea` del pin. No se «mejora» la redacción ni se traduce.
*Alcance:* `src/edge/**` y cualquier error que viaje al llamante o se compare por string.
*Ejemplo:* `#[error("connection closed for writes")]` en `src/edge/error.rs:169`, espejo literal de C1.
*Origen:* DV-11-SC, 2026-07-23 (`docs/superpowers/specs/2026-07-23-dv11-sc-stateclosed-write-abort-design.md:165`).
*Se falsa:* cambiar el literal a `"connection closed for write"` ⇒ el test del discriminante cae.

### RB-SDK-02: Un bug del oráculo se porta INERTE y NOMBRADO; arreglarlo es otra decisión.

Cuando el original tiene un defecto sin efecto observable, el port lo replica de forma que el efecto coincida (no que «funcione mejor»), lo nombra como desviación y deja el arreglo como decisión aparte.
*Alcance:* todo el port.
*Ejemplo:* la evicción de `refreshSessions()` es un NO-OP por clave mal tecleada (C4+C5 contra C6+C7); se portó inerte y el arreglo quedó nombrado en `docs/superpowers/specs/2026-07-10-dial-sessions-d2-refresh-sessions-design.md:170-172` y `:267`.
*Origen:* opción D2, 2026-07-10 (`docs/superpowers/specs/2026-07-10-dial-sessions-d2-refresh-sessions-design.md:267`).
*Se falsa:* «arreglar» la evicción ⇒ el port evicta donde el oráculo no evicta, sin que ningún test del oráculo lo pida.

### RB-SDK-03: Con dos variantes del oráculo y defaults distintos, se pinea el de la variante que modela NUESTRA API.

No se elige el default «razonable» ni el de la función más famosa: se elige el de la función cuyo contrato espejamos, y el spec cita las DOS líneas para dejar constancia de la que se descartó.
*Alcance:* timeouts, reintentos y cualquier default numérico.
*Ejemplo:* `DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15)` en `src/edge/conn/mod.rs:40`: `connect()` espeja `DialContextWithOptions` ⇒ **15 s** (C3), no los 5 s de `DialContext` (C2).
*Origen:* `docs/superpowers/specs/2026-06-18-edge-connect-timeout-design.md:126-127`.
*Se falsa:* poner 5 s ⇒ el test del default cae con el deadline observable.

### RB-SDK-04: La observabilidad del port NUNCA emite el secreto, aunque el oráculo sí lo emita.

Los logs emiten identificadores y el envelope de estado del controller; el token, el JWT y el material de clave no se emiten en ningún nivel, ni siquiera `trace`.
*Alcance:* todo `tracing::` del crate.
*Ejemplo:* `src/edge/client/sessions.rs:416-425` (el log del probe de `refresh_session`, «…never the token»), pineado por el assert de `src/edge/client/tests_sessions_probe.rs:355-358` (`refresh_recache_logs_and_never_logs_token`, fn en `:321`, que SÍ ejercita `refresh_session`; su mensaje dice «including by the D1 probe log»). ⚠ El falsador debe ejercitar la FUNCIÓN que contiene el Ejemplo: la corrección anterior citaba `src/edge/client/tests_sessions.rs:205-208`, que solo llama `cache_dial_session` — una cita viva-pero-FALSA en el eje función.
*Origen:* opción 3 (observabilidad del caché de dial-sessions), 2026-07-10 (`docs/superpowers/specs/2026-07-10-dial-sessions-observability-design.md:225-226`).
*Se falsa:* añadir el token al log del probe ⇒ el assert de `src/edge/client/tests_sessions_probe.rs:355-358` cae.

### RB-SDK-05: Todo `#[ignore]` lleva razón que NOMBRA el recurso externo que falta.

Un `#[ignore]` desnudo es un gate pendiente indistinguible de un gate por diseño.
*Alcance:* `src/**` y `tests/**`.
*Ejemplo:* `#[ignore = "requires a live OIDC-capable controller + online router + bindsvc + 2 JWTs; OIDC-2; pre-flight: scripts/rig-fixtures.sh"]` en `src/edge/bind/tests_live.rs:21`. Medición de hoy (2026-07-28): **56 atributos `#[ignore]`, 56 con razón, 0 desnudos** (`git ls-files 'src/*.rs' 'tests/*.rs' | xargs grep -cE '^[[:space:]]*#\[ignore'` = 9 en `src/` + 47 en `tests/`; el patrón desnudo `^[[:space:]]*#\[ignore\][[:space:]]*$` da 0 ficheros).
*Origen:* rebanada noa-sdk#3, 2026-07-28: sella la convención acumulada de los arcos live (`docs/superpowers/specs/2026-07-28-estado-determinista-design.md` §3.3, con la medición de arriba); es **lo que hace discriminante la señal (b)** de `scripts/next-candidates.sh`.
*Se falsa:* añadir un `#[ignore]` desnudo ⇒ `next-candidates.sh --cola` lo emite como `P2`.

### RB-SDK-06: La asimetría de visibilidad entre gemelos se decide por CALL-SITES medidos, no por simetría estética.

Dos módulos gemelos pueden tener visibilidades distintas para el mismo ítem: la correcta es la mínima que compila con sus importadores REALES. Alinearlas «por consistencia» es over-permit o build-break.
**Ampliada** (l3-listener-count-gate, paso 4, 2026-08-12): la regla cubre TODO lo que se justifique por consumidores, no solo la visibilidad — **el comentario de una supresión de lint (`#[allow(dead_code)]` y familia) que nombra a un consumidor futuro es una CITA al oráculo y se deriva del censo MEDIDO de call-sites por símbolo** (grep del pin), jamás se copia del ítem vecino suprimido en la misma tanda. Medido: dos `allow` gemelos con el mismo comentario; en uno el consumidor era real (`needsMoreListeners` ← 3 call-sites) y en el otro FALSO (`getUsableRouterCount` ← solo `sessionRefreshed`, cluster L2): compilar, tests y clippy salen verdes con la cita falsa; solo el censo destino-a-destino la caza. *Se falsa:* re-introducir un comentario de consumidor copiado sin censo ⇒ el grep del símbolo en el pin no contiene al nombrado.
**Ampliada 2×** (l3-listener-attempts, paso 4, 2026-08-13): (i) **una supresión de lint de MÓDULO
apaga el detector de TODA su superficie** ⇒ se acompaña del cardinal MEDIDO de esa superficie, del
comando de una línea que lo re-mide y del consumidor con su rebanada de retirada (censo 2026-08-13
de `attempts.rs`: 12 `pub(super)` + 2 privados = 14 ítems;
`grep -c 'pub(super)' src/edge/listener_manager/attempts.rs` = 12; fila T-8 de §12 del spec del
ledger); (ii) **el censo de consumidores de un símbolo `pub` incluye los crates DEPENDIENTES POR
PATH** (`noa-router`, `noa-router/Cargo.toml`): `publish = false` NO implica cero consumidores
externos, y el gate del movimiento de un troceo amplía su `git grep -nw <símbolo>` a esos
dependientes (fila T-9: censo sobre 192 ficheros `.rs` de los dos hermanos = 0 hits, control
positivo 8, control imposible 0). *Se falsa:* (i) un allow de módulo nuevo sin cardinal+comando ⇒
el grep del censo no aparece en su comentario ni en el spec; (ii) declarar «0 consumidores» desde
`publish = false` sin grepear a los hermanos ⇒ el censo de T-9 lo desmiente.
**Ampliada 3.ª** (l3-listener-loop-scan, corrección del paso 4, 2026-08-21): **el instrumento de
re-medida de una supresión no puede ser un flag que ignore TODAS las supresiones** — `--force-warn
<lint>` mide la ceguera del CRATE, no la atribución a UN `allow` concreto; el único procedimiento
que atribuye es QUITAR ese allow y correr el lint ordinario, con recompilación forzada delante
(`touch src/lib.rs`: la caché de clippy responde una re-invocación idéntica con salida VACÍA, y un
censo sobre ella mide la nada). Y **un ítem bajo `allow` se siembra como RAÍZ VIVA del análisis de
dead-code** ⇒ AÑADIR un allow cambia la superficie que los allow PREEXISTENTES silencian: toda tanda
que añada uno re-mide los preexistentes y actualiza su cardinal. Medido: el allow de `mod registry;`
SOBRABA (0 diagnósticos al retirarlo) y el de `mod attempts;` silenciaba **2** ítems, no los
«5 diagnostics / 14 items» de su comentario — la deriva la causaron los allow NUEVOS de la misma
rebanada. *Se falsa:* un comentario de allow nuevo que prescriba `--force-warn` como re-medida ⇒ el
grep de `force-warn` en comentarios de `#[allow(dead_code)]` bajo `src/` da hit fuera de los
registros fechados. **(Falsador de la 2.ª mitad, añadido en s18 — cada mitad con el suyo:** la
re-medida de los preexistentes la EJECUTA la tanda que añade la supresión y la publica como
TABLA en su retorno (supresión → medido → declarado → veredicto); si una sede de corrección cae
fuera del ámbito cerrado de la rebanada, entra como excepción ADJUDICADA en la tabla de ficheros
del spec — molde: la fila F-11 de qw-dg1-conninspect. *Se falsa:* una tanda que añada una
supresión sin esa tabla en el retorno ⇒ la deriva de un cardinal vecino queda sin detector,
que es exactamente lo MEDIDO el 2026-08-22: `needs_more_listeners` declaraba vivo lo que
silenciaba 0.)**
**Ampliada 4.ª** (apertura del arco qw-fidelidad, brazo A, 2026-08-21): **`#[expect(<lint>)]` NO
sustituye a `#[allow(<lint>)]` cuando el fichero se compila en VARIAS configuraciones** — la
expectativa se evalúa POR COMPILACIÓN, y un ítem muerto en `lib` pero vivo en `lib test` da
`unfulfilled_lint_expectation` y tumba un gate con `-D warnings`. La elección se MIDE ejecutando el
gate con cada forma, jamás se hereda de la sugerencia del compilador (que propone `expect` primero).
Medido: `#[expect(dead_code)]` sobre una variante muerta en `lib` y construida por un test ⇒
`error: this lint expectation is unfulfilled` en `lib test`; `#[allow]` pasa las dos. *Se falsa:* un
`#[expect]` nuevo sobre un ítem cuya vitalidad dependa de `cfg(test)`/features ⇒ el gate
`--all-targets -D warnings` sale rojo en la cfg donde el ítem vive.
**Ampliada 5.ª** (qw-dg1-conninspect, paso 4 E-6/L-FR-4 + árbitro y D4sp, 2026-08-22; dos
caras del MISMO error — decidir por el token y no por el alcance): (i) **la visibilidad se mide
por ALCANCE EFECTIVO** — `visibilidad_real = modificador × cadena de mod × re-exports` — nunca
por el keyword: un `pub` dentro de un `mod` privado sin re-export es inalcanzable desde otro
crate POR CONSTRUCCIÓN, y justificar un `pub` por ANALOGÍA con otro símbolo exige medir la RUTA
del ejemplar y la del nuevo (medido: `CT_BIND` era alcanzable por el `pub use` de su `mod.rs`,
no por su `pub`; las 3 constantes de `inspect.rs` no tenían re-export y su censo 8b era teatro
⇒ bajadas a `pub(super)`). *Se falsa:* declarar un `pub` nuevo «alineado con X» donde X solo es
alcanzable por re-export y el nuevo no lo tiene ⇒ compila y clippy calla, pero el alcance real
difiere del que la justificación afirma. (ii) **un censo de consumidores EXTERNOS en un hermano
path-dep decide por RESOLUCIÓN, jamás por NOMBRE**: los 3 repos noa portan el MISMO oráculo y
definen los mismos identificadores, así que `git grep -nw <S>` da falso positivo GARANTIZADO
(medido: noa-router define los 5 símbolos censados). Dos etapas: el grep por nombre es el CENSO
de lo mirado; el veredicto son los hits que llegan por ruta `noa_sdk::` (con control positivo
sobre un símbolo que el vecino SÍ consume, e imposible=0). ⚠ `\b` NO existe en el ERE de git
grep y produce un detector MUERTO (medido: 0 hits sobre `EdgeClient`, que sí se consume): la
forma es `-w`. *Se falsa:* un censo nuevo por nombre desnudo ⇒ 5/5 hits que son definiciones
propias del vecino, rojo falso; o censar un símbolo inalcanzable ⇒ verde vacuo.
*Alcance:* troceos y refactors de visibilidad (`src/tunnel/udp/` ↔ `src/tunnel/intercept/udp/`, y cualquier par futuro).
*Ejemplo:* `create_vconn` es `pub(super)` en el gemelo no-intercept (`src/tunnel/udp/vconn.rs:34`; lo importan módulos-hermano de test) y privado en el gemelo intercept (`src/tunnel/intercept/udp/vconn.rs:120`, sin importador).
*Origen:* `F6-UDP-TWIN-VIS`, WON'T-FIX **medido** (`docs/superpowers/specs/2026-07-17-f6-deuda-menor-cierre-design.md:16-24` — la frase load-bearing «Ningún hermano los importa» vive en `:24` — y la tabla de `:112`).
*Se falsa:* subir la visibilidad del gemelo privado sin un call-site nuevo ⇒ over-permit sin causa.

### RB-SDK-07: El identificador COMPLETO resuelve; el pelado solo se imprime.

Un script que pela un prefijo (`refs/remotes/origin/…`) y re-resuelve el nombre pelado mide otra cosa (o nada) según qué copias locales existan: `git rev-parse` no busca en `refs/remotes/*/<n>`. El SHA y el refname completo viajan juntos de la enumeración al diff; el nombre corto existe solo para el `<sujeto>` impreso.
*Alcance:* `scripts/*.sh` (cola y medición).
*Ejemplo:* `scripts/next-candidates.sh` enumera con `git for-each-ref --format='%(objectname)%09%(refname)'` y diffea por SHA; la versión que pelaba-y-resolvía dejó P1 MUERTA en un clon en frío (`--siguiente` devolvía un P3 con exit 0).
*Origen:* paso 4 de la rebanada noa-sdk#3 (hallazgo H-A, 4 lentes + 3 escépticos unánimes), 2026-07-29 (`docs/superpowers/specs/2026-07-28-estado-determinista-design.md` §5.2, bloque «2ª corrección»).
*Se falsa:* re-introducir un `git rev-parse` de nombre pelado ⇒ G9 (smoke de clon frío, §6 del spec) sale rojo: P3 en vez de P1.

### RB-SDK-08: El doc de un dato que una etapa previa NORMALIZA documenta la forma POST-normalización.

Todo tipo público, campo o callback que reciba un valor que el pipeline de ingesta reescribe documenta la forma que el consumidor VERÁ, con puntero a la etapa dueña de la reescritura; un ejemplo con la forma pre-normalización es el que el lector copia, y su filtro rechaza todo en silencio (under-report sin ningún rojo).
*Alcance:* docs de tipos/campos/callbacks públicos cuyo valor atraviesa una normalización.
*Ejemplo:* `EdgeRouterUrlFilter` (`src/edge/router_filter.rs`) documentaba `tls://host:port` mientras las 3 rutas de ingesta sanitizan `://`→`:` antes de todo consumidor (`src/edge/client/sessions.rs:103/:157/:204`); corregido en el fix del paso 4 de l3-listener-count-gate (2026-08-12), junto con el doc del setter (`src/edge/client/pool.rs`).
*Origen:* hallazgo F12 (lente reforzada + 3 escépticos unánimes, votos 3/3 CONFIRMADO), 2026-08-12.
*Se falsa:* documentar la forma pre-sanitize en un tipo consumidor nuevo ⇒ el grep de `tls://` en docs de tipos públicos (fuera de las etapas de ingesta, sus tests y los registros fechados) da hit; el residuo consciente declarado (las constantes de test de `router_filter.rs:35-36`) está exento y NOMBRADO.

### RB-SDK-09: la mutación de UN conjunto de un predicado COMPUESTO exige un vector que satisfaga los DEMÁS conjuntos.

Toda fila de censo que mute un conjunto de una conjunción (`A && B`) declara, junto a la mutación, el VECTOR de fixture que hace verdaderos los otros conjuntos; el vector se elige RESOLVIENDO el predicado entero, no leyendo el conjunto aislado. Para una mutación de frontera (`<=N` → `<=N+1`), el conjunto de valores cuya admisión CAMBIA es computable (un solo entero para desplazamiento 1): se computa y se comprueba que ESE valor satisface las demás cláusulas — si no, la fila es una ALARMA por inalcanzabilidad, no un falsador; y la conclusión «no hay hueco» NO se sigue: se re-vectoriza (quitar el conjunto entero, o mutar el VALOR de la constante, que compila sin orfanar) y solo el mutante superviviente o muerto decide.
*Alcance:* censos RAMA × mutación de los specs y breakers de este repo (predicados compuestos).
*Ejemplo:* el predicado de reflejo `(k & 0x80) != 0 && k <= MAX_REFLECTED_HEADER`: la mutación `k<=255`→`k<=256` es NO-OP (256&0x80==0, el único entero afectado ya falla la máscara); quitar el techo ENTERO o subir el VALOR de la constante sobrevive a los 23 tests del fixture {127,128,255,256,-1,-129} — y la clase ciega son los header ids REALES del protocolo (1000/1022: bit 7 y >255), con dirección over-permit (el reflejo sobrescribiría el ConnType que el peer usa para purgar terminadores).
*Origen:* apertura del arco qw-fidelidad, 2026-08-21 — MEDIDO 2× por brazos independientes (M4.5 NO-OP en ambos; M4.5b superviviente en A) + el mutante limpio del árbitro; ni el spec-pass ni su gate decorrelado lo vieron.
*Se falsa:* una fila nueva de censo que mute una frontera AND-eada sin declarar su vector ⇒ ejecutar la mutación con el fixture existente la deja VERDE (superviviente no declarado).
**Ampliada** (qw-dg1-conninspect, fila M-13 + hallazgo E-2 y árbitro L-FR-1, 2026-08-22 — el
mismo enunciado por el eje del ORDEN): **una desviación de DESEMPATE entre dos lookups
(«consulta A, si no B») es NO-OP bajo cualquier fixture que pueble UNO solo de los dos
conjuntos**: su falsador exige el VECTOR DE COLISIÓN (la misma clave en AMBOS), y si el vector
es construible la fila NO puede cerrarse como ALARMA. **Y el vector de colisión se AÑADE (test
propio), nunca SUSTITUYE al vector ordinario**: re-apuntar el único test que observa el estado
alcanzable BORRA su falsador anterior en VERDE (RB-5-ampliada; medido: con la colisión metida
en T-2, el mutante «Dial solo si está en AMBOS mapas» sobrevivía a los 709 — T-14 con el id
solo en `conns` lo mata). Un test cuya respuesta va a un write muerto (`DeadWrite`/
`BlackHoleWrite`) NO cuenta como observador. *Se falsa:* cerrar como ALARMA una fila de
desempate con vector construible, o re-vectorizar el test canónico ⇒ el mutante de conjunción
sobrevive a la suite entera.

**Ampliada** (qw-getnextid-clamp, paso 4 + árbitro L-4/escépticos 3/3, 2026-08-23): **el eje del ORDEN
cubre también las cadenas `else if` de predicados INDEPENDIENTES** (no solo el desempate entre dos
lookups): el orden de dos brazos solo es observable en un vector que instancie la CONJUNCIÓN de sus
dos condiciones, y un corpus que cubra cada brazo POR SEPARADO deja el orden SIN falsador aunque
todas las ramas tengan el suyo. Si el corpus es un golden CERRADO (celdas capturadas), el vector de
conjunción se CAPTURA del oráculo como celda nueva, jamás se teclea. Medido: la «mutación asesina»
de T-1 (invertir skip-en-uso y rebobinado) era VACUA sobre las 12 celdas; el ÚNICO separador es el
candidato `u32::MAX` (en-uso ∧ fuera-de-rango con sucesor en rango): oráculo 0, invertido 1 —
capturado como C-13. *Se falsa:* una cadena `else if` nueva cuyo censo no tenga fila de ORDEN con
vector de conjunción ⇒ intercambiar los brazos deja la suite VERDE.

### RB-SDK-10: toda espera CORRELADA de un arnés request/reply va acotada por timeout, aunque el camino feliz nunca lo necesite.

En un arnés duplex/rx-loop, un test que espera una respuesta correlada (`read_message`, `oneshot::Receiver`, `rx.recv()`) sin timeout no FALLA bajo una mutación de la clase «nunca responde»: CUELGA el proceso de test entero y vuelve impracticable el censo de mutaciones. Forma preferida (medida como más robusta): envolver el CUERPO entero del test en `tokio::time::timeout(5s, …)` — acotar cada `await` por separado deja fuera el teardown (`task.await`), que cuelga igual si el rx-loop no sale por EOF.
*Alcance:* `src/**` tests sobre `tokio::io::duplex` o canales de correlación request/reply.
*Origen:* apertura del arco qw-fidelidad, 2026-08-21: el brazo B midió DOS cuelgues >120 s (M1.1, M1.4) y añadió timeouts a mitad de censo; el brazo A no los sufrió porque envolvía el cuerpo entero desde el principio — convergencia independiente en 5 s.
*Se falsa:* un test nuevo del arnés con un `await` correlado sin timeout ⇒ la mutación «borrar la guarda del respondedor» lo cuelga en vez de ponerlo rojo.
**Ampliada** (qw-dg1-conninspect, defecto E-5, 2026-08-22): **un CUANTIFICADOR de una fila de
cumplimiento («en los N tests», «todos») se escribe con el conteo de los que caen bajo el
ALCANCE de la regla, MEDIDO en el artefacto ENTREGADO, y los excluidos se NOMBRAN**: un
universal heredado del spec-time se vuelve falso en cuanto la implementación exceptúa
legítimamente a un miembro (medido: «los 13 tests» con timeout cuando T-10/T-13 son `#[test]`
síncronos fuera del ámbito — la falsedad aterrizó en la fila de cumplimiento de ESTA regla).
*Se falsa:* contar en el fichero entregado los ítems bajo el alcance y compararlos con el N de
la fila ⇒ difieren y no hay clase exenta nombrada.
**Ampliada 2×** (qw-getnextid-clamp 2b, breaker, 2026-08-23): (i) **el alcance incluye
`tunnel::host`**: todo test que ejercite `complete_success`/`complete_failed` por esa ruta lleva
techo de cuerpo entero — hoy 5 no lo llevan (tests_fixed/tests_forward/tests_source_addr) y
cualquier rojo de esa ruta es un CUELGUE, no una firma, lo que vuelve ilegible a todo falsador que
los toque (medido: F-l colgó el universo pleno 3×, 1800/1800/480 s; F-p dio 5 TIMEOUT/0 FAILED con
el instrumento por-test). (ii) **el techo del ARNÉS debe SUPERAR estrictamente al techo interior
del sujeto**, o el `Elapsed` del arnés ENSOMBRECE los asserts (medido: T-11 con arnés a 5 s y
sujeto a 5 s ⇒ FAILED por `Elapsed(())`; a 8 s el MISMO código pasa). *Se falsa:* (i) un test
nuevo de `tunnel::host` sobre ese camino sin techo ⇒ la mutación de su rama cuelga; (ii) un arnés
nuevo con techo == techo del sujeto ⇒ el falsador muere con la firma equivocada.

### RB-SDK-12: al NACER una variante de error, el censo de `# Errors` cubre la cadena de propagación COMPLETA y se cruza con la lista de ámbito.

El gate de ámbito compara FICHEROS, no contenidos: que un fichero esté en la lista cerrada no
ORDENA el cambio que la rebanada le debe. Toda variante nueva de `EdgeError` (o cambio del conjunto
de errores que una función puede devolver) entra con el censo de los bloques `# Errors` de TODAS
las funciones `pub`/`pub(crate)` de su cadena de propagación hasta la frontera pública, publicado
con comando+salida, y cada bloque hallado se nombra EXPLÍCITAMENTE en la columna «Contenido» de su
fila de ámbito (o se declara por qué no aplica).
*Alcance:* specs y pases de este repo que toquen `EdgeError` o firmas `Result`.
*Origen:* qw-getnextid-clamp, 2.º re-gate decorrelado (B2) + fix-2, 2026-08-23: el censo de
propagación de `AcceptStartFailed` afirmaba «TRES funciones, TRES bloques `# Errors`» e hizo nacer
F-15 (`binding.rs`), pero la fila F-2 no prescribía el de `accept_next` (`channel.rs:530-532`) ⇒ un
2b conforme lo dejaba incompleto con el gate de ámbito VERDE (el fichero ya estaba en la lista por
otras razones).
*Se falsa:* añadir una variante a `EdgeError` sin el censo ⇒ el `# Errors` de algún propagador
queda incompleto y ningún gate lo caza (verde por construcción).

### RB-SDK-11: la REPRODUCIBILIDAD de un golden se MIDE (N≥3 ejecuciones) antes de pinear su digest; si el oráculo no es determinista, doble digest.

Si el generador da digests distintos entre ejecuciones (recorrido de mapa, orden de iteración, timestamps del oráculo), un gate que exija re-derivación byte a byte sale ROJO POR CONSTRUCCIÓN en la sesión siguiente y su rojo no distingue «el golden cambió» de «el oráculo no es determinista». El golden se parte en (a) un PLANO CANÓNICO reproducible cuyo digest SÍ gatea la re-derivación (comando de canonicalización publicado), y (b) el residuo no determinista CONGELADO como muestra, verificado por el digest del FICHERO commiteado; el spec declara AMBOS digests, el PLANO de equivalencia y qué queda cubierto SOLO por la captura congelada. El test del port consume el residuo por DECODIFICACIÓN (acepta cualquier forma), nunca exigiendo emitirla.
*Alcance:* goldens capturados de oráculo ejecutable en este repo.
*Ejemplo:* `channel.marshalHeaders` (channel v4.3.9 `message.go:635-653`) itera un `map[int32][]byte`: 5 ejecuciones del generador ⇒ 4 sha256 distintos del fichero, con el plano canónico idéntico en 4 derivaciones. El spec de qw-dg1-conninspect pina los dos digests y declara (D13) que las `wire_v2_forms` las cubre solo la captura.
*Origen:* qw-dg1-conninspect 2a real, 2026-08-21 (candidata del spec-pass, adjudicada por el driver). Sin la medición, el gate de 2b habría muerto en su paso 1.
*Se falsa:* pinear un digest de golden sin la medición de N ejecuciones ⇒ la re-derivación de la sesión siguiente sale roja con el oráculo y el port SANOS.
**Ampliada** (qw-wire-header-len paso 1, 2026-08-23): las N≥3 corridas se ESPACIAN por encima de la GRANULARIDAD de la fuente no determinista cuando esa fuente es un reloj. Medido: dos corridas back-to-back del stream FUNDIDO (stderr incluido) dieron el MISMO sha256 porque el timestamp de `pfxlog` tiene granularidad de SEGUNDO — un «N=2 seguidas» habría «probado» determinismo en falso; con las corridas ESPACIADAS >1 s el stream fundido da 3 digests distintos (⇒ no se pinea, se asserta el conteo) mientras el plano canónico (stdout puro) da el mismo en 5/5 (⇒ se pinea). *Se falsa:* medir la reproducibilidad con N corridas SEGUIDAS bajo una fuente de granularidad de segundo ⇒ falso determinismo (mismo digest por colisión de timestamp, no por reproducibilidad).
