# M3-UDP-e2e runbook — intercept UDP round-trip host→overlay (live)

> **Qué valida:** la aceptación de **M3-UDP** (el primer hito e2e del datapath UDP del arco intercept).
> Un DATAGRAMA UDP REAL del SO atraviesa el utun → la surface UDP de la pila netstack-smoltcp
> (`InterceptStack::new_with_udp`/`recv_from`) → el **overlay ziti** → el host del servicio (echo) → y
> vuelve. Cierra la mitad LIVE de M3-UDP. **M3-UDP-stack** (`03c5d2e`) + **M3-UDP-handler** (`57a3633`),
> ya mergeados, entregaron la surface UDP + el relay driver-validables; este runbook ejecuta la prueba en
> vivo que se ejecuta a mano (requiere **root** para el utun + el overlay).
>
> **Cableado bajo prueba:** `tests/intercept_m3_udp.rs` (test root-gated) → `run_udp_intercept`
> (`src/tunnel/intercept/udp/`) sobre `InterceptStack::new_with_udp` (`src/tunnel/intercept/stack/`).
> Emisor de `AppData`: `intercept_udp_appdata` = `build_app_data("udp", …)` (espejo de `GetAppInfo("udp",
> …)` del interceptor Go). Spec `docs/superpowers/specs/2026-06-27-tunnel-intercept-design.md`.

## ⚠ RIG DISTINTA de M2b/(B-e2e) — LÉELO ANTES DE LEVANTAR NADA

La M2b-e2e-runbook dice "reusa exactamente la misma rig" (servicios `testsvc`/`testsvc-noenc` hosteados
por `er1` con un echo externo `ncat` en `:19009`, y UNA sola identidad que dial-ea). **M3-UDP-e2e usa una
rig DISTINTA** (espejo de T3 `enrol_then_proxy_udp_round_trip`, NO de M2b):

| | M2b/(B-e2e) (TCP) | **M3-UDP-e2e (este runbook)** |
|---|---|---|
| Servicios | `testsvc`/`testsvc-noenc` (`host.v1`, hosteados por `er1`) | **`bindsvc`/`bindsvc-enc`** (Bind+Dial `#all`) |
| Echo | **externo** `ncat --exec /bin/cat :19009` (TCP) | **IN-PROCESS** (el test hace `bind`+echo) — **SIN `ncat`** |
| Identidades | **1** (dial-ea el servicio router-hosteado) | **2** (host=`ZITI_EDGE_JWT` hace bind+echo; intercept=`ZITI_EDGE_JWT_DIALER` dial-ea) |

**No levantes el `ncat` de `:19009` para M3-UDP** — no se usa. `ncat -u` con `--keep-open --exec` es
notoriamente frágil (UDP no tiene conexiones que forkear por origen). El eco vive DENTRO del test (una
identidad host hace `bind` de `bindsvc`/`bindsvc-enc` y devuelve cada chunk), el mismo paradigma que T3
prueba que round-trippea UDP cifrado. Rig completo: `docs/edge-integration.md`.

## 0. Prerrequisitos

- **Root** (macOS/Linux): abrir un dispositivo utun requiere privilegios.
- La rig OrbStack viva (contenedores `ziti-ctrl` + `ziti-router-er1`). **Sin echo externo.**
- **DOS** OTT JWTs **FRESCOS** por feature-set (OTT es de un solo uso): uno para el host (bind+echo) y
  uno para la identidad de intercept (dial). `bindsvc`/`bindsvc-enc` tienen Bind+Dial `#all` → basta con
  identidades normales sin atributos.
- `cargo`/toolchain disponibles bajo `sudo` (ver §4 si `sudo cargo` no encuentra cargo).

## 1. Levantar la rig (SIN echo externo)

```sh
orb start                            # OrbStack (NO Docker Desktop)
docker start ziti-ctrl ziti-router-er1
# esperar el puerto 1280:
until bash -c '</dev/tcp/localhost/1280' 2>/dev/null; do sleep 0.5; done
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge list edge-routers          # er1 debe estar ONLINE=true

# write-probe de líder estable (RAFT puede flapear tras un arranque en frío → CLUSTER_NO_LEADER, que
# haría salir VACÍO el mint de §2): crear+borrar un config debe pasar.
ziti edge create config _probe intercept.v1 '{"addresses":["x.probe"],"portRanges":[{"low":1,"high":1}],"protocols":["udp"]}' \
  && ziti edge delete config _probe

# NO hay que levantar ningún echo backend: el eco de bindsvc/bindsvc-enc es IN-PROCESS (en el test).
# `bindsvc`/`bindsvc-enc` NO son host.v1 → er1 no los auto-hostea; solo la identidad host que hace bind
# sirve el terminator. (Contrasta con testsvc/testsvc-noenc de M2b, que SÍ necesitan el ncat + restart.)
# Fixtures del servicio: MÍDELAS, no las des por persistentes (han desaparecido 2 veces).
bash scripts/rig-fixtures.sh            # 0 verde / 1 falta algo / 3 no se pudo medir (≠ verde)
```

⚠ El `ziti edge list services | grep bindsvc` que había aquí tenía **dos** agujeros, los dos medidos:
`ziti edge list` **pagina a 10** y la rig ya va por 9 servicios, así que el grep empezaría a mentir en
cuanto crezca; y un servicio presente **no implica** que sus policies autoricen — al borrar el
servicio, el controller deja la policy viva con `serviceRoles` **VACÍO**. El script filtra por nombre
exacto y valida por roles resueltos.

Si falta algo, reponerlo es **un comando idempotente**, no arqueología:

```sh
bash scripts/rig-fixtures.sh --ensure   # crea lo ausente, repara la policy huérfana, re-mide
```

⚠ Por qué no vale re-pegar los `ziti edge create ...` de siempre: si la policy sobrevivió huérfana,
`create` choca con el **nombre duplicado** y falla; hay que `update`arla. Eso es exactamente lo que
convertía la reposición en una excavación. El script distingue los dos casos.

## 2. Mintear 2 JWTs frescos por feature-set (nombres ÚNICOS por corrida)

```sh
# default: host (bind+echo) + dialer (intercept). OTT es de un solo uso → un JWT por rol y por corrida.
ziti edge create identity "m3host-$(date +%s)"   -o /tmp/m3-host.jwt
ziti edge create identity "m3dialer-$(date +%s)" -o /tmp/m3-dialer.jwt
for f in /tmp/m3-host.jwt /tmp/m3-dialer.jwt; do
  [ "$(wc -c <"$f")" -gt 500 ] || echo "⚠ $f vacío/corto — re-mintea con otro nombre (presión RAFT)"
done

# SOLO si vas a correr también la variante graviola de §3, mintea 2 JWTs frescos MÁS:
ziti edge create identity "m3host-grav-$(date +%s)"   -o /tmp/m3-host-grav.jwt
ziti edge create identity "m3dialer-grav-$(date +%s)" -o /tmp/m3-dialer-grav.jwt
```

> `ziti edge create identity` FALLA (y NO escribe el .jwt) si el nombre ya existe → usa siempre nombres
> únicos. **Mintea los JWTs de uno en uno con un poco de espaciado, NO en un bucle apretado**: crear
> varias identidades back-to-back presiona RAFT y algún `.jwt` puede salir vacío en silencio (cazado
> 2026-06-27). Si un `.jwt` sale corto, re-mintea con otro nombre +
> `sleep 3`. Las identidades tienen Bind+Dial vía `#all` — no necesitan atributos.

## 3. Correr la prueba e2e (como root)

> **Usa `sudo env VAR=… VAR2=…`, NO `sudo VAR=…`.** En macOS stock (sudo con `env_reset`, sin `setenv`),
> un `sudo ZITI_EDGE_JWT=… cargo …` **NO entrega la variable** → el test panica en `env::var(...)` en la
> PRIMERA corrida. `sudo env VAR=val VAR2=val cmd` fija las variables DENTRO del proceso ya elevado (las
> pone `env`, no sudo) → siempre funciona. Aquí son DOS variables (`ZITI_EDGE_JWT` + `ZITI_EDGE_JWT_DIALER`).

```sh
# default (aws-lc-rs):
sudo env ZITI_EDGE_JWT=/tmp/m3-host.jwt ZITI_EDGE_JWT_DIALER=/tmp/m3-dialer.jwt \
  cargo test --features intercept --test intercept_m3_udp -- --ignored --nocapture

# graviola (firma el client-auth mTLS con el provider graviola — usa los 2 JWTs frescos graviola de §2):
sudo env ZITI_EDGE_JWT=/tmp/m3-host-grav.jwt ZITI_EDGE_JWT_DIALER=/tmp/m3-dialer-grav.jwt \
  cargo test --features intercept,graviola --test intercept_m3_udp -- --ignored --nocapture
```

> **Diagnóstico (importante en una sesión live escasa):** el test NO instala un subscriber de `tracing`,
> así que un dial FALLIDO al overlay o un datagrama perdido es SILENCIOSO → se manifiesta como `timeout
> recibiendo el eco del datagrama` tras ~20 s. Casi siempre es la **rig** (falta de terminator del host,
> JWT consumido/duplicado, líder RAFT inestable), NO el código de intercept → re-revisa §1/§2, no toques
> `src/tunnel/intercept`. **UDP es lossy**: en loopback/utun no debería perderse, pero si un run falla y
> el siguiente pasa sin cambios de código, sospecha de la rig, no del relay.
>
> **⚠ `target/` queda root-owned:** este `sudo cargo test` COMPILA como root. Si lo prefieres, usa §4
> como camino primario (compila como usuario con `--no-run`, solo el binario de test corre bajo `sudo
> env`) → evita los artefactos root-owned Y el problema del PATH de root. Si no, `sudo chown -R "$USER"
> target/` tras correr.

**Salida esperada (éxito):**

```
intercept-udp: utunN 10.99.0.1/24 -> resolver(intercept.v1 udp) -> 'bindsvc', cliente -> 10.99.0.2:53
intercept M3-UDP-e2e round-trip OK para 'bindsvc'
intercept-udp: utunM 10.99.1.1/24 -> resolver(intercept.v1 udp) -> 'bindsvc-enc', cliente -> 10.99.1.2:53
intercept M3-UDP-e2e round-trip OK para 'bindsvc-enc'
test m3_intercept_udp_round_trips_host_to_overlay ... ok
```

La prueba enrola DOS identidades (host + intercept), y por cada servicio abre un utun propio
(`10.99.0.0/24` plano, `10.99.1.0/24` cifrado), hace `bind`+echo in-process del servicio, corre
`run_udp_intercept`, hace `send_to` de un datagrama desde un `UdpSocket` real del SO a `10.99.<i>.2:53`,
y asegura que el payload vuelve EXACTO. El servicio cifrado ejercita además la partición cripto a través
del relay UDP del lado intercept.

> Cada `--features` set necesita sus **2 JWTs frescos propios** (los OTT del primero ya se consumieron).

## 4. Si `sudo cargo` no encuentra cargo (PATH de root)

Compila como usuario normal y corre el binario de test bajo `sudo env` (evita el PATH de root **Y** el
problema de las variables de entorno de §3):

```sh
cargo test --features intercept --test intercept_m3_udp --no-run
BIN=$(cargo test --features intercept --test intercept_m3_udp --no-run --message-format=json 2>/dev/null \
  | jq -r 'select(.profile.test==true and .target.name=="intercept_m3_udp") | .executable' | tail -1)
sudo env ZITI_EDGE_JWT=/tmp/m3-host.jwt ZITI_EDGE_JWT_DIALER=/tmp/m3-dialer.jwt "$BIN" --ignored --nocapture
```

> Para **graviola** repite la captura de `$BIN` con `--features intercept,graviola` (es OTRO ejecutable —
> distinto hash de features) y usa los 2 JWTs graviola.

## 5. De-risk ANTES de la corrida root (recomendado)

Antes de la corrida root, valida la rig UDP con el probe **NO-root** `enrol_then_proxy_udp_round_trip`
(T3, `tests/edge_integration.rs`) — mismo enrol→dial→router→echo→cripto para `bindsvc`/`bindsvc-enc`, pero
con un `UdpSocket` local en vez del utun (sin root). Si PASA, la rig UDP está probada e2e → cualquier
fallo del test root queda AISLADO a la capa utun/intercept (o a root), no a la rig. Es el MISMO patrón que
de-riskeó M2b-e2e con el probe TCP `enrol_then_proxy_tcp_round_trip`.

```sh
# 2 JWTs frescos EXTRA para el probe (no consume los del test root):
ziti edge create identity "t3host-$(date +%s)"   -o /tmp/t3-host.jwt
ziti edge create identity "t3dialer-$(date +%s)" -o /tmp/t3-dialer.jwt
ZITI_EDGE_JWT=/tmp/t3-host.jwt ZITI_EDGE_JWT_DIALER=/tmp/t3-dialer.jwt \
  cargo test --test edge_integration enrol_then_proxy_udp_round_trip -- --ignored --nocapture
# (variante cifrada: enrol_then_proxy_udp_encrypted_round_trip, otros 2 JWTs)
```

## 6. Tras un éxito en vivo

- Es la **aceptación de M3-UDP** (primer hito e2e del datapath UDP del intercept). Registra el resultado
  (default + graviola) en `HANDOFF.md` / `CLAUDE.md` como M3-UDP-e2e VALIDADO EN VIVO.
- **SIGUIENTE:** **M3-rutas** (instalación OS-level de las rutas del `intercept.v1` al utun; desbloquea el
  diferido `source_addr`) + **M3-DNS** (DNS embebido → desbloquea `dst_hostname`; **5ª FRONTERA
  differential**). El cableado del subcomando `noa intercept` para
  correr TCP (`accept`) y UDP (`recv_from`) CONCURRENTEMENTE (partir el `InterceptStack`) sigue DIFERIDO —
  ver la nota abajo.

## Diferido NOMBRADO — el subcomando `noa intercept` NO gana modo UDP en esta rebanada

El test llama a `run_udp_intercept` DIRECTAMENTE, así que no necesita el subcomando. **A propósito NO se
añadió un modo `--udp` al subcomando** en esta rebanada, porque re-introduciría el caso SIMÉTRICO de la
clase de liveness HIGH que la review de M3-UDP-stack ya cazó: bajo `new_with_udp` (`enable_tcp(true)` +
`enable_udp(true)`), `run_udp_intercept` drena UDP (`recv_from`) pero NUNCA hace `accept()` de TCP; si
tráfico TCP real llega a la subred interceptada, netstack crea sockets TCP que nadie acepta, y si el
backlog de accept aplica backpressure a la ingress COMPARTIDA (comportamiento aún **sin analizar**, a
diferencia del path del buffer UDP), atascaría también el datapath UDP. El cableado del subcomando para
UDP se DIFIERE a la rebanada de **stack-split combinado** (que drena AMBOS `accept` y `recv_from` → sin
atasco por construcción), donde la pregunta discriminante ("¿un listener TCP no drenado bajo `new_with_udp`
aplica backpressure a la ingress compartida?") se responde con el análisis netstack + un test determinista.
Para una validación manual interactiva en esta rebanada, usa el test `intercept_m3_udp.rs` (§3).

## Gotchas (de la memoria del rig)

- **OTT single-use**: un JWT por rol, por corrida y por feature-set; nombre de identidad único.
- **Minteo en ráfaga falla en silencio** (presión RAFT): mintea los JWTs de uno en uno con espaciado y
  verifica el tamaño (`>500` bytes); re-mintea con nombre nuevo + `sleep 3` si sale corto.
- **RAFT cold-start flap** (`ziti-ctrl` v2.0.0 corre HA): tras `Exited 137`, la elección de líder puede
  flapear → `CLUSTER_NO_LEADER`. Arreglo: `docker restart ziti-ctrl`, esperar, write-probe (§1), luego
  `docker restart ziti-router-er1`.
- **macOS no tiene `timeout`**: no envuelvas los comandos en `timeout`.
- **utun**: la prueba usa subredes `10.99.0.0/24` y `10.99.1.0/24`. Si chocan con una ruta existente en
  tu Mac, cámbialas (en el test: `Ipv4Addr::new(10, 99, idx, 1)`).
