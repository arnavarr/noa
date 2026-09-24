# M2b-e2e runbook — intercept TCP round-trip host→overlay (live)

> **Qué valida:** la aceptación de **M2** (el primer hito validable extremo-a-extremo del arco
> intercept). Un flujo TCP REAL del SO atraviesa el utun → la pila netstack-smoltcp → el **overlay
> ziti** → el host del servicio (echo) → y vuelve. Cierra la mitad LIVE de M2b. **M2b-pre** (ya
> mergeado, `4f9c68f`) entregó el emisor de `AppData` + el cableado driver-validable; este runbook
> ejecuta la prueba en vivo que se ejecuta a mano (requiere **root** para el utun + el overlay).
>
> **Cableado bajo prueba:** `tests/intercept_m2b.rs` (test root-gated) y/o el subcomando
> `noa intercept` (`src/main.rs`). Ambos llaman a `run_tcp_intercept`
> (`src/tunnel/intercept/tcp.rs`). Oráculo del emisor: tproxy `tproxy_linux.go:325-331` → `GetAppInfo`
> (spec `docs/superpowers/specs/2026-06-27-tunnel-intercept-design.md` §4.2.2).

La prueba **reusa exactamente la misma rig** que `enrol_then_proxy_tcp_round_trip` (servicios
`testsvc-noenc` plano + `testsvc` cifrado, hosteados por `er1` con el echo backend en `:19009`); la
única diferencia es que la fuente de los flujos es un **utun real** en vez de un `TcpListener`, así que
necesita **root**. Rig completo: `docs/edge-integration.md`.

## 0. Prerrequisitos

- **Root** (macOS/Linux): abrir un dispositivo utun requiere privilegios.
- La rig OrbStack viva (contenedores `ziti-ctrl` + `ziti-router-er1`).
- El **echo backend** en `:19009` (no persiste — hay que levantarlo a mano).
- Un **OTT JWT FRESCO** (OTT es de un solo uso; un enrol lo consume) para una identidad con Dial sobre
  `testsvc-noenc`/`testsvc` (la dial-policy `#all` de la rig ya lo cubre — basta una identidad normal).
- `cargo`/toolchain disponibles bajo `sudo` (ver §4 si `sudo cargo` no encuentra cargo).

## 1. Levantar la rig + el echo

```sh
orb start                            # OrbStack (NO Docker Desktop) — el runtime de contenedores de esta máquina
docker start ziti-ctrl ziti-router-er1
# esperar el puerto 1280:
until bash -c '</dev/tcp/localhost/1280' 2>/dev/null; do sleep 0.5; done
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge list edge-routers          # er1 debe estar ONLINE=true

# write-probe de líder estable (RAFT puede flapear tras un arranque en frío → CLUSTER_NO_LEADER, que
# haría salir VACÍO el mint de §2): crear+borrar un config debe pasar.
ziti edge create config _probe intercept.v1 '{"addresses":["x.probe"],"portRanges":[{"low":1,"high":1}],"protocols":["tcp"]}' \
  && ziti edge delete config _probe

# echo backend (en el HOST mac), maneja half-close vía /bin/cat:
pkill -f 'ncat.*19009' 2>/dev/null   # mata un ncat viejo (evita EADDRINUSE en re-runs)
ncat --listen --keep-open --exec /bin/cat 0.0.0.0 19009 &
# RE-REGISTRAR los terminators tras arrancar el echo:
docker restart ziti-router-er1
ziti edge list terminators           # deben aparecer testsvc y testsvc-noenc
```

Si `list terminators` no muestra los dos servicios, el dial dará `service ... has no terminators` →
re-revisa que el echo esté arriba ANTES del `docker restart ziti-router-er1`.

## 2. Mintear un JWT fresco (nombre ÚNICO por corrida)

```sh
# un JWT por feature-set (OTT es de un solo uso); nombre único por corrida:
ziti edge create identity "m2b-$(date +%s)" -o /tmp/m2b.jwt
[ "$(wc -c </tmp/m2b.jwt)" -gt 500 ] || echo "⚠ JWT vacío/corto — re-mintea con otro nombre (presión RAFT)"

# SOLO si vas a correr también la variante graviola de §3, mintea un 2º JWT fresco:
ziti edge create identity "m2b-grav-$(date +%s)" -o /tmp/m2b-grav.jwt
[ "$(wc -c </tmp/m2b-grav.jwt)" -gt 500 ] || echo "⚠ re-mintea el JWT graviola"
```

> `ziti edge create identity` FALLA (y NO escribe el .jwt) si el nombre ya existe → usa siempre un
> nombre único. Si el .jwt sale vacío en ráfaga, es presión RAFT: re-mintea con otro nombre + `sleep 3`.
> **Si el controller arrancó en frío**, haz primero el write-probe de líder de §1 (un `CLUSTER_NO_LEADER`
> hace que el mint salga vacío). La identidad tiene Dial sobre testsvc/testsvc-noenc vía la dial-policy
> `#all` de la rig — no necesita atributos.

## 3. Correr la prueba e2e (como root)

> **Usa `sudo env VAR=…`, NO `sudo VAR=…`.** En macOS stock (sudo con `env_reset`, sin `setenv`), un
> `sudo ZITI_EDGE_JWT=… cargo …` **NO entrega la variable** (sudo la rechaza con "you are not allowed
> to set the following environment variables" o la descarta en silencio) → el test panica en
> `env::var("ZITI_EDGE_JWT").expect(...)` en la PRIMERA corrida. `sudo env VAR=val cmd` fija la
> variable DENTRO del proceso ya elevado (la pone `env`, no sudo) → siempre funciona. (M1 corría
> `sudo cargo … --ignored` SIN variable, así que esta forma nunca se ejercitó antes — de ahí el aviso.)

```sh
# default (aws-lc-rs):
sudo env ZITI_EDGE_JWT=/tmp/m2b.jwt \
  cargo test --features intercept --test intercept_m2b -- --ignored --nocapture

# graviola (firma el client-auth mTLS con el provider graviola — usa el 2º JWT fresco de §2):
sudo env ZITI_EDGE_JWT=/tmp/m2b-grav.jwt \
  cargo test --features intercept,graviola --test intercept_m2b -- --ignored --nocapture
```

> **Diagnóstico (importante en una sesión live escasa):** el test/bin NO instala un subscriber de
> `tracing`, así que un dial FALLIDO al overlay es SILENCIOSO → se manifiesta como `timeout leyendo
> el eco` (o un `nc` colgado) tras ~20s. Casi siempre es **falta de terminators o de dial-policy**,
> NO el código de intercept → re-revisa §1 (`ziti edge list terminators` debe mostrar testsvc/
> testsvc-noenc), no toques `src/tunnel/intercept`.
>
> **⚠ `target/` queda root-owned:** este `sudo cargo test` COMPILA como root → deja artefactos
> root-owned en `target/`, así que un `cargo build` NORMAL posterior puede fallar con permission-denied
> (bites DESPUÉS del test, fácil de mal-atribuir). Remedio: `sudo chown -R "$USER" target/` tras correr.
> **Si lo prefieres, usa §4 como camino primario** (compila como usuario con `--no-run`, solo el binario
> de test corre bajo `sudo env`) → evita los artefactos root-owned Y el problema del PATH de root.

**Salida esperada (éxito):**

```
intercept: utunN 10.99.0.1/24 -> 'testsvc-noenc', cliente -> 10.99.0.2:80
intercept M2b-e2e round-trip OK para 'testsvc-noenc'
intercept: utunM 10.99.1.1/24 -> 'testsvc', cliente -> 10.99.1.2:80
intercept M2b-e2e round-trip OK para 'testsvc'
test m2b_intercept_tcp_round_trips_host_to_overlay ... ok
```

La prueba enrola UNA identidad, y por cada servicio abre un utun propio (`10.99.0.0/24` plano,
`10.99.1.0/24` cifrado), corre `run_tcp_intercept`, conecta un cliente real del SO a `10.99.<i>.2:80`,
y asegura que el payload vuelve EXACTO + que el half-close propaga (EOF). El servicio cifrado ejercita
además la partición cripto a través del `splice` del lado intercept.

> Cada `--features` set necesita su **propio JWT fresco** (el OTT del primero ya se consumió).

## 4. Si `sudo cargo` no encuentra cargo (PATH de root)

Compila como usuario normal y corre el binario de test bajo `sudo env` (evita el PATH de root **Y**
el problema de la variable de entorno de §3):

```sh
cargo test --features intercept --test intercept_m2b --no-run
BIN=$(cargo test --features intercept --test intercept_m2b --no-run --message-format=json 2>/dev/null \
  | jq -r 'select(.profile.test==true and .target.name=="intercept_m2b") | .executable' | tail -1)
sudo env ZITI_EDGE_JWT=/tmp/m2b.jwt "$BIN" --ignored --nocapture
```

> Para **graviola** repite la captura de `$BIN` con `--features intercept,graviola` (es OTRO
> ejecutable — distinto hash de features) y usa el 2º JWT. Si prefieres `cargo` directo bajo sudo,
> `sudo -E env "PATH=$PATH" ZITI_EDGE_JWT=/tmp/m2b.jwt cargo …` también fija la variable (el
> `ZITI_EDGE_JWT=…` lo aplica `env`, no sudo).

## 5. Alternativa manual: el subcomando `noa intercept`

Para una validación interactiva sin el arnés de test:

```sh
# construye el bin CON la feature intercept (SIN ella el arm `noa intercept` avisa y sale FAILURE):
cargo build --features intercept

# enrola una identidad (consume el JWT, escribe id.json) — usa el binario ya construido:
target/debug/noa enroll /tmp/m2b.jwt --out /tmp/id.json

# corre el interceptor como root: ya NO toma <service>. El resolver `intercept.v1` (slice B) elige el
# servicio por el DESTINO de cada flujo, leyendo los `intercept.v1` que el controller sirve a la
# identidad. Un destino que ningún servicio intercepta → el flujo se cierra limpio.
sudo target/debug/noa intercept 10.99.0.1/24 /tmp/id.json

# en OTRA terminal: conecta a una IP on-link que un `intercept.v1` visible intercepte; debe hacer eco:
nc 10.99.0.2 80
hola
hola          # <- eco de vuelta por host->overlay->host
```

> Para este modo manual la identidad debe ver un servicio con un `intercept.v1` cuyas `addresses`
> incluyan la subred del utun (p. ej. `10.99.0.0/24`, `protocols:["tcp"]`, `portRanges:[{80,80}]`).
> El test `intercept_m2b.rs` evita este requisito construyendo el `intercept.v1` EN el test (no toca la
> rig). El subcomando, en cambio, lee los configs del controller.

> ⚠ NO uses `cargo run -- enroll …` aquí: reconstruiría `target/debug/noa` SIN la feature → el
> `noa intercept` siguiente caería en el arm de fallback (`#[cfg(not(feature="intercept"))]`) y saldría.
> Construye una vez con `--features intercept` y usa ese binario para AMBOS pasos.

## 6. Tras un éxito en vivo

- Es la **aceptación de M2** (PRIMER hito e2e del intercept). Registra el resultado (default +
  graviola) en `HANDOFF.md` / `CLAUDE.md` como M2b-e2e VALIDADO EN VIVO.
- **(B-pre) HECHO:** el `service` HARDCODED ya está sustituido por el resolver `intercept.v1`
  (`src/tunnel/intercept/resolve/`, dst→servicio, reusa `parse_ip_or_cidr` + differential). Esta
  prueba (`intercept_m2b.rs`) ya construye un `intercept.v1` en el test y rutea por dst → es la
  **(B-e2e)**. Tras el verde live: M3 (UDP + rutas + DNS embebido, que desbloquea los diferidos
  `dst_hostname`/`source_addr`/`DialOptions.Identity`) + spike de escala.

## Gotchas (de la memoria del rig)

- **OTT single-use**: un JWT por corrida y por feature-set; nombre de identidad único.
- **RAFT cold-start flap** (`ziti-ctrl` v2.0.0 corre HA): tras `Exited 137`, la elección de líder puede
  flapear → `CLUSTER_NO_LEADER`/`COULD_NOT_VALIDATE` en escrituras. Arreglo: `docker restart ziti-ctrl`,
  esperar, write-probe (`ziti edge create config _p intercept.v1 '{...}'` → ok ⇒ líder), luego
  `docker restart ziti-router-er1`.
- **macOS no tiene `timeout`**: no envuelvas los comandos en `timeout`.
- **utun**: la prueba usa subredes `10.99.0.0/24` y `10.99.1.0/24`. Si chocan con una ruta existente en
  tu Mac, cámbialas (en el test: `Ipv4Addr::new(10, 99, idx, 1)`; en el subcomando: el arg `<utun-cidr>`).
