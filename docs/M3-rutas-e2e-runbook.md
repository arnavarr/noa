# M3-rutas-e2e runbook — aceptación LIVE de la instalación de rutas OS-level (intercept)

> **Qué valida:** la aceptación LIVE de **M3-rutas** (mergeado `282c9ba`): que
> `plan_routes`/[`InstalledRoutes`] (`src/tunnel/intercept/routes/snapshot.rs`) instalan una ruta **OS-level
> REAL** (`route add -interface utunN`) para un CIDR `intercept.v1` que cae FUERA de la subred on-link
> del utun, y que un flujo TCP que SOLO llega al device por esa ruta round-trippea
> utun→netstack→overlay→echo. M3-rutas (categoría-C, sin oráculo darwin exacto) ya entregó
> `plan_routes`/`InstalledRoutes` driver-validables (unit tests puros, sin root); este runbook ejecuta
> el `route add`/`route delete` REAL, que se ejecuta a mano (root).
>
> **Cableado bajo prueba:** `tests/intercept_m3_routes.rs` (test root-gated). Reusa la MISMA tubería
> que el subcomando `noa intercept` (`src/main.rs::run_intercept`, live desde `282c9ba`): snapshot de
> `intercept.v1` → `plan_routes` → `InstalledRoutes::install`. Oráculo: `ziti-tunnel-sdk-c`
> `netif_driver/darwin/utun.c:103-108` (semántica del `route add`, no los bytes darwin exactos — ver el
> doc de módulo de `routes/mod.rs`).

**Discriminador vs M2b-e2e:** M2b conecta a una IP **on-link** (el SO ya la rutea al utun sin ninguna
ruta explícita) → NO prueba nada sobre `plan_routes`/`InstalledRoutes`. Esta prueba conecta a un destino
**fuera** del on-link (dos CIDRs RFC 5737 TEST-NET: `203.0.113.0/24`/`198.51.100.0/24` — reservados para
documentación, nunca asignables a infraestructura real, así que no pueden solapar con el underlay de
OrbStack) y solo llega al device porque el test instaló una ruta interface-scoped real hacia él. Tres
asserts en el propio test hacen el mecanismo verificable (no asumido): el CIDR se planifica, la ruta se
instala de verdad (`routes.len() == 1`), y el destino está probadamente fuera del on-link.

**Rig: la MISMA de (B-e2e)/M2b-e2e, SIN CAMBIOS.** Reusa `testsvc-noenc`/`testsvc` (host.v1
router-hosteados, echo externo `ncat :19009`, 1 identidad) — a diferencia de M3-UDP-e2e, no hace falta
tocar el controller. Rig completo: `docs/edge-integration.md`.

## 0. Prerrequisitos

- **Root** (macOS/Linux): abrir un utun **Y** instalar/borrar una ruta OS-level (`PF_ROUTE`) requieren
  privilegios.
- La rig OrbStack viva (contenedores `ziti-ctrl` + `ziti-router-er1`).
- El **echo backend** en `:19009` (no persiste — hay que levantarlo a mano).
- Un **OTT JWT FRESCO** (uno solo; a diferencia de M3-UDP-e2e esta prueba usa UNA identidad, igual que
  M2b) para una identidad con Dial sobre `testsvc-noenc`/`testsvc` (la dial-policy `#all` de la rig ya
  lo cubre).
- `cargo`/toolchain disponibles bajo `sudo` (ver §4 si `sudo cargo` no encuentra cargo).

## 1. Levantar la rig + el echo

Idéntico a M2b-e2e (`docs/M2b-e2e-runbook.md` §1) — cópialo tal cual:

```sh
orb start                            # OrbStack (NO Docker Desktop)
docker start ziti-ctrl ziti-router-er1
until bash -c '</dev/tcp/localhost/1280' 2>/dev/null; do sleep 0.5; done
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge list edge-routers          # er1 debe estar ONLINE=true

# write-probe de líder estable (RAFT puede flapear tras un arranque en frío):
ziti edge create config _probe intercept.v1 '{"addresses":["x.probe"],"portRanges":[{"low":1,"high":1}],"protocols":["tcp"]}' \
  && ziti edge delete config _probe

# echo backend (en el HOST mac):
pkill -f 'ncat.*19009' 2>/dev/null
ncat --listen --keep-open --exec /bin/cat 0.0.0.0 19009 &
docker restart ziti-router-er1        # re-registra los terminators
ziti edge list terminators            # deben aparecer testsvc y testsvc-noenc
```

## 2. Mintear un JWT fresco (nombre único por corrida)

```sh
ziti edge create identity "m3rt-$(date +%s)" -o /tmp/m3rt.jwt
[ "$(wc -c </tmp/m3rt.jwt)" -gt 500 ] || echo "⚠ JWT vacío/corto — re-mintea con otro nombre"

# SOLO si vas a correr también graviola, mintea un 2º JWT fresco:
ziti edge create identity "m3rt-grav-$(date +%s)" -o /tmp/m3rt-grav.jwt
```

## 3. Correr la prueba e2e (como root)

> **Usa `sudo env VAR=…`, NO `sudo VAR=…`** (ver M2b-e2e-runbook §3 para el porqué exacto).

```sh
# default (aws-lc-rs):
sudo env ZITI_EDGE_JWT=/tmp/m3rt.jwt \
  cargo test --features intercept --test intercept_m3_routes -- --ignored --nocapture

# graviola:
sudo env ZITI_EDGE_JWT=/tmp/m3rt-grav.jwt \
  cargo test --features intercept,graviola --test intercept_m3_routes -- --ignored --nocapture
```

**Salida esperada (éxito):**

```
intercept-rutas: utunN 10.99.0.1/24 + ruta OS-level -> 203.0.113.0/24 -> resolver(intercept.v1) -> 'testsvc-noenc', cliente -> 203.0.113.2:80
intercept M3-rutas-e2e round-trip OK para 'testsvc-noenc' vía 203.0.113.0/24
intercept-rutas: utunM 10.99.1.1/24 + ruta OS-level -> 198.51.100.0/24 -> resolver(intercept.v1) -> 'testsvc', cliente -> 198.51.100.2:80
intercept M3-rutas-e2e round-trip OK para 'testsvc' vía 198.51.100.0/24
test m3_intercept_routes_round_trip_host_to_overlay ... ok
```

> **Diagnóstico:** un `panicked at ... 'el CIDR ruteado debe planificarse'` ANTES de abrir ninguna
> conexión indica que el guard self-DoS de `plan_routes` rehusó el CIDR (comprueba que
> `ziti edge login`/`cfg.zt_api` no apunten, por coincidencia, a una IP dentro de `203.0.113.0/24` o
> `198.51.100.0/24` — no debería ocurrir con la rig OrbStack estándar). Un `timeout conectando a través
> de la ruta instalada` sin ese panic previo apunta a lo mismo que en M2b: falta de terminators/
> dial-policy, no un defecto de `routes/` (revisa §1). El test no instala un subscriber de `tracing`,
> así que los `warn!` de `plan_routes`/`InstalledRoutes` no se ven — si sospechas del guard, añade
> `--nocapture` (ya incluido arriba) y revisa el `assert_eq!` de `planned`, es más rápido que activar
> logging.
>
> **⚠ `target/` queda root-owned** tras este `sudo cargo test` (compila como root) — igual que M2b,
> usa §4 como camino primario si te preocupa, o `sudo chown -R "$USER" target/` después.
>
> **Ruta huérfana tras un crash:** `InstalledRoutes::Drop` borra la ruta al salir limpio; en un crash
> (`kill -9`, panic en medio de la instalación) el utun también muere con el proceso y el kernel purga
> igualmente la ruta interface-scoped (comportamiento oracle-fiel, ver el doc de `routes/mod.rs`). Si por
> alguna razón persistiera, verifica con `netstat -rn -f inet | grep -E '203.0.113|198.51.100'` y bórrala
> a mano con `sudo route delete -net 203.0.113.0/24` (ajusta el CIDR).

## 4. Si `sudo cargo` no encuentra cargo (PATH de root)

```sh
cargo test --features intercept --test intercept_m3_routes --no-run
BIN=$(cargo test --features intercept --test intercept_m3_routes --no-run --message-format=json 2>/dev/null \
  | jq -r 'select(.profile.test==true and .target.name=="intercept_m3_routes") | .executable' | tail -1)
sudo env ZITI_EDGE_JWT=/tmp/m3rt.jwt "$BIN" --ignored --nocapture
```

> Para graviola repite con `--features intercept,graviola` (otro ejecutable) y el 2º JWT.

## 5. Alternativa manual: el subcomando `noa intercept`

El subcomando YA instala rutas OS-level automáticamente desde `282c9ba` — no hace falta nada especial,
basta con que el `intercept.v1` de la identidad anuncie un CIDR fuera de la subred del utun que abras:

```sh
cargo build --features intercept
target/debug/noa enroll /tmp/m3rt.jwt --out /tmp/id.json
sudo target/debug/noa intercept 10.99.0.1/24 /tmp/id.json
# la salida imprime cuántas rutas OS-level instaló (desde el slice combinado el subcomando corre
# también UDP + el DNS embebido; el formato incluye la dirección del DNS):
# "intercept: utunN 10.99.0.1/24 -> resolver intercept.v1 (N servicios, R rutas OS-level, DNS embebido en 10.99.0.2:53; ...)"
```

Si `R` (rutas OS-level) es 0 pero esperabas alguna, revisa que el `intercept.v1` de algún servicio
anuncie una CIDR fuera de `10.99.0.0/24` Y que no cubra la IP del controller (el guard self-DoS la
rehusaría con un `warn!`).

## 5b. Gate LIVE del ciclo de rutas VIVO (rebanada RUTAS OS: `RouteLifecycle`)

Valida que `noa intercept` instala/quita rutas **mid-run** cuando el controller añade/retira un
servicio de CIDR literal (svc-poll → `apply_event` → `RouteDelta` → `RouteLifecycle`, espejo de
`stop_intercept`→`delete_route` / `ziti_tunneler_intercept`→`add_route` con refcount `route.c`).

```sh
# 1. Arranca el intercept (root) con la rig viva y déjalo corriendo:
sudo target/debug/noa intercept 10.99.0.1/24 /tmp/id.json
# 2. En OTRA terminal, crea un servicio nuevo con un CIDR FUERA de 10.99.0.0/24 (sin tocar el runner):
ziti edge create config rt-live-intercept intercept.v1 \
  '{"protocols":["tcp"],"addresses":["203.0.113.0/24"],"portRanges":[{"low":19009,"high":19009}]}'
ziti edge create service rt-live --configs rt-live-intercept,noenc-host -a rt-live
ziti edge create service-policy bind-rt-live Bind --service-roles '#rt-live' --identity-roles '@er1'
# (Dial lo cubre la dial-all de la rig.)
# 3. Espera el próximo tick del poll (≤5.5 min, timing de producción) y comprueba la ruta:
netstat -rn | grep 203.0.113        # debe APARECER apuntando al utunN, sin reiniciar el runner
# (opcional, round-trip por el overlay: exige que er1 registre el terminator del servicio nuevo →
#  docker restart ziti-router-er1 y verificar `ziti edge list terminators` ANTES del nc; el restart
#  NO toca el runner: solo re-registra el lado hosting)
# nc 203.0.113.5 19009 → eco = la ruta entrega Y despacha
# 4. Borra el servicio (y su policy/config, para que la 2ª corrida —graviola— pueda re-crearlos):
ziti edge delete service-policy bind-rt-live
ziti edge delete service rt-live
ziti edge delete config rt-live-intercept
# ...y espera otro tick:
netstat -rn | grep 203.0.113        # debe DESAPARECER (última referencia → delete_route)
```

Verde = las rutas OS siguen los eventos del controller en vivo (ambos sentidos), con los feature-sets
default **y** `--features graviola` (correr §5b entero DOS veces; el paso 4 deja el controller limpio
para la segunda). El refcount compartido (2 servicios mismo CIDR → borrar 1 conserva la ruta) está
pineado offline en `routes/tests_lifecycle.rs`; no hace falta reproducirlo live.

## 6. Tras un éxito en vivo

- Es la **aceptación de M3-rutas** (la mitad LIVE del mecanismo de instalación de rutas; el mecanismo en
  sí — `plan_routes`/`InstalledRoutes` — ya estaba mergeado y reforzadamente revisado en `282c9ba`).
  Registra el resultado (default + graviola) en `HANDOFF.md`/`CLAUDE.md` como M3-rutas-e2e VALIDADO EN
  VIVO.
- **Desbloqueado:** `source_addr`/T4b-2d-3 (su propia rebanada, plantilla sourceIp) puede aterrizar sin
  reservas sobre si las rutas OS-level funcionan de verdad.
- Tras el verde live: **M3-DNS** (5ª frontera differential, desbloquea `dst_hostname`) y/o **stack-split
  combinado** (subcomando TCP+UDP concurrente).

## Gotchas (de la memoria del rig + específicos de rutas)

- **OTT single-use**, **RAFT cold-start flap**, **macOS sin `timeout`**: idénticos a M2b-e2e-runbook.
- **Elige SIEMPRE un CIDR ruteado RFC 5737 TEST-NET** (`203.0.113.0/24`, `198.51.100.0/24`,
  `192.0.2.0/24`) si alguna vez cambias/añades una iteración — NUNCA `10.x`/`172.x`/`192.168.x`: son los
  rangos típicos del underlay de OrbStack/Docker, y una ruta ahí dispara la clase de self-DoS que la
  reinforced review 17-ag cazó en `plan_routes` (capturar los dials del propio SDK al controller).
- **utun**: la prueba usa subredes on-link `10.99.0.0/24`/`10.99.1.0/24` (igual que M2b). Si chocan con
  una ruta existente en tu Mac, cámbialas en el test.
