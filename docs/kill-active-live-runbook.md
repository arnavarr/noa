# Runbook: gate LIVE de `kill-active` (root)

> **Rebanada:** `kill-active` (rama `feat/tunnel-intercept-kill-active`, código `6b71c10`).
> **Spec:** `docs/superpowers/specs/2026-07-08-kill-active-design.md` §8.
> **Qué acepta:** *un flujo ESTABLECIDO muere a mitad de stream cuando su servicio se retira* — el
> único observable que el offline NO puede producir (los dials in-process nunca establecen: sin
> `EdgeConn` real, no hay nada que matar). Además el `fidelity_risk` toca `Drop`/`close` de una conn
> EN VUELO ⇒ la regla del paso 5 exige gate live root **con los caminos VECINOS**.
>
> **División de labor**: el asistente monta TODO el plano de control y
> conduce los `nc`/`dig` **sin root**. El operador con root solo ejecuta `sudo target/debug/noa intercept …`.
>
> **Rig compartida:** confirmar que no hay un gate live de `noa-router` en curso. Un `er2-noa` en
> `ziti edge list edge-routers` es esperado, no una anomalía.

## 0. Por qué DOS servicios y por qué mirar a `T`

`S` = el servicio que se retira (intercepta **tcp+udp**). `T` = el vecino que debe sobrevivir
(**tcp**). En esta rig hay **un solo router** (`er1`), así que los flujos de `S` y `T` comparten el
**mismo canal edge pooleado**. Eso convierte el paso 4(d) en la validación EN EL CABLE del
**invariante (ii)**: al matar `S` se emiten ≥2 `zw.close()` concurrentes sobre ese canal compartido
mientras `T` sigue escribiendo. Si el framing se corrompiese (un frame parcial), **`T` se rompe**.
Offline eso solo se ejerció contra un canal falso (tests 5 y 8b). Aquí es real.

**Por tanto: `T` no es un control secundario. Es la mitad más valiosa del gate.**

## 1. Rig (sin root; la levanta el asistente)

```sh
docker start ziti-ctrl ziti-router-er1        # si estuvieran fríos
ziti edge login localhost:1280 -u admin -p admin -y

# Echo backends (no persisten; hay que levantarlos a mano). TCP y UDP en el MISMO puerto.
pkill -f 'ncat.*19009' 2>/dev/null
ncat --listen --keep-open --exec /bin/cat 0.0.0.0 19009 &      # TCP echo
ncat -u --listen --keep-open --exec /bin/cat 0.0.0.0 19009 &   # UDP echo
```

CIDRs RFC 5737 TEST-NET (únicos en el Mac ⇒ una ruta ahí solo puede venir de nuestro intercept):
`S` → `203.0.113.0/24`, `T` → `198.51.100.0/24`. Ambos **fuera** del on-link del utun ⇒ el
`RouteLifecycle` instala su ruta (re-valida de paso el arco RUTAS OS).

```sh
# S: tcp + udp, hosteado por er1 con forwardProtocol (un solo host.v1 sirve ambos protocolos).
ziti edge create config ka-s-intercept intercept.v1 \
  '{"protocols":["tcp","udp"],"addresses":["203.0.113.0/24"],"portRanges":[{"low":19009,"high":19009}]}'
ziti edge create config ka-s-host host.v1 \
  '{"address":"localhost","port":19009,"forwardProtocol":true,"allowedProtocols":["tcp","udp"]}'
ziti edge create service ka-s --configs ka-s-intercept,ka-s-host -a ka-s
ziti edge create service-policy bind-ka-s Bind --service-roles '#ka-s' --identity-roles '@er1'

# T: tcp, el vecino que debe sobrevivir.
ziti edge create config ka-t-intercept intercept.v1 \
  '{"protocols":["tcp"],"addresses":["198.51.100.0/24"],"portRanges":[{"low":19009,"high":19009}]}'
ziti edge create service ka-t --configs ka-t-intercept,noenc-host -a ka-t
ziti edge create service-policy bind-ka-t Bind --service-roles '#ka-t' --identity-roles '@er1'

# El Dial lo cubre la `dial-all` (#all/#all) de la rig.
docker restart ziti-router-er1        # re-registra los terminators de los servicios nuevos
sleep 8
ziti edge list terminators | grep -E 'ka-s|ka-t'   # PRE-CHECK anti-falso-fallo: 1 terminator cada uno
ziti edge policy-advisor services ka-s -q          # Dial: Y
ziti edge policy-advisor services ka-t -q          # Dial: Y
```

Identidad + binarios:

```sh
ziti edge create identity ka-gate-$(date +%s) -o /tmp/ka.jwt      # o reusa /tmp/ka-id.json si sigue válido
cargo build --features intercept                                   # default (aws-lc-rs)
target/debug/noa enroll /tmp/ka.jwt --out /tmp/ka-id.json
```

## 2. El gate (×2: default y `--features graviola`)

**Terminal A (operador, root).** Anota el **pid** y el **sha del binario** de CADA corrida — dos
corridas con el mismo pid es el falso-×2 canónico:

```sh
sudo RUST_LOG=noa_sdk=debug target/debug/noa intercept 10.99.0.1/24 /tmp/ka-id.json
```

Espera a que imprima `… N servicios, R rutas OS-level …`, y a que `netstat -rn | grep -E '203.0.113|198.51.100'`
muestre AMBAS rutas (el svc-poll no ha corrido aún: vienen del snapshot de arranque).

**Terminal B (asistente, sin root).** Establece los tres flujos y déjalos vivos:

```sh
# (1) S / TCP — longevo, con tráfico periódico
( while true; do echo "s-tcp-$(date +%s)"; sleep 2; done ) | nc 203.0.113.5 19009 | tee /tmp/ka-s-tcp.log &
# (2) S / UDP — emisor CONSTANTE: exactamente el residual on-link que esta rebanada cierra
( while true; do echo "s-udp-$(date +%s)"; sleep 1; done ) | nc -u 203.0.113.5 19009 | tee /tmp/ka-s-udp.log &
# (3) T / TCP — el vecino; su continuidad es la prueba EN EL CABLE del invariante (ii)
( while true; do echo "t-tcp-$(date +%s)"; sleep 1; done ) | nc 198.51.100.5 19009 | tee /tmp/ka-t-tcp.log &
```

Comprueba que los TRES logs crecen (eco de vuelta) antes de seguir. **Si `S/UDP` no ecoa, PARA**: sin
flujo UDP establecido el gate no prueba nada (el `nc -u` no falla ruidoso).

### ⚠ El disparador NO puede ser `delete service` (corregido 2026-07-09, tras un verde falso)

**El borrador de este runbook decía "borra `ka-s`". Eso es un observable CONFUNDIDO.** Al borrar el
servicio, el controller elimina sus **sesiones** y el router **derriba los circuitos en ~20 s**. Los
flujos de `S` mueren, sí — pero **no los mata nuestro `kill_active`**, y a los ~5 min, cuando el
svc-poll aplica el `Removed`, `kill_service` encuentra los `Weak` ya muertos y devuelve `killed=0`.
Se midió en vivo: muerte a **t+20 s**, muy lejos del tick. Un verde sin valor.

Lo mismo vale para **quitar el permiso Dial** (la policy cambia ⇒ el controller borra las sesiones).

**El disparador correcto es REPLACE:** cambiar el CONTENIDO del `intercept.v1`. El servicio, la
policy y las sesiones siguen intactos, los circuitos en pie, y lo ÚNICO capaz de cerrar esos flujos
es nuestro kill al aplicar el `Changed` (`add_service` → `had_installed` ⇒ `kill_active = true`,
espejo de `stop_intercept(curr_i)` en `ziti_tunnel_cbs.c:632-635`).

**La firma es la LATENCIA:** los flujos deben sobrevivir MINUTOS al cambio y morir exactamente en el
tick del svc-poll. Muerte inmediata ⇒ fue el fabric, no nosotros.

```sh
date +%s > /tmp/ka-replace-at
ziti edge update config ka-s-intercept \
  -d '{"protocols":["tcp","udp"],"addresses":["203.0.113.0/24"],"portRanges":[{"low":19010,"high":19010}]}'
# El servicio y la policy siguen existiendo — compruébalo:
ziti edge list services 'name="ka-s"'; ziti edge list service-policies 'name="bind-ka-s"'
```

Espera el tick de producción del svc-poll (≤ ~5.5 min; medido: 152 s y 186 s tras el REPLACE).

## 3. Observables (los cinco, en orden)

| # | Qué | Verde |
|---|-----|-------|
| a | **`S`/TCP muere** | el `nc` de `/tmp/ka-s-tcp.log` recibe EOF y sale — **mid-stream**, en el tick, tras sobrevivir minutos al REPLACE |
| b | **`S`/UDP muere** | `/tmp/ka-s-udp.log` DEJA de crecer, pese a que el emisor sigue mandando 1 dgram/s (era el residual: su propia actividad posponía el reaper indefinidamente) |
| ~~c~~ | ~~el log del kill~~ | **NO PRODUCIBLE CUANDO SE CORRIÓ ESTE GATE** (2026-07-08): `src/main.rs` no instalaba ningún subscriber de `tracing`, así que `RUST_LOG` era inerte. Se sustituyó por **(c′)**. ⚠ **YA NO ES CIERTO:** la rebanada `tracing-subscriber` (2026-07-09) instala el subscriber ⇒ `RUST_LOG=noa_sdk=debug` **sí** emite los `tracing::debug!` del kill, **a stderr** (nunca a stdout). Si se re-corre este gate, (c) vuelve a ser un observable válido — pero (c′) sigue siendo evidencia de tercero, más fuerte |
| c′ | **corroboración del ROUTER** (evidencia de tercero, más fuerte) | en `docker logs ziti-router-er1`, en el instante del tick: **exactamente DOS** `read failed (… ->[::1]:19009)` (el backend hosteado ve EOF ⇒ el cierre lo inició NUESTRO cliente) seguidas de **DOS** `circuit unrouted`. El circuito de `T` no aparece |
| d | **`T` SOBREVIVE, sin hueco** | `/tmp/ka-t-tcp.log` sigue creciendo **DURANTE** el kill y después; el eco no se corrompe ni se detiene. **Ésta es la validación en el cable del invariante (ii)** (2 `zw.close()` concurrentes sobre el canal COMPARTIDO mientras `T` escribe) |
| e | **re-establecimiento limpio** | revertir el config a `19009` → siguiente tick → un `nc` NUEVO a `203.0.113.5:19009` vuelve a ecoar ⇒ el canal compartido quedó SANO |

**Anti-falso-verde:**
- **(a)/(b) deben tardar ~el tick.** Muerte a los pocos segundos del disparador ⇒ fue el fabric
  (sesiones borradas), no el kill. Compara `date` contra `/tmp/ka-replace-at`.
- (b) exige que el emisor UDP siga ACTIVO: refresca `last_use` cada segundo, así que el reaper de
  idle (5 min) NO puede ser la causa. Verifica que `nc -u` sigue vivo tras el kill.
- (b) sin (d) no vale: si `T` también muriese, habríamos matado el canal, no el servicio.
- Verificar en (d) que `T` NO se reconectó: es el MISMO proceso `nc` de antes (mismo pid).
- Verificar que el servicio y la policy SIGUEN existiendo tras el REPLACE (si no, es el camino
  confundido).
- Los CIDRs son TEST-NET: nada más en el Mac los usa.

> **Trampa de rig observada (no barrer bajo la alfombra):** establecer los tres flujos SIMULTÁNEAMENTE
> —dos de ellos dialando el MISMO servicio (`ka-s` tcp+udp) a la vez— produjo un `invalid session` en
> uno de los dials. Escalonando las altas 3 s desaparece. Puede ser una carrera real en el caché de
> dial-sessions ante dials concurrentes al mismo servicio; **queda como observación a investigar
> aparte**, no la resuelve este gate. Igualmente: si actualizas un servicio mientras un cliente lo
> tiene cacheado, el controller invalida sus dial-sessions y ese proceso ya no puede dialarlo —
> reinícialo.

## 4. Vecinos (OBLIGATORIOS — la regla del paso 5: el rx-loop es compartido por todas las conexiones)

El kill cierra un `EdgeConn` en vuelo ⇒ vecindario de `rx_loop`/`close-notify`. En CADA feature-set:

```sh
ziti edge login localhost:1280 -u admin -p admin -y
# (nombres verificados en tests/edge_integration.rs)
cargo test --features intercept --test edge_integration -- --ignored --exact enrol_then_connect_both
cargo test --features intercept --test edge_integration -- --ignored --exact enrol_then_proxy_tcp_round_trip
cargo test --features intercept --test edge_integration -- --ignored --exact enrol_then_proxy_udp_round_trip
```

`enrol_then_connect_both` cubre el round-trip cripto e2e; los dos `proxy_*` son el pase T1/T3, que
comparten `splice`/`rx_loop`/`close` con el camino que la rebanada toca.
Sin estos verdes, `gate_validation` = **NO_EJECUTADA** y la rebanada **no cierra**.

## 5. Segunda corrida (graviola)

```sh
pkill -f 'noa intercept'   # (o Ctrl-C en la terminal A)
cargo build --features intercept,graviola
shasum -a 256 target/debug/noa | cut -c1-8          # sha DISTINTO al de la corrida default
strings target/debug/noa | grep -ci graviola        # >0 (en default: 0)
```

Re-crear `S` (§1) y repetir §2-§4. **Exigir pid FRESCO y sha/flavor distintos** en cada corrida.

## 6. Limpieza (dejar la rig como estaba)

```sh
ziti edge delete service-policy bind-ka-s; ziti edge delete service-policy bind-ka-t
ziti edge delete service ka-s;             ziti edge delete service ka-t
ziti edge delete config ka-s-intercept;    ziti edge delete config ka-t-intercept
pkill -f 'ncat.*19009'
```

> ⚠ **Borra las identidades efímeras por NOMBRE EXACTO, nunca por `contains`.** En este gate un
> `name contains "nb-"` casó además con `fanb-*` y `nb-g-dial-*` de sesiones ANTERIORES y las borró.
> No hubo daño (son identidades de enrolment de un solo uso, que cada test live mintea fresco por
> corrida), pero la regla es: **mira el objeto antes de borrarlo, y borra solo lo que creaste tú.**

`ziti edge list terminators` debe volver a mostrar **0** de `ka-*` (para que futuros gates §5b/§4 vean
"0 rutas OS-level" al arrancar). **NO tocar** los residentes esperados: `dex`, `dexSpike*`, `dnssvc`,
`zet-dns`, `zet-dns-host`, `dnssvc-zet-host`.

## 7. RESULTADO — gate VERDE ×2 (2026-07-09)

| | Corrida 1 (default, aws-lc-rs) | Corrida 2 (`--features graviola`) |
|---|---|---|
| pid | **15605** | **20328** |
| sha binario | `ad95febf` | `723ac8f4` |
| graviola-strings | 0 | 62 |
| REPLACE en | 13:40:48 | 13:54:08 |
| `S`/TCP muere | **t+186 s** (13:43:53) | **t+152 s** (13:56:40) |
| `S`/UDP se congela | mismo instante, emisor vivo | mismo instante, emisor vivo |
| router: closes + unrouted | **2 + 2** | **2 + 2** |
| `T` (vecino) | +10 líneas/muestra, sin hueco, mismo pid `16918` | ídem, mismo pid `20431` |
| re-establecimiento (e) | t+172 s tras revertir | t+198 s tras revertir |

Pids **y** flavors distintos por corrida (el anti-falso-×2). El
`S`/TCP sobrevivió ~3 min al REPLACE en ambas: el fabric no lo tocó, lo cerró el svc-poll.

**Vecinos VERDES ×2** (`enrol_then_connect_both`, `enrol_then_proxy_tcp_round_trip`,
`enrol_then_proxy_udp_round_trip`), en default y graviola. Requieren `ZITI_EDGE_JWT` (y
`ZITI_EDGE_JWT_DIALER` el de UDP) con **un OTT fresco por test** (el token es de un solo uso).

### Diferidos NOMBRADOS que salieron de este gate (ninguno bloquea)

1. ~~**`noa` no emite logs.**~~ **CERRADO** por la rebanada `tracing-subscriber` (2026-07-09): el
   binario instala `EnvFilter` + `fmt` a **stderr**, default `WARN` sin `RUST_LOG`. La observabilidad
   O1-O5 del lib ya es visible en producción (`RUST_LOG=noa_sdk=debug`). Los logs van a **stderr**,
   nunca a stdout (los runbooks parsean stdout).
2. **Dials concurrentes al MISMO servicio → `invalid session`** en uno de ellos (reproducido; se evita
   escalonando). Posible carrera del caché de dial-sessions. Investigar aparte.
3. Actualizar un servicio invalida sus dial-sessions; un cliente que la tenga cacheada no se recupera
   y hay que reiniciarlo. Relacionado con (2); mismo seam (`dial_with_refresh_retry`).

Registrar en `HANDOFF.md` con pids/sha/flavors, mergear `feat/tunnel-intercept-kill-active` a `main`
con `--no-ff`, y actualizar `CLAUDE.md`.

**Baseline-before-swap (R6 de `noa-router`):** este gate añade a la suite live que `er2-noa` deberá
servir SIN TOCARLA el cierre de conns iniciado por el CLIENTE sobre flujos establecidos, concurrente
con tráfico vivo de otro servicio en el mismo canal.
