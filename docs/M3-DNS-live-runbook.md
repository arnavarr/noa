# M3-DNS live runbook — aceptación LIVE del intercept por hostname (DNS embebido + dispatch)

> **Qué valida:** la aceptación LIVE de **M3-DNS entero** (matcher `7dad52a` + pool `41a3060` +
> wiring `694366e` + servidor UDP:53 `5c367fd` + dispatch de wildcards `0211810` + subcomando
> combinado, este slice): que un **cliente real** resuelve un hostname interceptado contra el DNS
> embebido del subcomando (`dig @<utun+1> …` → IP sintética) y que el flujo TCP siguiente a esa IP
> despacha host→overlay→echo. Cada pieza ya está validada offline byte-a-byte (differential C +
> tests in-process, incluido el runner combinado REAL sirviendo DNS por un device mock); este runbook
> ejecuta la única parte que exige root + overlay: el utun real y el stub-resolver real del SO.
>
> **Cableado bajo prueba:** `src/main.rs::run_intercept` → `run_combined_intercept`
> (`src/tunnel/intercept/combined/`): pila con UDP + accept-loop TCP + manager UDP con el DNS
> embebido en `(utun_addr+1, 53)` y UN resolver compartido. Oráculo: `ziti-edge-tunnel run`
> (`ziti-edge-tunnel.c` a `2addfbb`/v1.15.1: `run_tunnel:849` → `ziti_dns_setup:940`;
> `dns_ip = tun_ip+1`, `:1491-1492`).

**Discriminador vs M2b-e2e/M3-rutas-e2e:** aquellas conectan a IPs/CIDRs literales (el paso DNS no
existe). Esta prueba intercepta por **hostname/dominio**: la IP no existe hasta que la query la
asigna, así que un round-trip exitoso solo puede haber pasado por servidor DNS embebido → asignación
→ dispatch (hostname exacto por su `/32`; nombre bajo `*.dominio` por el fallback per-paquete
`intercept_match_addr`).

## 0. Prerrequisitos

Los de `docs/M3-rutas-e2e-runbook.md` §0 (root, rig OrbStack `ziti-ctrl`+`ziti-router-er1`, echo
`ncat :19009`, 1 OTT JWT fresco, cargo bajo sudo). Rig completo: `docs/edge-integration.md`.

## 1. Delta de rig: un servicio interceptado por HOSTNAME

La rig M2b solo tiene servicios por IP/CIDR. Añade UNO por hostname + dominio wildcard (mismo patrón
host.v1 router-hosteado y bind-policy que `testsvc-noenc` — copia los de la memoria del rig):

```sh
ziti edge create config dnssvc-intercept intercept.v1 \
  '{"protocols":["tcp"],"addresses":["app.ziti.test","*.wild.ziti.test"],"portRanges":[{"low":19009,"high":19009}]}'
# host.v1 + service + bind-policy: MISMO patrón que testsvc-noenc (router-hosteado hacia el echo
# :19009 del host); dial-policy #all de la rig ya cubre la identidad.
ziti edge create service dnssvc --configs dnssvc-intercept,<host-v1-de-la-rig>
```

## 2. Correr el subcomando combinado (root)

```sh
cargo build --features intercept
target/debug/noa enroll /tmp/m3dns.jwt --out /tmp/id.json
sudo target/debug/noa intercept 100.64.0.1/10 /tmp/id.json
# espera:
# "intercept: utunN 100.64.0.1/10 -> resolver intercept.v1 (N servicios, R rutas OS-level, DNS embebido en 100.64.0.2:53; ...)"
```

## 3. Resolver + conectar (el cliente real)

```sh
dig +short @100.64.0.2 app.ziti.test          # → una IP sintética del pool (p. ej. 100.64.0.3)
dig +short @100.64.0.2 cual.sea.wild.ziti.test # → otra IP (asignación LAZY bajo el wildcard)
printf 'hola-dns\n' | nc <ip-de-app> 19009     # → eco: despacho por hostname exacto (/32)
printf 'hola-wild\n' | nc <ip-de-wild> 19009   # → eco: despacho por el fallback wildcard (#6)
dig @100.64.0.2 no.intercepted.example         # → SIN +short (con +short el status no se ve):
                                                #   la cabecera debe decir "status: REFUSED"
                                                #   (miss = REFUSE, nunca NXDOMAIN)
```

Éxito = ambos ecos + el REFUSED. Correr también la variante `--features intercept,graviola` (2º JWT
fresco). **Tras el verde live:** registrar M3-DNS VALIDADO EN VIVO en `HANDOFF.md`.

## 4. (Opcional) Forwarding a upstream DNS (`--dns-upstream`, M3-DNS #1)

Con `--dns-upstream <ip[:puerto]>` (repetible), una query recursiva que el resolver no responde
localmente se REENVÍA a ese servidor y su respuesta hace passthrough al cliente (en vez de REFUSED):

```sh
sudo target/debug/noa intercept 100.64.0.1/10 /tmp/id.json --dns-upstream 1.1.1.1
# ahora un nombre NO interceptado resuelve por upstream en vez de REFUSED:
dig +short @100.64.0.2 example.com     # → la(s) IP(s) reales de example.com (vía 1.1.1.1)
dig +short @100.64.0.2 app.ziti.test   # → SIGUE dando la IP sintética (el local gana al upstream)
```

Éxito = el nombre externo resuelve por upstream Y el interceptado sigue dando su IP sintética. La
cabecera de una respuesta con upstream activo lleva RA (recursion available); sin `--dns-upstream`,
no.

## 5. Proxy-resolve por el overlay (MX/SRV/TXT bajo un dominio, M3-DNS #2) — LIVE-ACEPTADO ×2 (2026-07-09)

> **VERDE ×2 (default aws-lc-rs + `--features graviola`) el 2026-07-09.** La receta CANÓNICA de infra
> (imagen `zet-dns:1.15.1` = `ziti-edge-tunnel` C v1.15.1 + dnsmasq, SWAP del Bind de `dnssvc`, pre-checks,
> RED-first, controles, drop/resurrect, vecino HOL, restore) está en **`docs/specs/m3dns-5-live-gate-prep.md`**
> + los artefactos reusables en **`docs/zet-dns/*`**. ⚠ Al construir la imagen, FORZAR `--platform linux/arm64`
> (el `debian:bookworm-slim` default salió amd64 → binario aarch64 bajo qemu, falla). Resultado y pids/flavors
> por corrida en `HANDOFF.md`. El boceto mínimo de abajo queda como referencia rápida.

Una query **MX/SRV/TXT** por un nombre bajo un dominio wildcard interceptado (`*.wild.ziti.test`)
NO se responde localmente ni va a upstream: se PROXY-resuelve preguntando al endpoint que HOSTEA el
servicio, por una conexión ziti dedicada (appData `{"connType":"resolver"}`). El lado hostante debe
ser un **`ziti-edge-tunnel` real** corriendo el host de ese servicio (es quien implementa el
resolver del lado servidor, `dns_host.c` — consulta los DNS del SO del host vía `res_n*`); el rig
mínimo:

1. En el host remoto (o un contenedor), `ziti-edge-tunnel run` con la identidad del lado Bind del
   servicio wildcard, y `host.v1` con `allowedAddresses` cubriendo `*.wild.ziti.test`.
2. **Provisionar los registros en el DNS del host remoto** (paso IMPRESCINDIBLE: `dns_host.c`
   consulta el resolver del SO del host — sin registros para `app.wild.ziti.test` un resolver real
   devuelve NXDOMAIN/vacío y el `dig` local ve NOERROR VACÍO, indistinguible de un proxy
   roto-pero-conectado). P. ej. un `dnsmasq` en el host remoto como su resolver:
   ```
   mx-host=app.wild.ziti.test,mail.wild.ziti.test,10
   txt-record=app.wild.ziti.test,"v=spf1 -all"
   srv-host=_sip._tcp.app.wild.ziti.test,sip.wild.ziti.test,5060,1,5
   ```
   y apuntar `/etc/resolv.conf` del host remoto a ese `dnsmasq`.
3. Cliente (nuestro lado):

```sh
sudo target/debug/noa intercept 100.64.0.1/10 /tmp/id.json
dig +short @100.64.0.2 app.wild.ziti.test MX    # → mail.wild.ziti.test (prio 10)
dig @100.64.0.2 app.wild.ziti.test TXT          # → "v=spf1 -all"; SRV con `dig ... SRV`
dig @100.64.0.2 app.wild.ziti.test PTR          # → rcode NOT_IMPL (síncrono, tipo no soportado)
```

Éxito = los MX/TXT/SRV **con la sección ANSWER POBLADA** (los valores del paso 2) llegan al `dig`
local (rcode NOERROR) y el PTR responde NOT_IMPL. **Ojo:** un NOERROR con ANSWER VACÍA NO es éxito
— es el quirk de `on_proxy_data` (el cliente IGNORA el status del peer) sobre un NXDOMAIN remoto:
verifica siempre que hay registros en la respuesta, no solo el rcode. Sin lado hostante alcanzable,
MX/SRV/TXT responden SERVFAIL (el dial/write falla — mismo observable que el oráculo). Correr
también `--features intercept,graviola`.

## 6. (Opcional) DNS-over-TCP (RFC 7766, beyond-oracle #4)

El oráculo C **no** sirve DNS-over-TCP (registra solo `"udp"` en el `:53`, `ziti_dns.c:190`; su
TCP:53 hace handshake-then-close). El subcomando combinado añade un stub **local** de DNS-over-TCP:
un flujo TCP a `(dns_ip, 53)` se sirve con el framing de RFC 7766 (prefijo de longitud de 2 bytes
big-endian por mensaje), reusando el MISMO `handle_query` local que el path UDP.

```bash
# Fuerza TCP contra el DNS embebido (dig +tcp / +vc):
dig +tcp @100.64.0.2 mi-servicio.ziti.test A    # → la MISMA IP sintética que por UDP (NOERROR + A)
# Un nombre wildcard también asigna/resuelve por TCP:
dig +tcp @100.64.0.2 app.wild.ziti.test A       # → IP sintética del pool
```

Éxito = `dig +tcp` recibe la respuesta enmarcada correctamente (mismo registro A que sin `+tcp`).

**Limitaciones conscientes del stub local (documentadas, siguen siendo mejores que el
handshake-then-close del oráculo):**
- Un nombre **EXTERNO** por TCP da **REFUSED**, aunque haya `--dns-upstream` configurado (el forward
  a upstream y el proxy-resolve MX/SRV/TXT **sobre TCP** están diferidos a #4b — viven en el manager
  UDP). Por UDP el mismo nombre SÍ reenvía. Verifícalo: `dig +tcp @100.64.0.2 <externo>` → REFUSED,
  `dig @100.64.0.2 <externo>` (UDP, con §4) → respuesta del upstream.
- `RA=0` siempre sobre TCP (sin recursión disponible en el stub local).
- Un mensaje >4096 B, malformado, o una conexión ociosa >10 s → se cierra (RFC 7766 §5.1/§6.2.3).

Correr también `--features intercept,graviola`.

## Gotchas

- `dig` a `100.64.0.2` solo llega si el utun cubre esa IP on-link (con `100.64.0.1/10` lo hace; no
  uses `/32`-`/0`, el subcomando los rechaza fail-loud).
- Sin `--dns-upstream`, CUALQUIER nombre no interceptado = REFUSED: no apuntes el resolver del SO
  entero al DNS embebido durante la prueba (usa `dig @` explícito) — o configura un upstream (§4).
- Un nombre bajo el wildcard consume una IP del pool por PRIMERA query; queries repetidas reusan la
  misma (caché) — si el pool se agota (rango pequeño), REFUSED.
