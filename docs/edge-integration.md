# Live edge auth + services integration test

Validates `enrol → authenticate → list services` against a real controller.
Reuses the controller from `docs/enrolment-integration.md` (container `ziti-ctrl`).

> ⚠ **Las secciones por rebanada de abajo son un REGISTRO fechado de cómo se validó cada una, no la
> receta de reposición.** Sus `ziti edge create ...` **no son idempotentes**: si la fixture ya está —
> o peor, si sobrevivió una policy huérfana con `serviceRoles` vacío tras borrarse su servicio —
> `create` falla por nombre duplicado. Para medir y reponer las fixtures `bindsvc`/`bindsvc-enc` y sus
> 4 policies, usa **`bash scripts/rig-fixtures.sh`** (`--ensure` para reponer). Han desaparecido de la
> rig compartida **dos veces** (s10 y 2026-08-05) sin que ninguna sesión las tocara, así que su
> presencia se mide al abrir un gate live; no se hereda de este documento.

1. Ensure the controller is up (see docs/enrolment-integration.md §1) and you are
   logged in: `ziti edge login localhost:1280 -u admin -p admin -y`.
2. (optional, to see a non-empty list) create a service + dial policy:
   ```
   ziti edge create config testcfg intercept.v1 '{"protocols":["tcp"],"addresses":["test.ziti"],"portRanges":[{"low":80,"high":80}]}'
   ziti edge create service testsvc --configs testcfg -e ON
   ziti edge create service-policy dial-all Dial --identity-roles '#all' --service-roles '#all'
   ```
3. Mint an enrolment JWT and run the test:
   ```
   ziti edge create identity edge-test -o /tmp/edge-test.jwt
   ZITI_EDGE_JWT=/tmp/edge-test.jwt \
     cargo test -p ziti-tunnel --test edge_integration -- --ignored --nocapture
   ```

The test enrols the identity with our crate, builds an `EdgeClient`, authenticates,
and lists services — asserting a session is obtained and the service list deserializes
(may be empty unless a dial policy grants the identity a service).

## Live create-session test (slice 2)

`enrol_then_create_session` additionally needs an **online edge router** and the
two router policies, on top of the service + dial policy above.

1. Controller up + logged in (see above).
2. Service + dial policy exist (see above), plus router policies:
   ```
   ziti edge create edge-router-policy erp-all --identity-roles '#all' --edge-router-roles '#all'
   ziti edge create service-edge-router-policy serp-all --service-roles '#all' --edge-router-roles '#all'
   ```
3. An edge router enrolled and **online**. Quick path with a container (host networking
   so the router reaches the controller's `localhost:1280`):
   ```
   ziti edge create edge-router er1 --tunneler-enabled -o /tmp/er1.jwt
   docker run -d --name ziti-router-er1 --network host \
     -e ZITI_CTRL_ADVERTISED_ADDRESS=localhost -e ZITI_CTRL_ADVERTISED_PORT=1280 \
     -e ZITI_ENROLL_TOKEN="$(cat /tmp/er1.jwt)" \
     -e ZITI_ROUTER_ADVERTISED_ADDRESS=localhost -e ZITI_ROUTER_PORT=3022 \
     -e ZITI_ROUTER_NAME=er1 openziti/ziti-router:latest
   ```
   Confirm `ziti edge list edge-routers` shows `ONLINE true`.
4. Mint a JWT and run:
   ```
   ziti edge create identity edge-test2 -o /tmp/edge-test2.jwt
   ZITI_EDGE_JWT=/tmp/edge-test2.jwt \
     cargo test --test edge_integration enrol_then_create_session -- --ignored --nocapture
   ```

The test enrols, authenticates, lists services to find a dial-able one, creates a
dial session, and asserts a session token + at least one edge router advertising `tls`.

## Rebanada 3: canal binario V2 (open_channel)

`enrol_then_open_channel` extends slice 2 by opening the binary channel V2 to the
edge router and completing the Hello/Result handshake.

### Protocol notes

- Transport: mTLS with the same identity certificate used for the REST API calls
  (no ALPN extension is set).
- Hello message: content-type 0 (`CT_HELLO`), sequence `-1`. The Hello **must**
  include header `1002` (`HDR_SESSION_TOKEN`) set to the api-session token (the
  `zt-session` / Bearer token from `authenticate`), **not** the dial-session JWT.
  The body is the identity common name.
- The router replies with a Result message (content-type 2, `CT_RESULT`).
  Header `4` (`HDR_HELLO_VERSION`) in the Result carries the router's version string
  (e.g. `v2.0.0|...`).

### Prerequisites (same as slice 2, plus policies)

All three router policies must exist:

```
ziti edge create edge-router-policy erp-all --identity-roles '#all' --edge-router-roles '#all'
ziti edge create service-edge-router-policy serp-all --service-roles '#all' --edge-router-roles '#all'
ziti edge create service-policy dial-all Dial --identity-roles '#all' --service-roles '#all'
```

### Running the test

Default feature set:

```
ziti edge create identity edgechan -o /tmp/edgechan.jwt
ZITI_EDGE_JWT=/tmp/edgechan.jwt \
  cargo test --test edge_integration enrol_then_open_channel -- --ignored --nocapture
```

Expected output: `channel open: router_id=Some("...") hello_version=Some("v2.0.0|...")`;
the channel closes without error.

## Rebanada 4: edge dial (Connect → StateConnected)

`enrol_then_dial` extends slice 3 by dialing a **plaintext** service over the open
channel and asserting `StateConnected`. It requires a service with
`encryptionRequired=false` **and a terminator** (StateConnected needs a circuit to
a host), on top of the slice-2/3 policies. The router-tunneler (`er1`,
`--tunneler-enabled`) hosts it:

```
ziti edge create config noenc-host host.v1 '{"protocol":"tcp","address":"localhost","port":1280}'
ziti edge create service testsvc-noenc -e OFF --configs noenc-host
ziti edge create service-policy bind-noenc Bind --service-roles '@testsvc-noenc' --identity-roles '@er1'
# wait until a terminator appears (router polls):
ziti edge list terminators   # expect one row for testsvc-noenc, router er1, binding=tunnel
```

The existing `dial-all` (#all/#all Dial) policy already lets the enrolled identity
dial it. Run:

```
ziti edge create identity edgedial -o /tmp/edgedial.jwt
ZITI_EDGE_JWT=/tmp/edgedial.jwt \
  cargo test --test edge_integration enrol_then_dial -- --ignored --nocapture
```

Expected: `dialed: conn_id=1 circuit_id=Some("...")`. The test selects the service
by `!encryption_required && Dial`, so it never picks the encrypted `testsvc`.

## Rebanada 4b: edge data (Data round-trip)

`enrol_then_dial` (extended) writes bytes over the dialed connection and asserts the
echo. It needs a **plaintext TCP echo** as the service host (the slice-4 `localhost:1280`
target is HTTPS — a plaintext write would hit a TLS listener). Run a published echo
container and repoint `noenc-host` at it:

```
docker run -d --name echo4b -p 19009:19009 python:3-alpine python3 -c "
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d=self.request.recv(4096)
            if not d: break
            self.request.sendall(d)
socketserver.ThreadingTCPServer.allow_reuse_address=True
socketserver.ThreadingTCPServer(('0.0.0.0',19009),H).serve_forever()
"
ziti edge update config noenc-host --data '{"protocol":"tcp","address":"localhost","port":19009}'
ziti edge list terminators   # testsvc-noenc / er1 / tunnel present
```

Run (fresh ott JWT per run):

```
ziti edge create identity edgedata -o /tmp/edgedata.jwt
ZITI_EDGE_JWT=/tmp/edgedata.jwt \
  cargo test --test edge_integration enrol_then_dial -- --ignored --nocapture
```

Expected: `data round-trip OK: conn_id=1 circuit=Some("...")`. The router echoes the
bytes back as a plain Data frame (no MULTIPART_MSG).

## Rebanada 5: cifrado e2e (dial encrypted)

`enrol_then_dial_encrypted` dials the **encryptionRequired=true** `testsvc` and asserts an
e2e-encrypted echo round-trip (secretstream/libsodium). It needs `testsvc` **hosted with crypto**
by the router-tunneler (`er1` does the host-side secretstream automatically for an encrypted
service), on top of the slice-2/3 policies and the `dial-all` Dial policy.

Host `testsvc` at the same plaintext TCP echo used in slice 4b (`echo4b` on :19009):

```
ziti edge create config enc-host host.v1 '{"protocol":"tcp","address":"localhost","port":19009}'
ziti edge update service testsvc --configs testcfg,enc-host
ziti edge create service-policy bind-enc Bind --service-roles '@testsvc' --identity-roles '@er1'
ziti edge list terminators   # expect a row for testsvc, router er1, binding=tunnel
```

Run (fresh ott JWT per run):

```
ziti edge create identity edgecrypto -o /tmp/edgecrypto.jwt
ZITI_EDGE_JWT=/tmp/edgecrypto.jwt \
  cargo test --test edge_integration enrol_then_dial_encrypted -- --ignored --nocapture
```

Expected: `encrypted round-trip OK: conn_id=1 circuit=Some("...")`. The payload on the wire is
ciphertext; the router decrypts (host side), echoes, and re-encrypts; our `EdgeConn` decrypts it.

## Rebanada 6 (API de conexión de producción: `connect`)

Reutiliza EXACTAMENTE el testbed de las rebanadas 4b/5: controller `ziti-ctrl` (:1280),
`ziti-router-er1` online (`--tunneler-enabled`), `echo4b` (:19009), y los servicios
`testsvc` (`encryptionRequired=true`, config `enc-host` → echo4b, policy `bind-enc`) y
`testsvc-noenc` (`encryptionRequired=false`, config `noenc-host` → echo4b, policy
`bind-noenc`), ambos dial-eados por la policy `dial-all` (#all/#all).

El test `enrol_then_connect_both` llama `client.connect("testsvc-noenc")` y
`client.connect("testsvc")` por NOMBRE: `connect` lista servicios, resuelve por nombre, lee
`Service.encryption_required` y activa (o no) la cripto sin que el test pase el flag.

```bash
# Mintea un JWT ott FRESCO (un solo uso) y corre el test:
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge create identity slice6 -o /tmp/slice6.jwt
ZITI_EDGE_JWT=/tmp/slice6.jwt cargo test --test edge_integration enrol_then_connect_both -- --ignored --nocapture
```

## Rebanada 7a (registrar el bind: `bind`)

Necesita un servicio DEDICADO `bindsvc` (NO reutilizar `testsvc-noenc`, que ya lo hostea
`er1`: un 2º terminator nuestro —muerto, porque 7a no acepta— podría enrutar mal el dial de
slice 6). `bindsvc` es `encryptionRequired=false` (7a es plaintext) y SIN host config (lo
hosteamos nosotros al bindear). La identidad de test necesita permiso **Bind** (`bind-bindsvc`)
+ la SERP `#all/#all` ya existente.

> ⚠ Registro fechado: para reponer HOY usa `bash scripts/rig-fixtures.sh --ensure` (estos `create`
> chocan por nombre duplicado si sobrevivió la policy huérfana).

```bash
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge create service bindsvc -e OFF
ziti edge create service-policy bind-bindsvc Bind --service-roles '@bindsvc' --identity-roles '#all'
# (service-edge-router-policy serp-all #all/#all ya existe desde la rebanada 2)

# Mintea un JWT ott FRESCO (un solo uso) y corre el test:
ziti edge create identity s7a -o /tmp/s7a.jwt
ZITI_EDGE_JWT=/tmp/s7a.jwt cargo test --test edge_integration enrol_then_bind -- --ignored --nocapture

# Verificar el terminator registrado (mientras el test corre, o si dejas el binding abierto):
ziti edge list terminators   # una fila para 'bindsvc' (router er1, nuestra identidad)
```

## Rebanada 7b-1 (servir: aceptar dials plaintext)

Reusa `bindsvc` (de 7a: `encryptionRequired=false`, sin host config — lo hosteamos nosotros), y
AÑADE una policy **Dial** para que un dialer pueda conectarlo. El test usa DOS identidades frescas
(host + dialer); el host hostea y acepta, el dialer usa nuestro propio `connect()` y el dato hace
round-trip eco a través de nuestro host.

> ⚠ Registro fechado: para reponer HOY usa `bash scripts/rig-fixtures.sh --ensure` (el `create`
> choca por nombre duplicado si sobrevivió la policy huérfana).

```bash
ziti edge login localhost:1280 -u admin -p admin -y
# bindsvc + su Bind policy ya existen desde 7a; añade la Dial policy:
ziti edge create service-policy dial-bindsvc Dial --service-roles '@bindsvc' --identity-roles '#all'
# (bind-bindsvc Bind y serp-all #all/#all ya existen)

# Dos JWT ott FRESCOS (un solo uso cada uno): host + dialer.
ziti edge create identity s7b1h -o /tmp/s7b1h.jwt
ziti edge create identity s7b1d -o /tmp/s7b1d.jwt
ZITI_EDGE_JWT=/tmp/s7b1h.jwt ZITI_EDGE_JWT_DIALER=/tmp/s7b1d.jwt \
  cargo test --test edge_integration bind_then_serve_roundtrip -- --ignored --nocapture

# Observa el terminator de nuestro host (cierra el pendiente honesto de 7a):
ziti edge list terminators   # una fila para 'bindsvc' (router er1, identidad host)
```

Si el loopback "mismo overlay, 2 identidades" diera problemas de enrutado, alternativa: usar el
`ziti` CLI como dialer. El cableado del eco (accept → read → write) vive en el propio test.

## Rebanada 7b-2 (servir con crypto: aceptar dials cifrados)

Añade un servicio dedicado `bindsvc-enc` con `encryptionRequired=true` y SIN host config (lo
hosteamos nosotros al bindear). Reusa las policies `serp-all` (#all/#all SERP) y `erp-all`
(#all/#all ERP) existentes desde la rebanada 2.

### Infraestructura (una sola vez)

> ⚠ Registro fechado: para reponer HOY usa `bash scripts/rig-fixtures.sh --ensure` (estos `create`
> chocan por nombre duplicado si sobrevivió la policy huérfana).

```bash
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge create service bindsvc-enc --encryption ON
ziti edge create service-policy bind-bindsvc-enc Bind --service-roles '@bindsvc-enc' --identity-roles '#all'
ziti edge create service-policy dial-bindsvc-enc Dial --service-roles '@bindsvc-enc' --identity-roles '#all'
ziti edge list services 'name="bindsvc-enc"'   # confirmar encryptionRequired=true
```

### JWTs necesarios

Dos identidades frescas (un solo uso cada una): la identidad **host** se bindea al servicio
y acepta el dial; la identidad **dialer** usa `connect()` para conectarse.

```bash
ziti edge create identity s7b2h  -o /tmp/s7b2h.jwt
ziti edge create identity s7b2d  -o /tmp/s7b2d.jwt
```

### Running the test

Equivalence gate: ruta default (aws-lc-rs):

```bash
ZITI_EDGE_JWT=/tmp/s7b2h.jwt ZITI_EDGE_JWT_DIALER=/tmp/s7b2d.jwt \
  cargo test --test edge_integration bind_then_serve_encrypted_roundtrip -- --ignored --nocapture
```

Salida esperada:

```
host bound 'bindsvc-enc' (encrypted): conn_id=1
host accepted encrypted child conn_id=<N>
7b-2 ENCRYPTED serve round-trip OK: data e2e-encrypted and echoed by our host
```

### Neighbour gate (enrol_then_connect_both)

Task 1 tocó el `Drop`/`close` compartido por dial y bind. Tras 7b-2, re-verificar también
el camino del cliente con el test vecino:

```bash
ziti edge create identity s7b2nb -o /tmp/s7b2nb.jwt
ZITI_EDGE_JWT=/tmp/s7b2nb.jwt \
  cargo test --test edge_integration enrol_then_connect_both -- --ignored --nocapture
```

Salida esperada: `slice 6 connect() round-trip OK (plaintext + encrypted, flag from Service)`.

## Rebanada 8 (propagación de `CallerId`: identidad del dialer)

Slice 8 no añade infraestructura nueva: reusa los mismos `bindsvc` (plano) y `bindsvc-enc`
(`encryptionRequired=true`) + sus políticas `bind-*`/`dial-*` (`#all`) de 7b-1/7b-2. El cambio es
que `bind_then_serve_roundtrip` y `bind_then_serve_encrypted_roundtrip` ahora asertan, además del eco
round-trip, que el `source_identity()` del lado host **==** el `identity_name()` propio del dialer
(dos derivaciones independientes: lectura del header `CallerId`=1008 del wire vs el `identity.name` del
api-session; sin literal fijo). El nombre observado será el de la 2ª identidad creada para el dialer.

### Puerta de equivalencia (ambos caminos de accept + vecino)

`accept_next`/`EdgeConn::new` son compartidos por el accept plano y el cifrado, así que el camino
cifrado NO es opcional. Por cada corrida, identidades OTT frescas (de un solo uso):

```bash
# Plaintext serve (default)
ziti edge create identity s8-host-pd  -o /tmp/s8-host-pd.jwt
ziti edge create identity s8-dialer-pd -o /tmp/s8-dialer-pd.jwt
ZITI_EDGE_JWT=/tmp/s8-host-pd.jwt ZITI_EDGE_JWT_DIALER=/tmp/s8-dialer-pd.jwt \
  cargo test --test edge_integration bind_then_serve_roundtrip -- --ignored --nocapture

# Encrypted serve (default) — reusa bindsvc-enc
ziti edge create identity s8-host-ed  -o /tmp/s8-host-ed.jwt
ziti edge create identity s8-dialer-ed -o /tmp/s8-dialer-ed.jwt
ZITI_EDGE_JWT=/tmp/s8-host-ed.jwt ZITI_EDGE_JWT_DIALER=/tmp/s8-dialer-ed.jwt \
  cargo test --test edge_integration bind_then_serve_encrypted_roundtrip -- --ignored --nocapture

# Vecino:
ziti edge create identity s8-conn-d -o /tmp/s8-conn-d.jwt
ZITI_EDGE_JWT=/tmp/s8-conn-d.jwt \
  cargo test --test edge_integration enrol_then_connect_both -- --ignored --nocapture
# (delete the test identities afterwards: ziti edge delete identity <name>)
```

Salida esperada de los serve: `slice 8 CallerId OK (plaintext|encrypted): host saw dialer 'Some("s8-dialer-…")'`.
