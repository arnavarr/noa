# ext-jwt × Dex live runbook — federación OIDC contra un IdP real (spike D1)

> **Qué valida:** que el cliente `noa-sdk` federa contra un **IdP OIDC real** (Dex) sin tocar
> `src/`: un `id_token` emitido por Dex se presenta como `Authorization: Bearer` en el login
> ext-jwt del controller → api-session Bearer → mint de session-cert Bearer-authed → connect
> round-trip. El éxito se mide con `git diff --stat -- src/` **vacío** (el SDK ya soportaba
> ext-jwt; Dex es el oráculo de contrato, no de código). Spec: `docs/specs/dex-prd.md`.
>
> **Oráculo de contrato (sustituye a fichero:línea):** el contrato OIDC observable de
> `dex-prd.md §1.2` (discovery/JWKS/mint/`id_token`). Dex pineado **v2.45.1**
> (`ghcr.io/dexidp/dex@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462`,
> digest anotado al primer pull 2026-07-08).
>
> **NO necesita root.** Todos los pasos corren desde la Bash del host contra la rig local +
> el controller (`admin/admin`). Cae bajo la regla **una-sesión-live** (muta el controller y
> levanta un contenedor; todo ADITIVO y reversible, limpieza en §6).

## 0. Prerrequisitos

- Rig OrbStack viva: `ziti-ctrl` + `ziti-router-er1` (ver `docs/edge-integration.md` / cualquier
  `docs/M3-*-runbook.md §1`). El echo backend en `:19009` vivo (round-trip de `testsvc-noenc`):
  `pkill -f 'ncat.*19009'; nohup ncat --listen --keep-open --exec /bin/cat 0.0.0.0 19009 &`.
- El servicio `testsvc-noenc` (host.v1 `noenc-host`, router-hosteado) + la policy `dial-all`
  (`#all/#all`) ya en la rig (no se tocan).
- Puerto **5556 libre** en el host (`lsof -iTCP:5556 -sTCP:LISTEN` vacío).
- `docker`, `curl`, `jq`, `openssl`, `ncat` en el host; `cargo` (default + `--features graviola`).

## 1. Desplegar Dex (I-001, aditivo)

```sh
cd noa-sdk   # raíz del repositorio
mkdir -p /tmp/dex && cp docs/dex/config.yaml /tmp/dex/
docker run -d --name dex --network host --restart unless-stopped \
  -v /tmp/dex/config.yaml:/etc/dex/config.yaml:ro \
  ghcr.io/dexidp/dex:v2.45.1 dex serve /etc/dex/config.yaml
docker inspect --format '{{index .RepoDigests 0}}' ghcr.io/dexidp/dex:v2.45.1   # anota el digest

# discovery sirve + issuer EXACTO (I-001), er1/ctrl intactos (sin reinicio):
until curl -fsS http://localhost:5556/dex/.well-known/openid-configuration -o /dev/null; do sleep 1; done
curl -fsS http://localhost:5556/dex/.well-known/openid-configuration | jq -r .issuer
#   -> http://host.docker.internal:5556/dex   (EXACTO; es la cadena comparada con el claim iss)
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'dex|ziti-ctrl|ziti-router-er1'
```

## 2. JWKS + mint (I-002, I-003)

```sh
# I-002 JWKS: >=1 clave RSA con kid
curl -fsS http://localhost:5556/dex/keys | jq '{n:(.keys|length), kid:.keys[0].kid, kty:.keys[0].kty}'

# I-003 mint: emite `export ZITI_EXT_JWT=<id_token>`; claims aud/email/email_verified
eval "$(bash docs/dex/mint.sh)"
echo "$ZITI_EXT_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq '{iss,aud,email,email_verified,name}'
#   -> aud=="noa-spike", email=="spike@noa.local", email_verified==true

# I-003 bad-creds-fails-loud: exit!=0, sin token exportado
DEX_PASSWORD=wrongpw bash docs/dex/mint.sh; echo "exit=$?"   # exit=1, stderr ruidoso
```

## 3. Signer + policy + identity en el controller (I-004, I-005)

```sh
ziti edge login localhost:1280 -u admin -p admin -y

# I-004 PRE-CHECK: el controller ALCANZA el JWKS por host.docker.internal (OrbStack la inyecta).
# La imagen del ctrl NO trae wget → usa curl (equivalente):
docker exec ziti-ctrl sh -c 'curl -fsS http://host.docker.internal:5556/dex/keys' | head -c 80
#   (si fallara: checkpoint rig-inaccesible con el error literal — NO improvisar IPs de gateway)

# I-004 signer: claimsProperty = email (NO el `sub` por defecto — desviación DI del PRD §1.4),
# targetToken ID, audience noa-spike:
ziti edge create ext-jwt-signer dexSpikeSigner "http://host.docker.internal:5556/dex" \
  -u "http://host.docker.internal:5556/dex/keys" -a noa-spike -c email --target-token ID

# I-005 policy + identity (externalId == el valor del claim email). Pasa el signer por ID
# (el name recién creado puede 404ear por carrera de resolución en la CLI):
SIGNER_ID=$(ziti edge list ext-jwt-signers | awk -F'│' '/dexSpikeSigner/{gsub(/ /,"",$2);print $2}')
ziti edge create auth-policy dexSpikePolicy --primary-ext-jwt-allowed --primary-ext-jwt-allowed-signers "$SIGNER_ID"
ziti edge create identity dexSpikeId --external-id "spike@noa.local" -P dexSpikePolicy
# dexSpikeId dialea testsvc-noenc vía dial-all (#all/#all). El Dial NO requiere policy propia.
```

## 4. Gate LIVE ext-jwt × Dex (I-007) — default Y graviola

```sh
# CA del controller (one-off, reusable; las fixtures no lo emiten):
curl -sk https://localhost:1280/edge/client/v1/.well-known/est/cacerts \
  | openssl base64 -d | openssl pkcs7 -inform DER -print_certs -out /tmp/ctrl-ca.pem
export ZITI_CTRL_CA=/tmp/ctrl-ca.pem

# default (aws-lc-rs) — mint FRESCO (el id_token es corto):
eval "$(bash docs/dex/mint.sh)"
cargo test --test edge_integration enrol_ext_jwt_then_connect -- --ignored --nocapture

# graviola — mint FRESCO de nuevo:
eval "$(bash docs/dex/mint.sh)"
cargo test --features graviola --test edge_integration enrol_ext_jwt_then_connect -- --ignored --nocapture

# criterio de éxito del spike: src/ INTACTO
git diff --stat -- src/    # DEBE estar vacío
```

**Salida esperada (ambos feature-sets):**

```
ext-jwt slice 1: from_ext_jwt + connect(testsvc-noenc) round-trip OK (identity=Some("dexSpikeId"))
test enrol_ext_jwt_then_connect ... ok
```

El `identity=Some("dexSpikeId")` confirma que el controller resolvió el `id_token` de Dex →
`dexSpikeSigner` (por `iss`) → claim `email` (`spike@noa.local`) → `dexSpikeId` (por `externalId`).

> **Resultado 2026-07-08:** VERDE ×2 (default + graviola), `git diff --stat -- src/` vacío.
> El JWT de Dex NO rompió el SDK (si lo hiciera, el checkpoint ES el entregable, `src/` es
> intocable — `dex-prd.md §6`).

## 5. Reuso del test (I-006)

`enrol_ext_jwt_then_connect` (`tests/edge_integration.rs`) se **reusa TAL CUAL**, sin variante:
lee el JWT SOLO de `ZITI_EXT_JWT` (valor, no ruta) y asierta `identity_name().is_some()` +
round-trip por `testsvc-noenc`. La resolución de identidad es controller-side (por el
`claimsProperty` del signer), así que el binding por `email` en vez de `sub` no cambia el test.
Cero código nuevo → no aplican los gates cargo estándar (no se añadió `.rs`).

## 6. Limpieza (reversibilidad; ejecutar solo si se quiere desmontar Dex)

```sh
ziti edge delete identity dexSpikeId; ziti edge delete auth-policy dexSpikePolicy
ziti edge delete ext-jwt-signer dexSpikeSigner
docker rm -f dex && rm -rf /tmp/dex
```

> Mientras el spike vive, el contenedor `dex` (`--restart unless-stopped`) es un **residente
> ESPERADO de la rig** (no cruft) — coordinar con la sesión de `noa-router` que comparte la rig.
