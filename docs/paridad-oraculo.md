# Paridad oráculo (B4)

**fichero GENERADO: no se edita a mano.** Se regenera con:
`bash scripts/paridad-oraculo.sh --escribir`

Checklist dominio -> estado del port frente al oráculo. Diseño completo en
`docs/superpowers/specs/2026-07-28-estado-determinista-design.md` §4; este fichero es
su salida, no una copia de la explicación.

## Taxonomía de dominios (§4.1)

`dominio(fichero)` para cada fichero de `git ls-files 'src/*.rs'` (pathspec SIN magia
`:(glob)`), partiendo por `/`: NF>=4 => `$2/$3` · NF==3 => `$2` · si no => `(raiz)`. Es
decir: subdirectorio de segundo nivel si existe, módulo de primer nivel si no, y
`(raiz)` para `src/*.rs`.

## Columnas

`ficheros` y `tests` se MIDEN (censo del árbol); `oraculo` y `nota` son DECLARADOS (mapa
del script); `live` se MIDE (§4.3); `estado` se DERIVA (abajo).

## Cómo se cuenta `tests`, y con qué NO se cuadra (D-3)

`tests` se cuenta **estáticamente** (atributos `#[test]` / `#[tokio::test]` en
`src/*.rs`), no con `cargo test -- --list`: el conteo estático es cfg-independiente,
instantáneo y corre en frío sin compilar. El `HANDOFF.md` registra además los conteos
de la suite COMPILADA, distintos por cfg (`default` e `intercept`). **Las tres cifras
miden cosas distintas y no deben «cuadrarse»**: una diferencia entre ellas no es
deriva.

## Derivación de `estado` (§4.4)

- `pendiente` si `tests == 0`.
- `parcial` si `tests > 0`, el mapa declara `espera_live = si` y `live == 0`.
- `hecho` en el resto.

`espera_live` es un dato DECLARADO en el mapa del script (D-6): sí cuando el dominio
produce o consume bytes del cable del controller/router (o del SO en modo
privilegiado); no cuando es lógica local pura o una fachada. Si ambas cláusulas aplican
(una fachada cuyos `run_*` mueven bytes), gana «produce/consume bytes» ⇒ `sí`.

## Qué mide `live`, y qué NO (§4.3, D-5)

Un fichero es «de gate live» si tiene >=1 atributo `#[ignore]`. Cubre un dominio si (a)
está DENTRO del dominio (`src/<dominio>/…`), o (b) está en `tests/` y lo IMPORTA con un
`use noa_sdk::a(::b)?` (resuelto a `a/b` si `src/a/b` es directorio, `a` si no; la
prosa NO puntúa: solo las líneas `use`).
**`live == 0` significa «ningún gate live NOMBRA este dominio», NO «no se ejercita»**:
p. ej. `tunnel/udp` sale `0` aunque su gate real es M3-UDP, porque
`tests/intercept_m3_udp.rs` importa `tunnel::intercept` y no `tunnel::udp` (ver su
`nota`).

## Tabla

| dominio | oraculo | ficheros | tests | live | estado | nota |
|---|---|---:|---:|---:|:--|---|
| (raiz) | - | 2 | 12 | 0 | hecho | fachada de la lib + CLI del bin; sin contraparte 1:1 en el oraculo |
| channel | sdk-golang@4b6a087:ziti/edge/channel.go | 6 | 17 | 0 | parcial |  |
| edge | sdk-golang@4b6a087:ziti/ziti.go | 13 | 102 | 4 | hecho |  |
| edge/bind | sdk-golang@4b6a087:ziti/edge/network/listener.go | 9 | 17 | 1 | hecho |  |
| edge/channel | sdk-golang@4b6a087:ziti/edge/channel.go | 10 | 39 | 0 | parcial |  |
| edge/client | sdk-golang@4b6a087:ziti/ziti.go | 18 | 96 | 7 | hecho |  |
| edge/conn | sdk-golang@4b6a087:ziti/edge/network/conn.go | 11 | 35 | 1 | hecho |  |
| edge/data | sdk-golang@4b6a087:ziti/edge/network/conn.go | 13 | 63 | 0 | parcial |  |
| edge/oidc | sdk-golang@4b6a087:edge-apis/oidc.go | 16 | 38 | 0 | parcial |  |
| edge/refresh | sdk-golang@4b6a087:ziti/ziti.go | 14 | 18 | 0 | parcial |  |
| edge/session_refresh | sdk-golang@4b6a087:ziti/ziti.go | 10 | 17 | 0 | parcial |  |
| enroll | sdk-golang@4b6a087:ziti/enroll | 9 | 52 | 5 | hecho |  |
| tunnel | ziti-tunnel-sdk-c@2addfbb:lib/ziti-tunnel/ziti_tunnel.c | 2 | 3 | 1 | hecho | fachada de funciones run_*; la logica vive en los subdominios |
| tunnel/host | sdk-golang@4b6a087:ziti/edge/network/hosting_conn.go | 8 | 14 | 0 | parcial |  |
| tunnel/intercept | ziti-tunnel-sdk-c@2addfbb:lib/ziti-tunnel/intercept.c | 102 | 234 | 5 | hecho | incluye dns_tcp, beyond-oracle (RFC 7766) |
| tunnel/resolve | ziti@9bf62f3:tunnel/dns/server.go | 14 | 84 | 0 | hecho | matcher/DNS local |
| tunnel/udp | ziti@9bf62f3:tunnel/udp_vconn/manager.go | 10 | 21 | 0 | parcial | gate live real = M3-UDP, que importa tunnel::intercept y no tunnel::udp |
