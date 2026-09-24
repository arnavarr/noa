#!/usr/bin/env bash
# B4 — checklist de paridad dominio->oraculo, generado.
#
# Ver docs/superpowers/specs/2026-07-28-estado-determinista-design.md §4 para el
# diseño completo (taxonomia, columnas, derivacion de `estado`, modos). Este script
# es la UNICA fuente de docs/paridad-oraculo.md: el .md se genera, no se edita a mano.
#
# D-4: solo git/grep/awk/sed en su interseccion BSD/GNU (sin `-P`), mas
# sort/wc/xargs/mktemp; nunca rg/fd (en un shell NO interactivo `rg` no existe).
# No compila, no toca la rig, no llama a la red.
#
# INVARIANTES CON rc EXPLICITO (§4.1, H-E del paso 4, MEDIDO): en bash 3.2 `set -e` no
# cruza una sustitucion de comandos, asi que una invariante escrita como `return 1`
# dentro de una funcion consumida por `$( )` es INERTE. Reglas de construccion de este
# fichero, sin excepcion:
#   1. La generacion escribe a FICHERO con invocacion DIRECTA y el llamante inspecciona
#      el exit (`|| return $?`); JAMAS `var=$(generar)` fiando el aborto a errexit.
#   2. Todo `grep` distingue sus exits: 0/1 = resultado legitimo (1 = 0 coincidencias),
#      >=2 = fichero ausente del worktree o ilegible => ABORTA con mensaje.
#   3. Todo conteo se valida NUMERICO antes de compararse.
#   4. Un indice SIN FUSIONAR aborta: `git ls-files -u` triplica rutas y las sumas
#      cuadrarian en falso.
#   5. `--escribir` genera a un temporal EN EL MISMO DIRECTORIO y solo hace `mv` con
#      exit 0: un aborto no puede dejar el doc mutilado.
#
# Modos: --generar | --check | --verificar-oraculo | --escribir
set -euo pipefail
export LC_ALL=C

REPO_ROOT="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
cd "$REPO_ROOT"

DOC_PATH="docs/paridad-oraculo.md"

TEST_ATTR_PATTERN='^[[:space:]]*#\[(tokio::)?test[^a-z_]'
IGNORE_ATTR_PATTERN='^[[:space:]]*#\[ignore'
# §4.3 (2ª correccion): el import se lee SOLO de lineas `use noa_sdk::…`; la prosa no
# puntua (un comentario que MENCIONA `noa_sdk::channel` volteaba la fila a `hecho`,
# contra D-5 — medido).
USE_ANCHOR='^[[:space:]]*use[[:space:]]+noa_sdk::'
SYM_PATTERN='noa_sdk::[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)?'

TMP=$(mktemp -d)
WRITE_TMP=""
cleanup() {
  rm -rf "$TMP"
  if [ -n "$WRITE_TMP" ]; then rm -f "$WRITE_TMP"; fi
  return 0
}
trap cleanup EXIT

# --- mapa declarado: dominio|oraculo|nota|espera_live (Sec.4.2, Sec.4.4; D-6) --------
# `oraculo` y `nota` son DECLARADOS (no se miden); `espera_live` tambien (D-6): "si"
# cuando el dominio produce o consume bytes del cable del controller/router (o del SO
# en modo privilegiado), "no" cuando es logica local pura o una fachada.
# PRECEDENCIA (§4.4): si ambas clausulas aplican (una fachada CUYOS run_* mueven
# bytes, p.ej. `tunnel`), GANA "produce/consume bytes" => "si" (under-permit: puede
# salir `parcial`, jamas `hecho` de mas).
read_map() {
  cat <<'MAP_EOF'
(raiz)|-|fachada de la lib + CLI del bin; sin contraparte 1:1 en el oraculo|no
channel|sdk-golang@4b6a087:ziti/edge/channel.go||si
edge|sdk-golang@4b6a087:ziti/ziti.go||si
edge/bind|sdk-golang@4b6a087:ziti/edge/network/listener.go||si
edge/channel|sdk-golang@4b6a087:ziti/edge/channel.go||si
edge/client|sdk-golang@4b6a087:ziti/ziti.go||si
edge/conn|sdk-golang@4b6a087:ziti/edge/network/conn.go||si
edge/data|sdk-golang@4b6a087:ziti/edge/network/conn.go||si
edge/oidc|sdk-golang@4b6a087:edge-apis/oidc.go||si
edge/refresh|sdk-golang@4b6a087:ziti/ziti.go||si
edge/session_refresh|sdk-golang@4b6a087:ziti/ziti.go||si
enroll|sdk-golang@4b6a087:ziti/enroll||si
tunnel|ziti-tunnel-sdk-c@2addfbb:lib/ziti-tunnel/ziti_tunnel.c|fachada de funciones run_*; la logica vive en los subdominios|si
tunnel/host|sdk-golang@4b6a087:ziti/edge/network/hosting_conn.go||si
tunnel/intercept|ziti-tunnel-sdk-c@2addfbb:lib/ziti-tunnel/intercept.c|incluye dns_tcp, beyond-oracle (RFC 7766)|si
tunnel/resolve|ziti@9bf62f3:tunnel/dns/server.go|matcher/DNS local|no
tunnel/udp|ziti@9bf62f3:tunnel/udp_vconn/manager.go|gate live real = M3-UDP, que importa tunnel::intercept y no tunnel::udp|si
MAP_EOF
}

# --- alias oraculo -> ruta del clon local (Sec.4.2; verificacion AL PIN) ------------
# Un alias del mapa SIN fila aqui es un mapa roto, no un clon ausente: se reporta como
# ALIAS DESCONOCIDO (exit 1), no como SALTADO (m4).
# Rutas configurables: ORACLES_DIR (por defecto `../.oracles` junto al repo, donde viven
# los clones de sdk-golang y ziti-tunnel-sdk-c) y ZITI_SRC_DIR (clon de openziti/ziti,
# por defecto /tmp/zsrc/ziti).
ORACLES_DIR="${ORACLES_DIR:-$REPO_ROOT/../.oracles}"
ZITI_SRC_DIR="${ZITI_SRC_DIR:-/tmp/zsrc/ziti}"
oracle_clone_path() {
  case "$1" in
    sdk-golang) printf '%s\n' "$ORACLES_DIR/sdk-golang" ;;
    ziti-tunnel-sdk-c) printf '%s\n' "$ORACLES_DIR/ziti-tunnel-sdk-c" ;;
    ziti) printf '%s\n' "$ZITI_SRC_DIR" ;;
    *) return 1 ;;
  esac
}

# --- censo del arbol: helpers con rc explicito --------------------------------------

# Un merge conflictivo triplica rutas en `git ls-files` y las sumas CUADRAN en falso.
check_index_merged() {
  local n
  n=$(git ls-files -u | wc -l | tr -d ' ')
  if [ "$n" != "0" ]; then
    echo "ÍNDICE SIN FUSIONAR: $n entradas en conflicto (git ls-files -u). Resuelve el merge antes de medir." >&2
    return 1
  fi
}

# El pathspec va SIN magia :(glob) (medido, Sec.4.1: con :(glob) el censo colapsa a 2
# ficheros en silencio). El `sort -u` es cinturon sobre check_index_merged.
list_src_files() { git ls-files 'src/*.rs' | sort -u; }
list_test_files() { git ls-files 'tests/*.rs' | sort -u; }

# Imprime el numero de coincidencias; rc 1 (con mensaje) si el grep fallo de verdad.
count_matches() {
  local pattern="$1" file="$2" n rc=0
  n=$(grep -cE "$pattern" "$file" 2>/dev/null) || rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "GREP FALLÓ (rc=$rc) sobre '$file': ¿fichero del índice ausente del worktree, o ilegible?" >&2
    return 1
  fi
  case "$n" in
    '' | *[!0-9]*)
      echo "CONTEO NO NUMÉRICO ('$n') sobre '$file'" >&2
      return 1
      ;;
  esac
  printf '%s\n' "$n"
}

# Imprime las lineas que casan (0 lineas es legitimo); rc 1 si el grep fallo de verdad.
grep_lines() {
  local pattern="$1" file="$2" rc=0
  grep -E "$pattern" "$file" || rc=$?
  if [ "$rc" -ge 2 ]; then
    echo "GREP FALLÓ (rc=$rc) sobre '$file': ¿fichero del índice ausente del worktree, o ilegible?" >&2
    return 1
  fi
  return 0
}

is_number() {
  case "${1:-}" in
    '' | *[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

# dominio(fichero) — Sec.4.1: NF>=4 => $2/$3 · NF==3 => $2 · si no => (raiz).
domain_of_stream() {
  awk -F'/' '{ if (NF>=4) print $2"/"$3; else if (NF==3) print $2; else print "(raiz)" }'
}

# domain|ficheros|tests medido sobre list_src_files.
measure_files_tests() {
  list_src_files | while IFS= read -r f; do
    local dom t
    dom=$(printf '%s\n' "$f" | domain_of_stream)
    if ! t=$(count_matches "$TEST_ATTR_PATTERN" "$f"); then exit 1; fi
    printf '%s\t1\t%s\n' "$dom" "$t"
  done | awk -F'\t' '{fc[$1]+=$2; tc[$1]+=$3} END{for (d in fc) print d"|"fc[d]"|"tc[d]}'
}

# (a) ficheros de src/ con >=1 #[ignore]: cubren su propio dominio.
measure_live_src() {
  list_src_files | while IFS= read -r f; do
    local c
    if ! c=$(count_matches "$IGNORE_ATTR_PATTERN" "$f"); then exit 1; fi
    if [ "$c" -gt 0 ]; then printf '%s\n' "$f" | domain_of_stream; fi
  done
}

# (b) ficheros de tests/ con >=1 #[ignore]: cubren cada dominio que IMPORTAN con un
# `use noa_sdk::…` (deduplicado por fichero: un import repetido no cuenta 2 veces).
measure_live_tests() {
  list_test_files | while IFS= read -r f; do
    local c uses
    if ! c=$(count_matches "$IGNORE_ATTR_PATTERN" "$f"); then exit 1; fi
    [ "$c" -gt 0 ] || continue
    if ! uses=$(grep_lines "$USE_ANCHOR" "$f"); then exit 1; fi
    [ -n "$uses" ] || continue
    # `|| true`: el grep lee una CADENA en memoria, no un fichero; 0 coincidencias es
    # el unico negativo posible y es legitimo.
    printf '%s\n' "$uses" |
      { grep -ohE "$SYM_PATTERN" || true; } |
      while IFS= read -r sym; do
        local a b
        a=$(printf '%s\n' "$sym" | awk -F'::' '{print $2}')
        b=$(printf '%s\n' "$sym" | awk -F'::' '{print $3}')
        if [ -n "$b" ] && [ -d "src/$a/$b" ]; then
          printf '%s\n' "$a/$b"
        else
          printf '%s\n' "$a"
        fi
      done | sort -u
  done
}

# domain|live — Sec.4.3: live = num de FICHEROS distintos que cubren el dominio.
measure_live() {
  {
    measure_live_src || exit 1
    measure_live_tests || exit 1
  } | sort | uniq -c | awk '{printf "%s|%s\n", $2, $1}'
}

# Combina mapa + medidas -> filas sin ordenar en $1:
# "dominio|oraculo|ficheros|tests|live|estado|nota".
# Aborta (exit 1, "DOMINIO SIN MAPA: <dominio>") si el censo encuentra un dominio sin
# fila en el mapa declarado (Sec.4.1: sin esto, la mutacion discriminante de G4 no
# pondria nada en rojo).
build_rows() {
  local out="$1" rc=0
  read_map > "$TMP/map.psv"
  measure_files_tests > "$TMP/ft.psv" || return $?
  measure_live > "$TMP/live.psv" || return $?

  awk -F'|' '
    FNR==1 { filenum++ }
    filenum==1 { oraculo[$1]=$2; nota[$1]=$3; espera[$1]=$4; inmap[$1]=1; next }
    filenum==2 {
      if (!($1 in inmap)) {
        print "DOMINIO SIN MAPA: " $1 > "/dev/stderr"
        exit 1
      }
      ficheros[$1]=$2; tests[$1]=$3; next
    }
    filenum==3 { live[$1]=$2; next }
    END {
      for (d in ficheros) {
        tst = tests[d] + 0
        lv  = live[d] + 0
        if (tst == 0) { estado = "pendiente" }
        else if (espera[d] == "si" && lv == 0) { estado = "parcial" }
        else { estado = "hecho" }
        printf "%s|%s|%s|%s|%s|%s|%s\n", d, oraculo[d], ficheros[d], tst, lv, estado, nota[d]
      }
    }
  ' "$TMP/map.psv" "$TMP/ft.psv" "$TMP/live.psv" > "$out" || rc=$?
  return "$rc"
}

# Verifica que ficheros/tests de la tabla sumen los totales del censo (Sec.4.1: la
# particion exhaustiva es invariante del script, no solo del gate G4). El total de
# tests se computa por una via INDEPENDIENTE del bucle por fichero: si viniera del
# mismo bucle, la comprobacion seria tautologica.
verify_partition() {
  local rows="$1" total_files total_tests sum_files sum_tests rc=0
  total_files=$(list_src_files | wc -l | tr -d ' ')
  : > "$TMP/tt.err"
  total_tests=$(list_src_files | tr '\n' '\0' |
    xargs -0 grep -hcE "$TEST_ATTR_PATTERN" 2>"$TMP/tt.err" |
    awk '{s+=$1} END{print s+0}') || rc=$?
  if [ -s "$TMP/tt.err" ]; then
    echo "CENSO DE TESTS NO FIABLE: grep escribió en stderr:" >&2
    cat "$TMP/tt.err" >&2
    return 1
  fi
  # rc 0 = hubo coincidencias; 1 (grep) y 123 (xargs) = algun batch sin ninguna, ambos
  # legitimos. Cualquier otro rc es un fallo real de xargs.
  case "$rc" in
    0 | 1 | 123) : ;;
    *)
      echo "CENSO DE TESTS NO FIABLE: xargs/grep abortó con rc=$rc" >&2
      return 1
      ;;
  esac
  sum_files=$(awk -F'|' '{s+=$3} END{print s+0}' "$rows")
  sum_tests=$(awk -F'|' '{s+=$4} END{print s+0}' "$rows")
  local v
  for v in "$total_files" "$total_tests" "$sum_files" "$sum_tests"; do
    if ! is_number "$v"; then
      echo "CONTEO NO NUMÉRICO en la verificación de partición ('$v')" >&2
      return 1
    fi
  done
  if [ "$sum_files" != "$total_files" ] || [ "$sum_tests" != "$total_tests" ]; then
    echo "PARTICION NO EXHAUSTIVA: ficheros $sum_files/$total_files, tests $sum_tests/$total_tests" >&2
    return 1
  fi
}

TABLE_HEADER='| dominio | oraculo | ficheros | tests | live | estado | nota |'
TABLE_ALIGN='|---|---|---:|---:|---:|:--|---|'

generate_table() {
  build_rows "$TMP/rows.psv" || return $?
  verify_partition "$TMP/rows.psv" || return $?
  printf '%s\n' "$TABLE_HEADER"
  printf '%s\n' "$TABLE_ALIGN"
  # -t'|' -k1,1: ordena SOLO por el campo dominio (LC_ALL=C). Ordenar por la línea
  # entera compararía el '|' separador (0x7C) contra el '/' de un dominio con
  # subcarpeta (0x2F) e invertiría "edge" respecto a "edge/bind" (medido).
  sort -t'|' -k1,1 "$TMP/rows.psv" |
    awk -F'|' '{printf "| %s | %s | %s | %s | %s | %s | %s |\n", $1,$2,$3,$4,$5,$6,$7}'
}

generate_header() {
  cat <<'HEADER_EOF'
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

HEADER_EOF
}

# La atomicidad cubre a TODOS los productores del fichero (3a correccion, §4.1 n.4): el
# rc de la CABECERA se inspecciona igual que el de la tabla. Blindar solo la mitad
# "tabla" dejaba la clase H-D abierta por la otra puerta — un fallo de escritura de la
# cabecera (ENOSPC) daba `ESCRITO … exit 0` con el doc DECAPITADO (medido con un stub).
# Con el llamante usando `|| rc=$?`, errexit NO actua aqui: el rc explicito es la unica
# guarda (regla de construccion n.1 de la cabecera de este fichero).
build_full_doc_to() {
  local out="$1" rc=0
  generate_header > "$out" || return $?
  generate_table >> "$out" || rc=$?
  return "$rc"
}

cmd_generar() {
  generate_table
}

# --escribir ATOMICO (§4.1 nº5): temporal EN EL MISMO DIRECTORIO que el doc (mismo
# volumen => `mv` atomico; el mktemp por defecto cae en otro volumen), trap de borrado,
# y `mv` SOLO con exit 0. Un aborto no puede dejar el doc mutilado (antes: DOMINIO SIN
# MAPA truncaba el doc a cabecera-sin-tabla y la cola aconsejaba re-ejecutar el
# destructor).
cmd_escribir() {
  local rc=0
  WRITE_TMP=$(mktemp "$DOC_PATH.XXXXXX")
  build_full_doc_to "$WRITE_TMP" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "ESCRITURA ABORTADA (el generador salió con $rc): $DOC_PATH NO se ha tocado" >&2
    return 1
  fi
  chmod 644 "$WRITE_TMP"
  mv "$WRITE_TMP" "$DOC_PATH"
  WRITE_TMP=""
  echo "ESCRITO: $DOC_PATH" >&2
}

cmd_check() {
  local rc=0
  build_full_doc_to "$TMP/new.md" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "PARIDAD NO VERIFICABLE (el generador salió con $rc)" >&2
    return 1
  fi
  if [ ! -e "$DOC_PATH" ]; then
    echo "PARIDAD DESACTUALIZADA (fichero ausente: $DOC_PATH)"
    return 1
  fi
  if [ ! -f "$DOC_PATH" ] || [ ! -r "$DOC_PATH" ]; then
    echo "DOC ILEGIBLE (no es un fichero regular legible): $DOC_PATH" >&2
    return 1
  fi
  # Comparacion de FICHEROS (no de `$(cat …)`): asi el newline final tambien cuenta.
  if cmp -s "$DOC_PATH" "$TMP/new.md"; then
    echo "PARIDAD OK"
    return 0
  fi
  echo "PARIDAD DESACTUALIZADA"
  # Se imprime TODA linea [+-] del diff (cabecera incluida), saltando solo las dos
  # lineas de cabecera del propio formato unificado: un filtro /^[+-][^+-]/ era ciego a
  # las vinetas de la cabecera del doc (`+- pendiente si …`).
  { diff -u "$DOC_PATH" "$TMP/new.md" || true; } | awk 'NR<=2 { next } /^[+-]/ { print }'
  return 1
}

# --verificar-oraculo: cada cita declarada del mapa (excepto "-") debe existir EN SU
# PIN (git cat-file -e <pin>:<ruta>, no test -e sobre el working tree). PASS <=> exit 0.
# Orden de comprobacion (2a correccion): alias -> clon -> PIN -> ruta. El clon efimero
# es SHALLOW: sin el chequeo del pin ANTES de la ruta, un re-clon en otro tip daria
# CITA FALSA (rojo mentiroso) en vez de SALTADO/BLOQUEADO.
# Todos los resultados salen por STDOUT (canal unico; el exit lleva la clase).
cmd_verificar_oraculo() {
  local any_falsa=0 any_saltado=0 any_alias=0
  local dom oraculo repo rest pin path clone
  while IFS='|' read -r dom oraculo _nota _espera; do
    [ "$oraculo" = "-" ] && continue
    repo="${oraculo%%@*}"
    rest="${oraculo#*@}"
    pin="${rest%%:*}"
    path="${rest#*:}"
    if ! clone=$(oracle_clone_path "$repo"); then
      echo "ALIAS DESCONOCIDO: $repo -> $dom (el mapa declara un alias sin ruta de clon)"
      any_alias=1
      continue
    fi
    if ! git -C "$clone" rev-parse --git-dir >/dev/null 2>&1; then
      echo "SALTADO (clon ausente): $repo -> $dom"
      any_saltado=1
      continue
    fi
    if ! git -C "$clone" cat-file -e "$pin^{commit}" 2>/dev/null; then
      echo "SALTADO (pin ausente): $repo@$pin -> $dom (clon presente pero sin el pin; re-clonar en el pin — el clon efímero es SHALLOW)"
      any_saltado=1
      continue
    fi
    if git -C "$clone" cat-file -e "$pin:$path" 2>/dev/null; then
      : # cita viva
    else
      echo "CITA FALSA: $dom -> $repo@$pin:$path"
      any_falsa=1
    fi
  done < <(read_map)

  if [ "$any_alias" -eq 1 ]; then
    return 1
  elif [ "$any_falsa" -eq 1 ]; then
    return 1
  elif [ "$any_saltado" -eq 1 ]; then
    return 2
  else
    echo "ORACULO OK (todas las citas del mapa resuelven en su pin)"
    return 0
  fi
}

usage() {
  cat >&2 <<'USAGE_EOF'
uso: paridad-oraculo.sh --generar|--check|--verificar-oraculo|--escribir
  --verificar-oraculo lee los clones de ORACLES_DIR (defecto: ../.oracles junto al repo)
  y ZITI_SRC_DIR (defecto: /tmp/zsrc/ziti).
USAGE_EOF
}

main() {
  local mode="${1:-}"
  case "$mode" in
    --generar | --check | --escribir)
      check_index_merged || exit 1
      ;;
  esac
  case "$mode" in
    --generar) cmd_generar ;;
    --check) cmd_check ;;
    --verificar-oraculo) cmd_verificar_oraculo ;;
    --escribir) cmd_escribir ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
