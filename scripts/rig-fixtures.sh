#!/usr/bin/env bash
# rig-fixtures.sh — las 6 fixtures bindsvc (2 servicios + 4 policies) que la suite LIVE presupone
# y nunca crea: MEDIRLAS, y reponerlas sin arqueología.
#
# ⚠ Alcance (2026-08-05): SOLO esas 6. La suite live presupone además `serp-all`/`erp-all`,
# `testsvc`/`testsvc-noenc` con sus configs host.v1, y que `bindsvc` NO tenga config host
# (docs/edge-integration.md:230). Medir esas queda PENDIENTE; este script no las cubre.
#
# Por qué existe (causa raíz medida, 2026-08-05): `bindsvc` desapareció de la rig compartida por
# SEGUNDA vez (la s10 ya los había «re-creado»), y el HANDOFF seguía afirmando en prosa que estaban
# ahí. Nuestros tests live NO crean estos servicios: los PRESUPONEN. Todos son `#[ignore]`, así que
# la suite offline sigue verde y el fallo queda LATENTE hasta el próximo gate live, donde aparece
# como un rojo indistinguible de una regresión del port. Un hecho sobre un recurso COMPARTIDO entre
# tres proyectos caduca sin que nadie lo toque: por eso esto se mide, no se recuerda.
#
# ⚠ El modo de fallo que de verdad importa NO es «la policy no existe». Cuando se borra el servicio
# al que apuntaba, el controller deja la policy VIVA con `serviceRoles` **VACÍO**. Comprobar
# existencia daría VERDE sobre una policy que no autoriza nada. Por eso cada policy se valida por
# sus ROLES resueltos, no por su nombre. Ese mismo residuo es lo que rompe la idempotencia del
# runbook a mano: su `create service-policy` choca con el nombre duplicado, y por eso reponer las
# fixtures se había vuelto arqueología. `--ensure` hace `update` cuando la policy ya está.
#
# ⚠ `ziti edge list` PAGINA a 10 y la rig ya llegó a 10 servicios
# (2026-08-05): grepear la primera página daría falsos negativos. Se consulta con filtro `name in
# [...]` EXACTO, nunca `contains` ni grep sobre el listado entero.
#
# ⚠ `--ensure` escribe `--identity-roles '#all'` y un update REEMPLAZA: el contrato de estas 4
# policies ES `#all`. Si algún consumidor de la rig las acotara a propósito por atributo, cambia
# la tabla FIXTURES en vez de dejar que `--ensure` lo pise en silencio.
#
# Fail-closed, como el pre-flight de la familia: si no se puede medir (rig parada, sesión caducada)
# el veredicto es **3 ENTORNO**, jamás un verde por vacuidad. «No pude comprobarlo» y «está bien»
# son respuestas distintas.
#
# Uso:
#   bash scripts/rig-fixtures.sh              # (--check) mide. 0 verde / 1 falta algo / 3 entorno
#   bash scripts/rig-fixtures.sh --ensure     # repone lo que falte (idempotente) y re-mide
#   bash scripts/rig-fixtures.sh --control    # RB-2: demuestra que sabe salir ROJO. NO toca la rig
#
# `--control` corre la capa de evaluación contra JSON fabricado, así que **no necesita la rig**:
# el detector se puede falsar con la rig fría. Un gate que solo ha visto éxitos no ha probado su
# detector.

set -uo pipefail

CTRL="${ZITI_CTRL:-localhost:1280}"

# Las 6 fixtures, en el orden en que hay que reponerlas (servicios antes que policies: el rol
# `@nombre` no resuelve si el servicio todavía no existe).
#   servicio: nombre|service|<ON|OFF de encryptionRequired>
#   policy:   nombre|<Bind|Dial>|<servicio al que debe apuntar>
FIXTURES='bindsvc|service|OFF
bindsvc-enc|service|ON
bind-bindsvc|Bind|bindsvc
dial-bindsvc|Dial|bindsvc
bind-bindsvc-enc|Bind|bindsvc-enc
dial-bindsvc-enc|Dial|bindsvc-enc'

SERVICIOS='bindsvc bindsvc-enc'
POLICIES='bind-bindsvc dial-bindsvc bind-bindsvc-enc dial-bindsvc-enc'

rojo() { printf '  \033[31m✗\033[0m %s\n' "$*"; }
verde() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '%s\n' "$*"; }

# ─────────────────────────────────────────────────────────────────────────────
# Capa de EVALUACIÓN (pura): dos ficheros JSON -> veredicto. Sin red, sin CLI.
# Separada a propósito de la captura para que `--control` pueda falsarla en frío.
# ─────────────────────────────────────────────────────────────────────────────
evaluar() {
  local svc_json="$1" pol_json="$2"
  local faltan=0 nombre clase arg

  while IFS='|' read -r nombre clase arg; do
    [ -n "$nombre" ] || continue
    if [ "$clase" = service ]; then
      local esperado_enc
      [ "$arg" = ON ] && esperado_enc=true || esperado_enc=false
      local encontrado
      encontrado="$(jq -r --arg n "$nombre" \
        '[.data[]? | select(.name==$n)] | if length==0 then "AUSENTE" else (.[0].encryptionRequired|tostring) end' \
        "$svc_json")"
      if [ "$encontrado" = AUSENTE ]; then
        rojo "servicio '$nombre' NO EXISTE"
        faltan=$((faltan + 1))
      elif [ "$encontrado" != "$esperado_enc" ]; then
        # No se auto-repara: cambiar encryptionRequired de un servicio vivo altera el contrato
        # cripto que los tests distinguen (plano vs cifrado). Es decisión humana.
        rojo "servicio '$nombre' tiene encryptionRequired=$encontrado, se esperaba $esperado_enc (ARREGLO MANUAL)"
        faltan=$((faltan + 1))
      else
        verde "servicio '$nombre' (encryptionRequired=$encontrado)"
      fi
      continue
    fi

    # Policy. Se valida por ROLES RESUELTOS, no por existencia: una policy huérfana sobrevive
    # con serviceRoles vacío y autorizaría nada mientras aparenta estar bien.
    local svc_id veredicto
    svc_id="$(jq -r --arg n "$arg" '[.data[]? | select(.name==$n)][0].id // ""' "$svc_json")"
    veredicto="$(jq -r \
      --arg n "$nombre" --arg tipo "$clase" --arg svc "$arg" --arg sid "$svc_id" '
      [.data[]? | select(.name==$n)] as $p
      | if ($p|length)==0 then "AUSENTE"
        elif $p[0].type != $tipo then "TIPO:" + ($p[0].type // "null")
        elif (($p[0].serviceRoles // []) | length) == 0 then "SIN-ROLES"
        elif ((($p[0].serviceRolesDisplay // []) | map(.name)) as $names
              | (($p[0].serviceRoles // []) as $roles
                 | ($names | index($svc)) != null
                   or ($roles | index("@" + $svc)) != null
                   or (($sid != "") and (($roles | index("@" + $sid)) != null))))
          then (if ((($p[0].identityRoles // []) | index("#all")) == null)
                then "SIN-IDENTITY-ALL" else "OK" end)
        else "OTRO-SERVICIO" end' "$pol_json")"

    case "$veredicto" in
      OK) verde "policy '$nombre' ($clase -> @$arg)" ;;
      AUSENTE)
        rojo "policy '$nombre' NO EXISTE"
        faltan=$((faltan + 1)) ;;
      SIN-ROLES)
        # La firma exacta del borrado del servicio: la policy sobrevive, vacía.
        rojo "policy '$nombre' existe pero con serviceRoles VACÍO (huérfana: su servicio fue borrado)"
        faltan=$((faltan + 1)) ;;
      SIN-IDENTITY-ALL)
        rojo "policy '$nombre' no tiene identityRoles '#all'"
        faltan=$((faltan + 1)) ;;
      TIPO:*)
        rojo "policy '$nombre' es de tipo ${veredicto#TIPO:}, se esperaba $clase (ARREGLO MANUAL)"
        faltan=$((faltan + 1)) ;;
      *)
        rojo "policy '$nombre' apunta a otro servicio, no a '$arg' (ARREGLO MANUAL)"
        faltan=$((faltan + 1)) ;;
    esac
  done <<<"$FIXTURES"

  return $((faltan > 0 ? 1 : 0))
}

# ─────────────────────────────────────────────────────────────────────────────
# Capa de CAPTURA: habla con el controller. Exit 3 si no se puede medir.
# ─────────────────────────────────────────────────────────────────────────────
como_filtro() { # nombres -> 'name in ["a","b"]'
  local out=""
  for n in $1; do out="$out\"$n\","; done
  printf 'name in [%s]' "${out%,}"
}

capturar() {
  local dir="$1"
  command -v jq >/dev/null || { info "ENTORNO: falta 'jq'."; return 3; }
  command -v ziti >/dev/null || { info "ENTORNO: falta el CLI 'ziti'."; return 3; }

  if ! ziti edge list services "$(como_filtro "$SERVICIOS")" -j >"$dir/services.json" 2>"$dir/err"; then
    info "ENTORNO: no se pudo leer el controller en $CTRL (rig parada o sesión caducada)."
    info "         Levanta la rig y/o: ziti edge login $CTRL -u admin -p admin -y"
    info "         (últimas líneas del error)"
    tail -3 "$dir/err" | sed 's/^/         /'
    return 3
  fi
  if ! ziti edge list service-policies "$(como_filtro "$POLICIES")" -j >"$dir/policies.json" 2>"$dir/err"; then
    info "ENTORNO: no se pudieron leer las service-policies."
    tail -3 "$dir/err" | sed 's/^/         /'
    return 3
  fi
  return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Reposición IDEMPOTENTE. Crea lo ausente, ACTUALIZA lo huérfano. Re-ejecutable.
# ─────────────────────────────────────────────────────────────────────────────
reponer() {
  local dir="$1" nombre clase arg cambios=0

  while IFS='|' read -r nombre clase arg; do
    [ -n "$nombre" ] || continue
    if [ "$clase" = service ]; then
      if [ "$(jq -r --arg n "$nombre" '[.data[]?|select(.name==$n)]|length' "$dir/services.json")" = 0 ]; then
        info "  + creando servicio '$nombre' (-e $arg)"
        ziti edge create service "$nombre" -e "$arg" >/dev/null || return 3
        cambios=$((cambios + 1))
      fi
      continue
    fi
    local existe roles idall apunta svc_id
    existe="$(jq -r --arg n "$nombre" '[.data[]?|select(.name==$n)]|length' "$dir/policies.json")"
    roles="$(jq -r --arg n "$nombre" '[.data[]?|select(.name==$n)][0].serviceRoles // [] | length' "$dir/policies.json")"
    idall="$(jq -r --arg n "$nombre" '([.data[]?|select(.name==$n)][0].identityRoles // []) | index("#all") != null' "$dir/policies.json")"
    # ¿Apunta ya al servicio correcto? Misma resolución triple que `evaluar` (display, @nombre, @id).
    svc_id="$(jq -r --arg n "$arg" '[.data[]?|select(.name==$n)][0].id // ""' "$dir/services.json")"
    apunta="$(jq -r --arg n "$nombre" --arg svc "$arg" --arg sid "$svc_id" '
      [.data[]?|select(.name==$n)][0] as $p
      | ((($p.serviceRolesDisplay // []) | map(.name) | index($svc)) != null)
        or ((($p.serviceRoles // []) | index("@" + $svc)) != null)
        or (($sid != "") and ((($p.serviceRoles // []) | index("@" + $sid)) != null))' "$dir/policies.json")"
    if [ "$existe" = 0 ]; then
      info "  + creando policy '$nombre' ($clase -> @$arg)"
      ziti edge create service-policy "$nombre" "$clase" \
        --service-roles "@$arg" --identity-roles '#all' >/dev/null || return 3
      cambios=$((cambios + 1))
    elif [ "$roles" = 0 ]; then
      # Aquí es donde el runbook a mano se atascaba: `create` choca con el nombre duplicado.
      info "  ~ reparando policy huérfana '$nombre' (serviceRoles vacío -> @$arg)"
      ziti edge update service-policy "$nombre" \
        --service-roles "@$arg" --identity-roles '#all' >/dev/null || return 3
      cambios=$((cambios + 1))
    elif [ "$apunta" = true ] && [ "$idall" = false ]; then
      # SIN-IDENTITY-ALL: el mismo update de la huérfana la cura. SOLO si la policy ya apunta
      # bien: si apunta a OTRO servicio no se re-apunta a ciegas (ARREGLO MANUAL, como el tipo
      # y el encryptionRequired — algo que no reconocemos no se pisa).
      info "  ~ reponiendo identityRoles '#all' en policy '$nombre'"
      ziti edge update service-policy "$nombre" \
        --service-roles "@$arg" --identity-roles '#all' >/dev/null || return 3
      cambios=$((cambios + 1))
    fi
  done <<<"$FIXTURES"

  info "  ($cambios cambio(s) aplicado(s))"
  return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Control negativo: la evaluación contra JSON fabricado. Sin rig.
# ─────────────────────────────────────────────────────────────────────────────
control() {
  local dir; dir="$(mktemp -d)"; trap 'rm -rf "$dir"' RETURN
  local fallos=0

  # Caso 1 — el estado REAL medido el 2026-08-05: falta `bindsvc`, sobrevive `bindsvc-enc`, y
  # `dial-bindsvc` sigue viva con serviceRoles vacío. Tiene que salir ROJO.
  cat >"$dir/services.json" <<'JSON'
{"data":[{"id":"SVCENC","name":"bindsvc-enc","encryptionRequired":true}]}
JSON
  cat >"$dir/policies.json" <<'JSON'
{"data":[
 {"name":"dial-bindsvc","type":"Dial","serviceRoles":[],"identityRoles":["#all"]},
 {"name":"bind-bindsvc","type":"Bind","serviceRoles":[],"identityRoles":["#all"]},
 {"name":"bind-bindsvc-enc","type":"Bind","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]},
 {"name":"dial-bindsvc-enc","type":"Dial","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]}]}
JSON
  info "control 1/4 — estado real del 2026-08-05 (bindsvc ausente + 2 policies huérfanas):"
  if evaluar "$dir/services.json" "$dir/policies.json"; then
    info "  ⚠ CONTROL FALLIDO: dio VERDE sobre un estado roto."; fallos=$((fallos + 1))
  else
    info "  ✓ salió ROJO, como debe"
  fi

  # Caso 2 — el punto ciego que motiva el script: TODO existe por nombre, pero las policies del
  # servicio plano están huérfanas. Un check por existencia daría verde aquí.
  cat >"$dir/services.json" <<'JSON'
{"data":[{"id":"SVC","name":"bindsvc","encryptionRequired":false},
         {"id":"SVCENC","name":"bindsvc-enc","encryptionRequired":true}]}
JSON
  cat >"$dir/policies.json" <<'JSON'
{"data":[
 {"name":"bind-bindsvc","type":"Bind","serviceRoles":[],"identityRoles":["#all"]},
 {"name":"dial-bindsvc","type":"Dial","serviceRoles":["@SVC"],
  "serviceRolesDisplay":[{"name":"bindsvc","id":"SVC"}],"identityRoles":["#all"]},
 {"name":"bind-bindsvc-enc","type":"Bind","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]},
 {"name":"dial-bindsvc-enc","type":"Dial","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]}]}
JSON
  info "control 2/4 — punto ciego (existen las 6 por nombre; 'bind-bindsvc' huérfana):"
  if evaluar "$dir/services.json" "$dir/policies.json"; then
    info "  ⚠ CONTROL FALLIDO: un check por existencia habría dado verde; este también."; fallos=$((fallos + 1))
  else
    info "  ✓ salió ROJO, como debe"
  fi

  # Caso 3 — POSITIVO. Sin esto, un script que devolviera siempre ROJO pasaría los dos anteriores.
  cat >"$dir/policies.json" <<'JSON'
{"data":[
 {"name":"bind-bindsvc","type":"Bind","serviceRoles":["@SVC"],
  "serviceRolesDisplay":[{"name":"bindsvc","id":"SVC"}],"identityRoles":["#all"]},
 {"name":"dial-bindsvc","type":"Dial","serviceRoles":["@SVC"],
  "serviceRolesDisplay":[{"name":"bindsvc","id":"SVC"}],"identityRoles":["#all"]},
 {"name":"bind-bindsvc-enc","type":"Bind","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]},
 {"name":"dial-bindsvc-enc","type":"Dial","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]}]}
JSON
  info "control 3/4 — POSITIVO (las 6 sanas), para que el rojo no sea incondicional:"
  if evaluar "$dir/services.json" "$dir/policies.json" >/dev/null; then
    info "  ✓ salió VERDE, como debe"
  else
    info "  ⚠ CONTROL FALLIDO: dio ROJO sobre un estado sano."; fallos=$((fallos + 1))
  fi

  # Caso 4 — el gap medido el 2026-08-05 (auditoría de la nota de noa-router): una policy con
  # serviceRoles CORRECTOS pero identityRoles sin '#all'. `evaluar` la marcaba SIN-IDENTITY-ALL
  # y `reponer` NO la tocaba, con el epílogo mandando a `--ensure` en bucle. Este caso falsa las
  # DOS mitades: el detector (rojo) y el reparador (que emita exactamente el update que cura),
  # con `ziti` stubbeado — sigue sin necesitar la rig.
  cat >"$dir/policies.json" <<'JSON'
{"data":[
 {"name":"bind-bindsvc","type":"Bind","serviceRoles":["@SVC"],
  "serviceRolesDisplay":[{"name":"bindsvc","id":"SVC"}],"identityRoles":["#all"]},
 {"name":"dial-bindsvc","type":"Dial","serviceRoles":["@SVC"],
  "serviceRolesDisplay":[{"name":"bindsvc","id":"SVC"}],"identityRoles":["#er1"]},
 {"name":"bind-bindsvc-enc","type":"Bind","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]},
 {"name":"dial-bindsvc-enc","type":"Dial","serviceRoles":["@SVCENC"],
  "serviceRolesDisplay":[{"name":"bindsvc-enc","id":"SVCENC"}],"identityRoles":["#all"]}]}
JSON
  info "control 4/4 — identityRoles sin '#all' (el detector en ROJO y el reparador CURÁNDOLO):"
  if evaluar "$dir/services.json" "$dir/policies.json" >/dev/null; then
    info "  ⚠ CONTROL FALLIDO: dio VERDE con 'dial-bindsvc' sin '#all'."; fallos=$((fallos + 1))
  else
    info "  ✓ el detector salió ROJO, como debe"
  fi
  local stub="$dir/stub"; mkdir -p "$stub"
  printf '#!/bin/sh\necho "$*" >>"%s/cmds"\n' "$dir" >"$stub/ziti"; chmod +x "$stub/ziti"
  : >"$dir/cmds"
  ( PATH="$stub:$PATH" reponer "$dir" >/dev/null )
  if grep -qx 'edge update service-policy dial-bindsvc --service-roles @bindsvc --identity-roles #all' "$dir/cmds" \
      && [ "$(grep -c . "$dir/cmds")" = 1 ]; then
    info "  ✓ el reparador emite EXACTAMENTE el update que la cura (y nada más)"
  else
    info "  ⚠ CONTROL FALLIDO: reponer no cura SIN-IDENTITY-ALL ($(grep -c . "$dir/cmds") comando(s) emitido(s))."
    fallos=$((fallos + 1))
  fi

  [ "$fallos" = 0 ] || { info ""; info "CONTROL ROJO: $fallos caso(s) mal. El detector NO es de fiar."; return 1; }
  info ""
  info "CONTROL VERDE: el detector distingue sano de roto, y caza la policy huérfana."
  return 0
}

main() {
  case "${1:---check}" in
    --control) control; exit $? ;;
    --check|--ensure) : ;;
    *) info "uso: $0 [--check|--ensure|--control]"; exit 2 ;;
  esac

  local dir; dir="$(mktemp -d)"; trap 'rm -rf "$dir"' EXIT
  capturar "$dir" || exit 3

  if [ "${1:---check}" = --ensure ]; then
    info "Reponiendo fixtures que falten (idempotente):"
    reponer "$dir" || { info "ENTORNO: falló una escritura contra el controller."; exit 3; }
    info ""
    info "Re-midiendo tras reponer:"
    capturar "$dir" || exit 3
  fi

  if evaluar "$dir/services.json" "$dir/policies.json"; then
    info ""
    info "VERDE: las 6 fixtures live (2 servicios + 4 policies) existen y autorizan."
    exit 0
  fi
  info ""
  info "ROJO: faltan fixtures. La suite live está CONDENADA hasta reponerlas — y su rojo"
  info "      es indistinguible de una regresión del port, así que no la corras antes."
  info "      Reponer: bash scripts/rig-fixtures.sh --ensure"
  exit 1
}

main "$@"
