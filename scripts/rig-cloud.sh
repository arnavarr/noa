#!/usr/bin/env bash
# rig-cloud.sh — rig OpenZiti de pruebas LIVE en una VM Linux limpia (root + Docker), equivalente a
# la rig de desarrollo: controller `ziti-ctrl` (:1280, admin/admin), edge router `ziti-router-er1`
# (`--tunneler-enabled`, :3022) y el eco TCP `echo4b` (:19009), más las fixtures que la suite live
# PRESUPONE y nunca crea (docs/edge-integration.md).
#
# Versiones: las del oráculo del repo (openziti/ziti v2.0.0). El CLI `ziti` del host se EXTRAE de la
# propia imagen del controller (mismo binario v2.0.0), así no hace falta alcanzar GitHub.
#
# Uso:
#   bash scripts/rig-cloud.sh up        # arranca dockerd si hace falta, levanta la rig y repone fixtures
#   bash scripts/rig-cloud.sh status    # mide: contenedores, router online, fixtures, terminators
#   bash scripts/rig-cloud.sh down      # borra los 3 contenedores (conserva volúmenes y dockerd)
#   bash scripts/rig-cloud.sh down --purge   # además borra los volúmenes (PKI + BD del controller)
#
# Idempotente: `up` re-ejecutado sobre una rig viva no crea nada nuevo; lo que ya existe se
# re-sincroniza (`update`) para que un er1 re-creado no deje las policies `@er1` huérfanas.
#
# Exit: 0 verde · 1 algo falta tras reponer · 3 entorno (Docker/controller inalcanzable).
#
# ⚠ Lo que esto NO monta (tests live que seguirán sin ejecutarse): la CA `ottca`, identidades
# `updb`, el IdP externo de ext-jwt (Dex), el fixture MFA `mfaspike` y las políticas de auth de
# enroll-at-login. Esos requieren pasos manuales documentados junto a cada test.

set -uo pipefail

ZITI_VERSION="${ZITI_VERSION:-2.0.0}"
IMG_CTRL="openziti/ziti-controller:${ZITI_VERSION}"
IMG_ROUTER="openziti/ziti-router:${ZITI_VERSION}"
IMG_ECHO="python:3-alpine"
CTRL="localhost:1280"
ADMIN_USER="admin"
ADMIN_PWD="admin"
ER_NAME="er1"
C_CTRL="ziti-ctrl"
C_ROUTER="ziti-router-er1"
C_ECHO="echo4b"
V_CTRL="ziti-ctrl-data"
V_ROUTER="ziti-router-er1-data"
ECHO_PORT=19009
AQUI="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

info() { printf '%s\n' "$*"; }
ok() { printf '  [OK] %s\n' "$*"; }
ko() { printf '  [FALTA] %s\n' "$*"; }
muere() { printf 'ENTORNO: %s\n' "$*" >&2; exit 3; }

# ─────────────────────────────────────────────────────────────────────────────
# Docker y CLI
# ─────────────────────────────────────────────────────────────────────────────
asegurar_dockerd() {
  command -v docker >/dev/null || muere "falta el cliente 'docker'."
  if docker info >/dev/null 2>&1; then return 0; fi
  command -v dockerd >/dev/null || muere "el daemon de Docker no responde y no hay 'dockerd'."
  info "Arrancando dockerd (persistente, log en /var/log/dockerd.log)..."
  nohup dockerd >/var/log/dockerd.log 2>&1 &
  local i
  for i in $(seq 1 60); do docker info >/dev/null 2>&1 && return 0; sleep 1; done
  muere "dockerd no respondió en 60 s (ver /var/log/dockerd.log)."
}

asegurar_imagen() {
  docker image inspect "$1" >/dev/null 2>&1 || docker pull -q "$1" >/dev/null || muere "no se pudo descargar $1"
}

asegurar_cli() {
  if command -v ziti >/dev/null && [ "$(ziti version 2>/dev/null)" = "v${ZITI_VERSION}" ]; then return 0; fi
  info "Extrayendo el CLI 'ziti' v${ZITI_VERSION} de ${IMG_CTRL} a /usr/local/bin/ziti..."
  local id
  id="$(docker create "$IMG_CTRL")" || muere "no se pudo crear un contenedor de ${IMG_CTRL}"
  docker cp "$id:/usr/local/bin/ziti" /usr/local/bin/ziti >/dev/null || { docker rm "$id" >/dev/null; muere "docker cp del CLI falló"; }
  docker rm "$id" >/dev/null
  chmod +x /usr/local/bin/ziti
}

existe_contenedor() { docker container inspect "$1" >/dev/null 2>&1; }
corriendo() { [ "$(docker container inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

esperar_controller() {
  local i
  for i in $(seq 1 90); do
    curl -skf "https://${CTRL}/.well-known/est/cacerts" >/dev/null 2>&1 && return 0
    sleep 2
  done
  muere "el controller no sirve /.well-known/est/cacerts en ${CTRL} tras 180 s."
}

login() {
  ziti edge login "$CTRL" -u "$ADMIN_USER" -p "$ADMIN_PWD" -y >/dev/null 2>&1 \
    || muere "ziti edge login contra ${CTRL} falló."
}

# ─────────────────────────────────────────────────────────────────────────────
# Contenedores
# ─────────────────────────────────────────────────────────────────────────────
subir_controller() {
  if existe_contenedor "$C_CTRL"; then
    corriendo "$C_CTRL" || docker start "$C_CTRL" >/dev/null
  else
    info "Creando ${C_CTRL} (${IMG_CTRL})..."
    docker run -d --name "$C_CTRL" --network host --restart unless-stopped \
      -e ZITI_CTRL_ADVERTISED_ADDRESS=localhost -e ZITI_CTRL_ADVERTISED_PORT=1280 \
      -e ZITI_PWD="$ADMIN_PWD" -e ZITI_BOOTSTRAP=true -e ZITI_BOOTSTRAP_DATABASE=true \
      -e ZITI_BOOTSTRAP_CLUSTER=true -e ZITI_CLUSTER_TRUST_DOMAIN=ziti-test \
      -e ZITI_CLUSTER_NODE_NAME=ctrl1 -v "${V_CTRL}:/ziti-controller" \
      "$IMG_CTRL" >/dev/null || muere "docker run ${C_CTRL} falló."
  fi
  esperar_controller
  # El bootstrap de la BD puede ir unos segundos por detrás del listener HTTPS.
  local i
  for i in $(seq 1 30); do
    ziti edge login "$CTRL" -u "$ADMIN_USER" -p "$ADMIN_PWD" -y >/dev/null 2>&1 && return 0
    sleep 2
  done
  muere "ziti edge login contra ${CTRL} no funcionó en 60 s."
}

n_filtro() { # tipo filtro -> nº de resultados (usa filtro EXACTO: `list` pagina a 10)
  ziti edge list "$1" "$2" -j 2>/dev/null | jq -r '.data | length'
}

subir_router() {
  local n_ctrl
  n_ctrl="$(n_filtro edge-routers "name=\"${ER_NAME}\"")"
  if existe_contenedor "$C_ROUTER" && [ "$n_ctrl" = 1 ]; then
    corriendo "$C_ROUTER" || docker start "$C_ROUTER" >/dev/null
  else
    # Estado incoherente (contenedor sin router en el controller o al revés): se re-crea entero.
    # Las policies `@er1` se re-sincronizan después en `fixtures_base`.
    info "Creando edge router ${ER_NAME} (${IMG_ROUTER})..."
    docker rm -f "$C_ROUTER" >/dev/null 2>&1
    docker volume rm "$V_ROUTER" >/dev/null 2>&1
    [ "$n_ctrl" = 1 ] && ziti edge delete edge-router "$ER_NAME" >/dev/null
    ziti edge create edge-router "$ER_NAME" --tunneler-enabled -o "$TMP/er1.jwt" >/dev/null \
      || muere "no se pudo crear el edge router ${ER_NAME}."
    docker run -d --name "$C_ROUTER" --network host --restart unless-stopped \
      -e ZITI_CTRL_ADVERTISED_ADDRESS=localhost -e ZITI_CTRL_ADVERTISED_PORT=1280 \
      -e ZITI_ENROLL_TOKEN="$(cat "$TMP/er1.jwt")" \
      -e ZITI_ROUTER_ADVERTISED_ADDRESS=localhost -e ZITI_ROUTER_PORT=3022 \
      -e ZITI_ROUTER_NAME="$ER_NAME" -e ZITI_BOOTSTRAP=true -v "${V_ROUTER}:/ziti-router" \
      "$IMG_ROUTER" >/dev/null || muere "docker run ${C_ROUTER} falló."
  fi
  local i
  for i in $(seq 1 60); do
    [ "$(ziti edge list edge-routers "name=\"${ER_NAME}\"" -j 2>/dev/null | jq -r '.data[0].isOnline')" = true ] && return 0
    sleep 2
  done
  muere "el edge router ${ER_NAME} no aparece ONLINE tras 120 s (docker logs ${C_ROUTER})."
}

subir_echo() {
  if existe_contenedor "$C_ECHO"; then
    corriendo "$C_ECHO" || docker start "$C_ECHO" >/dev/null
  else
    info "Creando ${C_ECHO} (eco TCP en :${ECHO_PORT})..."
    docker run -d --name "$C_ECHO" --network host --restart unless-stopped "$IMG_ECHO" python3 -c "
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d=self.request.recv(4096)
            if not d: break
            self.request.sendall(d)
socketserver.ThreadingTCPServer.allow_reuse_address=True
socketserver.ThreadingTCPServer(('0.0.0.0',${ECHO_PORT}),H).serve_forever()
" >/dev/null || muere "docker run ${C_ECHO} falló."
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Fixtures (idempotentes: crear si falta, `update` si ya está)
# ─────────────────────────────────────────────────────────────────────────────
config() { # nombre tipo json
  if [ "$(n_filtro configs "name=\"$1\"")" = 0 ]; then
    ziti edge create config "$1" "$2" "$3" >/dev/null || muere "create config $1"
  else
    ziti edge update config "$1" --data "$3" >/dev/null || muere "update config $1"
  fi
}

servicio() { # nombre ON|OFF configs(coma)
  if [ "$(n_filtro services "name=\"$1\"")" = 0 ]; then
    ziti edge create service "$1" -e "$2" --configs "$3" >/dev/null || muere "create service $1"
  else
    ziti edge update service "$1" --configs "$3" >/dev/null || muere "update service $1"
  fi
}

sp() { # nombre Bind|Dial service-roles identity-roles
  if [ "$(n_filtro service-policies "name=\"$1\"")" = 0 ]; then
    ziti edge create service-policy "$1" "$2" --service-roles "$3" --identity-roles "$4" >/dev/null \
      || muere "create service-policy $1"
  else
    ziti edge update service-policy "$1" --service-roles "$3" --identity-roles "$4" >/dev/null \
      || muere "update service-policy $1"
  fi
}

fixtures_base() {
  info "Reponiendo fixtures base (policies de router, testsvc*, fwdsvc*)..."
  if [ "$(n_filtro edge-router-policies 'name="erp-all"')" = 0 ]; then
    ziti edge create edge-router-policy erp-all --identity-roles '#all' --edge-router-roles '#all' >/dev/null || muere "erp-all"
  fi
  if [ "$(n_filtro service-edge-router-policies 'name="serp-all"')" = 0 ]; then
    ziti edge create service-edge-router-policy serp-all --service-roles '#all' --edge-router-roles '#all' >/dev/null || muere "serp-all"
  fi
  sp dial-all Dial '#all' '#all'

  # testsvc (cifrado) y testsvc-noenc (plano), hosteados por el tunneler de er1 contra echo4b.
  config testcfg intercept.v1 '{"protocols":["tcp"],"addresses":["test.ziti"],"portRanges":[{"low":80,"high":80}]}'
  config enc-host host.v1 "{\"protocol\":\"tcp\",\"address\":\"localhost\",\"port\":${ECHO_PORT}}"
  config noenc-host host.v1 "{\"protocol\":\"tcp\",\"address\":\"localhost\",\"port\":${ECHO_PORT}}"
  servicio testsvc ON testcfg,enc-host
  servicio testsvc-noenc OFF noenc-host
  sp bind-enc Bind '@testsvc' "@${ER_NAME}"
  sp bind-noenc Bind '@testsvc-noenc' "@${ER_NAME}"

  # Familia fwdsvc (tunneler T4b): Bind SOLO para identidades '#t4bhost' (el host del test), para
  # que el auto-host de er1 no compita por el terminator. Atributo de rol SIEMPRE literal inline.
  local rango='"forwardPort":true,"allowedPortRanges":[{"low":1,"high":65535}]'
  config fwdsvc-host host.v1 "{\"protocol\":\"tcp\",\"forwardAddress\":true,\"allowedAddresses\":[\"127.0.0.1/32\"],${rango}}"
  config fwdsvc-xlat-host host.v1 "{\"protocol\":\"tcp\",\"forwardAddress\":true,\"allowedAddresses\":[\"10.0.0.0/8\"],\"forwardAddressTranslations\":[{\"from\":\"10.0.0.0\",\"to\":\"127.0.0.0\",\"prefixLength\":24}],${rango}}"
  config fwdsvc-hn-host host.v1 "{\"protocol\":\"tcp\",\"forwardAddress\":true,\"allowedAddresses\":[\"localhost\"],${rango}}"
  config fwdsvc-fp-host host.v1 "{\"protocol\":\"tcp\",\"forwardProtocol\":true,\"allowedProtocols\":[\"tcp\"],\"forwardAddress\":true,\"allowedAddresses\":[\"127.0.0.1/32\"],${rango}}"
  config fwdsvc-ct-host host.v1 "{\"protocol\":\"tcp\",\"forwardAddress\":true,\"allowedAddresses\":[\"127.0.0.1/32\"],${rango},\"listenOptions\":{\"connectTimeout\":\"10s\"}}"
  local s
  for s in fwdsvc fwdsvc-xlat fwdsvc-hn fwdsvc-fp fwdsvc-ct; do
    servicio "$s" OFF "${s}-host"
    sp "bind-${s}" Bind "@${s}" '#t4bhost'
    sp "dial-${s}" Dial "@${s}" '#all'
  done

  # Las 6 fixtures bindsvc las mide y repone su script dedicado.
  bash "$AQUI/rig-fixtures.sh" --ensure >"$TMP/fixtures.log" 2>&1
  local rc=$?
  [ "$rc" = 0 ] || { cat "$TMP/fixtures.log"; return "$rc"; }
  return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# Medición
# ─────────────────────────────────────────────────────────────────────────────
terminator_de() { # servicio -> ID del terminator de er1 (vacío si no hay)
  ziti edge list terminators "service.name=\"$1\"" -j 2>/dev/null \
    | jq -r --arg r "$ER_NAME" '[.data[]? | select(.router.name==$r)][0].id // ""'
}

esperar_terminators() {
  # Tras un arranque en frío los terminators del tunneler de er1 tardan en aparecer (o quedan
  # rancios); se espera por ID con techo de 240 s y, si no aparecen, se reinicia er1 una vez.
  local i s falta reiniciado=0
  for i in $(seq 1 120); do
    falta=0
    for s in testsvc testsvc-noenc; do [ -n "$(terminator_de "$s")" ] || falta=1; done
    [ "$falta" = 0 ] && return 0
    if [ "$i" = 60 ] && [ "$reiniciado" = 0 ]; then
      info "  (sin terminators a los 120 s: docker restart ${C_ROUTER})"
      docker restart "$C_ROUTER" >/dev/null; reiniciado=1
    fi
    sleep 2
  done
  return 1
}

medir() {
  local rojo=0 c s t
  info "Contenedores:"
  for c in "$C_CTRL" "$C_ROUTER" "$C_ECHO"; do
    if corriendo "$c"; then ok "$c ($(docker container inspect -f '{{.Config.Image}}' "$c"))"; else ko "$c no corre"; rojo=1; fi
  done
  if ! curl -skf "https://${CTRL}/.well-known/est/cacerts" >/dev/null 2>&1; then
    ko "controller ${CTRL} no responde"; return 3
  fi
  login
  info "Controller ${CTRL}: $(curl -sk "https://${CTRL}/edge/client/v1/version" | jq -r '.data.version // "?"')"
  if [ "$(ziti edge list edge-routers "name=\"${ER_NAME}\"" -j | jq -r '.data[0].isOnline')" = true ]; then
    ok "edge router ${ER_NAME} ONLINE"
  else
    ko "edge router ${ER_NAME} no está ONLINE"; rojo=1
  fi
  if printf 'ping' | nc -w2 127.0.0.1 "$ECHO_PORT" 2>/dev/null | grep -q ping; then
    ok "eco TCP 127.0.0.1:${ECHO_PORT}"
  else
    ko "eco TCP 127.0.0.1:${ECHO_PORT} no responde"; rojo=1
  fi
  info "Terminators (por ID):"
  for s in testsvc testsvc-noenc; do
    t="$(terminator_de "$s")"
    if [ -n "$t" ]; then ok "$s -> $t"; else ko "$s sin terminator de ${ER_NAME}"; rojo=1; fi
  done
  info "Fixtures bindsvc (scripts/rig-fixtures.sh):"
  if bash "$AQUI/rig-fixtures.sh" --check >"$TMP/check.log" 2>&1; then
    ok "rig-fixtures.sh --check rc=0"
  else
    ko "rig-fixtures.sh --check rc=$?"; sed 's/^/    /' "$TMP/check.log"; rojo=1
  fi
  return "$rojo"
}

cmd_up() {
  command -v jq >/dev/null || muere "falta 'jq'."
  command -v curl >/dev/null || muere "falta 'curl'."
  asegurar_dockerd
  asegurar_imagen "$IMG_CTRL"; asegurar_imagen "$IMG_ROUTER"; asegurar_imagen "$IMG_ECHO"
  asegurar_cli
  subir_controller
  subir_router
  subir_echo
  fixtures_base || { info "ROJO: no se pudieron reponer las fixtures bindsvc."; exit 1; }
  info "Esperando terminators de er1 (testsvc, testsvc-noenc)..."
  esperar_terminators || info "  AVISO: siguen sin terminators; ver docker logs ${C_ROUTER}."
  info ""
  medir; local rc=$?
  [ "$rc" = 0 ] && info "" && info "RIG ARRIBA: verde."
  exit "$rc"
}

cmd_status() {
  docker info >/dev/null 2>&1 || { info "ENTORNO: el daemon de Docker no responde."; exit 3; }
  command -v ziti >/dev/null || { info "ENTORNO: falta el CLI 'ziti' (bash $0 up lo instala)."; exit 3; }
  medir; exit $?
}

cmd_down() {
  docker info >/dev/null 2>&1 || { info "ENTORNO: el daemon de Docker no responde."; exit 3; }
  docker rm -f "$C_ECHO" "$C_ROUTER" "$C_CTRL" >/dev/null 2>&1
  info "Contenedores borrados (${C_CTRL}, ${C_ROUTER}, ${C_ECHO}); dockerd sigue corriendo."
  if [ "${1:-}" = --purge ]; then
    docker volume rm "$V_CTRL" "$V_ROUTER" >/dev/null 2>&1
    info "Volúmenes borrados (${V_CTRL}, ${V_ROUTER}): el próximo 'up' re-crea PKI y BD."
  fi
}

case "${1:-}" in
  up) cmd_up ;;
  status) cmd_status ;;
  down) shift; cmd_down "${1:-}" ;;
  *) info "uso: $0 {up|status|down [--purge]}"; exit 2 ;;
esac
