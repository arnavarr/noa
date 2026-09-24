#!/usr/bin/env bash
# Mint an OIDC id_token from the local Dex spike (Resource Owner Password grant).
#
# Reference: docs/specs/dex-prd.md §1.2 (OIDC observable contract) + I-003. Dex runs with
# `--network host` (issuer `http://host.docker.internal:5556/dex`), so from the host mac we
# reach the token endpoint at http://localhost:5556/dex/token; the `iss` claim baked into the
# token stays `http://host.docker.internal:5556/dex` regardless of how the endpoint is reached.
#
# Emits exactly one line on stdout: `export ZITI_EXT_JWT=<id_token>` (the JWT is short-lived).
# Fails LOUD (exit != 0 + stderr, never a token-less export) on bad creds or a missing id_token.
#
# Usage:
#   eval "$(bash docs/dex/mint.sh)"   # sets ZITI_EXT_JWT in the current shell
# Override the endpoint/creds via env if needed (DEX_TOKEN_ENDPOINT, DEX_CLIENT_ID, ...).
set -euo pipefail

TOKEN_ENDPOINT="${DEX_TOKEN_ENDPOINT:-http://localhost:5556/dex/token}"
CLIENT_ID="${DEX_CLIENT_ID:-noa-spike}"
CLIENT_SECRET="${DEX_CLIENT_SECRET:-noa-spike-secret}"
USERNAME="${DEX_USERNAME:-spike@noa.local}"
PASSWORD="${DEX_PASSWORD:-password}"

resp="$(curl -fsS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d grant_type=password \
  -d 'scope=openid email profile' \
  --data-urlencode "username=${USERNAME}" \
  --data-urlencode "password=${PASSWORD}" \
  "${TOKEN_ENDPOINT}")" || {
    echo "mint: token request to ${TOKEN_ENDPOINT} failed (bad credentials or Dex unreachable)" >&2
    exit 1
  }

id_token="$(printf '%s' "${resp}" | jq -r '.id_token // empty')"
if [ -z "${id_token}" ]; then
  echo "mint: no id_token in response: ${resp}" >&2
  exit 1
fi

echo "export ZITI_EXT_JWT=${id_token}"
