# Live enrolment integration test

Validates the `ott` enrolment end-to-end against a **real OpenZiti controller**.
This is the true equivalence gate: the TLS trust flow (bootstrap leaf capture,
JWT verify, leaf-pinned cacerts fetch, CSR POST) only runs here.

Requires the upstream `ziti` CLI and a container runtime (OrbStack).

## 1. Start a controller in OrbStack

Enrolment is control-plane only, so a controller alone is enough (no router).
The official `openziti/ziti-controller` image auto-bootstraps PKI/DB from env vars:

```bash
docker run -d --name ziti-ctrl \
  -p 1280:1280 \
  -e ZITI_CTRL_ADVERTISED_ADDRESS=localhost \
  -e ZITI_CTRL_ADVERTISED_PORT=1280 \
  -e ZITI_PWD=admin \
  -e ZITI_BOOTSTRAP=true \
  -e ZITI_BOOTSTRAP_DATABASE=true \
  -e ZITI_BOOTSTRAP_CLUSTER=true \
  -e ZITI_CLUSTER_TRUST_DOMAIN=ziti-test \
  -e ZITI_CLUSTER_NODE_NAME=ctrl1 \
  openziti/ziti-controller:latest
# wait until logs show "cluster initialized successfully":
docker logs ziti-ctrl 2>&1 | tail -3
```

## 2. Log in and mint two enrolment JWTs

`ott` tokens are single-use, so we enroll two freshly-minted tokens (one per side).

```bash
ziti edge login localhost:1280 -u admin -p admin -y
ziti edge create identity rust-test -o /tmp/rust-test.jwt
ziti edge create identity go-test   -o /tmp/go-test.jwt
```

## 3. Run the ignored test

```bash
ZITI_RUST_JWT=/tmp/rust-test.jwt ZITI_GO_JWT=/tmp/go-test.jwt \
  cargo test -p ziti-tunnel --test integration_orbstack -- --ignored --nocapture
```

The test enrolls the Rust token with our crate and the Go token with the upstream
`ziti enroll identity` CLI, then asserts both identity JSONs have `ztAPI` and
non-empty `id.key`/`id.cert`/`id.ca`, and that the issued cert **chain** parses
(the controller returns leaf + issuing CA). Equivalence = both enrolments succeed
and produce usable identities (not byte-equality — the tokens and key algorithms
differ: ours EC P-384, upstream RSA-4096).

## 4. Tear down

```bash
docker rm -f ziti-ctrl
```
