# noa-sdk

An independent Rust reimplementation of the [OpenZiti](https://openziti.io) edge client SDK,
wire-compatible with an unmodified OpenZiti controller and edge routers. It covers the client side
of the overlay (enrolment, authentication, dial/bind with end-to-end encryption) and a tunneler
layer (TCP/UDP proxy and host, plus optional host-level interception).

> **Not affiliated with NetFoundry or the OpenZiti project.** noa-sdk is not a fork: OpenZiti is
> used as the *equivalence oracle* that this implementation is tested against. On-wire identifiers
> (headers, REST paths, JWT claims, crypto constants) are OpenZiti's because interoperability
> requires them. "Ziti" and "OpenZiti" are trademarks of NetFoundry Inc., used here only to describe
> the origin of this work; the product name (`noa`) is our own. See [`NOTICE`](NOTICE).

## Status

**Research / alpha.** The API is not stable, the crate is not published on crates.io, and the code
has not had an independent security audit. Do not use it in production.

- Behaviour is validated against pinned upstream versions used as the equivalence oracle:
  `openziti/sdk-golang` **v1.7.0** (`4b6a087`) for the SDK protocol, `openziti/ziti` **v2.0.0**
  (`9bf62f3`) for the tunnel/CLI behaviour and `openziti/ziti-tunnel-sdk-c` **v1.15.1** (`2addfbb`)
  for observable tunneler parity. Some test vectors were captured by running the Go oracle.
- Test suite, measured on Linux x86_64 with Rust 1.94.1 (2026-09-24):
  - default build: **808 tests**, of which **757 run offline** and **51 are `#[ignore]`d live tests**
    that need a running OpenZiti network; `cargo test --lib`: 729 passed, 9 ignored.
  - with `--features intercept`: **1051 tests**, 56 of them live-only. Three DNS-forwarding unit
    tests of this feature bind to IPv6 loopback (`[::1]`) and fail on hosts without IPv6.
- Where noa deliberately differs from the oracle (for example stricter input validation), the
  deviation is documented next to the code.

## What it covers

- **Enrolment**: one-time token (OTT), OTT with a third-party CA (OTT-CA) and username/password
  (UPDB); EC (default) or RSA keys; additional CA bundles; token issuer validation.
- **Authentication**: certificate (mTLS), UPDB, OIDC (authorization code + PKCE, token refresh),
  external JWT (ext-jwt), and TOTP multi-factor authentication (including enrolment at login).
- **Data plane**: edge channel over mTLS to edge routers; **dial** and **bind** of services with
  end-to-end encryption (libsodium-compatible key exchange + secretstream); multi-router selection
  with latency scoring and connection pooling; session caching, refresh and retry with backoff;
  API-session certificates and their renewal; latency probes and close handling.
- **Tunneler**: TCP and UDP proxy (local listener to a service), TCP host (service to a fixed local
  target) and forwarding host driven by the service's `host.v1` config; service polling.
- **`intercept` feature** (off by default): host-level capture through a TUN device, a userspace
  TCP/IP stack, an embedded DNS server with upstream forwarding and OS route management. Pure Rust,
  no C bindings of its own. Live-validated on macOS (`utun`, needs root); it builds and its unit
  tests run on Linux.

## Build and test

Requirements: Rust **1.94.1** (pinned in `rust-toolchain.toml`) and a C/C++ compiler (needed by
`aws-lc-rs`; `cmake` is not required).

```bash
cargo build                        # library + `noa` CLI
cargo build --features intercept   # with host-level interception
cargo test --lib                   # unit tests, offline
cargo test                         # unit + integration tests; live tests stay ignored
cargo clippy --all-targets -- -D warnings
```

Live tests are marked `#[ignore]` and run against a real OpenZiti network (a controller and at least
one edge router, for example the OpenZiti quickstart in Docker). They read enrolment tokens and
endpoints from environment variables documented at the top of each test file (for example
`ZITI_EDGE_JWT`); run them explicitly with `cargo test -- --ignored <name>`. The `intercept` live
tests also need root. `docs/edge-integration.md` and `docs/enrolment-integration.md` describe the
setup.

## Usage

The `noa` binary exposes the main flows:

```text
noa enroll <token.jwt> [--out <path>] [--keyAlg RSA|EC] [--ca <ca-bundle.pem>]
noa proxy <listen_addr> <service> <identity.json>
noa proxy-udp <listen_addr> <service> <identity.json>
noa host <service> <target_addr> <identity.json>
noa host-forward <service> <identity.json>
noa intercept <utun-cidr> <identity.json>        # feature `intercept`, root
```

Minimal library example (dial a service with an identity produced by `noa enroll`). The API is
still evolving; this reflects the current public items:

```rust
use noa_sdk::edge::client::EdgeClient;
use noa_sdk::enroll::identity::Config;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg: Config = serde_json::from_str(&std::fs::read_to_string("identity.json")?)?;

    let mut client = EdgeClient::from_identity(&cfg)?;
    client.authenticate().await?;

    let mut conn = client.connect("my-service").await?;
    conn.write(b"hello").await?;
    if let Some(reply) = conn.read().await? {
        println!("{}", String::from_utf8_lossy(&reply));
    }
    Ok(())
}
```

`EdgeClient::connect` returns a `!Send` future; drive per-connection work on a
`tokio::task::LocalSet` when spawning (see `src/main.rs`).

## Cryptography

- TLS is **rustls** (no OpenSSL / native-tls).
- The single crypto backend is **aws-lc-rs** (rustls' default; FFI over AWS-LC). `ring` is kept out
  of the dependency tree.
- End-to-end payload encryption uses `dryoc` (pure Rust, byte-compatible with OpenZiti's
  secretstream).

## Contributing and security

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Please report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md), not in public issues.

## License and credits

Licensed under the **Apache License, Version 2.0** ([`LICENSE`](LICENSE)).

The wire protocol, message and header constants, enrolment flow and some test vectors derive from
OpenZiti (Apache-2.0): [`openziti/sdk-golang`](https://github.com/openziti/sdk-golang),
[`openziti/secretstream`](https://github.com/openziti/secretstream),
[`openziti/ziti`](https://github.com/openziti/ziti) and
[`openziti/ziti-tunnel-sdk-c`](https://github.com/openziti/ziti-tunnel-sdk-c). Full attribution is
in [`NOTICE`](NOTICE). Thanks to the OpenZiti maintainers for an open, well-specified system to test
against.
