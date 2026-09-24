# Contributing to noa-sdk

Thanks for your interest. noa-sdk is an early-stage research project, so please open an issue to
discuss larger changes before sending a pull request.

## Ground rules

- **Equivalence first.** noa-sdk must stay wire-compatible with the pinned OpenZiti versions listed
  in the README. A behaviour change should cite the upstream code it follows, or document why noa
  deliberately differs (for example stricter validation).
- **Tests.** Add or update tests with every change. Offline unit tests are preferred; changes to
  what goes on the wire also deserve a live test (`#[ignore]`, run against a real OpenZiti network).
  Do not disable or weaken existing tests.
- **Before submitting**, all of these must pass:

  ```bash
  cargo fmt --all -- --check
  cargo clippy --all-targets --locked -- -D warnings
  cargo clippy --all-targets --locked --features intercept -- -D warnings
  cargo test --locked
  ```

- **Dependencies.** Keep a single crypto backend (aws-lc-rs) and keep `ring` out of the tree. New
  dependencies must use permissive licenses compatible with Apache-2.0.
- **Security issues** go through [`SECURITY.md`](SECURITY.md), never public issues.

## License

By contributing you agree that your contributions are licensed under the Apache License,
Version 2.0, as the rest of the project.
