//! Live enrolment against a real controller. Ignored by default; see
//! docs/enrolment-integration.md. Run with: `cargo test --test integration_orbstack -- --ignored`.

use noa_sdk::enroll::{self, identity::Config, ott::EnrollOptions};
use std::path::PathBuf;

fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("set {key} to a JWT path")))
}

fn assert_valid_identity(c: &Config) {
    assert!(c.zt_api.starts_with("http"), "ztAPI present");
    assert!(c.id.key.starts_with("pem:"), "key has pem: prefix");
    assert!(c.id.cert.contains("CERTIFICATE"), "cert present");
    assert!(c.id.ca.contains("CERTIFICATE"), "ca bundle present");
    // The controller returns the client cert AS A CHAIN (leaf + issuing CA), so
    // parse the whole PEM chain (not a single cert) and require the leaf is present.
    let pem = c.id.cert.trim_start_matches("pem:");
    let chain =
        x509_cert::Certificate::load_pem_chain(pem.as_bytes()).expect("issued cert chain parses");
    assert!(!chain.is_empty(), "at least the leaf cert is present");
}

#[tokio::test]
#[ignore = "requires a live OpenZiti controller (OrbStack); see docs/enrolment-integration.md"]
async fn rust_enrolment_produces_valid_identity() {
    let jwt = std::fs::read_to_string(env_path("ZITI_RUST_JWT")).unwrap();
    let config = enroll::ott::enroll(jwt.trim(), EnrollOptions::default())
        .await
        .expect("rust enrolment succeeds");
    assert_valid_identity(&config);
}

#[tokio::test]
#[ignore = "requires the upstream `ziti` CLI + live controller; structural equivalence check"]
async fn go_enrolment_is_structurally_equivalent() {
    let go_jwt = env_path("ZITI_GO_JWT");
    let go_out = go_jwt.with_extension("json");
    let status = std::process::Command::new("ziti")
        .args([
            "enroll",
            "identity",
            go_jwt.to_str().unwrap(),
            "--out",
            go_out.to_str().unwrap(),
        ])
        .status()
        .expect("run upstream ziti enroll");
    assert!(status.success(), "upstream enrol failed");
    let go_config: Config =
        serde_json::from_str(&std::fs::read_to_string(&go_out).unwrap()).unwrap();
    assert_valid_identity(&go_config);
}
