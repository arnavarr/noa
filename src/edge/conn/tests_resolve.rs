//! Tests de `resolve` (F6 tramo 5: movidos verbatim del monolito de `edge/conn`).

use super::*;
use crate::edge::error::EdgeError;
use crate::edge::model::Service;

fn svc(id: &str, name: &str, enc: bool) -> Service {
    Service {
        id: id.into(),
        name: name.into(),
        encryption_required: enc,
        permissions: vec![],
        config: serde_json::Map::new(),
        configs: vec![],
    }
}

#[test]
fn resolve_finds_exact_name() {
    let services = vec![svc("a", "alpha", false), svc("b", "testsvc", true)];
    let found = resolve_service(&services, "testsvc").unwrap();
    assert_eq!(found.id, "b");
    assert!(found.encryption_required);
}

#[test]
fn resolve_is_case_sensitive() {
    let services = vec![svc("b", "testsvc", true)];
    let err = resolve_service(&services, "TestSvc").unwrap_err();
    assert!(matches!(err, EdgeError::ServiceNotFound(n) if n == "TestSvc"));
}

#[test]
fn resolve_empty_and_no_match_are_not_found() {
    assert!(matches!(
        resolve_service(&[], "x").unwrap_err(),
        EdgeError::ServiceNotFound(_)
    ));
    let services = vec![svc("a", "alpha", false)];
    assert!(matches!(
        resolve_service(&services, "beta").unwrap_err(),
        EdgeError::ServiceNotFound(_)
    ));
}

#[test]
fn resolve_does_not_filter_by_permission() {
    // A service with NO Dial permission still resolves; the controller (not us) rejects
    // the dial at create_session. Faithful to the oracle (no local Permissions pre-check).
    let services = vec![svc("b", "bindonly", false)];
    assert_eq!(resolve_service(&services, "bindonly").unwrap().id, "b");
}
