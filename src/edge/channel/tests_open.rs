//! Tests de `tls_addrs`, del filtro 4c en dial/bind, y de la selección primer-router de
//! `open_channel` (bind). (F6 tramo 6: movidos verbatim del monolito de `edge/channel`.)

use std::sync::Arc;

use crate::edge::client::EdgeClient;
use crate::edge::error::EdgeError;
use crate::edge::router_filter::EdgeRouterUrlFilter;

use super::open::tls_addrs;
use super::testsupport::{detail_with, er};

// ----- tls_addrs / open_channel first-router selection (bind-path regression) -----

#[test]
fn tls_addrs_collects_every_tls_router_in_order() {
    let d = detail_with(vec![
        er("r1", Some("tls:a:1")),
        er("r2", None), // no tls → skipped
        er("r3", Some("tls:c:3")),
    ]);
    assert_eq!(
        tls_addrs(&d, None),
        vec!["tls:a:1".to_string(), "tls:c:3".to_string()]
    );
}

#[test]
fn tls_addrs_empty_when_no_tls_router() {
    let d = detail_with(vec![er("r1", None)]);
    assert!(tls_addrs(&d, None).is_empty());
}

// ----- slice 4c: the `EdgeRouterUrlFilter` (oracle `options.go:47`, applied at `ziti.go:1710`
// (dial) and `ziti.go:2528-2533` (bind)). The filter can only REMOVE routers: under-permit, never
// over-permit. Everything is asserted on STATE (the router set, the surfaced error, the TLS-open
// counter), never on logs.

/// A filter that ACCEPTS only the urls it names. The `EdgeRouterUrlFilter` type is
/// `Arc<dyn Fn(&str) -> bool + Send + Sync>` (the oracle's `func(string) bool`).
fn accept_only(urls: &'static [&'static str]) -> EdgeRouterUrlFilter {
    Arc::new(move |u: &str| urls.contains(&u))
}

fn reject_all() -> EdgeRouterUrlFilter {
    Arc::new(|_: &str| false)
}

/// ★ POSITIVE control (anti-no-op) of the dial-side filter: with NO filter installed the dial's
/// router set is UNCHANGED — the oracle's `EdgeRouterUrlFilter == nil ⇒ accept` (`options.go:51`),
/// which is what makes this slice a no-op for every existing client. MUTATION → RED: invert the
/// `None` default in `is_edge_router_url_accepted` (reject when no filter is installed) — the dial
/// set collapses to 0.
#[test]
fn url_filter_absent_leaves_the_dial_router_set_unchanged() {
    let d = detail_with(vec![er("r1", Some("tls:a:1")), er("r2", Some("tls:b:2"))]);
    assert_eq!(tls_addrs(&d, None).len(), 2);
}

/// The dial's router set keeps ONLY the urls the filter accepts, and the filter is consulted with
/// the ROUTER'S OWN url (`isEdgeRouterUrlAccepted(addr)`, `ziti.go:1710`). Selective (not
/// accept-all/reject-all), so it also pins the ARGUMENT. MUTATION → RED: drop the `.filter(..)` in
/// `tls_addrs` (both routers survive), or consult the filter with anything but the router's url.
#[test]
fn url_filter_keeps_only_the_accepted_routers_in_the_dial_set() {
    let d = detail_with(vec![er("r1", Some("tls:a:1")), er("r2", Some("tls:b:2"))]);
    assert_eq!(
        tls_addrs(&d, Some(&accept_only(&["tls:b:2"]))),
        vec!["tls:b:2".to_string()],
        "the dial set keeps only the filter-accepted router url"
    );
}

/// END-TO-END on the DIAL path: a filter that rejects EVERY router makes `connect`'s channel opener
/// fail with `NoTlsEdgeRouter` and open ZERO TLS channels — the candidate set is empty before any
/// scoring or fan-out (DV-4c-REJECTALL: the oracle instead BLOCKS until its connect-timeout).
/// Non-vacuous: the routers' addresses are UNPARSEABLE, so WITHOUT the filter the fan-out reaches
/// `parse_tls_address`, whose `ChannelError::AddressParse` surfaces as `EdgeError::Channel` naming a
/// router (that is exactly what the existing `empty_edge_routers_*` tests rely on). Needs the cert
/// identity so `channel_client_config()` builds offline (else the mutation would fail earlier, on
/// `IdentityLoad`). MUTATION → RED: don't apply the filter in `tls_addrs` ⇒ the error becomes
/// `Channel` (address parse), not `NoTlsEdgeRouter`.
#[tokio::test]
async fn url_filter_rejecting_every_router_makes_connect_fail_with_no_tls_edge_router() {
    let mut client = EdgeClient::for_test_with_cert_identity("http://x/edge/client/v1", "API-TOK");
    client.set_edge_router_url_filter(Some(reject_all()));
    let d = detail_with(vec![er("r1", Some("tls:bad1")), er("r2", Some("tls:bad2"))]);

    let err = client
        .open_or_reuse_pooled_channel(&d)
        .await
        .map(|_| ())
        .unwrap_err();
    assert!(
        matches!(err, EdgeError::NoTlsEdgeRouter),
        "a filter rejecting every router leaves NO dial candidate: {err:?}"
    );
    assert_eq!(
        client.tls_channel_opens(),
        0,
        "a rejected router is never dialed (no TLS handshake attempted)"
    );
}

/// The BIND path's first-router pick also honors the filter — the oracle SKIPS a non-accepted url
/// and keeps looking (`if !isEdgeRouterUrlAccepted(routerUrl) { continue }`, `ziti.go:2528-2533`), it
/// does NOT give up. Same observation seam as `open_channel_selects_the_first_tls_router` (its
/// POSITIVE control: with no filter, `badfirst` is picked): both addresses are unparseable, so the
/// surfaced error NAMES the router that was picked. MUTATION → RED: don't apply the filter in
/// `open_channel` ⇒ `badfirst` is picked again.
#[tokio::test]
async fn url_filter_is_applied_to_the_bind_first_router_pick() {
    let mut client = EdgeClient::for_test_with("http://x/edge/client/v1", "API-TOK");
    client.set_edge_router_url_filter(Some(accept_only(&["tls:badsecond"])));
    let d = detail_with(vec![
        er("r1", Some("tls:badfirst")), // rejected by the filter → SKIPPED, not fatal
        er("r2", Some("tls:badsecond")),
    ]);

    let err = client.open_channel(&d).await.map(|_| ()).unwrap_err();
    let s = err.to_string();
    assert!(
        s.contains("badsecond") && !s.contains("badfirst"),
        "bind must SKIP the filter-rejected router and pick the next accepted one: {s}"
    );
}

/// The BIND path with EVERY router rejected ⇒ `NoTlsEdgeRouter` (the oracle's loop finds no usable
/// url). The other half of the pair with the test above: together they pin "skip, then give up only
/// when nothing is left". MUTATION → RED: don't apply the filter ⇒ `badfirst` is dialed and the error
/// is a `Channel` parse failure naming it.
#[tokio::test]
async fn url_filter_rejecting_every_router_makes_bind_fail_with_no_tls_edge_router() {
    let mut client = EdgeClient::for_test_with("http://x/edge/client/v1", "API-TOK");
    client.set_edge_router_url_filter(Some(reject_all()));
    let d = detail_with(vec![er("r1", Some("tls:badfirst"))]);

    let err = client.open_channel(&d).await.map(|_| ()).unwrap_err();
    assert!(
        matches!(err, EdgeError::NoTlsEdgeRouter),
        "a filter rejecting every router leaves NO bind candidate: {err:?}"
    );
}

#[tokio::test]
async fn open_channel_no_tls_router_is_no_tls_edge_router() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "API-TOK");
    let d = detail_with(vec![er("r1", None)]);
    // EdgeChannel is not Debug, so map the Ok away before unwrap_err.
    let err = client.open_channel(&d).await.map(|_| ()).unwrap_err();
    assert!(matches!(err, EdgeError::NoTlsEdgeRouter));
}

// The bind path's contract is unchanged by slice 10c / the pool: `open_channel` selects the FIRST
// tls router, NOT the race, and never touches the pool. Observable without a live router: two
// UNPARSEABLE tls addrs fail in `parse_tls_address` (which runs before `client_config`/TLS) and
// name themselves, so the FIRST router's address surfaces. A regression routing `open_channel`
// through the raced/pooled opener would surface the LAST address (`select_ok`'s all-fail returns
// the last error).
#[tokio::test]
async fn open_channel_selects_the_first_tls_router() {
    let client = EdgeClient::for_test_with("http://x/edge/client/v1", "API-TOK");
    let d = detail_with(vec![
        er("r1", Some("tls:badfirst")), // no port → parse fails naming it
        er("r2", Some("tls:badsecond")),
    ]);
    let err = client.open_channel(&d).await.map(|_| ()).unwrap_err();
    let s = err.to_string();
    assert!(
        s.contains("badfirst") && !s.contains("badsecond"),
        "open_channel must use the FIRST tls router (not the race): {s}"
    );
}
