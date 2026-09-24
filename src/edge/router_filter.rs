//! `EdgeRouterUrlFilter` — the consumer-supplied hook that decides which edge-router URLs this client
//! is allowed to open a channel to. Faithful port of the oracle's `Options.EdgeRouterUrlFilter`
//! (`sdk-golang@4b6a087 ziti/options.go:47`) and its accessor `isEdgeRouterUrlAccepted`
//! (`options.go:50-51`), whose contract is exactly:
//!
//! ```go
//! func (self *Options) isEdgeRouterUrlAccepted(url string) bool {
//!     return self.EdgeRouterUrlFilter == nil || self.EdgeRouterUrlFilter(url)   // :51
//! }
//! ```
//!
//! **`nil` (our `None`) ⇒ ACCEPT EVERY URL** — the default (`DefaultOptions` never sets the field,
//! `options.go:54-59`), so a client that never installs a filter behaves byte-identically to before this
//! slice. The filter can only ever *remove* routers from the candidate set: its direction is
//! **under-permit, never over-permit** (and opening a channel is not authorization anyway — every dial
//! and bind still carries the controller-minted session token).

use std::sync::Arc;

/// A consumer-supplied predicate over an edge-router protocol URL: `true` = usable.
/// Mirror of the oracle's `EdgeRouterUrlFilter func(string) bool` (`options.go:47`). `Arc` + `Send + Sync`
/// because the router-selection paths that consult it are shared across tasks.
///
/// **FORM of the url the filter receives: the SANITIZED one, `tls:host:port`** — never the
/// `tls://host:port` the controller emits. The rewrite `://` → `:` happens upstream, in the oracle
/// at `sanitizeSessionUrls` (`ziti/client.go:534`) and here at `sanitize_supported_protocols`
/// (`crate::edge::model`), before any enumeration site consults this predicate. The «always» is
/// about what the SDK produces: a consumer that hand-builds a `SessionDetail` and skips the
/// sanitize step feeds this predicate whatever it wrote — the tests below do exactly that, on
/// purpose, since to the predicate a url is an opaque string.
pub type EdgeRouterUrlFilter = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Is this edge-router URL usable by this client? Literal mirror of `isEdgeRouterUrlAccepted`
/// (`options.go:50-51`): **no filter installed ⇒ accept** (the oracle's `== nil ||` short-circuit).
pub(crate) fn is_edge_router_url_accepted(filter: Option<&EdgeRouterUrlFilter>, url: &str) -> bool {
    filter.is_none_or(|f| f(url))
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1: &str = "tls://r1:443";
    const R2: &str = "tls://r2:443";

    /// A filter that rejects everything EXCLUDES the url (the `EdgeRouterUrlFilter(url)` arm of
    /// `options.go:51`). MUTATION → RED: ignore the filter (`fn(..) -> true`), i.e. never consult it.
    #[test]
    fn a_filter_rejecting_the_url_excludes_it() {
        let reject_all: EdgeRouterUrlFilter = Arc::new(|_| false);
        assert!(!is_edge_router_url_accepted(Some(&reject_all), R1));
        assert!(!is_edge_router_url_accepted(Some(&reject_all), R2));
    }

    /// ★ POSITIVE control (anti-no-op) of the test above: with NO filter every url is ACCEPTED — the
    /// oracle's `EdgeRouterUrlFilter == nil ||` default (`options.go:51`), which is what keeps a
    /// filter-less client identical to before this slice. MUTATION → RED: invert the `None` default
    /// (`filter.is_some_and(..)`), i.e. reject when no filter is installed.
    #[test]
    fn an_absent_filter_accepts_every_url() {
        assert!(is_edge_router_url_accepted(None, R1));
        assert!(is_edge_router_url_accepted(None, R2));
    }

    /// The filter is called WITH THE URL and its per-url verdict is honored (not a constant). Pins the
    /// ARGUMENT, which the two tests above cannot: they would both stay green under an implementation
    /// that calls `f("")`. MUTATION → RED: pass anything but the url (or collapse to a constant verdict).
    #[test]
    fn a_selective_filter_accepts_only_the_urls_it_names() {
        let only_r2: EdgeRouterUrlFilter = Arc::new(|u: &str| u == R2);
        assert!(!is_edge_router_url_accepted(Some(&only_r2), R1));
        assert!(is_edge_router_url_accepted(Some(&only_r2), R2));
    }
}
