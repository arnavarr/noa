//! Tunneler host appData resolver (T4b-1 + T4b-2a): turn an inbound dial's `AppData` (header 1011, the
//! tunneler `dst_*` JSON map) into the dynamic dial target (`protocol`/`address`/`port`) the host
//! should connect to, validated against the service's `host.v1` config (`forwardAddress` +
//! `allowedAddresses`, `forwardPort` + `allowedPortRanges`, fixed `protocol`).
//!
//! Oracle: `ziti/tunnel/intercept/hosting.go` `Dial` (`:385-409`, `GetProtocol`→`GetAddress`→
//! `GetPort` then `dialAddress(protocol, address+":"+port)`) + `ziti/tunnel/entities/service.go`
//! `GetProtocol`/`GetAddress`/`GetPort` (`:263-331`) + the `allowedAddress` matchers
//! (`cidrAddress`/`hostnameAddress`/`domainAddress` + `makeAllowedAddress`, `:168-215`) +
//! `ziti/tunnel/provider.go` `AppDataToMap` (`:75`, JSON `string`→`interface{}` map; called `:144`) +
//! `ziti/tunnel/const.go` (`dst_*` keys).
//!
//! **T4b-2a (matchers string-vs-IP):** this slice adds the `dst_hostname` string-matched path and the
//! full `allowedAddress` matcher type-dispatch (`cidrAddress`/`hostnameAddress`/`domainAddress`). The
//! CRUX is the oracle's `interface{}` type-dispatch (`service.go:176-200`): the inbound value's TYPE
//! decides which matcher class can match. A `dst_hostname` is a `string` → only `hostnameAddress`
//! (exact, case-insensitive) and `domainAddress` (`*` / `*.suffix`) can match it; a `cidrAddress`
//! returns `false` for a string. A `dst_ip` is a `net.IP` → only `cidrAddress` can match it. So
//! `dst_hostname="1.2.3.4"` does NOT match a CIDR `1.2.3.4/32` (it is not IP-parsed), and `dst_ip` never
//! matches a hostname/domain matcher. The oracle tries `dst_hostname` FIRST and, when present, does NOT
//! fall back to `dst_ip` on a no-match — a present-but-unmatched hostname rejects (`GetAddress`,
//! `service.go:285-308`).
//!
//! **T4b-2b (forwardProtocol):** this slice adds the `forwardProtocol` path: when set, `GetProtocol`
//! reads `dst_protocol` from the appData and validates it against `allowedProtocols` (case-sensitive
//! `stringz.Contains`), returning the resolved protocol. The resolver is protocol-AGNOSTIC (it faithfully
//! resolves `udp`); the TCP-only limitation lives at the host ([`crate::tunnel::run_tcp_host_forwarding`]),
//! which rejects a resolved non-`tcp` protocol — a CONSCIOUS, dialer-observable deviation (the oracle's
//! `dialAddress` would udp-dial it). See [`get_protocol`](crate::tunnel::resolve::hostcfg::get_protocol).
//!
//! **T4b-2c (connectTimeout):** this slice adds [`get_dial_timeout`], a faithful port of the oracle's
//! `GetDialTimeout` (`service.go:222-232`): the `host.v1` `connectTimeout` (a Go-duration string) wins
//! over `connectTimeoutSeconds` (whole seconds), and neither falls back to the host's no-config default
//! (`HOST_DIAL_TIMEOUT` = 5s). The Go-duration string is parsed by [`parse_go_duration`](crate::tunnel::resolve::timeout::parse_go_duration), a faithful port
//! of `time.ParseDuration` (the oracle parses it at config-decode via `mapstructure`'s
//! `StringToTimeDurationHookFunc`, `service.go:391`). It is computed ONCE at host startup (the oracle
//! computes `dialTimeout` once in `newHostingContext`, `hosting.go:144`), not per-dial.
//!
//! **T4b-2d-1 (forwardAddressTranslations):** this slice adds [`build_address_translations`] (a faithful
//! port of the oracle's `newHostingContext` translation build, computed ONCE at host startup) and
//! [`translate_address`] (a faithful port of `translateAddress`, applied per-dial AFTER the allow-list
//! check and BEFORE the dial). A resolved address is renumbered onto the configured `to` network — the
//! CIDR→CIDR host-bit translation of `translateIP`. So `forwardAddressTranslations` is no longer deferred.
//!
//! **T4b-2d-2 (source_addr socket bind):** a per-dial `source_addr` (appData) now binds the LOCAL end of
//! the host's outbound dial (`net.Dialer{LocalAddr}`): [`resolve_target`] parses it into the
//! [`ResolvedTarget::source_bind`] `SocketAddr` (via [`parse_source_bind`](crate::tunnel::resolve::target::parse_source_bind)) and the host
//! ([`crate::tunnel::host`]) applies it with a `TcpSocket` bind+connect. A bad source value rejects loudly
//! → DialFailed (the oracle's `dialAddress` parse). Faithfulness note: the oracle binds `source_addr`
//! UNCONDITIONALLY — it is the local end of the host's own dial, NEVER checked against an allow-list — so
//! binding without the still-deferred `allowedSourceAddresses` route setup is faithful (an already-local
//! source IP binds identically; a non-local one fails until the routes land — see below).
//!
//! **Still-deferred fail-loud contract (T4b-2d-3):** the LAST capability — the config-level
//! `allowedSourceAddresses` host routes (which `router.AddLocalAddress` source IPs onto `lo` so a NON-local
//! source IP becomes bindable; an OS-level netlink/root operation) — is REJECTED LOUDLY at startup
//! ([`check_deferred_config`]), NEVER silently ignored — so it remains a pure capability ADD, not a bug
//! fix. The reject reason is the dialer-OBSERVABLE DialFailed body (T4a proved the host's DialFailed reason
//! surfaces as the dialer's `DialRejected("...")`), so where the oracle's `Dial` returns a validation error
//! the reason string is matched BYTE-EXACT to the oracle (`GetProtocol`/`GetAddress` errors, and
//! `GetPort`'s port-range error) — with ONE named exception: `GetPort`'s non-numeric-port reason is a
//! CONSCIOUS TRUNCATION of the oracle's `errors.Wrapf` prefix (it omits Go's wrapped `strconv.Atoi` text;
//! see `get_port` deviation #1), reachable only from a non-conformant dialer.
//!
//! The `allowedAddresses` allow-list is parsed LENIENTLY per-entry, faithfully mirroring the oracle's
//! `GetAllowedAddresses` (append-on-ok / `log.Warn`-on-err, NEVER fatal, `service.go:234-249`): an
//! invalid entry is dropped, every valid one builds a matcher. A mixed list like
//! `["10.0.0.0/8","*.example.com"]` keeps BOTH a `cidrAddress` (for `dst_ip`) and a `domainAddress` (for
//! `dst_hostname`); the type-dispatch decides which participates per inbound value.
//!
//! Troceo F6 tramo 2a: este módulo era el monolito `tunnel/resolve` (2.791 líneas); se partió en
//! submódulos por dominio (`target`/`hostcfg`/`allowed`/`timeout`/`translate`/`deferred`), preservando
//! byte-a-byte las rutas públicas `tunnel::resolve::*` y las re-exportaciones de `tunnel::mod.rs`. Cada
//! tipo/`impl` vive en el dominio que lo usa (funciones puras, sin `impl` dispersos); los privados
//! llamados cross-dominio suben a `pub(super)`. Ver
//! `docs/superpowers/specs/2026-07-15-f6-tramo2-troceo-resolve-design.md` §2.1.

mod target;

mod hostcfg;

mod allowed;

mod timeout;

mod translate;

mod deferred;

#[cfg(test)]
mod tests_allowed;
#[cfg(test)]
mod tests_deferred;
#[cfg(test)]
mod tests_hostcfg;
#[cfg(test)]
mod tests_target;
#[cfg(test)]
mod tests_timeout;
#[cfg(test)]
mod tests_translate;
#[cfg(test)]
mod testsupport;

pub use target::{ResolvedTarget, resolve_target};

// Re-exported only for `tunnel::intercept::resolve` (`crate::tunnel::resolve::parse_ip_or_cidr`,
// the one symbol shared between the two resolvers); unused when the `intercept` feature is off,
// since its sole consumer (`tunnel::intercept`) is itself gated on that feature.
#[cfg(feature = "intercept")]
pub(crate) use allowed::parse_ip_or_cidr;

pub use timeout::get_dial_timeout;

pub use translate::{AddressTranslationPrefix, build_address_translations, translate_address};

pub use deferred::{DEFERRED_SOURCE_ADDR_CONFIG, check_deferred_config};
