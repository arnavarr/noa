/// Derive the OIDC base (`https://host[:port]`) from the ztAPI base_url
/// (`https://host:port/edge/client/v1`). The OIDC endpoints live at the controller ROOT
/// (`/oidc/...`), not under the edge path. Best-effort: on a parse failure returns the base_url
/// verbatim (the subsequent OIDC GET then errors visibly). `pub(crate)` since OIDC-3: the proactive
/// timer (`run_refreshes`, in `edge::refresh`) derives the OIDC base from its ztAPI `base_url` too.
pub(crate) fn oidc_base(base_url: &str) -> String {
    url::Url::parse(base_url)
        .ok()
        .and_then(|u| {
            let scheme = u.scheme();
            let host = u.host_str()?;
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            Some(format!("{scheme}://{host}{port}"))
        })
        .unwrap_or_else(|| base_url.to_string())
}

/// Convert an OIDC `expires_in` (seconds from now) to an RFC3339 timestamp string of the absolute
/// expiry (`now + expires_in`), so the shared `store_token_and_expiry` (which parses RFC3339) drives
/// the refresh timer for OIDC sessions too. Oracle deadline: `now + expires_in`
/// (`clients_shared.go:786`). `0` (unknown) → `None` (the timer falls back to its DEFAULT interval).
/// `pub(crate)` since OIDC-3: the shared OIDC session-refresh helper (`do_oidc_session_refresh`, in
/// `edge::refresh`) reuses it to drive the timer off the refreshed OIDC access expiry.
pub(crate) fn expires_in_to_rfc3339(expires_in: u64) -> Option<String> {
    if expires_in == 0 {
        return None;
    }
    // Cap at i64::MAX seconds (absurdly far future) rather than wrap a pathological `expires_in`.
    let secs = i64::try_from(expires_in).unwrap_or(i64::MAX);
    let deadline = time::OffsetDateTime::now_utc() + time::Duration::seconds(secs);
    deadline
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Whether the controller advertises the `OIDC_AUTH` capability (`GET {base_url}/version` →
/// `data.capabilities` contains `OIDC_AUTH`). Oracle gate: `ControllerSupportsOidc` →
/// `stringz.Contains(versionInfo.Capabilities, CapabilitiesOIDCAUTH)`
/// (`client_edge_management.go:258`; `CapabilitiesOIDCAUTH = "OIDC_AUTH"`). Best-effort: a transport
/// or parse failure yields `false` (fail-closed → the OIDC constructors error clearly).
pub(crate) async fn controller_supports_oidc(http: &reqwest::Client, base_url: &str) -> bool {
    let url = format!("{base_url}/version");
    let Ok(resp) = http.get(&url).send().await else {
        return false;
    };
    let Ok(text) = resp.text().await else {
        return false;
    };
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| {
            let caps = v.get("data")?.get("capabilities")?.as_array()?;
            Some(caps.iter().any(|c| c.as_str() == Some("OIDC_AUTH")))
        })
        .unwrap_or(false)
}

pub(crate) fn parse_error_envelope(body: &str) -> (String, String) {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let e = v.get("error")?;
            let code = e
                .get("code")
                .and_then(|c| c.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let msg = e
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            Some((code, msg))
        })
        .unwrap_or_else(|| ("UNKNOWN".into(), body.chars().take(200).collect()))
}
