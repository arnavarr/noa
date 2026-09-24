//! Parser de transport address `tls:host:port`. Oráculo: transport `ParseAddressHostPort`.
//! Porta la validación que la rebanada 2 difirió (`sanitizeSessionUrls` ya reescribió `://`->`:`).

use crate::channel::error::ChannelError;

/// Parsea `tls:host:port` -> `(host, port)`. Acepta hostname, IPv4 e IPv6 con corchetes
/// (`tls:[::1]:443`). El argumento NUNCA debe contener `://` (la rebanada 2 ya lo reescribió).
///
/// # Errors
/// `ChannelError::AddressParse` si falta el prefijo `tls:`, falta el puerto, o el puerto no
/// es un `u16` válido.
pub fn parse_tls_address(s: &str) -> Result<(String, u16), ChannelError> {
    let host_port = s
        .strip_prefix("tls:")
        .ok_or_else(|| ChannelError::AddressParse(format!("not a tls address: {s}")))?;
    let (host, port_str) = split_host_port(host_port)
        .ok_or_else(|| ChannelError::AddressParse(format!("invalid host:port in {s}")))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ChannelError::AddressParse(format!("invalid port in {s}")))?;
    Ok((host, port))
}

/// Separa `host:port`, soportando IPv6 entre corchetes. Espejo de `net.SplitHostPort`.
fn split_host_port(hp: &str) -> Option<(String, &str)> {
    if let Some(rest) = hp.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        Some((host.to_string(), port))
    } else {
        let (host, port) = hp.rsplit_once(':')?;
        Some((host.to_string(), port))
    }
}

#[cfg(test)]
mod tests {
    use crate::channel::error::ChannelError;

    use super::parse_tls_address;

    #[test]
    fn parses_hostname() {
        assert_eq!(
            parse_tls_address("tls:localhost:3022").unwrap(),
            ("localhost".into(), 3022)
        );
    }

    #[test]
    fn parses_ipv4() {
        assert_eq!(
            parse_tls_address("tls:127.0.0.1:8080").unwrap(),
            ("127.0.0.1".into(), 8080)
        );
    }

    #[test]
    fn parses_bracketed_ipv6() {
        assert_eq!(
            parse_tls_address("tls:[::1]:8080").unwrap(),
            ("::1".into(), 8080)
        );
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(matches!(
            parse_tls_address("tcp:localhost:8080"),
            Err(ChannelError::AddressParse(_))
        ));
    }

    #[test]
    fn rejects_missing_port() {
        assert!(matches!(
            parse_tls_address("tls:localhost"),
            Err(ChannelError::AddressParse(_))
        ));
    }

    #[test]
    fn rejects_bad_port() {
        assert!(matches!(
            parse_tls_address("tls:localhost:99999"),
            Err(ChannelError::AddressParse(_))
        ));
    }
}
