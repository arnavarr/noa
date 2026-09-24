//! Output identity JSON (the ziti identity config). Oracle: sdk-golang config.go.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "ztAPI")]
    pub zt_api: String,
    #[serde(rename = "ztAPIs", skip_serializing_if = "Option::is_none")]
    pub zt_apis: Option<Vec<String>>,
    #[serde(rename = "configTypes", skip_serializing_if = "Option::is_none")]
    pub config_types: Option<Vec<String>>,
    pub id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Id {
    pub key: String,
    pub cert: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub ca: String,
}

impl Config {
    /// Build from enrolment outputs. Values are wrapped with the `pem:` prefix
    /// exactly as the Go client does (enroll.go assembly).
    #[must_use]
    pub fn from_enrolment(zt_api: String, key_pem: &str, cert_pem: &str, ca_pem: &str) -> Self {
        Config {
            zt_api,
            zt_apis: None,
            config_types: None,
            id: Id {
                key: format!("pem:{key_pem}"),
                cert: format!("pem:{cert_pem}"),
                ca: if ca_pem.is_empty() {
                    String::new()
                } else {
                    format!("pem:{ca_pem}")
                },
            },
        }
    }

    /// Serialize like the Go client: pretty JSON, HTML escaping disabled.
    ///
    /// # Errors
    /// Returns [`crate::enroll::error::EnrollError::IdentityWrite`] if serialization fails.
    pub fn to_json(&self) -> Result<String, crate::enroll::error::EnrollError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| crate::enroll::error::EnrollError::IdentityWrite(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_identity_with_pem_prefixes() {
        let c = Config::from_enrolment(
            "https://ctrl.example:1280/edge/client/v1".into(),
            "KEYPEM",
            "CERTPEM",
            "CAPEM",
        );
        assert_eq!(c.id.key, "pem:KEYPEM");
        assert_eq!(c.id.cert, "pem:CERTPEM");
        assert_eq!(c.id.ca, "pem:CAPEM");
        let json = c.to_json().unwrap();
        assert!(json.contains("\"ztAPI\""));
        assert!(!json.contains("ztAPIs"), "None fields are omitted");
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn empty_ca_is_omitted() {
        let c = Config::from_enrolment("https://x/edge/client/v1".into(), "K", "C", "");
        let json = c.to_json().unwrap();
        assert!(!json.contains("\"ca\""));
    }
}
