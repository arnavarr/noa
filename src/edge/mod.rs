//! Edge client (data plane) del cliente OpenZiti. Oráculo: sdk-golang v1.7.0 ziti/client.go.
//! Rebanada 1: autenticación legacy (`zt-session`) + listado de servicios.
//! Rebanada 2: creación de sesión (`POST /sessions`, dial). REST sobre mTLS.
//! Rebanada 3: canal binario V2 al edge router (`channel::*` + `edge::channel`).

pub mod auth_token;
pub mod bind;
pub mod channel;
pub mod client;
pub mod conn;
pub mod crypto;
pub mod data;
pub mod dial;
pub mod error;
pub mod identity_tls;
pub mod listener_manager;
pub mod model;
pub mod oidc;
pub mod reauth;
pub mod refresh;
pub mod router_filter;
pub mod service_refresh;
pub mod services;
pub mod session_cert;
pub mod session_cert_renew;
pub mod session_refresh;
