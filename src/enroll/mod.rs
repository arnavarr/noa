//! Enrolment del edge client de OpenZiti. Oráculo: sdk-golang/ziti/enroll/enroll.go v1.7.0.
//! `enroll::ott::enroll` dispatcha por método: `ott` (genera clave/CSR) y `ottca` (mTLS con una
//! identidad pre-existente). `ca`/`updb` quedan pendientes.
//!
//! Consumers use full paths (e.g. `enroll::ott::enroll`).

pub mod csr;
pub mod error;
pub mod identity;
pub mod ott;
pub mod ottca;
pub mod token;
pub mod trust;
pub mod updb;
