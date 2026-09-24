//! OpenZiti channel V2 binary protocol (genérico). Oráculo: openziti/channel v4.3.9.
//! Rebanada 3: framing V2 + Hello/Result + handshake del dialer sobre un stream async.

pub mod address;
pub mod connect;
pub mod error;
pub mod hello;
pub mod message;
