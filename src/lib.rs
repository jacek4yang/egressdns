//! EgressDNS: an adaptive, highly available DNS caching forwarder for enterprise LANs
//! that share a single Internet egress.
//!
//! The crate is organised around a strict separation between a low-latency **foreground
//! data plane** and an asynchronous **background control plane**:
//!
//! * The foreground path ([`dns`]) parses a query, applies access control and rate
//!   limits, consults local data and the cache, coalesces concurrent misses, asks the
//!   scheduler for an upstream route, validates the response, applies standards-safe
//!   ordering, caps the client TTL and serialises the answer. It never performs disk
//!   I/O, database access, TLS/HTTP/QUIC probing or dataset parsing.
//! * The background plane ([`cloudflare`], [`probe`], [`network`], [`datasets`],
//!   [`storage`]) gathers evidence that *may* improve later answers. Every component is
//!   supervised, bounded and independently disableable. If all of them fail the process
//!   continues to operate as a correct caching forwarder.
#![warn(missing_docs)]
#![warn(clippy::todo, clippy::unimplemented, clippy::dbg_macro)]
#![forbid(unsafe_code)]

pub mod admin;
pub mod bench;
pub mod cache;
pub mod cloudflare;
pub mod config;
pub mod datasets;
pub mod dns;
pub mod doctor;
pub mod error;
pub mod metrics;
pub mod network;
pub mod platform;
pub mod policy;
pub mod probe;
pub mod ranking;
pub mod runtime;
pub mod storage;
pub mod tasks;
pub mod tls;
pub mod upstream;
pub mod util;

/// Crate version, taken from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Product name used in banners, metrics and the admin protocol.
pub const PRODUCT: &str = "EgressDNS";
