//! Answer policy: standards-safe ordering, Cloudflare modes, DNSSEC state and TTL caps.
//!
//! This module is where the correctness contract lives, and it is deliberately pure: every
//! function takes a message and a context and returns a decision, with no I/O and no
//! ambient state. That makes each invariant directly testable by unit and property tests.

pub mod answer;
pub mod cloudflare;
pub mod dnssec;
pub mod ttl;

pub use answer::{apply_answer_policy, AnswerContext, AnswerOutcome, VerifiedCandidate};
pub use dnssec::dnssec_status;
pub use ttl::{effective_client_ttl, TtlReason};
