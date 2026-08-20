//! Library error types.
//!
//! Every fallible library operation returns a `thiserror`-derived error. `anyhow` is used
//! only at the binary/application boundary (see `src/bin/`).

use std::net::SocketAddr;

use thiserror::Error;

/// Errors produced while loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("cannot read configuration file {path}: {source}")]
    Read {
        /// Path that failed to open.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The configuration file is not valid TOML or contains unknown fields.
    #[error("invalid TOML in {path}: {source}")]
    Toml {
        /// Path that failed to parse.
        path: String,
        /// Underlying parse error, which carries the full field path.
        #[source]
        source: toml::de::Error,
    },
    /// A semantic validation rule was violated.
    #[error("configuration error at `{path}`: {message}")]
    Invalid {
        /// Dotted path of the offending field.
        path: String,
        /// Human readable explanation.
        message: String,
    },
    /// A referenced secret file could not be read.
    #[error("cannot read secret file {path}: {source}")]
    Secret {
        /// Path that failed to open.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl ConfigError {
    /// Convenience constructor for [`ConfigError::Invalid`].
    pub fn invalid(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Errors produced by the DNS ingress listeners.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// A socket could not be bound.
    #[error("cannot bind {proto} listener on {addr}: {source}")]
    Bind {
        /// `udp` or `tcp`.
        proto: &'static str,
        /// Requested socket address.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A socket option could not be applied.
    #[error("cannot configure {proto} socket on {addr}: {source}")]
    SocketOption {
        /// `udp` or `tcp`.
        proto: &'static str,
        /// Socket address being configured.
        addr: SocketAddr,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Reasons an inbound DNS message was rejected before resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RejectReason {
    /// Source address is outside every configured ACL entry.
    #[error("client not permitted by ACL")]
    Acl,
    /// Per-client or global rate limit exceeded.
    #[error("rate limited")]
    RateLimited,
    /// Message failed to parse.
    #[error("malformed DNS message")]
    Malformed,
    /// Message was not a query, or used an unsupported opcode.
    #[error("unsupported opcode")]
    UnsupportedOpCode,
    /// Message carried an unsupported number of questions.
    #[error("unsupported question count")]
    QuestionCount,
    /// Unsupported EDNS version (RFC 6891 requires BADVERS).
    #[error("unsupported EDNS version")]
    BadEdnsVersion,
    /// Message exceeded configured size limits.
    #[error("message too large")]
    TooLarge,
    /// The query class is not supported.
    #[error("unsupported class")]
    UnsupportedClass,
}

/// Errors produced while resolving a query through upstream servers.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// No upstream route was available in the selected group.
    #[error("no upstream route available in group `{group}`")]
    NoRoute {
        /// Group name.
        group: String,
    },
    /// Every attempted upstream failed.
    #[error("all upstreams failed: {detail}")]
    AllFailed {
        /// Short, bounded description of the last failure.
        detail: String,
    },
    /// The foreground budget elapsed before any acceptable answer arrived.
    #[error("foreground budget exceeded after {elapsed_ms} ms")]
    Timeout {
        /// Elapsed milliseconds.
        elapsed_ms: u64,
    },
    /// The upstream answer failed local validation.
    #[error("upstream response rejected: {reason}")]
    InvalidResponse {
        /// Bounded reason string.
        reason: &'static str,
    },
    /// Local DNSSEC validation determined the data is bogus.
    #[error("DNSSEC validation failed (bogus)")]
    DnssecBogus,

    /// Validation could not be completed, for a reason of ours rather than the answer's.
    ///
    /// Deliberately *not* [`ResolveError::DnssecBogus`]. A chain lookup that never
    /// finished is not a verdict on the data, and treating it as one lets anyone able to
    /// slow this resolver's auxiliary queries make names disappear. Never cached.
    #[error("DNSSEC proof could not be completed ({outcome})")]
    ProofIncomplete {
        /// Which typed outcome the validation ended in.
        outcome: &'static str,
    },
    /// The resolver is shutting down.
    #[error("resolver shutting down")]
    ShuttingDown,
    /// A global concurrency ceiling was reached and the request was shed rather than
    /// queued. Shedding is deliberate: an unbounded queue converts an overload into a
    /// latency collapse that outlasts the overload itself.
    #[error("upstream concurrency ceiling reached ({limit} permits configured)")]
    Overloaded {
        /// Configured ceiling of the semaphore whose permits were exhausted.
        limit: usize,
    },
}

impl ResolveError {
    /// Whether this failure is about us rather than about the answer.
    ///
    /// A transient failure must not enter the failure cache: remembering "I could not
    /// check this name" as "this name is broken" denies a working name for the whole
    /// failure TTL, long after the interruption that caused it has passed.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::ProofIncomplete { .. })
    }
}

/// Errors produced by the persistent storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    /// SQLite reported an error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Filesystem error while preparing the database directory.
    #[error("storage io error at {path}: {source}")]
    Io {
        /// Offending path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The on-disk schema version is newer than this build understands.
    #[error("unsupported schema version {found} (max supported {supported})")]
    SchemaTooNew {
        /// Version found on disk.
        found: i64,
        /// Highest version this build understands.
        supported: i64,
    },
    /// The database file was detected as corrupt and quarantined.
    #[error("database quarantined: {reason}")]
    Quarantined {
        /// Reason for quarantine.
        reason: String,
    },
    /// The storage worker is no longer running.
    #[error("storage worker stopped")]
    WorkerStopped,
}

/// Errors produced by the probe subsystem.
#[derive(Debug, Error)]
pub enum ProbeError {
    /// The target address is not permitted by probe safety policy.
    #[error("probe target blocked by policy: {reason}")]
    PolicyBlocked {
        /// Bounded reason string.
        reason: &'static str,
    },
    /// TCP connection failed.
    #[error("tcp connect failed: {0}")]
    Connect(String),
    /// TLS handshake failed.
    #[error("tls handshake failed: {0}")]
    Tls(String),
    /// HTTP exchange failed.
    #[error("http exchange failed: {0}")]
    Http(String),
    /// QUIC handshake failed.
    #[error("quic handshake failed: {0}")]
    Quic(String),
    /// The operation timed out.
    #[error("probe timed out")]
    Timeout,
    /// The requested capability is not supported by this build or endpoint.
    #[error("probe capability unsupported: {0}")]
    Unsupported(&'static str),
}

/// Errors produced by the Cloudflare dataset subsystem.
#[derive(Debug, Error)]
pub enum CloudflareError {
    /// A remote source could not be fetched.
    #[error("source fetch failed: {0}")]
    Fetch(String),
    /// A remote source returned data that failed strict parsing.
    #[error("source parse failed: {0}")]
    Parse(String),
    /// The response exceeded the configured size cap.
    #[error("source response too large: {got} bytes > {limit} bytes")]
    TooLarge {
        /// Observed size.
        got: usize,
        /// Configured limit.
        limit: usize,
    },
    /// The parsed snapshot failed sanity checks and was discarded.
    #[error("snapshot rejected: {0}")]
    SnapshotRejected(&'static str),
}

/// Errors produced by the administration socket.
#[derive(Debug, Error)]
pub enum AdminError {
    /// I/O failure on the control socket.
    #[error("admin io error: {0}")]
    Io(#[from] std::io::Error),
    /// The request could not be decoded.
    #[error("malformed admin request: {0}")]
    Malformed(&'static str),
    /// The request named an unknown command.
    #[error("unknown command `{0}`")]
    UnknownCommand(String),
    /// The command arguments were invalid.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
    /// The daemon refused the operation.
    #[error("operation refused: {0}")]
    Refused(String),
}
