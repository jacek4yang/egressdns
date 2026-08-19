//! Local administration over a Unix domain socket.
//!
//! The protocol is newline-delimited JSON: one request object per line, one response
//! object per line. There is deliberately no network-facing administration interface, and
//! no authentication mechanism beyond filesystem permissions on the socket, because adding
//! a bespoke authentication scheme to a DNS daemon is a larger risk than it removes.

pub mod client;
pub mod server;

use serde::{Deserialize, Serialize};

use crate::error::AdminError;

/// A request from `egressdnsctl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Command name.
    pub command: String,
    /// Positional arguments.
    #[serde(default)]
    pub args: Vec<String>,
}

/// A response to `egressdnsctl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Whether the command succeeded.
    pub ok: bool,
    /// Structured result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Human-readable error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    /// A successful response.
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// A failed response.
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Every command the daemon accepts.
pub const COMMANDS: &[&str] = &[
    "status",
    "check-config",
    "reload",
    "upstreams",
    "network",
    "cache-stats",
    "flush-name",
    "flush-all",
    "cloudflare",
    "dump-effective-config",
];

/// Sub-commands of `cloudflare`.
pub const CLOUDFLARE_SUBCOMMANDS: &[&str] = &[
    "status",
    "sources",
    "candidates",
    "scan-now",
    "verify-domain",
    "set-mode",
    "clear-mode-override",
];

/// Parse one request line, enforcing a size bound.
pub fn parse_request(line: &str, max_bytes: usize) -> Result<Request, AdminError> {
    if line.len() > max_bytes {
        return Err(AdminError::Malformed(
            "request exceeds the configured size limit",
        ));
    }
    let request: Request = serde_json::from_str(line)
        .map_err(|_| AdminError::Malformed("request was not a valid JSON object"))?;
    if request.command.is_empty() || request.command.len() > 64 {
        return Err(AdminError::Malformed(
            "command name is missing or implausible",
        ));
    }
    if request.args.len() > 8 {
        return Err(AdminError::InvalidArguments("too many arguments".into()));
    }
    for arg in &request.args {
        if arg.len() > 512 {
            return Err(AdminError::InvalidArguments("argument is too long".into()));
        }
    }
    if !COMMANDS.contains(&request.command.as_str()) {
        return Err(AdminError::UnknownCommand(crate::util::bounded(
            &request.command,
            64,
        )));
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_request() {
        let r = parse_request(r#"{"command":"status","args":[]}"#, 4_096).expect("parses");
        assert_eq!(r.command, "status");
        assert!(r.args.is_empty());
    }

    #[test]
    fn rejects_unknown_commands() {
        let err =
            parse_request(r#"{"command":"rm-rf","args":[]}"#, 4_096).expect_err("must reject");
        assert!(matches!(err, AdminError::UnknownCommand(_)));
    }

    #[test]
    fn rejects_unknown_fields_and_garbage() {
        assert!(parse_request(r#"{"command":"status","extra":1}"#, 4_096).is_err());
        assert!(parse_request("not json", 4_096).is_err());
        assert!(parse_request("", 4_096).is_err());
        assert!(parse_request("[]", 4_096).is_err());
    }

    #[test]
    fn enforces_size_and_argument_bounds() {
        let big = format!(r#"{{"command":"status","args":["{}"]}}"#, "x".repeat(4_096));
        assert!(matches!(
            parse_request(&big, 128),
            Err(AdminError::Malformed(_))
        ));
        let long_arg = format!(
            r#"{{"command":"flush-name","args":["{}"]}}"#,
            "x".repeat(600)
        );
        assert!(matches!(
            parse_request(&long_arg, 1_000_000),
            Err(AdminError::InvalidArguments(_))
        ));
        let many = format!(
            r#"{{"command":"status","args":[{}]}}"#,
            (0..20).map(|_| "\"a\"").collect::<Vec<_>>().join(",")
        );
        assert!(matches!(
            parse_request(&many, 1_000_000),
            Err(AdminError::InvalidArguments(_))
        ));
    }

    #[test]
    fn response_round_trips() {
        let r = Response::ok(serde_json::json!({"a": 1}));
        let text = serde_json::to_string(&r).expect("serialise");
        let back: Response = serde_json::from_str(&text).expect("deserialise");
        assert!(back.ok);
        assert_eq!(back.data.expect("data")["a"], 1);

        let e = Response::err("nope");
        let text = serde_json::to_string(&e).expect("serialise");
        assert!(text.contains("nope"));
    }

    #[test]
    fn every_documented_command_is_accepted() {
        for command in COMMANDS {
            let line = format!(r#"{{"command":"{command}","args":[]}}"#);
            assert!(parse_request(&line, 4_096).is_ok(), "{command} rejected");
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        for seed in 0u32..256 {
            let bytes: Vec<u8> = (0..48u32)
                .map(|i| ((seed.wrapping_mul(2_246_822_519).wrapping_add(i)) & 0xff) as u8)
                .collect();
            let text = String::from_utf8_lossy(&bytes);
            let _ = parse_request(&text, 4_096);
        }
    }
}
