//! Proxy endpoint parsing and capability description.
//!
//! A proxy is an egress *path*, never a DNS authority. Two routes to one resolver — one
//! direct, one tunnelled — are path diversity; they are not two opinions about what the
//! answer should be, and nothing in this crate may treat them as such.
//!
//! The capability matrix here is load-bearing rather than descriptive. An ordinary HTTP
//! `CONNECT` proxy carries a TCP byte stream and nothing else, so claiming it can carry
//! DoQ or HTTP/3 would send QUIC datagrams into a tunnel that cannot express them and
//! produce a timeout instead of an error. Every capability this module reports is one the
//! transport layer actually implements.

use std::fmt;

use url::Url;

/// How a proxy is spoken to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyKind {
    /// SOCKS5 with names resolved locally before the request (RFC 1928 ATYP 1/4).
    Socks5,
    /// SOCKS5 with names passed to the proxy for resolution (RFC 1928 ATYP 3).
    ///
    /// This is also a bootstrap source: a proxy that resolves names on our behalf can
    /// reach an endpoint whose address we do not yet know.
    Socks5Hostname,
    /// HTTP `CONNECT` over a cleartext connection to the proxy.
    HttpConnect,
    /// HTTP `CONNECT` over TLS to the proxy itself.
    HttpsConnect,
}

impl ProxyKind {
    /// Stable metrics label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Socks5Hostname => "socks5h",
            Self::HttpConnect => "http",
            Self::HttpsConnect => "https",
        }
    }

    /// Whether the proxy resolves target names itself.
    pub fn resolves_target_names(self) -> bool {
        matches!(
            self,
            Self::Socks5Hostname | Self::HttpConnect | Self::HttpsConnect
        )
    }

    /// Whether this proxy can carry a TCP byte stream.
    ///
    /// All four can; the method exists so callers state the requirement rather than
    /// assuming it.
    pub fn carries_tcp(self) -> bool {
        true
    }

    /// Whether this proxy can carry UDP datagrams.
    ///
    /// Uniformly false. SOCKS5 `UDP ASSOCIATE` and MASQUE `CONNECT-UDP` both exist and
    /// both could carry Do53, DoQ and HTTP/3; neither is implemented here, so neither is
    /// claimed. A transport that needs datagrams asks this and takes the direct path.
    pub fn carries_udp(self) -> bool {
        false
    }
}

impl fmt::Display for ProxyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Credentials for a proxy that demands them.
///
/// Deliberately not `Debug`-printable in full: the whole point is that it never reaches a
/// log line, a metric label, an error chain or `--dump-config`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The username is as sensitive as the password for this purpose: together they
        // identify an account, and a leaked half is a head start.
        f.write_str("ProxyCredentials(<redacted>)")
    }
}

/// One configured egress proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    /// Protocol spoken to the proxy.
    pub kind: ProxyKind,
    /// Proxy host, as written.
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// Optional credentials.
    pub credentials: Option<ProxyCredentials>,
}

impl ProxyEndpoint {
    /// Stable identity for metrics, health state and diagnostics.
    ///
    /// Never contains credentials, because it is used as a metrics label and appears in
    /// operator-facing output.
    pub fn id(&self) -> String {
        format!("{}://{}:{}", self.kind.label(), self.host, self.port)
    }

    /// `host:port`, for dialling.
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id())
    }
}

/// Parse one proxy URI.
pub fn parse(entry: &str) -> Result<ProxyEndpoint, String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return Err(String::from("empty proxy entry"));
    }
    let url = Url::parse(entry).map_err(|e| format!("`{entry}` is not a valid proxy URI: {e}"))?;

    let kind = match url.scheme() {
        "socks5" => ProxyKind::Socks5,
        "socks5h" => ProxyKind::Socks5Hostname,
        "http" => ProxyKind::HttpConnect,
        "https" => ProxyKind::HttpsConnect,
        other => {
            return Err(format!(
                "`{entry}` uses the unsupported proxy scheme `{other}`; supported schemes \
                 are socks5, socks5h, http and https"
            ))
        }
    };

    let host = url
        .host_str()
        .ok_or_else(|| format!("`{entry}` has no proxy host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    let port = url.port().unwrap_or(match kind {
        ProxyKind::Socks5 | ProxyKind::Socks5Hostname => 1080,
        ProxyKind::HttpConnect => 8080,
        ProxyKind::HttpsConnect => 8443,
    });

    // A path on a proxy URI is meaningless and is almost always a mistake — someone has
    // pasted a DoH endpoint into the proxy list. Refusing is kinder than ignoring it.
    if !url.path().is_empty() && url.path() != "/" {
        return Err(format!(
            "`{entry}` has a path, which a proxy URI cannot use; a proxy is addressed as \
             scheme://host:port"
        ));
    }

    let credentials = if url.username().is_empty() {
        None
    } else {
        let username = percent_decode(url.username());
        let password = percent_decode(url.password().unwrap_or_default());
        Some(ProxyCredentials { username, password })
    };

    Ok(ProxyEndpoint {
        kind,
        host,
        port,
        credentials,
    })
}

/// Minimal percent-decoding for the userinfo component.
///
/// Credentials routinely contain characters that must be escaped in a URI, and a password
/// silently mangled into a different password produces an authentication failure that
/// looks like a wrong password rather than a parsing bug.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse every configured proxy, rejecting duplicates.
pub fn parse_all(entries: &[String]) -> Result<Vec<ProxyEndpoint>, String> {
    let mut out: Vec<ProxyEndpoint> = Vec::with_capacity(entries.len());
    for entry in entries {
        let proxy = parse(entry)?;
        // Two identical proxies would carry two independent health records for one
        // server, so a failure would have to be learned twice.
        if out.iter().any(|p| p.id() == proxy.id()) {
            return Err(format!("`{}` is listed more than once", proxy.id()));
        }
        out.push(proxy);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_scheme_parses_with_its_default_port() {
        assert_eq!(parse("socks5://127.0.0.1").expect("ok").port, 1080);
        assert_eq!(parse("socks5h://127.0.0.1").expect("ok").port, 1080);
        assert_eq!(parse("http://127.0.0.1").expect("ok").port, 8080);
        assert_eq!(parse("https://127.0.0.1").expect("ok").port, 8443);
    }

    #[test]
    fn explicit_ports_and_kinds_are_preserved() {
        let p = parse("socks5h://127.0.0.1:1080").expect("ok");
        assert_eq!(p.kind, ProxyKind::Socks5Hostname);
        assert_eq!(p.authority(), "127.0.0.1:1080");
        let h = parse("http://127.0.0.1:7890").expect("ok");
        assert_eq!(h.kind, ProxyKind::HttpConnect);
        assert_eq!(h.authority(), "127.0.0.1:7890");
    }

    #[test]
    fn ipv6_proxies_are_bracketed_when_dialled() {
        let p = parse("socks5://[::1]:1080").expect("ok");
        assert_eq!(p.host, "::1");
        assert_eq!(p.authority(), "[::1]:1080");
    }

    /// SOCKS5 and SOCKS5h differ in exactly one way, and it is the one that matters for
    /// bootstrap: who resolves the target name.
    #[test]
    fn socks5h_delegates_name_resolution_and_socks5_does_not() {
        assert!(!parse("socks5://h:1")
            .expect("ok")
            .kind
            .resolves_target_names());
        assert!(parse("socks5h://h:1")
            .expect("ok")
            .kind
            .resolves_target_names());
    }

    /// The capability matrix is a promise the transport layer has to keep.
    #[test]
    fn no_proxy_claims_udp_capability() {
        for entry in ["socks5://h:1", "socks5h://h:1", "http://h:1", "https://h:1"] {
            let p = parse(entry).expect("ok");
            assert!(p.kind.carries_tcp(), "{entry} must carry TCP");
            assert!(
                !p.kind.carries_udp(),
                "{entry} must not claim UDP: neither SOCKS5 UDP ASSOCIATE nor MASQUE is \
                 implemented, and claiming it would send QUIC into a TCP tunnel"
            );
        }
    }

    #[test]
    fn credentials_are_parsed_and_percent_decoded() {
        let p = parse("socks5://user:p%40ss%3Aword@127.0.0.1:1080").expect("ok");
        let c = p.credentials.expect("credentials");
        assert_eq!(c.username, "user");
        assert_eq!(c.password, "p@ss:word");
    }

    /// Credentials must not survive a debug print, which is how they reach logs.
    #[test]
    fn credentials_never_appear_in_debug_or_identity_output() {
        let p = parse("socks5://user:hunter2@127.0.0.1:1080").expect("ok");
        let debug = format!("{p:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(!debug.contains("user"), "{debug}");
        assert!(!p.id().contains("hunter2"));
        assert!(!p.to_string().contains("hunter2"));
        assert_eq!(p.id(), "socks5://127.0.0.1:1080");
    }

    #[test]
    fn an_unsupported_scheme_lists_what_is_supported() {
        let e = parse("ftp://127.0.0.1").expect_err("refused");
        assert!(e.contains("unsupported proxy scheme"), "{e}");
        assert!(e.contains("socks5h"), "{e}");
    }

    /// A DoH URL pasted into `proxies` is a mistake worth naming.
    #[test]
    fn a_proxy_uri_with_a_path_is_refused() {
        let e = parse("http://127.0.0.1:8080/dns-query").expect_err("refused");
        assert!(e.contains("path"), "{e}");
    }

    #[test]
    fn an_empty_entry_is_refused() {
        assert!(parse("   ").is_err());
    }

    #[test]
    fn duplicate_proxies_are_refused() {
        let e = parse_all(&[
            String::from("socks5://127.0.0.1:1080"),
            String::from("socks5://127.0.0.1:1080"),
        ])
        .expect_err("refused");
        assert!(e.contains("more than once"), "{e}");
    }

    #[test]
    fn an_empty_proxy_list_is_fine() {
        assert!(parse_all(&[]).expect("ok").is_empty());
    }
}
