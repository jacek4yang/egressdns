//! Built-in defaults referenced by `serde(default)` attributes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{SeedEndpoint, TransportKind, UpstreamServerConfig};

/// Default listen set: loopback only, so that an unconfigured daemon can never become an
/// open resolver. Production configuration must widen this deliberately.
pub fn default_listen() -> Vec<SocketAddr> {
    vec![
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
    ]
}

/// Default upstream set: two widely available public resolvers reached over DNS-over-TLS,
/// each with literal bootstrap addresses so the daemon never has to resolve its own
/// upstream name.
pub fn default_upstreams() -> Vec<UpstreamServerConfig> {
    vec![
        UpstreamServerConfig {
            name: "cloudflare-dot".to_string(),
            transport: TransportKind::Dot,
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            ],
            server_name: Some("cloudflare-dns.com".to_string()),
            ..UpstreamServerConfig::default()
        },
        UpstreamServerConfig {
            name: "quad9-dot".to_string(),
            transport: TransportKind::Dot,
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
            ],
            server_name: Some("dns.quad9.net".to_string()),
            ..UpstreamServerConfig::default()
        },
    ]
}

/// Default untrusted candidate seed endpoints. Disabled unless `cloudflare.seeds.enabled`
/// is set; every returned address is filtered against the official prefix snapshot before
/// it can enter the candidate pool.
pub fn default_seed_endpoints() -> Vec<SeedEndpoint> {
    vec![
        SeedEndpoint {
            name: "ct".to_string(),
            url: "https://cf.090227.xyz/ct?ips=6".to_string(),
            enabled: true,
        },
        SeedEndpoint {
            name: "cu".to_string(),
            url: "https://cf.090227.xyz/cu".to_string(),
            enabled: true,
        },
        SeedEndpoint {
            name: "cmcc".to_string(),
            url: "https://cf.090227.xyz/cmcc?ips=8".to_string(),
            enabled: true,
        },
    ]
}
