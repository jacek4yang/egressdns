//! Client access control.
//!
//! The resolver is default-deny: a client address must match an entry in `allow_from` and
//! must not match `deny_from`. An empty allow list refuses every client, which prevents an
//! accidentally exposed daemon from ever becoming an open resolver.

use std::net::IpAddr;

use ipnet::IpNet;

/// An immutable access control decision table.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}

/// Result of an ACL evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclDecision {
    /// The client may use the resolver.
    Allow,
    /// The client matched an explicit deny entry.
    Denied,
    /// The client matched no allow entry.
    NotAllowed,
}

impl Acl {
    /// Build an ACL from configured networks.
    pub fn new(allow: Vec<IpNet>, deny: Vec<IpNet>) -> Self {
        Self { allow, deny }
    }

    /// Evaluate a client address.
    pub fn evaluate(&self, addr: IpAddr) -> AclDecision {
        // An IPv4-mapped IPv6 client address is normalised so that a v4 CIDR matches a
        // client that arrived on a dual-stack socket.
        let addr = normalise(addr);
        if self.deny.iter().any(|n| contains(n, addr)) {
            return AclDecision::Denied;
        }
        if self.allow.iter().any(|n| contains(n, addr)) {
            return AclDecision::Allow;
        }
        AclDecision::NotAllowed
    }

    /// Convenience predicate.
    pub fn permits(&self, addr: IpAddr) -> bool {
        matches!(self.evaluate(addr), AclDecision::Allow)
    }

    /// Number of configured allow entries.
    pub fn allow_len(&self) -> usize {
        self.allow.len()
    }
}

fn normalise(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn contains(net: &IpNet, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpNet::V4(n), IpAddr::V4(a)) => n.contains(&a),
        (IpNet::V6(n), IpAddr::V6(a)) => n.contains(&a),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn acl(allow: &[&str], deny: &[&str]) -> Acl {
        Acl::new(
            allow
                .iter()
                .map(|s| IpNet::from_str(s).expect("cidr"))
                .collect(),
            deny.iter()
                .map(|s| IpNet::from_str(s).expect("cidr"))
                .collect(),
        )
    }

    #[test]
    fn empty_allow_list_denies_everything() {
        let a = acl(&[], &[]);
        assert_eq!(
            a.evaluate(IpAddr::from_str("10.0.0.5").expect("ip")),
            AclDecision::NotAllowed
        );
        assert_eq!(
            a.evaluate(IpAddr::from_str("127.0.0.1").expect("ip")),
            AclDecision::NotAllowed
        );
    }

    #[test]
    fn deny_wins_over_allow() {
        let a = acl(&["10.0.0.0/8"], &["10.1.0.0/16"]);
        assert_eq!(
            a.evaluate(IpAddr::from_str("10.0.0.5").expect("ip")),
            AclDecision::Allow
        );
        assert_eq!(
            a.evaluate(IpAddr::from_str("10.1.2.3").expect("ip")),
            AclDecision::Denied
        );
    }

    #[test]
    fn mapped_v6_client_matches_v4_rule() {
        let a = acl(&["10.0.0.0/8"], &[]);
        assert_eq!(
            a.evaluate(IpAddr::from_str("::ffff:10.0.0.7").expect("ip")),
            AclDecision::Allow
        );
    }

    #[test]
    fn v6_rules_work() {
        let a = acl(&["fd00::/8"], &[]);
        assert_eq!(
            a.evaluate(IpAddr::from_str("fd12::1").expect("ip")),
            AclDecision::Allow
        );
        assert_eq!(
            a.evaluate(IpAddr::from_str("2606:4700::1").expect("ip")),
            AclDecision::NotAllowed
        );
    }
}
