//! Deployment-shaped failures.
//!
//! These cover the class of defect that does not show up in a unit test and does not show
//! up at install time either: the daemon starts, reports ready, satisfies its health
//! check and its watchdog, and then answers nothing.

mod common;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// Address-family detection failing must not black-hole every query.
///
/// The detector derives family usability from the host routing table. On a host where it
/// cannot read the routing table — a sandbox that hides `/proc/net`, an unusual container,
/// a platform whose route file moved — every family reads as `Unusable`, and a scheduler
/// that filters unusable families then has nothing left to rank.
///
/// The circuit breaker already refuses to turn "nothing is healthy" into "nothing is
/// tried", for exactly this reason. Absence of a *measurement* is not evidence that the
/// network is gone, and it must not be more fatal than every circuit being open.
#[tokio::test]
async fn a_failed_address_family_detection_still_resolves() {
    let handler = MockUpstream::new();
    handler.set(
        "family.example.test.",
        RecordType::A,
        Behaviour::Answer(vec![a("family.example.test.", 300, "203.0.113.77")]),
    );
    let ca = TestCa::new();
    let servers = common::start_mock(
        handler.clone(),
        &ca,
        "dns.example.test",
        Transports::plain(),
    )
    .await;
    let daemon = Daemon::start(&common::udp_upstream_fragment(servers.udp.expect("udp"))).await;

    // Exactly what the detector publishes when it cannot read the routing table: no
    // default interface, no gateway, no source address, for either family.
    let blind = egressdns::network::RawNetworkState::default();
    assert_eq!(
        blind.v4_state(),
        egressdns::network::FamilyState::Unusable,
        "the fixture must actually model a failed detection"
    );
    assert_eq!(blind.v6_state(), egressdns::network::FamilyState::Unusable);
    daemon.app.network.publish(blind, 1_000);

    let response = daemon
        .query_udp(&common::query("family.example.test.", RecordType::A, false))
        .await;

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "a resolver that cannot measure its own egress must still try its upstreams"
    );
    assert_eq!(
        common::addresses(&response),
        vec!["203.0.113.77".parse::<std::net::IpAddr>().expect("ip")]
    );
}

/// The shipped systemd unit must leave `/proc/net` readable.
///
/// `ProcSubset=pid` hides every non-PID file in `/proc`, including `/proc/net/route` and
/// `/proc/net/ipv6_route`. The daemon then detects no default route on either family and
/// SERVFAILs every query while still reporting ready — which is how this was found, on a
/// real host, after a green install.
///
/// `ProtectProc=invisible` is the directive that hides *other processes* and is kept.
#[test]
fn the_systemd_unit_does_not_hide_proc_net_from_the_detector() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/packaging/systemd/egressdns.service"
    ))
    .expect("the packaged unit must exist");

    let directives: Vec<&str> = unit
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();

    assert!(
        !directives
            .iter()
            .any(|l| l.starts_with("ProcSubset=") && !l.starts_with("ProcSubset=all")),
        "ProcSubset hides /proc/net/route, which the address-family detector reads; \
         without it every family reads as unusable and the resolver answers nothing"
    );

    // The hardening that does not break detection must stay.
    for expected in [
        "ProtectProc=invisible",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "PrivateTmp=true",
        "RestrictSUIDSGID=true",
    ] {
        assert!(
            directives.contains(&expected),
            "{expected} must remain in the unit"
        );
    }
}

/// The unit must not stop another resolver as a side effect of being enabled.
///
/// `Conflicts=` does not mean "refuse to start if busy" — systemd stops the conflicting
/// unit. Shipping `Conflicts=systemd-resolved.service` therefore meant that enabling
/// EgressDNS silently took down whatever was resolving DNS for the host, at boot, with
/// nobody watching. Port ownership is the installer's and `doctor`'s job, and both of
/// them report rather than kill.
#[test]
fn the_systemd_unit_does_not_stop_another_resolver() {
    let unit = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/packaging/systemd/egressdns.service"
    ))
    .expect("the packaged unit must exist");

    for line in unit.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        assert!(
            !line.starts_with("Conflicts="),
            "the unit must not declare Conflicts=, which stops the other unit: {line}"
        );
    }
}
