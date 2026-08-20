//! The installer's post-install canary.
//!
//! `install.sh` decides whether a freshly installed resolver works, and on that decision
//! rests whether it keeps the new installation or rolls back. It therefore has to be able
//! to tell "answered correctly" from "answered at all".
//!
//! It could not. `dig` exits 0 for SERVFAIL, REFUSED and NXDOMAIN alike — as far as it is
//! concerned it asked a question and got a reply — so a check that only inspected the exit
//! status passed against a resolver that refused or failed every single query. That is
//! exactly the state the installer exists to catch, and it is how a daemon that SERVFAILed
//! everything shipped green. See `docs/incidents/2026-08-deployment-failure.md`.
//!
//! These tests run the `canary` function out of the shipped `install.sh` verbatim, so they
//! exercise the deployed code rather than a copy of it.

mod common;

use std::net::SocketAddr;

use common::{a, Behaviour, Daemon, MockUpstream, TestCa, Transports};
use hickory_proto::rr::RecordType;

/// Extract `canary()` from `install.sh` and run it against one address.
///
/// The shipped function shells out to `egressdnsctl query`, so the test points `BIN_DIR`
/// and `CONTROL` at the binary this workspace just built — exercising the deployed code
/// path rather than a copy of it.
///
/// Runs on a blocking thread. `Command::output` parks the calling thread until the child
/// exits, and the resolver under test lives on this same runtime — running it inline made
/// every query time out, so the negative cases passed for the wrong reason and the
/// positive one failed outright.
async fn canary(addr: SocketAddr, tcp: bool) -> Option<bool> {
    tokio::task::spawn_blocking(move || canary_blocking(addr, tcp))
        .await
        .expect("canary task")
}

fn canary_blocking(addr: SocketAddr, tcp: bool) -> Option<bool> {
    let install_sh = concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh");
    // The test binary lives beside the built `egressdnsctl`.
    let bin_dir = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .to_path_buf();
    if !bin_dir.join("egressdnsctl").exists() {
        // `cargo test` has not built the binary; skip rather than fail.
        return None;
    }
    let proto = if tcp { "tcp" } else { "udp" };
    let script = format!(
        r#"
warn() {{ printf '[warn] %s\n' "$*" >&2; }}
path() {{ printf '%s' "$1"; }}
BIN_DIR="{bin}"
CONTROL="egressdnsctl"
eval "$(sed -n '/^canary() {{/,/^}}/p' {install_sh})"
canary {host} {port} "{proto}" "example.com"
"#,
        bin = bin_dir.display(),
        host = addr.ip(),
        port = addr.port(),
    );

    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        .output()
        .ok()?;
    Some(out.status.success())
}

/// A UDP responder that answers every query with a given rcode and no records.
///
/// This is what the canary has to reject, and a mock is the only honest way to produce it
/// on demand.
async fn responder_with_rcode(rcode: u8) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(request) = hickory_proto::op::Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut response =
                hickory_proto::op::Message::response(request.id, request.metadata.op_code);
            response.add_queries(request.queries.iter().cloned());
            response.metadata.response_code = hickory_proto::op::ResponseCode::from(0, rcode);
            response.metadata.recursion_available = true;
            if let Ok(bytes) = response.to_vec() {
                let _ = socket.send_to(&bytes, peer).await;
            }
        }
    });
    addr
}

/// A resolver that answers correctly must pass, over both transports.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_canary_passes_a_resolver_that_actually_answers() {
    let handler = MockUpstream::new();
    handler.set_default(Behaviour::Answer(vec![a(
        "example.com.",
        300,
        "203.0.113.42",
    )]));
    let ca = TestCa::new();
    let servers = common::start_mock(handler, &ca, "dns.example.test", Transports::plain()).await;
    let upstream = servers.udp.expect("udp");
    std::mem::forget(servers);

    let daemon = Daemon::start(&common::udp_upstream_fragment(upstream)).await;

    // Warm the path once so a cold miss does not race the canary's own timeout.
    let _ = daemon
        .query_udp(&common::query("example.com.", RecordType::A, false))
        .await;

    let Some(udp) = canary(daemon.udp, false).await else {
        eprintln!("skipping: egressdnsctl is not built");
        return;
    };
    assert!(udp, "a resolver that answers must pass the UDP canary");

    let tcp_addr = daemon.tcp;
    assert_eq!(
        canary(tcp_addr, true).await,
        Some(true),
        "a resolver that answers must pass the TCP canary"
    );
}

/// A resolver that refuses every query must fail.
///
/// This is the case the old check passed: `dig` exits 0, so nothing noticed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_canary_fails_a_resolver_that_refuses_everything() {
    // RFC 1035 rcode 5, REFUSED.
    let addr = responder_with_rcode(5).await;
    let Some(result) = canary(addr, false).await else {
        eprintln!("skipping: egressdnsctl is not built");
        return;
    };
    assert!(
        !result,
        "a resolver that REFUSES every query must not pass the canary"
    );
}

/// The failure mode from the incident: everything SERVFAILs, and `dig` still exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_canary_fails_a_resolver_that_servfails_everything() {
    // RFC 1035 rcode 2, SERVFAIL.
    let addr = responder_with_rcode(2).await;
    let Some(result) = canary(addr, false).await else {
        eprintln!("skipping: egressdnsctl is not built");
        return;
    };
    assert!(
        !result,
        "a resolver that SERVFAILs every query must not pass the canary"
    );
}

/// NOERROR with an empty answer section is not a working resolver either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_canary_fails_a_resolver_that_returns_noerror_with_no_answer() {
    // RFC 1035 rcode 0, NOERROR, but the responder adds no records.
    let addr = responder_with_rcode(0).await;
    let Some(result) = canary(addr, false).await else {
        eprintln!("skipping: egressdnsctl is not built");
        return;
    };
    assert!(
        !result,
        "NOERROR with no address in the answer section must not pass the canary"
    );
}

/// Nothing listening must fail rather than hang or pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_canary_fails_when_nothing_is_listening() {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = socket.local_addr().expect("addr");
    drop(socket);

    let Some(result) = canary(addr, false).await else {
        eprintln!("skipping: egressdnsctl is not built");
        return;
    };
    assert!(!result, "a dead address must not pass the canary");
}

/// Rollback must restore a *working* service, not merely the right files.
///
/// Exercising a genuinely failed cutover on a real host found two defects that both left
/// DNS down while the installer reported the rollback had succeeded:
///
///   * the restored configuration was written by `install` running as root, which leaves
///     it `root:root` — the daemon reads it through its *group*, so the previous
///     configuration came back unreadable;
///   * a unit that has just failed repeatedly is rate-limited by systemd, so the restart
///     was silently declined and the service stayed dead.
///
/// This is a source-level guard for both, plus the self-verification that turns a silent
/// half-rollback into a loud one. The end-to-end behaviour is exercised on a real host,
/// which a unit test cannot do.
#[test]
fn rollback_restores_ownership_resets_failure_state_and_verifies_itself() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh must exist");

    let start = script
        .find("\nrollback() {")
        .expect("install.sh must define rollback()");
    let body = &script[start..];
    let end = body.find("\n}\n").expect("rollback() must be terminated");
    let rollback = &body[..end];

    assert!(
        rollback.contains("chown \"root:$SERVICE_USER\""),
        "rollback must restore the configuration's group, or the daemon cannot read it:\n{rollback}"
    );
    assert!(
        rollback.contains("systemctl reset-failed"),
        "rollback must clear the failed state, or systemd refuses the restart:\n{rollback}"
    );
    assert!(
        rollback.contains("is-active --quiet"),
        "rollback must verify the service actually came back:\n{rollback}"
    );
    assert!(
        rollback.contains("ROLLBACK INCOMPLETE"),
        "a rollback that did not recover must say so plainly:\n{rollback}"
    );
}
