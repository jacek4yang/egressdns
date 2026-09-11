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

// The installer is a bash script and its canaries are POSIX shell; there is nothing to
// exercise on Windows, where installation is PowerShell based.
#![cfg(unix)]

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

// ---------------------------------------------------------------------------
// The proxychains incident
// ---------------------------------------------------------------------------

/// A local canary must not be routed through a proxy.
///
/// `proxychains` hooks `connect(2)` through `LD_PRELOAD`. With no `localnet` bypass — the
/// default on Debian — *every* TCP connection the process makes goes to the SOCKS proxy,
/// including one to 127.0.0.1. So the installer's TCP canary asked a proxy on another host
/// to reach `127.0.0.1:53`, got that host's loopback, and the stream closed with no RFC
/// 7766 length prefix. UDP was untouched, because proxychains intercepts TCP connect and
/// not datagram sends, which is why the failure looked like a TCP ingress defect in the
/// daemon rather than what it was.
///
/// The question a local canary asks is "is the resolver on *this machine* answering". Sent
/// through an intermediary it answers a different question, so the interception is cleared
/// for the canary command — and only for it, because artifact downloads genuinely do need
/// the proxy.
///
/// See `docs/incidents/2026-08-installer-tcp-canary.md`.
#[test]
fn a_local_canary_runs_with_proxy_interception_cleared() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).expect("mkdir");

    // Stand in for `egressdnsctl`, recording the environment it was given.
    let stub = bin.join("egressdnsctl");
    let env_dump = dir.path().join("env.txt");
    std::fs::write(
        &stub,
        format!("#!/bin/sh\nenv > {}\nexit 0\n", env_dump.display()),
    )
    .expect("write stub");
    let mut perms = std::fs::metadata(&stub).expect("stat").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&stub, perms).expect("chmod");

    let install_sh = concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh");
    let script = format!(
        r#"
warn() {{ printf '[warn] %s\n' "$*" >&2; }}
log()  {{ printf '[log] %s\n' "$*"; }}
path() {{ printf '%s' "$1"; }}
BIN_DIR="{bin}"
CONTROL="egressdnsctl"
eval "$(sed -n '/^canary() {{/,/^}}/p' {install_sh})"
canary 127.0.0.1 53 "tcp" "localhost"
"#,
        bin = bin.display(),
    );

    let out = std::process::Command::new("bash")
        .arg("-c")
        .arg(&script)
        // Exactly what `proxychains -q bash` leaves in the environment.
        .env(
            "LD_PRELOAD",
            "/usr/lib/x86_64-linux-gnu/libproxychains.so.4",
        )
        .env("ALL_PROXY", "socks5://192.168.31.105:10808")
        .env("http_proxy", "http://192.168.31.105:10809")
        .env("HTTPS_PROXY", "http://192.168.31.105:10809")
        .output()
        .expect("bash");
    assert!(out.status.success(), "canary should have run: {out:?}");

    let recorded = std::fs::read_to_string(&env_dump).expect("the stub must have run");
    let seen: Vec<&str> = recorded.lines().collect();

    for leaked in ["LD_PRELOAD=", "ALL_PROXY=", "http_proxy=", "HTTPS_PROXY="] {
        assert!(
            !seen.iter().any(|l| l.starts_with(leaked)),
            "a local canary must not inherit `{leaked}`: sending a loopback health check \
             through a proxy asks a different question, and under proxychains it fails \
             outright.\nEnvironment seen:\n{recorded}"
        );
    }
}

/// The local canary must not depend on the Internet.
///
/// Resolving `example.com` to prove a *listener* works means upstream trouble fails the
/// listener test. `localhost` is answered by EgressDNS itself from the special-use
/// registry, so it proves binding, ACL admission, parsing, TCP framing and serialisation
/// and nothing else.
#[test]
fn the_local_canary_uses_a_name_the_daemon_answers_itself() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh");
    let start = script
        .find("\nlocal_canaries() {")
        .expect("install.sh must define local_canaries()");
    let body = &script[start..];
    let end = body.find("\n}\n").expect("terminated");
    let local = &body[..end];

    assert!(
        local.contains("localhost"),
        "local ingress must be proven with a locally answered name:\n{local}"
    );
    assert!(
        !local.contains("example.com"),
        "a local listener test must not depend on a public name:\n{local}"
    );
}

/// A failed canary must say why.
///
/// The original discarded stdout and stderr, so an operator saw "did not return a usable
/// answer" and had nothing to act on.
#[test]
fn a_failing_canary_reports_the_reason_rather_than_discarding_it() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh");
    let start = script.find("\ncanary() {").expect("canary()");
    let body = &script[start..];
    let end = body.find("\n}\n").expect("terminated");
    let canary = &body[..end];

    assert!(
        !canary.contains(">/dev/null 2>&1"),
        "the canary must not discard the reason it failed:\n{canary}"
    );
    assert!(
        canary.contains("--json"),
        "the canary should capture a structured result it can report:\n{canary}"
    );
}

// ---------------------------------------------------------------------------
// The interview
// ---------------------------------------------------------------------------

/// Run install.sh's function library with a script of our own appended.
///
/// The installer is sourced rather than executed, so a single function can be exercised
/// without installing anything. `main "$@"` is the last line, so trimming it leaves the
/// definitions and nothing that acts.
fn with_installer(body: &str) -> std::process::Output {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh");
    let defs = script
        .rsplit_once("\nmain \"$@\"")
        .map(|(head, _)| head)
        .expect("install.sh must end with main \"$@\"");

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("harness.sh");
    std::fs::write(&path, format!("{defs}\n{body}\n")).expect("write");

    std::process::Command::new("bash")
        .arg(&path)
        .env("EGRESSDNS_TEST_ROOT", dir.path())
        .output()
        .expect("bash")
}

/// The prompts must not read stdin.
///
/// This installer's documented invocation is `curl ... | sudo bash`, which makes stdin the
/// script itself. A prompt that read stdin would consume the installer's own remaining
/// lines: the read succeeds, the answer is a line of shell, and the rest of the install
/// never runs. Every prompt therefore reads /dev/tty.
#[test]
fn prompts_read_the_terminal_and_never_stdin() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh");

    for name in ["ask_yes_no", "ask_line", "ask_choice"] {
        let start = script
            .find(&format!("\n{name}() {{"))
            .unwrap_or_else(|| panic!("install.sh must define {name}()"));
        let body = &script[start..];
        let end = body.find("\n}\n").expect("terminated");
        let func = &body[..end];

        let reads: Vec<&str> = func.lines().filter(|l| l.contains("read -r")).collect();
        assert!(!reads.is_empty(), "{name} should read an answer:\n{func}");
        for line in reads {
            assert!(
                line.contains("</dev/tty"),
                "{name} reads an answer from somewhere other than the terminal, which \
                 under `curl | bash` eats the script itself:\n{line}"
            );
        }
    }
}

/// With no terminal, every choice takes the option that changes the least.
#[test]
fn without_a_terminal_the_defaults_are_the_safe_ones() {
    let out = with_installer(
        r#"
        NON_INTERACTIVE=1
        EXISTING_INSTALL=0
        SYSTEM_RESOLVER_UNIT=""
        interview
        printf 'MODE=%s CIDRS=[%s] RESOLVER=%s PROFILE=%s\n' \
            "$MODE" "$LAN_CIDRS" "$SYSTEM_RESOLVER_ACTION" "$PROFILE"
        "#,
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("MODE=local"),
        "an unattended install must serve only this machine: {text}"
    );
    assert!(
        text.contains("CIDRS=[]"),
        "an unattended install must not admit any network: {text}"
    );
    assert!(
        text.contains("RESOLVER=keep"),
        "an unattended install must not repoint the system resolver: {text}"
    );
    assert!(
        text.contains("PROFILE=recommended"),
        "the default resolver set should be the curated one: {text}"
    );
}

/// A LAN configuration that admits the whole Internet is refused.
///
/// An open resolver is found by scanners within hours and used to amplify traffic at
/// somebody else. Refusing is not paternalism: nobody types `0.0.0.0/0` meaning it.
#[test]
fn an_allow_from_covering_the_internet_is_refused() {
    for prefix in ["0.0.0.0/0", "::/0"] {
        let out = with_installer(&format!(
            r#"
            NON_INTERACTIVE=1
            MODE=lan
            LAN_CIDRS="{prefix}"
            EXISTING_INSTALL=0
            interview
            echo REACHED_THE_END
            "#
        ));
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !text.contains("REACHED_THE_END"),
            "{prefix} must stop the install: {text}"
        );
        assert!(
            text.contains("open resolver"),
            "the refusal must explain what {prefix} would do: {text}"
        );
    }

    // ...and the explicit override still works, because an operator running a deliberate
    // public resolver on an isolated network is entitled to do so.
    let out = with_installer(
        r#"
        NON_INTERACTIVE=1
        MODE=lan
        LAN_CIDRS="0.0.0.0/0"
        ALLOW_OPEN_RESOLVER=1
        EXISTING_INSTALL=0
        interview
        echo REACHED_THE_END
        "#,
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("REACHED_THE_END"),
        "the documented override must work"
    );
}

/// The generated configuration must be valid and mean what the answers said.
#[test]
fn the_generated_configuration_matches_the_answers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let local = dir.path().join("local.toml");
    let lan = dir.path().join("lan.toml");

    let out = with_installer(&format!(
        r#"
        MODE=local
        PROFILE=recommended
        LAN_CIDRS=""
        render_config "{}"
        MODE=lan
        LAN_CIDRS="192.168.31.0/24 10.0.0.0/8"
        LISTEN_V4_ALL=1
        render_config "{}"
        "#,
        local.display(),
        lan.display()
    ));
    assert!(out.status.success(), "{out:?}");

    let local_text = std::fs::read_to_string(&local).expect("local config");
    assert!(
        local_text.contains(r#"upstreams = ["builtin:recommended"]"#),
        "a default install should use the curated set:\n{local_text}"
    );
    assert!(
        local_text.contains("proxies = []"),
        "proxies must default to none:\n{local_text}"
    );
    assert!(
        !local_text.contains("allow_from"),
        "a loopback-only resolver needs no allow list; naming one would replace the \
         loopback default with something wider:\n{local_text}"
    );
    assert!(
        !local_text.contains("0.0.0.0"),
        "a local install must not bind a wildcard address:\n{local_text}"
    );

    let lan_text = std::fs::read_to_string(&lan).expect("lan config");
    for cidr in ["192.168.31.0/24", "10.0.0.0/8", "127.0.0.0/8", "::1/128"] {
        assert!(
            lan_text.contains(cidr),
            "the LAN config must admit {cidr}:\n{lan_text}"
        );
    }
    assert!(
        lan_text.contains(r#""0.0.0.0:53""#),
        "--listen-ipv4-all should bind the wildcard:\n{lan_text}"
    );

    // The real test of a generated file: the daemon accepts it.
    for file in [&local, &lan] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_egressdnsd"))
            .arg("--config")
            .arg(file)
            .arg("--check-config")
            .output()
            .expect("check-config");
        assert!(
            out.status.success(),
            "the installer generated a configuration the daemon rejects: {}\n{}",
            file.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Interface addresses are reduced to the networks they sit on.
#[test]
fn a_detected_interface_address_becomes_its_network() {
    let out = with_installer(
        r#"
        network_of "192.168.31.204/24"; echo
        network_of "10.11.12.13/8";     echo
        network_of "172.16.5.9/16";     echo
        network_of "2001:db8:1:2:3:4:5:6/64"; echo
        "#,
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines,
        vec![
            "192.168.31.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16",
            "2001:db8:1:2::/64"
        ]
    );
}

/// Only real client networks are proposed.
///
/// Offering `docker0` or a WireGuard tunnel as "your LAN" invites an operator to admit a
/// network whose members are not what they think they are.
#[test]
fn container_and_tunnel_interfaces_are_not_offered_as_a_lan() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh");
    let start = script
        .find("\ndetect_lan_cidrs() {")
        .expect("detect_lan_cidrs()");
    let body = &script[start..];
    let end = body.find("\n}\n").expect("terminated");
    let func = &body[..end];

    for excluded in ["docker", "veth", "br-", "wg", "tun", "169.254.", "fe80:"] {
        assert!(
            func.contains(excluded),
            "detect_lan_cidrs must skip {excluded}:\n{func}"
        );
    }
}

/// The system resolver is left alone unless the operator asks otherwise, and the
/// previous /etc/resolv.conf is always recoverable.
#[test]
fn the_system_resolver_is_only_touched_on_request_and_is_recoverable() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh");

    let start = script
        .find("\nreplace_system_resolver() {")
        .expect("replace_system_resolver()");
    let body = &script[start..];
    let end = body.find("\n}\n").expect("terminated");
    let func = &body[..end];

    assert!(
        func.contains(r#"[ "$SYSTEM_RESOLVER_ACTION" = "replace" ] || return 0"#),
        "resolv.conf must be left alone unless replacement was asked for:\n{func}"
    );
    assert!(
        func.contains("readlink /etc/resolv.conf"),
        "a symlinked resolv.conf must be recorded as a symlink, or the host cannot be \
         put back:\n{func}"
    );
    assert!(
        script.contains("restore_system_resolver"),
        "rollback must be able to put resolv.conf back"
    );

    // Ordering is the whole point: repointing the machine's DNS at a resolver that has
    // not been proven to answer takes name resolution down, including whatever the
    // operator would use to repair it.
    let main = script.rsplit_once("\nmain() {").expect("main()").1;
    let health = main.find("health_check").expect("health_check in main");
    let cutover = main
        .find("replace_system_resolver")
        .expect("replace_system_resolver in main");
    assert!(
        health < cutover,
        "the resolver must be verified answering before /etc/resolv.conf is moved onto it"
    );
}

/// Rollback must restore DNS before anything else it does.
#[test]
fn rollback_restores_name_resolution_first() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
        .expect("install.sh");
    let start = script.find("\nrollback() {").expect("rollback()");
    let body = &script[start..];
    let end = body.find("\n}\n").expect("terminated");
    let func = &body[..end];

    let restore = func
        .find("restore_system_resolver")
        .expect("rollback must restore resolv.conf");
    let binaries = func
        .find("for binary in")
        .expect("rollback restores binaries");
    assert!(
        restore < binaries,
        "restoring resolv.conf comes first; everything after it is easier to debug on a \
         host whose DNS works:\n{func}"
    );
}
