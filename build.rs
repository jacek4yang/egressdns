//! Build script: records the compiler version so it can be exported as build metadata.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let version = Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=EGRESSDNS_RUSTC_VERSION={version}");
}
