//! Cross-platform defaults for the filesystem paths and the control-plane endpoint.
//!
//! Everything here is a *default*, not a rule: every one of these paths is overridable in
//! the configuration file. The point is that a fresh install on either supported platform
//! lands somewhere conventional for that platform, without the rest of the codebase ever
//! having to ask which platform it is on.
//!
//! | Concern | Linux | Windows |
//! | --- | --- | --- |
//! | Configuration | `/etc/egressdns/config.toml` | `%ProgramData%\egressdns\config.toml` |
//! | State database | `/var/lib/egressdns/state.sqlite3` | `%ProgramData%\egressdns\state.sqlite3` |
//! | Prefix cache | `/var/lib/egressdns/cloudflare-prefixes.json` | `%ProgramData%\egressdns\cloudflare-prefixes.json` |
//! | Admin control plane | `/run/egressdns/admin.sock` (Unix socket) | `\\.\pipe\egressdns-admin` (named pipe) |

use std::path::PathBuf;

/// Default daemon configuration file.
pub const DEFAULT_CONFIG_PATH: &str = if cfg!(windows) {
    r"C:\ProgramData\egressdns\config.toml"
} else {
    "/etc/egressdns/config.toml"
};

/// Default administration endpoint: a Unix domain socket path on Unix, a named pipe path
/// on Windows. Both spellings are understood by `admin::server::bind` and
/// `admin::client::send` on their own platform.
pub const DEFAULT_ADMIN_ENDPOINT: &str = if cfg!(windows) {
    r"\\.\pipe\egressdns-admin"
} else {
    "/run/egressdns/admin.sock"
};

/// Directory prefix for pipe paths on Windows.
pub const WINDOWS_PIPE_PREFIX: &str = r"\\.\pipe\";

/// The name the daemon registers under in the Windows service control manager.
pub const WINDOWS_SERVICE_NAME: &str = "egressdns";

/// The directory that holds mutable daemon state.
///
/// `%ProgramData%` on Windows (the machine-wide application-data directory, writable by
/// administrators and by services) and `/var/lib/egressdns` on Linux.
pub fn state_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("egressdns")
    } else {
        PathBuf::from("/var/lib/egressdns")
    }
}

/// Default path of the SQLite state database.
pub fn default_state_db_path() -> PathBuf {
    state_dir().join("state.sqlite3")
}

/// Default path of the Cloudflare official-prefix snapshot cache.
pub fn default_prefix_cache_path() -> PathBuf {
    state_dir().join("cloudflare-prefixes.json")
}

/// Whether `path` refers to a local control-plane endpoint this platform accepts.
///
/// On Unix that is any absolute path; on Windows it is additionally the `\\.\pipe\`
/// device namespace, which is not a filesystem path but is a perfectly good control-plane
/// address.
pub fn is_valid_admin_endpoint(path: &std::path::Path) -> bool {
    if path.is_absolute() {
        return true;
    }
    cfg!(windows)
        && path
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with(&WINDOWS_PIPE_PREFIX.to_ascii_lowercase())
}
