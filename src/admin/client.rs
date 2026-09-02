//! Client side of the administration protocol, used by `egressdnsctl`.
//!
//! On Unix this connects to a Unix domain socket; on Windows it opens the named pipe.
//! Both expose the same newline-delimited JSON request/response exchange.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[cfg(windows)]
use tokio::net::windows::named_pipe::ClientOptions;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::admin::{Request, Response};
use crate::error::AdminError;

/// Send one command and read one response.
pub async fn send(
    socket: &Path,
    command: &str,
    args: &[String],
    timeout: Duration,
) -> Result<Response, AdminError> {
    #[cfg(unix)]
    let stream = tokio::time::timeout(timeout, UnixStream::connect(socket))
        .await
        .map_err(|_| AdminError::Refused("connection timed out".into()))??;
    #[cfg(windows)]
    let stream = tokio::time::timeout(timeout, connect_pipe(socket))
        .await
        .map_err(|_| AdminError::Refused("connection timed out".into()))??;
    let (reader, mut writer) = tokio::io::split(stream);
    let request = Request {
        command: command.to_string(),
        args: args.to_vec(),
    };
    let mut line = serde_json::to_string(&request)
        .map_err(|_| AdminError::Malformed("request could not be serialised"))?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;

    let mut lines = BufReader::new(reader).lines();
    let response = tokio::time::timeout(timeout, lines.next_line())
        .await
        .map_err(|_| AdminError::Refused("no response before the timeout".into()))??;
    let Some(response) = response else {
        return Err(AdminError::Refused("daemon closed the connection".into()));
    };
    serde_json::from_str(&response)
        .map_err(|_| AdminError::Malformed("response was not valid JSON"))
}

/// Open the named pipe, retrying briefly while every instance is busy.
///
/// `ERROR_PIPE_BUSY` means the daemon is alive but all current pipe instances have
/// clients. A blocking Win32 client would call `WaitNamedPipeW` here; a short bounded
/// retry gives `egressdnsctl` the same behaviour without an extra binding.
#[cfg(windows)]
async fn connect_pipe(
    path: &Path,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    loop {
        match ClientOptions::new().open(path) {
            Ok(client) => return Ok(client),
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                    && std::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connecting_to_a_missing_socket_fails_cleanly() {
        #[cfg(unix)]
        let dir = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        let path = dir.path().join("absent.sock");
        #[cfg(windows)]
        let path =
            std::path::PathBuf::from(format!(r"\\.\pipe\egressdns-absent-{}", std::process::id()));
        let err = send(&path, "status", &[], Duration::from_millis(500))
            .await
            .expect_err("must fail");
        assert!(matches!(err, AdminError::Io(_)));
    }
}
