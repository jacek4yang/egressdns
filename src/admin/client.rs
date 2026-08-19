//! Client side of the administration protocol, used by `egressdnsctl`.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    let stream = tokio::time::timeout(timeout, UnixStream::connect(socket))
        .await
        .map_err(|_| AdminError::Refused("connection timed out".into()))??;
    let (reader, mut writer) = stream.into_split();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connecting_to_a_missing_socket_fails_cleanly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.sock");
        let err = send(&path, "status", &[], Duration::from_millis(500))
            .await
            .expect_err("must fail");
        assert!(matches!(err, AdminError::Io(_)));
    }
}
