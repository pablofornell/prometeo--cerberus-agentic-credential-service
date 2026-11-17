//! Server-Sent Events of `GET /v1/requests/{id}/events` (ADR-0018).

use cerberus_types::wire::{AccessRequestView, ErrorResponse};

use crate::error::{ApiError, ClientError};
use crate::transport::Response;

/// Longest event block the parser keeps. The real events are about 500 bytes.
const MAX_BLOCK: usize = 1 << 20;

/// A stream of approval state changes. Read it with [`RequestEvents::next`].
#[derive(Debug)]
pub struct RequestEvents {
    response: Response,
    buf: Vec<u8>,
    done: bool,
}

impl RequestEvents {
    pub(crate) fn new(response: Response) -> Self {
        Self {
            response,
            buf: Vec::new(),
            done: false,
        }
    }

    /// The next state change, or `None` when the server closed the stream (after a final status).
    /// An `event: error` from the server ends the stream with [`ClientError::Api`].
    pub async fn next(&mut self) -> Option<Result<AccessRequestView, ClientError>> {
        loop {
            if self.done {
                return None;
            }
            match self.take_block() {
                Some(block) => match parse_block(&block) {
                    Ok(Some(view)) => return Some(Ok(view)),
                    Ok(None) => {}
                    Err(error) => {
                        self.done = true;
                        return Some(Err(error));
                    }
                },
                None => match self.response.chunk().await {
                    Ok(Some(chunk)) => {
                        self.buf.extend(chunk.iter().filter(|b| **b != b'\r'));
                        if self.buf.len() > MAX_BLOCK {
                            self.done = true;
                            return Some(Err(ClientError::Decode("event too long".to_owned())));
                        }
                    }
                    Ok(None) => {
                        self.done = true;
                        return None;
                    }
                    Err(error) => {
                        self.done = true;
                        return Some(Err(error));
                    }
                },
            }
        }
    }

    /// Removes one complete block (ends with a blank line) from the buffer.
    fn take_block(&mut self) -> Option<String> {
        let end = self.buf.windows(2).position(|w| w == b"\n\n")?;
        let block: Vec<u8> = self.buf.drain(..end + 2).collect();
        Some(String::from_utf8_lossy(&block).into_owned())
    }
}

/// Parses one block. Comment-only blocks (heartbeats) give `Ok(None)`.
fn parse_block(block: &str) -> Result<Option<AccessRequestView>, ClientError> {
    let mut event = "message";
    let mut data = String::new();
    for line in block.lines() {
        if line.starts_with(':') || line.is_empty() {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event = value,
            "data" => {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value);
            }
            _ => {}
        }
    }
    if data.is_empty() {
        return Ok(None);
    }
    match event {
        "error" => {
            let body: ErrorResponse = serde_json::from_str(&data)
                .map_err(|_| ClientError::Decode("bad error event".to_owned()))?;
            let status = cerberus_types::ErrorCode::from(body.error.code).http_status();
            Err(ClientError::Api(Box::new(ApiError::from_response(
                status, body,
            ))))
        }
        _ => serde_json::from_str(&data)
            .map(Some)
            .map_err(|_| ClientError::Decode("bad status event".to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIEW: &str = r#"{"id":"0190f000-0000-7000-8000-000000000001","item_id":"0190f000-0000-7000-8000-000000000002","permission":"read","status":"pending","requested_ttl_seconds":900,"created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:02:00Z","decided_at":null,"lease":null}"#;

    #[test]
    fn status_event_parses() {
        let view = parse_block(&format!("event: status\nid: 1\ndata: {VIEW}\n\n")).unwrap();
        assert!(view.is_some());
    }

    #[test]
    fn heartbeat_is_skipped() {
        assert!(parse_block(": keep-alive\n\n").unwrap().is_none());
    }

    #[test]
    fn error_event_is_an_api_error() {
        let data = r#"{"error":{"code":"vault_locked","message":"The vault is locked.","request_id":"0190f000-0000-7000-8000-000000000003","retryable":true}}"#;
        let error = parse_block(&format!("event: error\ndata: {data}\n\n")).unwrap_err();
        assert_eq!(error.code(), Some(cerberus_types::ErrorCode::VaultLocked));
    }
}
