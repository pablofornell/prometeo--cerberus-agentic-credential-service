//! Server-Sent Events.
//!
//! - [`EventStream`]: a generic reader of any `text/event-stream` answer. It gives each event as
//!   its name and its data; comment lines (heartbeats) and blocks without data are skipped. The
//!   desktop in remote mode reads `GET /admin/v1/events` with it (ADR-0034).
//! - [`RequestEvents`]: the approval state changes of `GET /v1/requests/{id}/events`
//!   (ADR-0018), built on [`EventStream`].

use cerberus_types::wire::{AccessRequestView, ErrorResponse};

use crate::error::{ApiError, ClientError};
use crate::transport::Response;

/// Longest event block the parser keeps. The real events are about 500 bytes.
const MAX_BLOCK: usize = 1 << 20;

/// A generic event stream over a [`Response`]. Read it with [`EventStream::next`].
#[derive(Debug)]
pub struct EventStream {
    response: Response,
    buf: Vec<u8>,
    done: bool,
}

impl EventStream {
    /// Reads events from `response` (send the request with the transport, check the status, then
    /// wrap the response).
    #[must_use]
    pub fn new(response: Response) -> Self {
        Self {
            response,
            buf: Vec::new(),
            done: false,
        }
    }

    /// The next event as its name (`message` when the block has no `event:` line) and its data
    /// (several `data:` lines joined with `\n`). `None` when the server closed the stream. An
    /// error (a timeout without a heartbeat, a transport error, a block over 1 MiB) ends the
    /// stream.
    pub async fn next(&mut self) -> Option<Result<(String, Vec<u8>), ClientError>> {
        loop {
            if self.done {
                return None;
            }
            match self.take_block() {
                Some(block) => {
                    if let Some(event) = parse_event(&block) {
                        return Some(Ok(event));
                    }
                }
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
    fn take_block(&mut self) -> Option<Vec<u8>> {
        let end = self.buf.windows(2).position(|w| w == b"\n\n")?;
        Some(self.buf.drain(..end + 2).collect())
    }
}

/// Parses one block into its event name and data. `None` for a block without data: a comment
/// (heartbeat), or `event:` / `id:` / `retry:` lines alone.
fn parse_event(block: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut event: &[u8] = b"message";
    let mut data: Vec<u8> = Vec::new();
    let mut has_data = false;
    for line in block.split(|b| *b == b'\n') {
        if line.is_empty() || line.starts_with(b":") {
            continue;
        }
        let (field, value) = match line.iter().position(|b| *b == b':') {
            Some(at) => (&line[..at], &line[at + 1..]),
            None => (line, &[][..]),
        };
        let value = value.strip_prefix(b" ").unwrap_or(value);
        match field {
            b"event" => event = value,
            b"data" => {
                if has_data {
                    data.push(b'\n');
                }
                data.extend_from_slice(value);
                has_data = true;
            }
            _ => {}
        }
    }
    has_data.then(|| (String::from_utf8_lossy(event).into_owned(), data))
}

/// A stream of approval state changes. Read it with [`RequestEvents::next`].
#[derive(Debug)]
pub struct RequestEvents {
    events: EventStream,
    done: bool,
}

impl RequestEvents {
    pub(crate) fn new(response: Response) -> Self {
        Self {
            events: EventStream::new(response),
            done: false,
        }
    }

    /// The next state change, or `None` when the server closed the stream (after a final status).
    /// An `event: error` from the server ends the stream with [`ClientError::Api`].
    pub async fn next(&mut self) -> Option<Result<AccessRequestView, ClientError>> {
        if self.done {
            return None;
        }
        let result = match self.events.next().await? {
            Ok((name, data)) => parse_status(&name, &data),
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

/// One event of the approval stream: a status, or the error that ends it.
fn parse_status(event: &str, data: &[u8]) -> Result<AccessRequestView, ClientError> {
    match event {
        "error" => {
            let body: ErrorResponse = serde_json::from_slice(data)
                .map_err(|_| ClientError::Decode("bad error event".to_owned()))?;
            let status = cerberus_types::ErrorCode::from(body.error.code).http_status();
            Err(ClientError::Api(Box::new(ApiError::from_response(
                status, body,
            ))))
        }
        _ => serde_json::from_slice(data)
            .map_err(|_| ClientError::Decode("bad status event".to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIEW: &str = r#"{"id":"0190f000-0000-7000-8000-000000000001","item_id":"0190f000-0000-7000-8000-000000000002","permission":"read","status":"pending","requested_ttl_seconds":900,"created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-01T00:02:00Z","decided_at":null,"lease":null}"#;

    fn status_of(block: &str) -> Option<Result<AccessRequestView, ClientError>> {
        parse_event(block.as_bytes()).map(|(name, data)| parse_status(&name, &data))
    }

    #[test]
    fn status_event_parses() {
        let view = status_of(&format!("event: status\nid: 1\ndata: {VIEW}\n\n")).unwrap();
        assert!(view.is_ok());
    }

    #[test]
    fn heartbeat_is_skipped() {
        assert!(parse_event(b": keep-alive\n\n").is_none());
        assert!(parse_event(b"event: ping\nid: 3\nretry: 10\n\n").is_none());
    }

    #[test]
    fn error_event_is_an_api_error() {
        let data = r#"{"error":{"code":"vault_locked","message":"The vault is locked.","request_id":"0190f000-0000-7000-8000-000000000003","retryable":true}}"#;
        let error = status_of(&format!("event: error\ndata: {data}\n\n"))
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), Some(cerberus_types::ErrorCode::VaultLocked));
    }

    #[test]
    fn generic_events_keep_their_name_and_join_data_lines() {
        let (name, data) = parse_event(
            b"event: LeaseChanged\ndata: {\"event\":\"LeaseChanged\",\ndata:\"id\":\"x\"}\n\n",
        )
        .unwrap();
        assert_eq!(name, "LeaseChanged");
        assert_eq!(data, b"{\"event\":\"LeaseChanged\",\n\"id\":\"x\"}");
        let (name, data) = parse_event(b"data: plain\n\n").unwrap();
        assert_eq!(name, "message");
        assert_eq!(data, b"plain");
        // A comment line inside a block, an unknown field and an empty data line.
        let (name, data) = parse_event(b": hi\nevent:Tick\nfoo: bar\ndata:\n\n").unwrap();
        assert_eq!(name, "Tick");
        assert!(data.is_empty());
    }
}
