//! The stdio shim (ADR-0029): reads JSON-RPC messages from a host on stdin, sends each one to
//! `https://<host>/mcp` over the pinned transport of `cerberus-client`, and writes the replies to
//! stdout. Messages are one JSON value per line, as MCP stdio defines.
//!
//! The shim keeps no secrets and logs no message bodies. Its only state is the MCP session ID and the
//! negotiated protocol version, which it copies into the headers of later requests.

use std::sync::{Arc, Mutex, PoisonError};

use cerberus_client::config::Overrides;
use cerberus_client::transport::{Request, Response};
use cerberus_client::{ClientConfig, ClientError, PinnedHttps};
use serde_json::{Value, json};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::MCP_PATH;

/// The longest message the shim accepts from the host (the server limit is the same).
const MAX_MESSAGE_BYTES: usize = 1024 * 1024 + 4096;
/// The longest reply body the shim reads in one piece.
const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
/// First protocol version that has the `Mcp-Method` and `Mcp-Name` headers (SEP-2243).
const STANDARD_HEADERS_VERSION: &str = "2026-07-28";
/// JSON-RPC code of an error the shim makes itself (the server-error range).
const SHIM_ERROR_CODE: i64 = -32000;
/// JSON-RPC code of a message that is not JSON.
const PARSE_ERROR_CODE: i64 = -32700;

const SESSION_HEADER: &str = "Mcp-Session-Id";
const VERSION_HEADER: &str = "MCP-Protocol-Version";
const VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";

/// Settings of the shim: a client configuration (URL, token, CA file and pin).
#[derive(Debug)]
pub struct ShimConfig {
    /// The pinned HTTPS settings.
    pub client: ClientConfig,
}

impl ShimConfig {
    /// Reads the settings from the environment (ADR-0029): `CERBERUS_URL`, `CERBERUS_TOKEN` or
    /// `CERBERUS_TOKEN_FILE`, and `CERBERUS_CA_FILE` (also `CERBERUS_CA_CERT`) and/or `CERBERUS_CA_PIN`
    /// (also `CERBERUS_PIN`). Without a CA file or a pin it refuses to start.
    ///
    /// # Errors
    /// [`ClientError::Config`] when a setting is missing or not valid.
    pub fn from_env() -> Result<Self, ClientError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// As [`ShimConfig::from_env`], with a lookup function in place of the process environment.
    ///
    /// # Errors
    /// [`ClientError::Config`] when a setting is missing or not valid.
    pub fn from_lookup(env: impl Fn(&str) -> Option<String>) -> Result<Self, ClientError> {
        let lookup = |name: &str| {
            env(name).or_else(|| match name {
                "CERBERUS_CA_FILE" => env("CERBERUS_CA_CERT"),
                "CERBERUS_CA_PIN" => env("CERBERUS_PIN"),
                _ => None,
            })
        };
        Ok(Self {
            client: ClientConfig::from_lookup(&Overrides::default(), lookup)?,
        })
    }
}

/// What the shim remembers about the MCP session.
#[derive(Default)]
struct Session {
    id: Option<String>,
    version: Option<String>,
}

type Shared = Arc<Mutex<Session>>;

/// The facts of one message that decide its headers.
struct Meta {
    /// `Some` for a request (a reply is expected).
    id: Option<Value>,
    method: Option<String>,
    name: Option<String>,
    version: Option<String>,
}

impl Meta {
    fn of(message: &Value) -> Self {
        let params = message.get("params");
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let name = params
            .and_then(|params| match method.as_deref() {
                Some("tools/call" | "prompts/get") => params.get("name"),
                Some("resources/read" | "resources/subscribe" | "resources/unsubscribe") => {
                    params.get("uri")
                }
                _ => None,
            })
            .and_then(Value::as_str)
            .map(str::to_owned);
        let version = params
            .and_then(|params| params.get("_meta"))
            .and_then(|meta| meta.get(VERSION_META))
            .and_then(Value::as_str)
            .map(str::to_owned);
        Self {
            id: message.get("id").filter(|_| method.is_some()).cloned(),
            method,
            name,
            version,
        }
    }
}

/// A header value that is safe as it is, or its `=?base64?...?=` form (SEP-2243).
fn header_value(value: &str) -> String {
    let plain = !value.is_empty()
        && !value.starts_with([' ', '\t'])
        && !value.ends_with([' ', '\t'])
        && value.chars().all(|c| ('\u{20}'..='\u{7e}').contains(&c))
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    if plain || value.is_empty() {
        value.to_owned()
    } else {
        format!(
            "=?base64?{}?=",
            data_encoding::BASE64.encode(value.as_bytes())
        )
    }
}

fn request_headers(meta: &Meta, session: &Shared) -> Vec<(String, String)> {
    let mut headers = vec![
        (
            "Accept".to_owned(),
            "application/json, text/event-stream".to_owned(),
        ),
        ("Content-Type".to_owned(), "application/json".to_owned()),
    ];
    let state = session.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(id) = &state.id {
        headers.push((SESSION_HEADER.to_owned(), id.clone()));
    }
    let version = meta.version.clone().or_else(|| state.version.clone());
    if let Some(version) = &version
        && meta.method.as_deref() != Some("initialize")
    {
        headers.push((VERSION_HEADER.to_owned(), version.clone()));
    }
    if version.as_deref() >= Some(STANDARD_HEADERS_VERSION)
        && meta.method.as_deref() != Some("initialize")
        && let Some(method) = &meta.method
    {
        headers.push(("Mcp-Method".to_owned(), header_value(method)));
        if let Some(name) = &meta.name {
            headers.push(("Mcp-Name".to_owned(), header_value(name)));
        }
    }
    headers
}

/// Runs the shim on the process stdin and stdout. Logs to stderr only (through `tracing`).
///
/// # Errors
/// [`ClientError`] when the transport cannot be built or stdin fails.
pub async fn run_stdio(config: ShimConfig) -> Result<(), ClientError> {
    run(
        config,
        BufReader::new(tokio::io::stdin()),
        tokio::io::stdout(),
    )
    .await
}

/// Runs the shim on any reader and writer: one JSON value per line in, one per line out. It
/// returns when the reader ends.
///
/// # Errors
/// [`ClientError`] when the transport cannot be built, a message is longer than the limit, or
/// reading fails.
pub async fn run<R, W>(config: ShimConfig, mut input: R, output: W) -> Result<(), ClientError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let http = PinnedHttps::from_config(&config.client)?;
    drop(config);
    let session: Shared = Arc::default();
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(write_lines(output, rx));
    let mut tasks = JoinSet::new();
    let mut line = Vec::new();
    let result = loop {
        line.clear();
        match read_message(&mut input, &mut line).await {
            Ok(true) => {}
            Ok(false) => break Ok(()),
            Err(error) => break Err(error),
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let body = std::mem::take(&mut line);
        let (http, session, tx) = (http.clone(), Arc::clone(&session), tx.clone());
        tasks.spawn(async move { forward(&http, &session, &tx, body).await });
    };
    // The host is gone or done: stop the calls in flight (the server sees the closed connection),
    // then end the session.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    end_session(&http, &session).await;
    drop(tx);
    if writer.await.is_err() {
        tracing::warn!("the stdout writer stopped");
    }
    result
}

/// Reads one line (without a limit on what the host may send, except [`MAX_MESSAGE_BYTES`]).
/// `false` at the end of the input.
async fn read_message<R: AsyncBufRead + Unpin>(
    input: &mut R,
    line: &mut Vec<u8>,
) -> Result<bool, ClientError> {
    let mut limited = (&mut *input).take(u64::try_from(MAX_MESSAGE_BYTES + 1).unwrap_or(u64::MAX));
    let read = limited.read_until(b'\n', line).await?;
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(ClientError::Decode(
            "message from the host is too long".to_owned(),
        ));
    }
    Ok(read > 0)
}

async fn write_lines<W: AsyncWrite + Unpin>(
    mut output: W,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(mut message) = rx.recv().await {
        message.push(b'\n');
        if output.write_all(&message).await.is_err() || output.flush().await.is_err() {
            tracing::warn!("cannot write to stdout");
            return;
        }
    }
}

/// Sends the message and writes what comes back.
async fn forward(
    http: &PinnedHttps,
    session: &Shared,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
    body: Vec<u8>,
) {
    let message: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            send(
                tx,
                &error_message(&Value::Null, PARSE_ERROR_CODE, "Parse error", None),
            );
            return;
        }
    };
    let meta = Meta::of(&message);
    let headers = request_headers(&meta, session);
    let mut request = Request::post_json(MCP_PATH, body);
    request.headers = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let id = meta.id.clone().unwrap_or(Value::Null);
    let outcome = match http.send(request).await {
        Ok(response) => handle(response, &meta, session, tx, &id).await,
        Err(error) => Err(error),
    };
    if let Err(error) = outcome
        && meta.id.is_some()
    {
        send(
            tx,
            &error_message(&id, SHIM_ERROR_CODE, &describe(&error), None),
        );
    }
}

async fn handle(
    mut response: Response,
    meta: &Meta,
    session: &Shared,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
    id: &Value,
) -> Result<(), ClientError> {
    let status = response.status();
    if let Some(value) = response.header(SESSION_HEADER) {
        let mut state = session.lock().unwrap_or_else(PoisonError::into_inner);
        state.id = Some(value.to_owned());
    }
    if !(200..300).contains(&status) {
        let bytes = response.bytes(MAX_REPLY_BYTES).await?;
        if meta.id.is_some() {
            send(tx, &http_error(id, status, &bytes));
        }
        return Ok(());
    }
    let is_stream = response
        .header("content-type")
        .is_some_and(|value| value.starts_with("text/event-stream"));
    if is_stream {
        let mut events = EventBuffer::default();
        while let Some(chunk) = response.chunk().await? {
            for data in events.push(&chunk)? {
                note_initialize(&data, meta, session);
                send(tx, &data);
            }
        }
        return Ok(());
    }
    let bytes = response.bytes(MAX_REPLY_BYTES).await?;
    if !bytes.iter().all(u8::is_ascii_whitespace) {
        let compact = compact(&bytes);
        note_initialize(&compact, meta, session);
        send(tx, &compact);
    }
    Ok(())
}

/// Remembers the protocol version the server chose in its `initialize` reply.
fn note_initialize(reply: &[u8], meta: &Meta, session: &Shared) {
    if meta.method.as_deref() != Some("initialize") {
        return;
    }
    let version = serde_json::from_slice::<Value>(reply)
        .ok()
        .and_then(|value| {
            value
                .get("result")?
                .get("protocolVersion")?
                .as_str()
                .map(str::to_owned)
        });
    if let Some(version) = version {
        session
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .version = Some(version);
    }
}

fn send(tx: &mpsc::UnboundedSender<Vec<u8>>, message: &[u8]) {
    if tx.send(message.to_vec()).is_err() {
        tracing::debug!("stdout is closed");
    }
}

/// The JSON of `bytes` on one line (SSE and JSON bodies may hold line breaks).
fn compact(bytes: &[u8]) -> Vec<u8> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| serde_json::to_vec(&value).ok())
        .unwrap_or_else(|| bytes.trim_ascii().to_vec())
}

/// A JSON-RPC error that the shim makes. `data` is the Cerberus error object when the server sent one.
fn error_message(id: &Value, code: i64, message: &str, data: Option<Value>) -> Vec<u8> {
    let mut error = json!({ "code": code, "message": message });
    if let (Some(data), Some(map)) = (data, error.as_object_mut()) {
        map.insert("data".to_owned(), data);
    }
    serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "error": error })).unwrap_or_default()
}

/// A JSON-RPC error for an HTTP error status. The body is passed on only when it is the ADR-0021
/// error object (the server never puts a secret in it).
fn http_error(id: &Value, status: u16, body: &[u8]) -> Vec<u8> {
    let object = serde_json::from_slice::<Value>(body).ok().filter(|value| {
        value
            .get("error")
            .is_some_and(|error| error.get("code").is_some())
    });
    let code = object
        .as_ref()
        .and_then(|value| value.pointer("/error/code"))
        .and_then(Value::as_str)
        .map_or_else(|| format!("http_{status}"), str::to_owned);
    error_message(id, SHIM_ERROR_CODE, &code, object)
}

/// What the host sees when the call failed before an answer: no detail that is not already public.
fn describe(error: &ClientError) -> String {
    match error {
        ClientError::PinMismatch => "certificate pin mismatch".to_owned(),
        ClientError::Timeout => "timeout".to_owned(),
        ClientError::Connect(_) => "cannot connect to Cerberus".to_owned(),
        other => other.to_string(),
    }
}

/// Collects SSE events from chunks and returns the `data` of each complete event.
#[derive(Default)]
struct EventBuffer {
    text: String,
    pending: Vec<u8>,
}

impl EventBuffer {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, ClientError> {
        self.pending.extend_from_slice(chunk);
        // A chunk can end inside a UTF-8 character: keep the unfinished bytes for the next one.
        let valid = match std::str::from_utf8(&self.pending) {
            Ok(text) => text.len(),
            Err(error) => error.valid_up_to(),
        };
        let rest = self.pending.split_off(valid);
        let head = std::mem::replace(&mut self.pending, rest);
        self.text.push_str(
            &String::from_utf8(head).map_err(|_| ClientError::Decode("not UTF-8".to_owned()))?,
        );
        if self.text.len() > MAX_REPLY_BYTES {
            return Err(ClientError::Decode("event is too long".to_owned()));
        }
        self.text = self.text.replace("\r\n", "\n");
        let mut out = Vec::new();
        while let Some(end) = self.text.find("\n\n") {
            let block: String = self.text.drain(..end + 2).collect();
            let data: Vec<&str> = block
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(|data| data.strip_prefix(' ').unwrap_or(data))
                .collect();
            let data = data.join("\n");
            if !data.trim().is_empty() {
                out.push(compact(data.as_bytes()));
            }
        }
        Ok(out)
    }
}

/// `DELETE /mcp` ends the session on the server. Best effort.
async fn end_session(http: &PinnedHttps, session: &Shared) {
    let id = session
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .id
        .clone();
    let Some(id) = id else { return };
    let request = Request {
        method: hyper::Method::DELETE,
        path: MCP_PATH,
        headers: vec![(SESSION_HEADER, id.as_str())],
        body: None,
    };
    if http.send(request).await.is_err() {
        tracing::debug!("the session could not be ended");
    }
}
