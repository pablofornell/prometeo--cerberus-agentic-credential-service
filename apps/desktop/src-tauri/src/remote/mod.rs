//! The desktop in remote mode (ADR-0034 point 7, DEC-RM-9): no local vault and no local server.
//! The commands of the remote allowlist go to one `cerberusd` over pinned HTTPS with the client
//! certificate of an imported bundle; every other command is refused here with
//! `remote_unsupported`, before any network call (DEC-RM-11).
//!
//! - [`RemoteBackend`]: the transport, the admin session (its token lives only here, zeroized on
//!   drop and never logged) and what the desktop last saw of the server ([`Link`]).
//! - [`profile`]: bundle import, the profile files and the trust settings.
//! - [`setup`]: the first-time setup of a server that has no vault: the setup code and its errors.
//! - [`pump`]: the live events of the server, turned into the same Tauri events as the local pump.
//!
//! A session that ends on the server (expiry, lock, revoke) is noticed at the next call or by the
//! event stream: the token is dropped and the link changes, so the pump emits
//! `VaultStateChanged { sealed }` and the UI shows the unlock screen (ADR-0034 point 7.4).

pub mod profile;
pub mod pump;
pub mod setup;

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::http::Method;
use cerberus_admin::dto::{RemoteStatusView, Secret, SessionView, VaultState, VaultStatusView, ts};
use cerberus_admin::error::{IpcError, IpcResult};
use cerberus_admin::remote::{ADMIN_PROTOCOL, Gate, REMOTE_COMMANDS, counts_as_activity, gate};
use cerberus_admin::rpc::{self, VaultStatusArgs, VaultUnlockArgs};
use cerberus_admin::wire::{
    AdminErrorBody, EVENTS_PATH, HELLO_PATH, HelloView, RPC_PREFIX, SESSION_PATH, SessionOpenedView,
};
use cerberus_client::transport::{Request, Response};
use cerberus_client::{ClientError, EventStream, PinnedHttps, WireSecret, zeroizing_body};
use cerberus_core::CoreError;
use cerberus_types::Clock;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{Mutex as AsyncMutex, watch};
use zeroize::Zeroizing;

use crate::prefs::RemoteProfile;

/// Time limit of one call. The event stream uses it as its idle limit; the server sends a
/// heartbeat every 15 s.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest answer the desktop reads. A browser session reveal is the largest answer (1 MiB of
/// storage state plus JSON escapes).
const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;
/// Largest answer of `hello`, the session route and an error.
const MAX_SMALL_ANSWER_BYTES: usize = 64 * 1024;
/// `ui_activity` goes to the server at most once in this time (ADR-0034 point 6.5).
const KEEPALIVE_GAP_MS: i64 = 30_000;
/// Longest the desktop waits for `DELETE /admin/v1/session` (at quit, ADR-0034 point 7.5).
pub const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// The IPC commands that run in remote mode through their own `ops` function instead of the
/// generic forward of the `ipc!(@remote ...)` arm: the session commands and the status. Together
/// with the `@remote` commands they are exactly the remote allowlist (a contract test checks it).
pub const CUSTOM_REMOTE_COMMANDS: [&str; 5] = [
    "vault_status",
    "vault_unlock",
    "vault_lock",
    "vault_panic",
    "ui_activity",
];

/// The error of a command that the remote server does not answer.
#[must_use]
pub fn unsupported() -> IpcError {
    IpcError::remote_unsupported("not available for a remote server")
}

/// What the desktop last saw of the server. The event pump follows it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Link {
    /// Serial of the live admin session of this desktop. A new session gets a new serial.
    pub session: Option<u64>,
    /// True when the last call reached the server.
    pub reachable: bool,
    /// The server vault state, as last seen.
    pub server_state: Option<VaultState>,
    /// The server version, from `hello`.
    pub server_version: Option<String>,
    /// Code of the last failed contact; `None` after a good answer.
    pub problem: Option<String>,
}

/// The admin session of this desktop. The token is zeroized when the last copy drops.
struct Session {
    serial: u64,
    token: Arc<WireSecret>,
    view: SessionView,
    /// The idle and absolute limits the server gave at the open. The desktop applies them too, so a
    /// session it cannot confirm (server out of reach) still ends on time (DEC-RM-26).
    idle_seconds: u32,
    max_seconds: u32,
    opened_ms: i64,
}

/// Why a session ends on the desktop's own clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expiry {
    Idle,
    Max,
}

impl Session {
    /// The limit this session passed at `now`, given the last activity at `used`.
    fn expiry(&self, now: i64, used: i64) -> Option<Expiry> {
        if now.saturating_sub(used) >= i64::from(self.idle_seconds) * 1000 {
            Some(Expiry::Idle)
        } else if now.saturating_sub(self.opened_ms) >= i64::from(self.max_seconds) * 1000 {
            Some(Expiry::Max)
        } else {
            None
        }
    }

    /// Whole seconds until the first limit, at `now`.
    fn seconds_left(&self, now: i64, used: i64) -> u32 {
        let idle = (i64::from(self.idle_seconds) * 1000).saturating_sub(now.saturating_sub(used));
        let max =
            (i64::from(self.max_seconds) * 1000).saturating_sub(now.saturating_sub(self.opened_ms));
        u32::try_from(idle.min(max).max(0) / 1000).unwrap_or(u32::MAX)
    }
}

/// The desktop's client of one `cerberusd` admin API.
pub struct RemoteBackend {
    profile: RemoteProfile,
    http: PinnedHttps,
    clock: Arc<dyn Clock>,
    session: Mutex<Option<Session>>,
    /// One session open at a time.
    open_gate: AsyncMutex<()>,
    serial: AtomicU64,
    link: watch::Sender<Link>,
    /// Last activity of the person that the server saw (ms since 1970): the open, a keep-alive, an
    /// action (`remote::counts_as_activity`). Reads do not count, as on the server.
    last_use_ms: AtomicI64,
    /// Last `ui_activity` sent to the server.
    last_keepalive_ms: AtomicI64,
    /// The last `vault_status` of the server, for the view while the server cannot be reached.
    last_status: Mutex<Option<VaultStatusView>>,
}

impl std::fmt::Debug for RemoteBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteBackend")
            .field("profile", &self.profile.id)
            .field("url", &self.profile.url)
            .finish_non_exhaustive()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The IPC error of a transport failure. The text never holds the URL or a header.
fn transport_error(error: &ClientError) -> IpcError {
    match error {
        ClientError::PinMismatch => IpcError::new(
            "remote_pin_mismatch",
            "the server certificate does not match the CA pin of this profile",
        ),
        ClientError::Connect(_)
        | ClientError::Tls(_)
        | ClientError::Timeout
        | ClientError::Transport(_) => {
            tracing::warn!(%error, "the remote server cannot be reached");
            IpcError::new("remote_unreachable", "cannot reach the server")
        }
        ClientError::Decode(_) => protocol_mismatch(),
        other => IpcError::internal(other),
    }
}

fn protocol_mismatch() -> IpcError {
    IpcError::new(
        "remote_protocol_mismatch",
        "the server does not speak the admin protocol of this desktop",
    )
}

/// The IPC error of an error answer: the admin body when the server sent one (ADR-0034 point
/// 5.4), else a code by the status (errors of the shared outer layers keep the agent shape).
fn answer_error(status: u16, retry_after: Option<u32>, body: &[u8]) -> IpcError {
    if let Ok(AdminErrorBody { mut error, .. }) = serde_json::from_slice::<AdminErrorBody>(body) {
        if error.retry_after_seconds.is_none() {
            error.retry_after_seconds = retry_after;
        }
        return error;
    }
    let mut error = match status {
        401 => IpcError::admin_session_required(),
        403 => IpcError::new(
            "forbidden",
            "the server refused the request (its host or origin rules)",
        ),
        404 => IpcError::new(
            "remote_protocol_mismatch",
            "the server has no admin API (turn on [admin] in cerberusd.toml)",
        ),
        413 => IpcError::new("payload_too_large", "the request is too large"),
        423 => CoreError::Locked.into(),
        429 => IpcError::new("rate_limited", "too many requests; wait and try again"),
        _ => IpcError::new("internal", "the server failed to answer the request"),
    };
    error.retry_after_seconds = retry_after;
    error
}

impl RemoteBackend {
    /// A backend for `profile` over `http` (built by [`profile::transport`]).
    #[must_use]
    pub fn new(profile: RemoteProfile, http: PinnedHttps, clock: Arc<dyn Clock>) -> Self {
        Self {
            profile,
            http,
            clock,
            session: Mutex::new(None),
            open_gate: AsyncMutex::new(()),
            serial: AtomicU64::new(0),
            link: watch::channel(Link::default()).0,
            last_use_ms: AtomicI64::new(0),
            last_keepalive_ms: AtomicI64::new(0),
            last_status: Mutex::new(None),
        }
    }

    /// The profile in use.
    #[must_use]
    pub const fn profile(&self) -> &RemoteProfile {
        &self.profile
    }

    /// A receiver that changes with the session and the reachability of the server.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Link> {
        self.link.subscribe()
    }

    /// What the desktop last saw of the server.
    #[must_use]
    pub fn link(&self) -> Link {
        self.link.borrow().clone()
    }

    /// True while this desktop holds an admin session.
    #[must_use]
    pub fn has_session(&self) -> bool {
        locked(&self.session).is_some()
    }

    /// The vault session that the admin session acts in.
    #[must_use]
    pub fn session_view(&self) -> Option<SessionView> {
        locked(&self.session).as_ref().map(|s| s.view.clone())
    }

    fn token(&self) -> Option<(u64, Arc<WireSecret>)> {
        self.expire_if_due();
        locked(&self.session)
            .as_ref()
            .map(|s| (s.serial, Arc::clone(&s.token)))
    }

    fn now_ms(&self) -> i64 {
        self.clock.now().as_millisecond()
    }

    /// Ends the session when its idle or absolute limit passed on the desktop's clock, also when the
    /// server cannot confirm it (DEC-RM-26). The link change makes the pump report `sealed`, so the
    /// UI drops its data as at a local lock. True when a session was ended.
    pub fn expire_if_due(&self) -> bool {
        let now = self.now_ms();
        let used = self.last_use_ms.load(Ordering::SeqCst);
        let ended = {
            let mut session = locked(&self.session);
            match session.as_ref().and_then(|s| s.expiry(now, used)) {
                Some(why) => session.take().map(|_| why),
                None => None,
            }
        };
        let Some(why) = ended else {
            return false;
        };
        tracing::info!(
            ?why,
            "the remote admin session passed its limit on this desktop"
        );
        self.link.send_modify(|link| link.session = None);
        true
    }

    /// Seconds until this desktop's session ends on its own limits, or `None` without a session.
    /// The rail's auto-lock countdown shows it in remote mode (DEC-RM-26).
    #[must_use]
    pub fn session_seconds_left(&self) -> Option<u32> {
        let now = self.now_ms();
        let used = self.last_use_ms.load(Ordering::SeqCst);
        locked(&self.session)
            .as_ref()
            .map(|s| s.seconds_left(now, used))
    }

    /// Forgets the session, if it is still the one with `serial` (`None`: any session). A stale
    /// answer of an old session never drops a newer one.
    pub fn drop_session(&self, serial: Option<u64>) {
        let dropped = {
            let mut session = locked(&self.session);
            let matches = match (session.as_ref(), serial) {
                (Some(live), Some(serial)) => live.serial == serial,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if matches { session.take() } else { None }
        };
        if dropped.is_some() {
            tracing::info!("the remote admin session ended");
            self.link.send_modify(|link| link.session = None);
        }
    }

    /// The server vault state that an event reported.
    pub fn note_server_state(&self, state: VaultState) {
        self.link.send_if_modified(|link| {
            let changed = link.server_state != Some(state);
            link.server_state = Some(state);
            changed
        });
    }

    /// The panic hook: drops the token without waiting (a busy lock is skipped).
    pub fn wipe(&self) {
        if let Ok(mut session) = self.session.try_lock() {
            session.take();
        }
    }

    /// The server answered. An error answer sets its problem again right after ([`Self::read`]).
    fn note_reached(&self) {
        self.link.send_if_modified(|link| {
            let changed = !link.reachable || link.problem.is_some();
            link.reachable = true;
            link.problem = None;
            changed
        });
    }

    fn note_problem(&self, error: &IpcError) {
        let code = error.code.as_str();
        let contact = matches!(
            code,
            "remote_unreachable" | "remote_pin_mismatch" | "remote_protocol_mismatch"
        );
        if !contact && code != "admin_cert_required" {
            return;
        }
        self.link.send_if_modified(|link| {
            let before = link.clone();
            link.reachable = !contact;
            link.problem = Some(code.to_owned());
            *link != before
        });
    }

    /// Sends one request, with the session token when `bearer` is set.
    async fn send(&self, request: Request<'_>, bearer: Option<&WireSecret>) -> IpcResult<Response> {
        match self.http.send_bearer(request, bearer).await {
            Ok(response) => {
                self.note_reached();
                Ok(response)
            }
            Err(error) => {
                let error = transport_error(&error);
                self.note_problem(&error);
                Err(error)
            }
        }
    }

    /// Reads an answer: the body of a 2xx, else the error.
    async fn read(&self, response: Response, limit: usize) -> IpcResult<Zeroizing<Vec<u8>>> {
        let status = response.status();
        let retry = response
            .header("retry-after")
            .and_then(|text| text.trim().parse::<u32>().ok());
        let body = response.bytes_zeroizing(limit).await.map_err(|error| {
            let error = transport_error(&error);
            self.note_problem(&error);
            error
        })?;
        if (200..300).contains(&status) {
            return Ok(body);
        }
        let error = answer_error(status, retry, &body);
        self.note_problem(&error);
        Err(error)
    }

    /// `GET /admin/v1/hello`: the server version, protocol and vault state. A server with another
    /// admin protocol is refused (`remote_protocol_mismatch`).
    ///
    /// # Errors
    /// `remote_unreachable`, `remote_pin_mismatch`, `remote_protocol_mismatch`,
    /// `admin_cert_required` (the enrolment is revoked or expired).
    pub async fn hello(&self) -> IpcResult<HelloView> {
        let response = self.send(Request::get(HELLO_PATH), None).await?;
        let body = self.read(response, MAX_SMALL_ANSWER_BYTES).await?;
        let hello: HelloView = serde_json::from_slice(&body).map_err(|_| protocol_mismatch())?;
        if hello.admin_protocol != ADMIN_PROTOCOL {
            let error = protocol_mismatch();
            self.note_problem(&error);
            return Err(error);
        }
        self.link.send_if_modified(|link| {
            let before = link.clone();
            link.server_version = Some(hello.server_version.clone());
            link.server_state = Some(hello.vault_state);
            *link != before
        });
        Ok(hello)
    }

    /// Runs one command of the allowlist on the server with `body` (its JSON arguments) and
    /// decodes the answer as the IPC result type.
    ///
    /// A command off the list is `remote_unsupported` with no network call; a session command
    /// without a session is `vault_locked`, also with no network call. An answer that says the
    /// session is gone (`admin_session_required`, `vault_locked`, `admin_cert_required`) drops
    /// the token.
    ///
    /// # Errors
    /// The `IpcError` of the server, or a transport error as [`Self::hello`].
    pub async fn call<R: DeserializeOwned>(
        &self,
        command: &str,
        body: Zeroizing<Vec<u8>>,
    ) -> IpcResult<R> {
        let session = match gate(command) {
            None | Some(Gate::OpensSession) => return Err(unsupported()),
            Some(Gate::PreSession) => None,
            Some(Gate::Session) => Some(self.token().ok_or(CoreError::Locked)?),
        };
        let path = format!("{RPC_PREFIX}{command}");
        let request = Request::post_json(&path, zeroizing_body(body));
        let bearer = session.as_ref().map(|(_, token)| &**token);
        let answer = match self.send(request, bearer).await {
            Ok(response) => self.read(response, MAX_ANSWER_BYTES).await,
            Err(error) => Err(error),
        };
        match answer {
            Ok(body) => {
                if session.is_some() && counts_as_activity(command) {
                    self.last_use_ms.store(self.now_ms(), Ordering::SeqCst);
                }
                // The serde text is not kept: it can quote a secret of the answer.
                serde_json::from_slice(&body).map_err(|_| protocol_mismatch())
            }
            Err(error) => {
                if let Some((serial, _)) = session
                    && matches!(
                        error.code.as_str(),
                        "admin_session_required" | "vault_locked" | "admin_cert_required"
                    )
                {
                    self.drop_session(Some(serial));
                }
                Err(error)
            }
        }
    }

    /// As [`Self::call`], with the arguments written into a zeroizing buffer first.
    ///
    /// # Errors
    /// As [`Self::call`].
    pub async fn forward<R: DeserializeOwned, A: Serialize + ?Sized>(
        &self,
        command: &str,
        args: &A,
    ) -> IpcResult<R> {
        self.call(command, rpc::to_body(args)?).await
    }

    /// `POST /admin/v1/session` (`vault_unlock` in remote mode): opens an admin session with the
    /// phrase of the bound operator. A sealed server vault is unlocked by it (ADR-0034 point 6.3).
    /// A session this desktop held before is closed.
    ///
    /// # Errors
    /// `forbidden` (another operator than the bound one), `conflict` (another operator unlocked
    /// the server vault), `bad_credentials`, `too_many_failures`, `rate_limited`, or a transport
    /// error.
    pub async fn open_session(
        &self,
        operator_id: String,
        phrase: Secret,
    ) -> IpcResult<SessionView> {
        let _gate = self.open_gate.lock().await;
        let body = rpc::to_body(&VaultUnlockArgs {
            operator_id,
            phrase,
        })?;
        let response = self
            .send(Request::post_json(SESSION_PATH, zeroizing_body(body)), None)
            .await?;
        let body = self.read(response, MAX_SMALL_ANSWER_BYTES).await?;
        let opened: SessionOpenedView =
            serde_json::from_slice(&body).map_err(|_| protocol_mismatch())?;
        let serial = self.serial.fetch_add(1, Ordering::SeqCst) + 1;
        let view = opened.session.clone();
        let old = locked(&self.session).replace(Session {
            serial,
            token: Arc::new(opened.token),
            view: view.clone(),
            idle_seconds: opened.idle_seconds,
            max_seconds: opened.max_seconds,
            opened_ms: self.now_ms(),
        });
        let now = self.now_ms();
        self.last_use_ms.store(now, Ordering::SeqCst);
        self.last_keepalive_ms.store(now, Ordering::SeqCst);
        self.link.send_modify(|link| {
            link.session = Some(serial);
            link.server_state = Some(VaultState::Unlocked);
        });
        if let Some(old) = old {
            self.delete_session(&old.token).await;
        }
        tracing::info!(profile = %self.profile.id, "remote admin session opened");
        Ok(view)
    }

    async fn delete_session(&self, token: &WireSecret) {
        let request = Request {
            method: Method::DELETE,
            path: SESSION_PATH,
            headers: Vec::new(),
            body: None,
        };
        let sent = tokio::time::timeout(CLOSE_WAIT, self.http.send_bearer(request, Some(token)));
        match sent.await {
            Ok(Ok(response)) if (200..300).contains(&response.status()) => {}
            Ok(Ok(response)) => {
                tracing::info!(
                    status = response.status(),
                    "the server did not close the admin session"
                );
            }
            Ok(Err(error)) => tracing::info!(%error, "the admin session close was not sent"),
            Err(_) => tracing::info!("the admin session close timed out"),
        }
    }

    /// Ends this desktop's session: the token is dropped at once, then `DELETE` tells the server
    /// (bounded by [`CLOSE_WAIT`]). The server vault stays as it is (DEC-RM-8).
    pub async fn close_session(&self) {
        let session = locked(&self.session).take();
        let Some(session) = session else {
            return;
        };
        self.link.send_modify(|link| link.session = None);
        self.delete_session(&session.token).await;
        tracing::info!("remote admin session closed");
    }

    /// The person is at work: sends `ui_activity` (the session keep-alive) when the last one is
    /// at least 30 s old. Returns at once; the call runs on the async runtime.
    pub fn keepalive(self: &Arc<Self>) {
        if !self.has_session() {
            return;
        }
        let now = self.now_ms();
        let last = self.last_keepalive_ms.load(Ordering::SeqCst);
        if now.saturating_sub(last) < KEEPALIVE_GAP_MS
            || self
                .last_keepalive_ms
                .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return;
        }
        let backend = Arc::clone(self);
        drop(tauri::async_runtime::spawn(async move {
            if let Err(error) = backend.forward::<(), _>("ui_activity", &EMPTY).await {
                tracing::info!(code = %error.code, "remote keep-alive failed");
            }
        }));
    }

    /// `GET /admin/v1/events` with the session token. The session serial comes with the stream,
    /// so the pump can tell when it belongs to an old session.
    ///
    /// # Errors
    /// `vault_locked` without a session; else as [`Self::call`] (`admin_session_required` drops
    /// the session).
    pub async fn events(&self) -> IpcResult<(u64, EventStream)> {
        let (serial, token) = self.token().ok_or(CoreError::Locked)?;
        let response = self.send(Request::get(EVENTS_PATH), Some(&token)).await?;
        if response.status() == 200 {
            return Ok((serial, EventStream::new(response)));
        }
        let error = match self.read(response, MAX_SMALL_ANSWER_BYTES).await {
            Ok(_) => protocol_mismatch(),
            Err(error) => error,
        };
        if matches!(
            error.code.as_str(),
            "admin_session_required" | "vault_locked" | "admin_cert_required"
        ) {
            self.drop_session(Some(serial));
        }
        Err(error)
    }

    /// The remote part of `vault_status`.
    #[must_use]
    pub fn remote_view(&self) -> RemoteStatusView {
        let link = self.link();
        RemoteStatusView {
            profile_id: self.profile.id.clone(),
            label: self.profile.label.clone(),
            url: self.profile.url.clone(),
            operator_id: self.profile.operator_id.clone(),
            not_after: ts(self.profile.not_after),
            server_state: link.server_state,
            reachable: link.reachable,
            has_session: link.session.is_some(),
            server_version: link.server_version,
            problem: link.problem,
        }
    }

    /// `vault_status` in remote mode (DEC-RM-10): the server's status (`rpc/vault_status`), with
    /// the state `unlocked` only while this desktop holds a session, and the `remote` field. An
    /// unreachable server is a normal answer (`remote.reachable = false`).
    pub async fn status_view(&self, os_hook_ok: bool) -> VaultStatusView {
        let link = self.link();
        if link.server_version.is_none() || !link.reachable {
            // The answer goes into the link; a failure is in the link too.
            let _ = self.hello().await;
        }
        let answer = self
            .forward::<VaultStatusView, _>("vault_status", &VaultStatusArgs {})
            .await;
        let mut view = match answer {
            Ok(view) => {
                self.link.send_if_modified(|link| {
                    let changed = link.server_state != Some(view.state);
                    link.server_state = Some(view.state);
                    changed
                });
                *locked(&self.last_status) = Some(view.clone());
                view
            }
            Err(_) => locked(&self.last_status)
                .clone()
                .unwrap_or_else(sealed_view),
        };
        let server = self.link().server_state;
        // A server vault that is not open has no session of ours any more (sessions end at a lock).
        if matches!(server, Some(VaultState::Sealed | VaultState::NoVault)) {
            self.drop_session(None);
        }
        self.expire_if_due();
        let session = locked(&self.session).as_ref().map(|s| s.view.clone());
        match session {
            Some(session) => {
                view.state = match server {
                    Some(VaultState::Locking) => VaultState::Locking,
                    _ => VaultState::Unlocked,
                };
                view.operator = Some(session.operator_id);
                view.role = Some(session.role);
                // The countdown of this desktop's session, as the rail shows it (DEC-RM-26).
                view.idle_seconds_left = self.session_seconds_left();
            }
            None => {
                view.state = VaultState::Sealed;
                view.operator = None;
                view.role = None;
                view.idle_seconds_left = None;
                view.hard_lock_at = None;
                view.kdf = None;
            }
        }
        view.os_hook_ok = os_hook_ok;
        view.stranded_restore = Vec::new();
        view.remote = Some(self.remote_view());
        view
    }
}

/// The arguments of a command without arguments.
pub(crate) const EMPTY: Empty = Empty {};

/// `{}`.
#[derive(Serialize)]
pub(crate) struct Empty {}

/// The status before the server ever answered.
fn sealed_view() -> VaultStatusView {
    VaultStatusView {
        state: VaultState::Sealed,
        operator: None,
        role: None,
        idle_seconds_left: None,
        hard_lock_at: None,
        memlock_ok: true,
        os_hook_ok: false,
        header_ok: true,
        kdf: None,
        last_lock_reason: None,
        failed_unlocks: 0,
        free_unlock_tries_left: 5,
        retry_after_seconds: None,
        stranded_restore: Vec::new(),
        remote: None,
    }
}

/// The names of the remote allowlist, in order.
#[must_use]
pub fn remote_command_names() -> Vec<String> {
    REMOTE_COMMANDS
        .iter()
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_admin_error_body_is_the_error_and_other_bodies_map_by_status() {
        let body = serde_json::to_vec(&AdminErrorBody {
            request_id: "r".to_owned(),
            error: IpcError::new("bad_credentials", "wrong"),
        })
        .expect("json");
        let error = answer_error(401, Some(3), &body);
        assert_eq!(error.code, "bad_credentials");
        assert_eq!(error.retry_after_seconds, Some(3));
        let agent_shape = br#"{"error":{"code":"route_not_found","message":"no route"}}"#;
        assert_eq!(
            answer_error(404, None, agent_shape).code,
            "remote_protocol_mismatch"
        );
        assert_eq!(answer_error(403, None, b"").code, "forbidden");
        assert_eq!(answer_error(401, None, b"").code, "admin_session_required");
        assert_eq!(answer_error(423, None, b"").code, "vault_locked");
        let limited = answer_error(429, Some(9), b"x");
        assert_eq!(
            (limited.code.as_str(), limited.retry_after_seconds),
            ("rate_limited", Some(9))
        );
        assert_eq!(answer_error(502, None, b"").code, "internal");
    }

    #[test]
    fn transport_errors_have_remote_codes() {
        assert_eq!(
            transport_error(&ClientError::PinMismatch).code,
            "remote_pin_mismatch"
        );
        assert_eq!(
            transport_error(&ClientError::Connect("refused".to_owned())).code,
            "remote_unreachable"
        );
        assert_eq!(
            transport_error(&ClientError::Timeout).code,
            "remote_unreachable"
        );
        assert_eq!(
            transport_error(&ClientError::Decode("x".to_owned())).code,
            "remote_protocol_mismatch"
        );
    }

    #[test]
    fn custom_commands_are_on_the_allowlist() {
        for name in CUSTOM_REMOTE_COMMANDS {
            assert!(gate(name).is_some(), "{name}");
        }
        assert_eq!(remote_command_names().len(), REMOTE_COMMANDS.len());
    }
}
