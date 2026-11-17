//! OS sleep and screen-lock watchers that feed `VaultService::on_os_event` (ADR-0026).
//!
//! - Linux: systemd-logind over D-Bus, through `zbus`. Three watchers: `PrepareForSleep` on the
//!   manager, `Lock` on the session, and `PropertiesChanged` of the session `LockedHint` (many
//!   desktops lock the screen and only set the hint). The sleep watcher holds a logind `delay`
//!   inhibitor, so the machine does not suspend before the vault is locked, and releases it after
//!   the lock (AUD-16, DEC-T27-C-9). Without logind the hook is reported as off
//!   (`os_hook_ok = false`).
//! - macOS and Windows: not built. A watcher needs `NSWorkspace` and distributed notifications
//!   (macOS) or `WTSRegisterSessionNotification` (Windows), which need unsafe FFI that this
//!   workspace forbids outside `cerberus-crypto` (ADR-0012). Neither Tauri, tao nor a safe crate
//!   that we use gives these events. The hook reports "off", the status view shows it, and the
//!   idle lock and the hard limit still apply (DEC-T15-8, accepted risk in DEC-T27-C-9).

use std::sync::Arc;

use cerberus_core::OsLockEvents;

/// Tells whether the vault is already locked. The sleep watcher polls it before it lets the
/// machine suspend.
pub type IsLocked = Arc<dyn Fn() -> bool + Send + Sync>;

/// The watcher of this platform. `is_locked` is polled after a sleep event until the vault is locked.
#[must_use]
pub fn platform_source(is_locked: IsLocked) -> Arc<dyn OsLockEvents> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(linux::Logind::new(is_locked))
    }
    #[cfg(not(target_os = "linux"))]
    {
        drop(is_locked);
        Arc::new(Unsupported)
    }
}

/// A platform without a watcher.
#[cfg(not(target_os = "linux"))]
struct Unsupported;

#[cfg(not(target_os = "linux"))]
impl OsLockEvents for Unsupported {
    fn start(&self, _sink: cerberus_core::OsEventSink) -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::mpsc::{Sender, channel};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use cerberus_core::{OsEvent, OsEventSink, OsLockEvents};
    use cerberus_types::Stopwatch;
    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::{OwnedFd, OwnedObjectPath};

    use super::IsLocked;

    const DEST: &str = "org.freedesktop.login1";
    const MANAGER_PATH: &str = "/org/freedesktop/login1";
    const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
    const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
    /// How long `start` waits for the watcher threads to connect.
    const READY_WAIT: Duration = Duration::from_secs(5);
    /// Longest the delay inhibitor is held after a sleep signal. logind forces the sleep after
    /// `InhibitDelayMaxSec` (5 s by default) anyway.
    const LOCK_WAIT: Duration = Duration::from_millis(3500);
    const LOCK_POLL: Duration = Duration::from_millis(25);

    type SharedSink = Arc<Mutex<Option<OsEventSink>>>;

    /// The logind watcher. The sink sits in a shared cell, so a new vault service (after a
    /// restore) only replaces the sink and the threads keep running.
    pub struct Logind {
        sink: SharedSink,
        started: Mutex<Option<bool>>,
        is_locked: IsLocked,
    }

    impl Logind {
        pub fn new(is_locked: IsLocked) -> Self {
            Self {
                sink: Arc::default(),
                started: Mutex::new(None),
                is_locked,
            }
        }
    }

    impl OsLockEvents for Logind {
        fn start(&self, sink: OsEventSink) -> bool {
            *self.sink.lock().unwrap_or_else(PoisonError::into_inner) = Some(sink);
            let mut started = self.started.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(ok) = *started {
                return ok;
            }
            let ok = spawn_watchers(&self.sink, &self.is_locked);
            *started = Some(ok);
            ok
        }
    }

    #[derive(Clone, Copy)]
    enum Watch {
        Sleep,
        Lock,
        Hint,
    }

    fn spawn_watchers(sink: &SharedSink, is_locked: &IsLocked) -> bool {
        let (ready_tx, ready_rx) = channel::<bool>();
        let kinds = [Watch::Sleep, Watch::Lock, Watch::Hint];
        for kind in kinds {
            let sink = Arc::clone(sink);
            let is_locked = Arc::clone(is_locked);
            let ready = ready_tx.clone();
            let spawned = std::thread::Builder::new()
                .name("cerberus-logind".to_owned())
                .spawn(move || watch(kind, &sink, &is_locked, &ready));
            if let Err(error) = spawned {
                tracing::warn!(%error, "could not start the logind watcher thread");
                return false;
            }
        }
        drop(ready_tx);
        (0..kinds.len()).all(|_| ready_rx.recv_timeout(READY_WAIT).unwrap_or(false))
    }

    fn send(sink: &Mutex<Option<OsEventSink>>, event: OsEvent) {
        if let Some(sink) = sink.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
            sink.send(event);
        }
    }

    fn watch(kind: Watch, sink: &SharedSink, is_locked: &IsLocked, ready: &Sender<bool>) {
        let result = match kind {
            Watch::Sleep => watch_sleep(sink, is_locked, ready),
            Watch::Lock => watch_lock(sink, ready),
            Watch::Hint => watch_hint(sink, ready),
        };
        if let Err(error) = result {
            tracing::warn!(%error, "no logind signals; the OS lock hook is off");
            ready.send(false).ok();
        } else {
            tracing::warn!("a logind signal stream ended");
        }
    }

    fn manager(connection: &Connection) -> zbus::Result<Proxy<'static>> {
        Proxy::new(connection, DEST, MANAGER_PATH, MANAGER_IFACE)
    }

    fn session(connection: &Connection) -> zbus::Result<Proxy<'static>> {
        let manager = manager(connection)?;
        let path = session_path(&manager)?;
        Proxy::new(connection, DEST, path, SESSION_IFACE)
    }

    /// Takes a logind `delay` inhibitor on sleep. The returned descriptor is the lock: logind
    /// waits for it to close (or for its own limit) before it suspends.
    fn take_inhibitor(manager: &Proxy<'_>) -> Option<OwnedFd> {
        let taken = manager.call::<_, _, OwnedFd>(
            "Inhibit",
            &(
                "sleep",
                "Cerberus",
                "Lock the vault before the machine sleeps",
                "delay",
            ),
        );
        match taken {
            Ok(fd) => Some(fd),
            Err(error) => {
                tracing::warn!(%error, "no sleep delay inhibitor; the lock may come after the sleep starts");
                None
            }
        }
    }

    fn watch_sleep(
        sink: &SharedSink,
        is_locked: &IsLocked,
        ready: &Sender<bool>,
    ) -> zbus::Result<()> {
        let connection = Connection::system()?;
        let manager = manager(&connection)?;
        let signals = manager.receive_signal("PrepareForSleep")?;
        let mut inhibitor = take_inhibitor(&manager);
        ready.send(true).ok();
        for message in signals {
            match message.body().deserialize::<bool>() {
                // `true`: the machine is about to sleep. Lock, then let it go.
                Ok(true) => {
                    send(sink, OsEvent::Sleep);
                    wait_until(|| is_locked(), LOCK_WAIT, LOCK_POLL);
                    inhibitor = None;
                }
                // `false`: it woke up. Take the inhibitor for the next sleep.
                Ok(false) => {
                    if inhibitor.is_none() {
                        inhibitor = take_inhibitor(&manager);
                    }
                }
                Err(_) => {}
            }
        }
        drop(inhibitor);
        Ok(())
    }

    fn watch_lock(sink: &SharedSink, ready: &Sender<bool>) -> zbus::Result<()> {
        let connection = Connection::system()?;
        let signals = session(&connection)?.receive_signal("Lock")?;
        ready.send(true).ok();
        for _ in signals {
            send(sink, OsEvent::ScreenLocked);
        }
        Ok(())
    }

    /// Many desktops lock the screen and only set `LockedHint` on the session (AUD-16).
    fn watch_hint(sink: &SharedSink, ready: &Sender<bool>) -> zbus::Result<()> {
        let connection = Connection::system()?;
        let changes = session(&connection)?.receive_property_changed::<bool>("LockedHint");
        ready.send(true).ok();
        for change in changes {
            if let Ok(locked) = change.get()
                && let Some(event) = hint_event(locked)
            {
                send(sink, event);
            }
        }
        Ok(())
    }

    /// The event for a new `LockedHint` value: only "locked" counts.
    pub(super) const fn hint_event(locked: bool) -> Option<OsEvent> {
        if locked {
            Some(OsEvent::ScreenLocked)
        } else {
            None
        }
    }

    /// Polls `done` every `poll` until it is true or `max` passed. Returns the last answer.
    pub(super) fn wait_until(done: impl Fn() -> bool, max: Duration, poll: Duration) -> bool {
        let watch = Stopwatch::start();
        loop {
            if done() {
                return true;
            }
            if watch.elapsed() >= max {
                return false;
            }
            std::thread::sleep(poll);
        }
    }

    /// The logind session of this process: `XDG_SESSION_ID` when set, else by process ID.
    fn session_path(manager: &Proxy<'_>) -> zbus::Result<OwnedObjectPath> {
        if let Ok(id) = std::env::var("XDG_SESSION_ID")
            && let Ok(path) = manager.call::<_, _, OwnedObjectPath>("GetSession", &(id.as_str(),))
        {
            return Ok(path);
        }
        manager.call("GetSessionByPID", &(std::process::id(),))
    }

    #[cfg(test)]
    mod tests {
        use std::sync::atomic::{AtomicU32, Ordering};

        use super::*;

        #[test]
        fn a_locked_hint_locks_and_an_unlocked_hint_does_not() {
            assert_eq!(hint_event(true), Some(OsEvent::ScreenLocked));
            assert_eq!(hint_event(false), None);
        }

        #[test]
        fn the_inhibitor_wait_ends_when_the_vault_is_locked() {
            let calls = AtomicU32::new(0);
            let done = || calls.fetch_add(1, Ordering::SeqCst) >= 3;
            assert!(wait_until(
                done,
                Duration::from_secs(5),
                Duration::from_millis(1)
            ));
        }

        #[test]
        fn the_inhibitor_wait_is_bounded() {
            let start = Stopwatch::start();
            assert!(!wait_until(
                || false,
                Duration::from_millis(40),
                Duration::from_millis(5)
            ));
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    }
}
