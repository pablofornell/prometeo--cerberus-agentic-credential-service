//! Locked memory for keys and process hardening (ADR-0012).
//!
//! This is the only module of the workspace that may contain `unsafe` code. Linux needs none:
//! `region` and `rustix` give safe calls. macOS (`ptrace`) and Windows (`SetErrorMode`) each
//! need one call without a safe wrapper.
//!
//! Page locks do not nest in the OS: one `munlock` unlocks a page for every value on it.
//! So a registry counts the values per page, and a page is unlocked only when its count is zero.

// ADR-0012: the only `allow` of this lint in the workspace. The crate root denies it.
#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Locked pages: page address -> (number of values on the page, OS lock guard).
static PAGES: Mutex<BTreeMap<usize, (usize, region::LockGuard)>> = Mutex::new(BTreeMap::new());
/// Set when one lock call failed. The health panel shows "memory lock off" (ADR-0012 point 6).
static LOCK_FAILED: AtomicBool = AtomicBool::new(false);

// A panic while the registry is held must not stop later unlocks, so a poisoned lock is still used.
fn pages() -> MutexGuard<'static, BTreeMap<usize, (usize, region::LockGuard)>> {
    PAGES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Start addresses of the pages that hold `len` bytes at `ptr`.
fn page_starts(ptr: *const u8, len: usize) -> impl Iterator<Item = *const u8> {
    let size = region::page::size();
    let first = region::page::floor(ptr);
    let end = ptr.wrapping_add(len);
    let count = end.addr().saturating_sub(first.addr()).div_ceil(size);
    (0..count).map(move |i| first.wrapping_add(i * size))
}

/// Locks the pages of `len` bytes at `ptr`. Returns false (and changes nothing) on failure.
fn lock_range(ptr: *const u8, len: usize) -> bool {
    let size = region::page::size();
    let mut map = pages();
    let mut counted: Vec<usize> = Vec::new();
    for page in page_starts(ptr, len) {
        if let Some(entry) = map.get_mut(&page.addr()) {
            entry.0 += 1;
            counted.push(page.addr());
            continue;
        }
        match region::lock(page, size) {
            Ok(guard) => {
                map.insert(page.addr(), (1, guard));
                counted.push(page.addr());
            }
            Err(_) => {
                for addr in counted {
                    release_page(&mut map, addr);
                }
                drop(map);
                note_lock_failure();
                return false;
            }
        }
    }
    true
}

/// Unlocks the pages of `len` bytes at `ptr` that no other value uses.
fn unlock_range(ptr: *const u8, len: usize) {
    let mut map = pages();
    for page in page_starts(ptr, len) {
        release_page(&mut map, page.addr());
    }
}

fn release_page(map: &mut BTreeMap<usize, (usize, region::LockGuard)>, addr: usize) {
    if let Some(entry) = map.get_mut(&addr) {
        entry.0 = entry.0.saturating_sub(1);
        if entry.0 == 0 {
            // Dropping the guard calls munlock for this page.
            map.remove(&addr);
        }
    }
}

fn note_lock_failure() {
    if !LOCK_FAILED.swap(true, Ordering::Relaxed) {
        tracing::warn!("memory lock failed; keys may be written to swap (RLIMIT_MEMLOCK too low?)");
    }
}

/// True when at least one memory lock failed in this process (health panel, ADR-0012 point 6).
#[must_use]
pub fn lock_failed() -> bool {
    LOCK_FAILED.load(Ordering::Relaxed)
}

/// Heap value with locked pages (best effort) that is zeroized on drop.
///
/// Prefer [`LockedBox::new_with`]: it writes the value straight into the locked heap memory.
/// [`LockedBox::new`] moves a value in, and the moved-from copy (for example on the stack) is not
/// erased by this type.
pub struct LockedBox<T: Zeroize + Default> {
    inner: Box<T>,
    locked: bool,
}

impl<T: Zeroize + Default> LockedBox<T> {
    /// Moves `value` into locked heap memory.
    pub fn new(value: T) -> Self {
        let mut slot = Some(value);
        Self::new_with(|target| {
            if let Some(value) = slot.take() {
                *target = value;
            }
        })
    }

    /// Makes a default value in locked memory, then lets `init` fill it in place.
    pub fn new_with(init: impl FnOnce(&mut T)) -> Self {
        let mut boxed = Self::empty();
        init(&mut boxed.inner);
        boxed
    }

    /// Like [`LockedBox::new_with`], but `init` can fail. On failure the memory is zeroized.
    ///
    /// # Errors
    /// Returns the error of `init`.
    pub fn try_new_with<E>(init: impl FnOnce(&mut T) -> Result<(), E>) -> Result<Self, E> {
        let mut boxed = Self::empty();
        init(&mut boxed.inner)?;
        Ok(boxed)
    }

    fn empty() -> Self {
        let inner = Box::new(T::default());
        let len = size_of::<T>();
        let ptr: *const T = &raw const *inner;
        let locked = len > 0 && lock_range(ptr.cast::<u8>(), len);
        Self { inner, locked }
    }

    /// True when the pages of the value are locked in RAM.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// The value.
    pub fn get(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize + Default> Drop for LockedBox<T> {
    fn drop(&mut self) {
        // Erase first, while the pages are still locked.
        self.inner.zeroize();
        if self.locked {
            let ptr: *const T = &raw const *self.inner;
            unlock_range(ptr.cast::<u8>(), size_of::<T>());
        }
    }
}

impl<T: Zeroize + Default> ZeroizeOnDrop for LockedBox<T> {}

impl<T: Zeroize + Default> fmt::Debug for LockedBox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Result of [`harden_process`]. Each field is true only when the OS call succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardeningReport {
    /// Linux: `prctl(PR_SET_DUMPABLE, 0)` done. Other OSs: always false (no such setting).
    pub dumpable_off: bool,
    /// Unix: `RLIMIT_CORE` soft and hard limits set to 0. Windows: always false.
    pub core_limit_zero: bool,
    /// Linux: true when not dumpable, because the kernel then refuses `ptrace` attach by other
    /// processes of the same user. macOS: `ptrace(PT_DENY_ATTACH)` done. Windows: always false.
    pub ptrace_denied: bool,
    /// Windows: `SetErrorMode` set, so a crash shows no error dialog and no report. Others: false.
    pub crash_dialog_off: bool,
}

/// Turns off core dumps and debugger attach for this process (ADR-0012 point 3). Best effort.
///
/// Call it once, early in `main`. It does not fail: the report says what worked.
pub fn harden_process() -> HardeningReport {
    let mut report = HardeningReport {
        dumpable_off: false,
        core_limit_zero: false,
        ptrace_denied: false,
        crash_dialog_off: false,
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use rustix::process::{DumpableBehavior, set_dumpable_behavior};
        report.dumpable_off = set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok();
        report.ptrace_denied = report.dumpable_off;
    }
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let zero = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        report.core_limit_zero = setrlimit(Resource::Core, zero).is_ok();
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: PT_DENY_ATTACH takes no address or data. The null pointer is never read.
        let result = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        report.ptrace_denied = result == 0;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
        };
        // SAFETY: SetErrorMode only changes a process flag. It has no pointer arguments.
        unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
        report.crash_dialog_off = true;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn count_of(addr: usize) -> Option<usize> {
        pages().get(&addr).map(|entry| entry.0)
    }

    #[test]
    fn locked_box_holds_the_value() {
        let boxed = LockedBox::new([7u8; 32]);
        assert_eq!(boxed.get(), &[7u8; 32]);
        let filled = LockedBox::new_with(|b: &mut [u8; 32]| b[0] = 1);
        assert_eq!(filled.get()[0], 1);
        assert_eq!(format!("{boxed:?}"), "[REDACTED]");
    }

    #[test]
    fn locked_box_is_locked_on_linux() {
        let boxed = LockedBox::new([1u8; 32]);
        if cfg!(target_os = "linux") {
            // The default RLIMIT_MEMLOCK (8 MiB on current distributions) is enough for a page.
            assert!(boxed.is_locked(), "mlock failed; check `ulimit -l`");
        }
    }

    #[test]
    fn page_stays_locked_until_the_last_user_unlocks() {
        // Two users of the same page: the first unlock must not unlock the page.
        // The page is inside a buffer that this test owns, so no other value can be on it.
        let buf = vec![0u8; region::page::size() * 2];
        let start = region::page::ceil(buf.as_ptr());
        let page = start.addr();
        assert_eq!(count_of(page), None);
        assert!(lock_range(start, 32), "mlock failed; check `ulimit -l`");
        assert!(lock_range(start.wrapping_add(32), 32));
        assert_eq!(count_of(page), Some(2));
        unlock_range(start, 32);
        assert_eq!(count_of(page), Some(1));
        unlock_range(start.wrapping_add(32), 32);
        assert_eq!(count_of(page), None);
    }

    #[test]
    fn range_over_a_page_border_counts_both_pages() {
        let size = region::page::size();
        let buf = vec![0u8; size * 3];
        let border = region::page::ceil(buf.as_ptr().wrapping_add(1));
        let start = border.wrapping_sub(8);
        assert_eq!(page_starts(start, 16).count(), 2);
        assert_eq!(page_starts(border, size).count(), 1);
    }

    #[test]
    fn failed_init_returns_the_error() {
        let result = LockedBox::<[u8; 32]>::try_new_with(|_| Err("no"));
        assert!(matches!(result, Err("no")));
    }

    /// A value that counts calls to `zeroize`, so the test can see the drop path.
    #[derive(Default)]
    struct Probe(u8);
    static ZEROIZED: AtomicUsize = AtomicUsize::new(0);
    impl Zeroize for Probe {
        fn zeroize(&mut self) {
            self.0 = 0;
            ZEROIZED.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn drop_calls_zeroize() {
        let before = ZEROIZED.load(Ordering::SeqCst);
        let boxed = LockedBox::new(Probe(9));
        assert_eq!(boxed.get().0, 9);
        drop(boxed);
        assert_eq!(ZEROIZED.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn harden_process_reports_what_it_did() {
        let report = harden_process();
        #[cfg(target_os = "linux")]
        {
            use rustix::process::{DumpableBehavior, Resource, dumpable_behavior, getrlimit};
            assert!(report.dumpable_off);
            assert!(report.ptrace_denied);
            assert!(report.core_limit_zero);
            assert_eq!(
                dumpable_behavior().ok(),
                Some(DumpableBehavior::NotDumpable)
            );
            let core = getrlimit(Resource::Core);
            assert_eq!((core.current, core.maximum), (Some(0), Some(0)));
        }
        assert!(!report.crash_dialog_off || cfg!(windows));
    }
}
