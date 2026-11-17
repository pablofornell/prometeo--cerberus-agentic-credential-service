# ADR-0012: No unsafe code, except in the `memlock` module

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D12
- Related: ADR-0011, ADR-0024, ADR-0026

## Context

Memory safety is a main reason to use Rust. Locking memory pages and process hardening need OS calls.

## Decision

1. Every crate root has `#![forbid(unsafe_code)]`, except `cerberus-crypto`.
2. `cerberus-crypto` has `#![deny(unsafe_code)]` at the root and `#[allow(unsafe_code)] mod memlock;`.
   No other module in the crate has an `allow`.
3. `memlock` contains all code that needs `unsafe` or raw OS calls:
   - `LockedBox<T>`: a heap box whose pages are locked with `region::lock` and zeroized on drop.
   - `harden_process()`: Linux `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, 0)`; macOS
     `setrlimit(RLIMIT_CORE, 0)` and `ptrace(PT_DENY_ATTACH)`; Windows `SetErrorMode` to stop crash dumps
     (best effort).
   - Prefer safe wrappers (`rustix`, `region`) when they exist. `unsafe` blocks are allowed only where no safe
     wrapper exists.
4. Each `unsafe` block has a `// SAFETY:` comment. Clippy lint `undocumented_unsafe_blocks` is `deny`.
5. CI step: `grep -rn "unsafe" crates/ --include=*.rs` must match only files under `crates/cerberus-crypto/src/memlock/`.
6. If `mlock` fails (for example a low `RLIMIT_MEMLOCK`), the app continues, logs a warning once, and shows
   "memory lock off" in the dashboard health panel.
7. Third-party crates may use `unsafe` internally. `cargo deny` and `cargo audit` cover them.

## Consequences

- An audit of unsafe code covers one module.
- The Tauri crate and its plugins contain unsafe code that we do not control. This is accepted.

## Alternatives considered

- **Allow unsafe with review.** Rejected. A rule is easier to check than a review habit.
