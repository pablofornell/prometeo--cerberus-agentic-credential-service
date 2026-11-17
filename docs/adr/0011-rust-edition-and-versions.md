# ADR-0011: Rust edition 2024 and the version policy

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D11
- Related: ADR-0012, ADR-0024

## Context

Crate versions change often. Wrong guesses break the build or bring old bugs.

## Decision

1. All crates use `edition = "2024"`. `rust-toolchain.toml` pins channel `1.100.0` (stable on 2026-11-16) with
   components `rustfmt`, `clippy`.
2. The root `Cargo.toml` has `[workspace.dependencies]`. Member crates use `dep.workspace = true`. Only the root
   names versions.
3. `Cargo.lock` is committed. `cargo deny` checks licenses, bans duplicates where possible, and checks advisories.
   `cargo audit` runs in CI.
4. Each task that adds or changes a dependency checks crates.io first and writes the version it found in its report.
5. Versions checked on crates.io on 2026-11-16 (starting point for T02):

   | Crate | Version | Crate | Version |
   |---|---|---|---|
   | tokio | 1.54.1 | sqlx (sqlite) | 0.9.0 |
   | axum | 0.8.9 | rmcp | 3.10.0 |
   | tower | 0.5.3 | utoipa | 6.0.0 |
   | tower-http | 0.7.1 | totp-rs | 6.0.0 |
   | rustls | 0.23.46 | ssh-key | 0.6.7 |
   | tokio-rustls | 0.26.6 | tracing | 0.1.44 |
   | rcgen | 0.14.10 | thiserror | 2.0.21 |
   | argon2 | 0.6.0 | proptest | 1.12.0 |
   | chacha20poly1305 | 0.11.0 | zxcvbn | 3.1.1 |
   | hkdf | 0.13.0 | tauri | 2.12.5 |
   | sha2 | 0.11.1 | tauri-build | 2.7.4 |
   | hmac | 0.13.0 | tauri-specta | 1.0.2 |
   | rand | 0.10.4 | specta | 1.0.5 |
   | getrandom | 0.4.3 | tauri-plugin-single-instance | 2.5.5 |
   | zeroize | 1.9.1 | tauri-plugin-autostart | 2.7.0 |
   | secrecy | 0.10.3 | tauri-plugin-clipboard-manager | 2.5.0 |
   | subtle | 2.6.1 | serde / serde_json | 1.0.229 / 1.0.154 |
   | region | 4.0.1 | uuid | 1.29.2 |
   | jiff | 1.0.0 | data-encoding | 2.11.1 |
   | governor | 0.10.4 | tokio-stream | 0.1.19 |
   | unicode-normalization | 0.1.26 | sd-notify | 0.5.0 |
   | rustix | 1.1.6 | base64 | 0.23.1 |

   Tools: cargo-deny 0.20.2, cargo-audit 0.23.0, cargo-cyclonedx 0.5.10, cargo-fuzz 0.13.2.

6. Memory lock crate: `region` (4.0.1, updated 2026) is chosen over `memsec` (0.7.0, last release 2024).

## Consequences

- The RustCrypto crates above are a new major line (argon2 0.6, chacha20poly1305 0.11, hkdf 0.13, hmac 0.13, sha2 0.11).
  T03 must use one matching set so the `digest` and `rand_core` traits agree. `cargo tree -d` must show no
  duplicate `digest` or `rand_core`.
- The toolchain pin is changed by a deliberate commit, not by CI drift.

## Alternatives considered

- **Floating `stable` toolchain.** Rejected. Builds would change without a commit.
