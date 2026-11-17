# Packaging and release

How Cerberus is built, checked and released. For a person who cuts a release or reviews one. Decisions: `docs/decisions.md`
(DEC-T29-1 to DEC-T29-6).

## What a release holds

| File | What | Built on |
|------|------|----------|
| `Cerberus_<version>_amd64.deb`, `Cerberus-<version>-1.x86_64.rpm`, `Cerberus_<version>_amd64.AppImage` | Desktop app (vault, UI, HTTPS API, tray) | Linux |
| `Cerberus_<version>_aarch64.dmg` | Desktop app, Apple silicon | macOS |
| `Cerberus_<version>_x64-setup.exe` | Desktop app, NSIS installer | Windows |
| `cerberus-<version>-<target>.tar.gz` | `cerberus` (CLI), `cerberus-mcp` (stdio shim), `LICENSE`, `README.md`. The Linux one also has `cerberusd` and `systemd/` (unit and config example) | each OS |
| `*_bin.cdx.json` | CycloneDX 1.5 SBOM of `cerberusd`, `cerberus`, `cerberus-mcp`, `cerberus-desktop` (Rust dependencies, Linux build) | Linux |
| `SHA256SUMS` | SHA-256 of every file above | Linux (publish job) |

`cerberusd` is Linux only: it uses Unix sockets and file modes (DEC-T29-3). The UI dependencies (pnpm) are not in the SBOM;
they are in `apps/desktop/ui/pnpm-lock.yaml` and are bundled into the app.

## Build on your machine

Needs: the Rust toolchain from `rust-toolchain.toml` (rustup installs it), Node 22 (`nvm use`, see `.nvmrc`), pnpm, `just`,
`jq`, the Tauri CLI (`cargo install tauri-cli --locked --version 2.12.4`) and, on Linux, the Tauri libraries
(`libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev`). For the SBOM:
`cargo install cargo-cyclonedx`.

```
just package             # desktop installers for this OS, copied to dist/
just package --bundles deb   # only one kind
just package-binaries    # cerberus, cerberus-mcp (and cerberusd on Linux) as dist/cerberus-<version>-<target>.tar.gz
just sbom                # SBOMs into dist/
just checksums           # dist/SHA256SUMS, then a check of it
just release-local       # all of the above
```

The first `just package` compiles the whole desktop app in release mode and takes a long time; it needs several GiB of RAM
(the `jobs = 6` cap in `.cargo/config.toml` keeps it down). Release builds use `panic = "abort"` (a panic wipes the keys and
ends the process, see the threat model). `--locked` is used where the recipe calls `cargo build`: `Cargo.lock` decides the
versions.

## CI (`.github/workflows/ci.yml`)

Runs on every pull request and push to `main`, weekly, and when the release workflow calls it. Each job runs one `just`
recipe, so a local `just <recipe>` reproduces it.

| Job | Recipe | Notes |
|-----|--------|-------|
| `fmt`, `clippy` | `just fmt-check`, `just clippy` | clippy needs the Tauri libraries |
| `deny`, `audit` | `just deny`, `just audit` | licenses, bans, sources, advisories. Ignores are in `deny.toml` and `.cargo/audit.toml` with reasons. The weekly run catches new advisories |
| `deps` | `just deps-check client-deps-check` | ADR-0024 dependency direction |
| `ui` | `just ui-check` | `tsc` and ESLint, Node from `.nvmrc` |
| `test` | `just test` | all Rust crates (including the A1 to A12 suite), then the UI tests |
| `acceptance` | `just acceptance` | A1 to A12 alone |
| `coverage` | `just coverage` | at least 90 % lines for `cerberus-crypto` and `cerberus-core`; the summary JSON is uploaded |
| `fuzz-smoke` | `just fuzz-smoke` | 10 targets, 30 s each, nightly. Not on pull requests; crash files are uploaded on failure |
| `cross-platform-build` | `cargo check` | macOS and Windows: everything except `cerberusd` and the acceptance crate |

Rules for workflows: `permissions: contents: read` at the top, wider only on the one job that needs it; every `uses:` is a
full commit SHA with the tag in a comment; `persist-credentials: false` on checkout; cargo cache by `Swatinem/rust-cache`,
pnpm cache by `actions/setup-node`; the Rust toolchain comes from `rust-toolchain.toml` (rustup installs it at the first
`cargo` call).

Update a pin: `gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object` and, if the type is `tag`, one more call to
`git/tags/<sha>` to reach the commit. Put that commit in `uses:` and the tag in the comment. Do it in a reviewed pull
request, never by a floating tag.

## Release (`.github/workflows/release.yml`)

1. Raise the version in `Cargo.toml` (`[workspace.package]`) and `apps/desktop/src-tauri/tauri.conf.json`. Both must be the
   same; `Cargo.lock` follows (`cargo update --workspace`).
2. Merge to `main`. CI must be green.
3. Tag and push: `git tag -s v0.1.0 -m "Cerberus 0.1.0" && git push origin v0.1.0`.
4. The workflow runs `preflight` (tag equals both versions), `ci` (all gates again), then builds on Linux, macOS and Windows,
   then `publish`: SHA256SUMS, a provenance attestation for every file, and a **draft** GitHub release. Nobody gets a
   release without a person pressing "Publish".
5. Review the draft: file list against the table above, the checksums, the notes. Publish.

A run started by hand (`workflow_dispatch`) builds everything and keeps the files as workflow artifacts, with no release.

### Secrets

None is needed for an unsigned release: the provenance uses the GitHub OIDC token (keyless, Sigstore) and `GITHUB_TOKEN`.
Optional, for a signed and notarized macOS app (set in the repository settings, environment `release` recommended):

| Secret | Content |
|--------|---------|
| `APPLE_CERTIFICATE` | Base64 of the Developer ID Application `.p12` |
| `APPLE_CERTIFICATE_PASSWORD` | Password of that `.p12` |
| `APPLE_SIGNING_IDENTITY` | For example `Developer ID Application: Name (TEAMID)` |
| `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID` | Apple account, app-specific password and team, for notarization |

If `APPLE_CERTIFICATE` is empty the macOS app is built unsigned. Windows installers are unsigned (no code-signing
certificate is planned; DEC-T29-4). There is no auto-updater: users install a new version by hand (DEC-T29-5).

## Verify a download

```
sha256sum --check --ignore-missing SHA256SUMS         # the files you downloaded match
gh attestation verify <file> --repo <owner>/<repo>    # the file was built by this repository's release workflow
```

The attestation also proves which commit and workflow built it. On macOS and Windows without signing, the OS warns on first
start; verify the checksum first.

## Install

- Desktop: `sudo apt install ./Cerberus_<version>_amd64.deb` (or the rpm), run the AppImage (`chmod +x`), open the dmg, run
  the setup exe.
- CLI and shim: unpack the tarball and copy `cerberus` and `cerberus-mcp` to a folder in `PATH`.
- Daemon: follow `docs/guides/cerberusd.md`. The tarball holds `cerberusd` and `systemd/cerberusd.service` (hardened:
  syscall filter, loopback-only IP allow list, no capabilities, no core dumps; `systemd-analyze security` scores it 0.9
  SAFE) and `systemd/cerberusd.toml.example`.

## Not covered here

- Reproducible builds are not claimed. `SOURCE_DATE_EPOCH` is honored by the SBOM tool only.
- The macOS and Windows jobs were not run when this was written (no such runners locally): the first release run is their
  first test (see `docs/orchestration-status.md` for the state at hand-over).
