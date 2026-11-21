# Cerberus task runner. Install with `cargo install just`. Needs jq for `deps-check`.
# Run `just` to list the recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

ui := "apps/desktop/ui"

default:
    @just --list

# Everything CI checks: formatting, lints, licenses, advisories, dependency direction, UI types and lint.
check: node-check fmt-check clippy deny audit deps-check client-deps-check ui-check
    @echo "just check: all checks passed"

# Unit tests for every Rust crate, then the UI test suite.
test: node-check ui-install
    cargo test --workspace
    pnpm --dir {{ui}} test
    @echo "just test: all tests passed"

# Acceptance scenarios A1 to A12 of docs/PLAN.md section 11, one test each, through the real TLS server, MCP and the `cerberus`
# binary, and A13, the remote admin API of a real `cerberusd` (ADR-0034). The suite is the `tests/acceptance` crate
# (DEC-T24-1). `just test` runs it too.
acceptance:
    cargo test -p cerberus-acceptance
    @echo "just acceptance: A1 to A13 passed"

# Line coverage of cerberus-crypto and cerberus-core, each at least 90 percent. Needs cargo-llvm-cov.
# The test helpers `testkit.rs` and `regressions.rs` are left out of the numbers (DEC-T24-6).
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target
    cargo llvm-cov --package cerberus-crypto --package cerberus-core \
      --ignore-filename-regex '(testkit|regressions)\.rs$' \
      --json --summary-only --output-path target/coverage-summary.json
    fail=0
    for crate in cerberus-crypto cerberus-core; do
      pct=$(jq -r --arg c "crates/$crate/" '
        [.data[0].files[] | select(.filename | contains($c)) | .summary.lines]
        | (map(.covered) | add) / (map(.count) | add) * 100' target/coverage-summary.json)
      printf 'coverage: %s lines %.2f%%\n' "$crate" "$pct"
      if ! jq -en --argjson p "$pct" '$p >= 90' > /dev/null; then echo "coverage: $crate is below 90%"; fail=1; fi
    done
    exit $fail

# Run the desktop app with hot reload. Needs the Tauri Linux system libraries (see .github/workflows/ci.yml).
dev: node-check ui-install
    cd apps/desktop && cargo tauri dev

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

deny:
    cargo deny check

# The ignores and their reasons are in `.cargo/audit.toml`, which plain `cargo audit` reads too (AUD-28).
# RUSTSEC-2026-0459 is also ignored in `deny.toml`.
audit:
    cargo audit

# ADR-0024 rule 5: fail on any crate dependency edge that is not in the allowed table. Only normal and build
# dependencies count: tests may use any member crate (DEC-T10-10).
deps-check:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo metadata --format-version 1 --no-deps | jq -e '
      {
        "cerberus-types": [],
        "cerberus-crypto": ["cerberus-types"],
        "cerberus-store": ["cerberus-crypto", "cerberus-types"],
        "cerberus-core": ["cerberus-store", "cerberus-crypto", "cerberus-types"],
        "cerberus-ssh-agent": ["cerberus-core", "cerberus-crypto", "cerberus-types"],
        "cerberus-admin": ["cerberus-core", "cerberus-store", "cerberus-crypto", "cerberus-types"],
        "cerberus-api": ["cerberus-admin", "cerberus-core", "cerberus-crypto", "cerberus-types", "cerberus-ssh-agent"],
        "cerberus-client": ["cerberus-types"],
        "cerberus-mcp": ["cerberus-api", "cerberus-core", "cerberus-client", "cerberus-types"],
        "cerberusd": ["cerberus-admin", "cerberus-api", "cerberus-mcp", "cerberus-core", "cerberus-store", "cerberus-crypto", "cerberus-types"],
        "cerberus-acceptance": [],
        "cerberus-desktop": ["cerberus-admin", "cerberus-api", "cerberus-client", "cerberus-mcp", "cerberus-core", "cerberus-store", "cerberus-crypto", "cerberus-types"]
      } as $allowed
      | [.packages[].name] as $members
      | ([ .packages[] as $p
            | $p.dependencies[] as $dep
            | select($dep.kind != "dev")
            | select($members | index($dep.name) != null)
            | select((($allowed[$p.name] // []) | index($dep.name)) == null)
            | "\($p.name) -> \($dep.name)" ]) as $bad
      | ($members - ($allowed | keys)) as $unlisted
      | if ($bad | length) == 0 and ($unlisted | length) == 0
        then true
        else error("forbidden edges: \($bad) unlisted crates: \($unlisted)")
        end
    ' > /dev/null
    echo "deps-check: all crate dependency edges match ADR-0024"

# ADR-0024 rule 4: the client SDK builds without the vault and the server stack.
client-deps-check:
    #!/usr/bin/env bash
    set -euo pipefail
    tree=$(cargo tree -p cerberus-client -e normal --prefix none)
    for banned in axum sqlx argon2 tauri utoipa cerberus-api cerberus-core cerberus-store cerberus-crypto cerberus-mcp; do
      if grep -q "^${banned} " <<< "$tree"; then echo "client-deps-check: ${banned} is in the client tree"; exit 1; fi
    done
    echo "client-deps-check: the client tree has no vault or server crates"

# The UI tools need Node 22 or newer (.nvmrc, `engines` in the UI package.json). Fails at once with a clear message.
node-check:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v node > /dev/null; then
      echo "node-check: node is not installed. Run 'nvm install' and 'nvm use' (see .nvmrc)." >&2
      exit 1
    fi
    major=$(node -p 'process.versions.node.split(".")[0]')
    if [ "$major" -lt 22 ]; then
      echo "node-check: Node 22 or newer is needed, found $(node -v). Run 'nvm use' (see .nvmrc)." >&2
      exit 1
    fi

ui-install: node-check
    pnpm --dir {{ui}} install --frozen-lockfile

ui-check: node-check ui-install
    pnpm --dir {{ui}} typecheck
    pnpm --dir {{ui}} lint

# Packaging and release (T29). Guide: docs/guides/packaging-and-release.md. Everything lands in `dist/` (ignored by git).
dist := "dist"

# Locked to Cargo.lock, needs no Tauri libraries. `cerberusd` and the systemd files are in the Linux tarball only (DEC-T29-3).
# Release binaries (`cerberus`, `cerberus-mcp`, `cerberusd`) as one tar.gz in `dist/`.
package-binaries:
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc -vV | sed -n 's/^host: //p')
    version=$(cargo metadata --format-version 1 --no-deps | jq -r '.packages[] | select(.name == "cerberusd") | .version')
    exe=""; case "$host" in *windows*) exe=".exe" ;; esac
    bins="cerberus cerberus-mcp"; pkgs="-p cerberus-client -p cerberus-mcp"
    case "$host" in *linux*) bins="$bins cerberusd"; pkgs="$pkgs -p cerberusd" ;; esac
    cargo build --release --locked $pkgs
    name="cerberus-${version}-${host}"
    rm -rf "{{dist}}/stage/$name"; mkdir -p "{{dist}}/stage/$name"
    for b in $bins; do cp "target/release/${b}${exe}" "{{dist}}/stage/$name/"; done
    cp LICENSE README.md "{{dist}}/stage/$name/"
    case "$host" in *linux*) cp -r packaging/systemd "{{dist}}/stage/$name/systemd" ;; esac
    tar -C "{{dist}}/stage" -czf "{{dist}}/${name}.tar.gz" "$name"
    rm -rf "{{dist}}/stage"
    echo "package-binaries: {{dist}}/${name}.tar.gz"

# Needs the Tauri system libraries (see .github/workflows/ci.yml). One kind only: `just package --bundles deb`.
# Desktop installers for the host OS (bundle.targets in tauri.conf.json: deb, rpm, AppImage, dmg, NSIS) in `dist/`.
package *args: node-check ui-install
    #!/usr/bin/env bash
    set -euo pipefail
    (cd apps/desktop && cargo tauri build --ci {{args}})
    mkdir -p "{{dist}}"
    find target/release/bundle -type f \( -name '*.deb' -o -name '*.rpm' -o -name '*.AppImage' -o -name '*.dmg' -o -name '*-setup.exe' \) \
      -exec cp -v {} "{{dist}}/" \;

# One CycloneDX 1.5 SBOM per shipped binary (cerberusd, cerberus, cerberus-mcp, cerberus-desktop). Needs cargo-cyclonedx.
sbom:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{dist}}"
    cargo cyclonedx --format json --spec-version 1.5 --describe binaries
    # cargo-cyclonedx writes next to each Cargo.toml: move the files so the work tree stays clean.
    find crates apps -name '*_bin.cdx.json' -not -path '*/node_modules/*' -exec mv -v {} "{{dist}}/" \;

# SHA256SUMS over every file in `dist/` (installers, tarballs, SBOMs; no subfolders), then check it.
checksums:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{dist}}"
    rm -f SHA256SUMS
    find . -maxdepth 1 -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS
    sha256sum --check --strict SHA256SUMS

# Everything a release holds, for the host: installers, binaries, SBOMs and checksums.
release-local: package package-binaries sbom checksums

# Fuzzing (T25). Needs nightly and cargo-fuzz. Not part of `check` or `test`. The targets live in `fuzz/`,
# outside the main workspace. Seed corpora are in `fuzz/corpus/<target>/` (read only: new inputs go to the ignored `fuzz/work/`), crash files go to `fuzz/artifacts/` (ignored by git).
fuzz_targets := "envelope_open key_slot recovery_parse token_parse rest_json resolve_query mcp_args ssh_frames phrase_policy csv_import"

# Run every fuzz target for about 30 seconds.
fuzz-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    export CARGO_TARGET_DIR="$PWD/fuzz/target"
    cd fuzz
    for target in {{fuzz_targets}}; do
      echo "fuzz-smoke: $target"
      mkdir -p "work/$target"
      cargo +nightly fuzz run "$target" "work/$target" "corpus/$target" -- -max_total_time=30
    done
    echo "fuzz-smoke: no crash"

# Run one fuzz target (default: every target) for `seconds` each, for example `just fuzz rest_json 600`.
fuzz target="all" seconds="180":
    #!/usr/bin/env bash
    set -euo pipefail
    export CARGO_TARGET_DIR="$PWD/fuzz/target"
    cd fuzz
    targets="{{target}}"
    if [ "$targets" = "all" ]; then targets="{{fuzz_targets}}"; fi
    for target in $targets; do
      echo "fuzz: $target for {{seconds}} s"
      mkdir -p "work/$target"
      cargo +nightly fuzz run "$target" "work/$target" "corpus/$target" -- -max_total_time={{seconds}}
    done
