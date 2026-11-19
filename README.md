# Cerberus

Cerberus is a credential vault for AI agents. A person unlocks the vault once with a master phrase.
After that, agents ask for credentials. They use the HTTPS REST API, the MCP server, the `cerberus` command line
client, or the SSH agent socket. Cerberus checks each request against grants. Some requests wait for a person to
approve them. Every call writes an audit event. No secret value goes into the audit log.

Example: a QA agent needs the staging login for `shop-frontend`. It asks for the app, the environment and the role.
It does not need to know the user name. Cerberus returns the best item the agent may read, or it asks the person
for approval first.

Status: version 0.2.0. Linux installers (deb, rpm, AppImage) and binary tarballs are built with `just package`
and `just package-binaries`; see [packaging and release](docs/guides/packaging-and-release.md). macOS and Windows
builds are set up in CI but not yet tested. Final acceptance: [docs/acceptance-report.md](docs/acceptance-report.md).

## What is in this repository

| Part | What it is | Where |
|---|---|---|
| Desktop app | The person's screen: create and unlock the vault, manage items, agents, grants, approvals, backups | `apps/desktop` (Tauri shell in `src-tauri`, React UI in `ui`) |
| `cerberusd` | Headless daemon for a server with no screen. Serves the Agent API only | `crates/cerberusd` |
| `cerberus` | Command line client for agents, including `cerberus run` | `crates/cerberus-client` |
| `cerberus-mcp` | MCP server at `/mcp`, and the stdio shim for hosts that start local commands | `crates/cerberus-mcp` |
| `cerberus-api` | HTTPS server (TLS 1.3 only), REST routes, OpenAPI | `crates/cerberus-api` |
| Vault core, store, crypto, types, SSH bridge | Library crates behind the parts above | `crates/cerberus-core`, `crates/cerberus-store`, `crates/cerberus-crypto`, `crates/cerberus-types`, `crates/cerberus-ssh-agent` |

## Requirements

- Rust 1.100.0. `rust-toolchain.toml` selects it.
- Node 22 or newer, for the desktop UI (`.nvmrc`). The justfile uses `pnpm`.
- `just` (`cargo install just`). `just check` also needs `cargo-deny`, `cargo-audit` and `jq` (for `deps-check`).
- The Linux system libraries that Tauri needs, as in `.github/workflows/ci.yml`.

## Build from source

Run these from the repository root:

```
cargo build --release -p cerberus-client    # target/release/cerberus
cargo build --release -p cerberus-mcp       # target/release/cerberus-mcp (the shim is a default feature)
cargo build --release -p cerberusd          # target/release/cerberusd
just check
just test
```

To run the desktop app with hot reload, use `just dev`. It needs the Tauri CLI, as the justfile recipe does.

## Quickstart

1. Start the desktop app with `just dev`.
2. Create the vault. Choose a name and a master phrase. Save the recovery key that the app shows once. The phrase
   and the recovery key are the only ways back in. Cerberus has no backdoor.
3. In the vault screen, create a workspace and an item. For example, an API key for `shop-frontend` in `staging`.
4. In the agents screen, create an agent and an agent key. The token (`cvt_...`) is shown once. Store it in a file
   with mode `0600`.
5. In the policies screen, give the agent a grant on that item. An agent without a grant sees nothing.
6. In the settings screen, export the Cerberus CA certificate. Save it as a file.
7. Test the connection from a shell:

   ```
   export CERBERUS_TOKEN_FILE=$HOME/.config/cerberus/token
   export CERBERUS_CA_FILE=$HOME/.config/cerberus/ca.pem
   cerberus status
   cerberus run --app shop-frontend --env staging -- env
   ```

   The child process sees the credential variables. The output of `cerberus run` masks the secret values.

## Documentation

| Read this | If you are |
|---|---|
| [User guide](docs/guides/user-guide.md) | A person who runs the desktop app |
| [Operator guide](docs/guides/operator-guide.md) | The owner of a vault: roles, limits, network, platform gaps |
| [Agent integration guide](docs/guides/agent-integration.md) | Building an agent: REST, MCP, the CLI, `cerberus run`, the SSH bridge |
| [MCP client configuration](docs/guides/mcp-client-config.md) | Connecting an MCP host to Cerberus |
| [Backup and restore](docs/guides/backup-and-restore.md) | Keeping a copy of the vault, or moving it |
| [Troubleshooting](docs/guides/troubleshooting.md) | Something does not work |
| [Headless daemon](docs/guides/cerberusd.md) | Running `cerberusd` on a server |
| [Security model](docs/guides/security-model.md) | Reviewing what Cerberus protects, and what it does not |

Design and reference documents:

- [Plan](docs/PLAN.md) and [decision log](docs/decisions.md).
- [Architecture decision records](docs/adr/README.md).
- [Module interfaces](docs/interfaces.md), [OpenAPI draft](docs/api/openapi-draft.yaml), [MCP tools](docs/api/mcp-tools.md).
- [Threat model](docs/security/threat-model.md) and [security audit report](docs/security/audit-report.md).

## Security in one paragraph

The vault file is encrypted. Item content and item metadata are encrypted. Keys come from the master phrase through
Argon2id. The HTTPS server uses TLS 1.3 only, with a local CA that clients pin or trust by file. Agent tokens carry
256 random bits, and the server stores only a hash. A locked vault answers HTTP 423 and returns no data. Known gaps
and accepted risks are listed in the [security model](docs/guides/security-model.md).

## License

MIT. See [LICENSE](LICENSE).
