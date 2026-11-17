# ADR-0001: One Tauri process holds the vault and runs the HTTPS server

- Status: Accepted
- Date: 2026-11-16
- Plan reference: D1
- Related: ADR-0002, ADR-0003, ADR-0023, ADR-0024, ADR-0026

## Context

The vault keys must live in one place. If the UI and the agent server are two processes,
the keys must cross a process boundary, or both processes must hold them.
Both options give a larger attack surface and more code that touches keys.

## Decision

1. The desktop app is one Tauri v2 process.
2. That process holds the unlocked vault (`VaultService` in `cerberus-core`) in memory.
3. The same process runs the HTTPS server (`cerberus-api`) and the MCP endpoint (`cerberus-mcp`)
   on a tokio runtime that Tauri starts.
4. The UI (webview) never holds a key. It gets data only through IPC commands (ADR-0003).
5. Only one instance can run per OS user (`tauri-plugin-single-instance`). A second start
   gives focus to the first window and then exits.
6. Closing the main window hides it to the tray. "Quit" locks the vault, stops the server and exits.

## Consequences

- Keys exist in one address space only. `mlock`, no-core-dump and zeroize apply to one process.
- A crash of the UI layer stops the server too. This is acceptable: a locked or stopped vault is the safe state.
- The server stops when the person quits the app. Servers without a screen use `cerberusd` (ADR-0002).
- The webview is untrusted input for the backend. Each IPC command checks the window label and
  the operator role (ADR-0003).

## Alternatives considered

- **UI process + separate vault daemon with local IPC.** Rejected. Two processes, a new IPC protocol
  and a second place that must authenticate the person.
- **Vault in the webview (WebCrypto).** Rejected. JavaScript cannot erase or lock memory.
