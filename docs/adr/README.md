# Architecture Decision Records

Format of each ADR: status, date, plan reference, context, decision, consequences, alternatives considered.
The ADRs D1–D12 and the gap ADRs have status **Accepted** (task T01, 2026-11-16); ADR-0034 was added on 2026-11-21. A changed decision gets a new ADR that supersedes
the old one; the old one is not edited except to add "Superseded by ADR-NNNN".

Related design documents:
- Threat model: [`../security/threat-model.md`](../security/threat-model.md)
- REST contract: [`../api/openapi-draft.yaml`](../api/openapi-draft.yaml)
- MCP tools: [`../api/mcp-tools.md`](../api/mcp-tools.md)
- DB schema draft: [`../schema.sql`](../schema.sql)
- Module interfaces and IPC commands: [`../interfaces.md`](../interfaces.md)
- Running log of smaller decisions: [`../decisions.md`](../decisions.md)

## Plan decisions D1–D12

| ADR | Title | Plan reference | Status |
|---|---|---|---|
| [ADR-0001](0001-single-tauri-process.md) | One Tauri process holds the vault and runs the HTTPS server | D1 | Accepted; amended by ADR-0034 |
| [ADR-0002](0002-headless-daemon.md) | Headless daemon `cerberusd` uses the same library | D2 | Accepted; amended by ADR-0034 |
| [ADR-0003](0003-admin-over-ipc-only.md) | Admin actions use Tauri IPC only | D3 | Accepted; amended by ADR-0034 |
| [ADR-0004](0004-agents-use-agent-api-only.md) | Agents use only the Agent API (HTTPS REST and MCP) | D4 | Accepted |
| [ADR-0005](0005-encrypt-content-and-metadata.md) | Item content and item metadata are encrypted | D5 | Accepted |
| [ADR-0006](0006-in-memory-search-index.md) | Search runs on an in-memory index built at unlock | D6 | Accepted |
| [ADR-0007](0007-session-ttl.md) | Session TTL default 60 minutes, maximum 24 hours | D7 | Accepted |
| [ADR-0008](0008-http-423-when-locked.md) | The API returns HTTP 423 when the vault is locked | D8 | Accepted |
| [ADR-0009](0009-operators-key-slots-roles.md) | Operators have their own key slots and roles | D9 | Accepted |
| [ADR-0010](0010-ui-stack.md) | UI uses React, TypeScript, Vite, Tailwind and shadcn/ui; languages English and Spanish | D10 | Accepted |
| [ADR-0011](0011-rust-edition-and-versions.md) | Rust edition 2024 and the version policy | D11 | Accepted |
| [ADR-0012](0012-unsafe-code-policy.md) | No unsafe code, except in the `memlock` module | D12 | Accepted |

## Decisions that fill gaps in the plan

| ADR | Title | Plan reference | Status |
|---|---|---|---|
| [ADR-0013](0013-vault-file-header-and-kdf.md) | Vault file, header and KDF parameter format | 4.1, 4.5 (gap: file and header format) | Accepted |
| [ADR-0014](0014-key-hierarchy-and-envelope.md) | Key hierarchy, AEAD envelope and AAD format | 4.1 (gap: exact derivation labels, blob layout, AAD layout) | Accepted |
| [ADR-0015](0015-identifiers-and-request-ids.md) | Identifier format and request IDs | 1.1 ("every call has a request ID"); gap: ID format | Accepted |
| [ADR-0016](0016-agent-token-format-and-auth.md) | Agent token format, storage, scopes and checks | 4.4 | Accepted |
| [ADR-0017](0017-grants-and-policy-evaluation.md) | Grants and policy evaluation | 3 (grant fields), T07 ("deny wins, then most specific") | Accepted |
| [ADR-0018](0018-approval-flow.md) | Approval flow (access requests) | 3 (AccessRequest), 5.1 (`/requests`), 7 screen 8, A6 | Accepted |
| [ADR-0019](0019-lease-semantics.md) | Lease semantics | 3 (Lease), 5.1 (`reveal`, `/leases/{id}/release`), 4.2 (panic button) | Accepted |
| [ADR-0020](0020-resolve-scoring.md) | Resolve scoring | 5.1 (resolve rules), A2, A4, T06 (40+ table cases) | Accepted |
| [ADR-0021](0021-error-shape-and-codes.md) | One error shape and a fixed list of error codes | 1.1, 5.1 ("Error JSON") | Accepted |
| [ADR-0022](0022-clock-abstraction.md) | Clock abstraction for TTL and time tests | A3 ("after 3600 s (test clock)"), 4.2 (idle lock), T07 (leases) | Accepted |
| [ADR-0023](0023-network-boundary-tls.md) | Network boundary — TLS, bind, local CA, browser and webview rules | 4.3, 4.7, A8 | Accepted; amended by ADR-0034 |
| [ADR-0024](0024-crate-layout-and-dependency-rules.md) | Workspace crate layout and dependency rules | 6 (repository layout) | Accepted; amended by ADR-0034 |
| [ADR-0025](0025-audit-hash-chain.md) | Audit log with hash chain and HMAC | 4.5, A9, T08 | Accepted |
| [ADR-0026](0026-vault-state-machine-and-lock.md) | Vault state machine, unlock limits and lock triggers | 4.2, T05 | Accepted |
| [ADR-0027](0027-item-kinds-versions-expiry.md) | Item kinds, payloads, versions, expiry and the sweeper | 3, 4.5, T04, T06, A3 | Accepted |
| [ADR-0028](0028-secret-responses-and-env-injection.md) | Secret responses, the `handling` field and env injection | 4.6, 5.1, A2, A12 | Accepted |
| [ADR-0029](0029-mcp-transport-and-stdio-shim.md) | MCP transport and the stdio shim | 5.2, T11 | Accepted |
| [ADR-0030](0030-rate-limits-and-lockouts.md) | Rate limits and lockouts | 4.4, 14 ("many secrets"), T09, T10 | Accepted |
| [ADR-0031](0031-backup-and-restore.md) | Backup and restore | 4.5, 7 screen 11 | Accepted |
| [ADR-0032](0032-logging-and-redaction.md) | Logging and redaction | 4.2 ("Logs never contain secrets. A test checks this."), 2 (`tracing` with redaction) | Accepted |
| [ADR-0033](0033-row-macs-for-plain-columns.md) | Row MACs protect security-relevant plain columns | 4.1, 4.4, 4.5 (gap found in the T01 threat model, T-5) | Accepted |

## Later decisions

| ADR | Title | Plan reference | Status |
|---|---|---|---|
| [ADR-0034](0034-remote-backend-mode.md) | Remote backend mode — opt-in admin API on `cerberusd` for the desktop app | D1, D2, D3 (owner request, 2026-11-21) | Accepted (design; phase 2 in `../remote-mode-plan.md`) |

## Topic finder

| Topic | ADRs |
|---|---|
| Key custody and crypto formats | 0005, 0009, 0012, 0013, 0014, 0026, 0033 |
| Agent identity and access | 0004, 0016, 0017, 0018, 0019, 0030 |
| Agent-facing contract | 0008, 0015, 0020, 0021, 0028, 0029 |
| Network and desktop boundary | 0001, 0003, 0023, 0034 |
| Storage, expiry, backup | 0005, 0007, 0027, 0031 |
| Audit and logging | 0025, 0032 |
| Code structure and tooling | 0002, 0010, 0011, 0012, 0022, 0024, 0034 |
