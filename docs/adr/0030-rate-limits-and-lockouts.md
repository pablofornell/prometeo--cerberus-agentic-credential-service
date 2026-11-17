# ADR-0030: Rate limits and lockouts

- Status: Accepted
- Date: 2026-11-16
- Plan reference: 4.4, 14 ("many secrets"), T09, T10
- Related: ADR-0016, ADR-0017, ADR-0018, ADR-0021, ADR-0022

## Context

A prompt-injected agent may try to read many secrets fast. A local attacker may guess tokens.

## Decision

All limits are settings (owner). Defaults:

| Limit | Key | Default | Result |
|---|---|---|---|
| Requests per source IP (before auth) | IP | 30/s, burst 60 | `429 rate_limited` |
| Auth failures per source IP | IP | 10 per 5 min, then lockout 300 s | `429 too_many_failures` |
| Requests per agent | agent ID | 20/s, burst 40 | `429 rate_limited` |
| Secret reads per agent (reveal, resolve with secret, totp, ssh-prepare) | agent ID | 60 per min | `429 rate_limited` |
| Distinct items read per agent per hour | agent ID | 30 | `429 rate_limited` and a dashboard alert |
| Access requests per agent | agent ID | 10 per 10 min; max 5 pending | `429 rate_limited` |
| Grant `max_reads_per_hour` | grant + agent | per grant | `429 grant_rate_limited` |
| Unlock attempts | vault | ADR-0026 back-off | UI countdown |
| Pending audit rows while locked | vault | 10,000 | overflow counter |

- Implementation: `governor` keyed limiters (GCRA), in memory. A restart resets them; a restart needs local access.
- The "distinct items per hour" alert shows on the dashboard: "Agent X read 30 different secrets in one hour". This
  catches mass exfiltration that stays under the request rate.
- Each `429` sets `Retry-After` and `details.retry_after_seconds`.
- A lockout writes `auth.lockout` (or `api.locked_call` while locked, through `audit_pending`).

## Consequences

- Normal agents (a few reads per task) never hit the limits. Mass reads are slow and visible.

## Alternatives considered

- **Persistent counters in SQLite.** Rejected. Write load on every call, and little gain.

## Amended by DEC-T27-E-1

- The first row ("Requests per source IP (before auth)") now means **failed token checks per source IP**. The
  source bucket and the source lockout count failed checks only. A good token is limited per agent only, and no
  per-IP limit refuses it. On loopback every agent shares one address with any local user, so a per-IP limit on good
  tokens would be a lockout tool (NEW-5). A global lockout (100 failed checks from all sources in 300 s) is added.
- The request and token limits (`AuthLimits`, `ApiLimits`) are fixed defaults in the build, not owner settings. The
  policy limits in this table (secret reads, distinct items, access requests, approval wait) are owner settings
  (`PolicySettings`).
- Source: `docs/decisions.md`, DEC-T27-E-1. The table above is not rewritten.
