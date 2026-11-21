# Open security findings: remote mode and RustDesk

Status: 21-11-2026. This file lists the review findings and residual risks that are **not solved** by code.
Each one is either an accepted risk (it has an AR row in [threat-model.md](threat-model.md)) or a planned
follow-up. The solved findings are not listed here. You find them in `docs/decisions.md`
(DEC-RM-22, DEC-RD-5, DEC-RD-6).

Sources:
- Security review of the remote admin API, commits `a2ccc61..476f77d`. Fixes are in `2203f50` (DEC-RM-22).
- Review of the RustDesk item kind, commit `95c58d4`. Fixes are in `e48a930` (DEC-RD-5, DEC-RD-6).
- The as-built residuals that the implementers wrote in DEC-RM-18 and DEC-RM-20.

## Summary

| ID | Area | Severity | What stays open | State |
|---|---|---|---|---|
| OF-1 | Admin API, desktop | Low | Unwiped copies of escaped JSON strings (phrases, PEMs) in freed heap | Accepted: AR-21 |
| OF-2 | Admin API | Low | A sealed vault that a session open unlocked stays unlocked when the device is revoked during the phrase check | Accepted by design (invariant 10) |
| OF-3 | `cerberusd` | Low | An offline revoke (no daemon running) writes no `admin.client_revoke` audit event | Open, follow-up |
| OF-4 | `cerberusd` | Low | `admin-clients.json` has no MAC; a same-UID attacker can add an enrolment | Accepted: AR-19, follow-up |
| OF-5 | Desktop | Low | The enrolled client key is a 0600 file, not in the OS keychain | Accepted: AR-20, follow-up |
| OF-6 | Admin bundle | Low | The bundle private key passes once through a plain `String` (`IssuedCert::key_pem`) | Accepted: DEC-RM-18 (f) |
| OF-7 | Admin API | Info | Only one operator can work on a server vault at a time (409 `conflict` for a second operator) | Design limit, ADR-0034 |
| OF-8 | RustDesk | Low | A server key with `+` is changed to a space when RustDesk is already open | Open, mitigated in the UI |
| OF-9 | RustDesk | Info | The real launch of the RustDesk client has no automated test | Open, manual test needed |

## Details

### OF-1: Unwiped JSON scratch copies (AR-21)
- **Finding:** `crates/cerberus-admin/src/rpc.rs` (`from_body`) decodes request bodies with serde_json. serde_json
  decodes each string that has an escape (`\"`, `\\`, `\n`, `\uXXXX`) in a private scratch buffer and frees that
  buffer without a wipe. A passphrase with a quote, a backslash or a control character, and every PEM or SSH key,
  so leave copies in freed heap memory. This applies to `cerberusd` (admin bodies, unlock socket) and to the desktop
  (IPC arguments, admin answers).
- **Why not fixed:** the serde_json reader trait is sealed and the scratch buffer is private. `RawValue` does not work
  in the internally tagged payload type. A second JSON parser adds more risk than it removes.
- **Risk:** only the attacker of AR-8 can read freed heap, and that attacker can read live memory too. Both processes
  are not dumpable on Linux.
- **Action:** none now. Do the check again if serde_json gets a zeroizing scratch option.

### OF-2: Unlock kept after a revoke during session open
- **Finding:** a session open on a sealed vault runs the phrase check (about 1 s KDF). If the admin revokes the device
  in that time, the fix in `2203f50` refuses the session (`403 admin_cert_required`). But the unlock that the correct
  phrase did stays in effect.
- **Why accepted:** the result is the same as an open that ends just before the revoke. A revoke never locks the vault
  (invariant 10). The attacker needs a stolen bundle **and** the operator phrase.
- **Action:** if you also want to lock, run a lock on the server after a revoke.

### OF-3: No audit event for an offline revoke
- **Finding:** when no daemon runs, `cerberusd admin revoke` edits `admin-clients.json` directly. The vault is not open,
  so no `admin.client_revoke` event goes into the audit chain. ADR-0034 says that it must (DEC-RM-20).
- **Risk:** a revoke has no audit record. The revoke itself works.
- **Follow-up:** write a pending revoke marker. Then the daemon audits it at the next unlock.

### OF-4: Plain client registry (AR-19)
- **Finding:** `admin-clients.json` has no MAC. A same-UID attacker on the server can add a certificate hash.
- **Mitigation:** mode 0600 is checked at start. Each enrolment is audited. A session still needs an operator phrase.
- **Follow-up:** keep a sealed mirror of the registry and compare it at unlock.

### OF-5: Client key on disk (AR-20)
- **Finding:** the desktop keeps the enrolled client certificate key as a 0600 file, not in the OS keychain.
- **Mitigation:** same-UID malware can copy it, but it still needs an operator phrase (S-9).
- **Follow-up:** keep the key in the OS keychain (Secret Service on Linux).

### OF-6: Bundle key in a plain String
- **Finding:** while a bundle is issued, the private key passes once through `IssuedCert::key_pem`, which is a plain
  `String`.
- **Action:** wrap it in `Zeroizing` when `rcgen` gives a way to get the PEM without a plain `String`.

### OF-7: One operator per server vault
- **Finding:** core supports one unlocked session. If operator A has the server vault unlocked, operator B gets
  `409 conflict`.
- **Action:** none for the MVP. Multi-operator sessions need a core change.

### OF-8: RustDesk key with `+`
- **Finding:** when RustDesk is already open, `--connect` is forwarded as a link. The RustDesk link parser changes `+`
  to a space, so a server key with `+` arrives wrong. A fresh start reads the argument raw and is correct.
- **Mitigation:** the item card tells the user to close RustDesk first for such keys. The copied share link encodes
  the key and is correct.
- **Follow-up:** report it upstream to RustDesk, or detect a running client and warn before Connect.

### OF-9: RustDesk launch not tested end to end
- **Finding:** `TauriShell::launch` and the real RustDesk client have no automated test. All tests use fakes.
- **Action:** test it by hand on one deb install and one Flatpak install, with a public server and a self-hosted
  server, before the release notes say that the feature is supported.
