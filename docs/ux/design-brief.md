# Cerberus design brief (T14)

Status: accepted for T16–T21. Date: 2026-11-16.
Inputs: `docs/PLAN.md` section 7, ADR-0010, ADR-0018, `docs/interfaces.md` section 9, `docs/security/threat-model.md`.

## 1. Product in one line

Cerberus is a local credential vault for AI agents. A person unlocks it once. Agents ask for credentials by
app, environment and role. Cerberus answers, or it asks the person.

**The guard dog keeps the gate. Agents ask. The dog decides. The hard cases come to you.**

## 2. Audience

| Who | Situation | What they need from the UI |
|---|---|---|
| Owner (developer, team lead) | Sets up the vault, runs agents on a laptop or CI box | Fast setup, clear grants, a panic button, trust that nothing leaks |
| Operator (team member) | Adds items, approves requests during the day | Quick approve or deny with full context; keyboard first |
| Viewer (QA lead, auditor) | Checks what agents did | Read-only audit, leases, health; no secret values |

They are technical. They read `curl` and JSON. They do not want a marketing tone. They are often in the middle of
other work when an approval window appears, so the window must be readable in 3 seconds.

## 3. Principles

1. **Identity before story.** Every decision screen shows who is asking (from the token) before what they say
   (the untrusted reason). The reason is never styled like system text.
2. **Masked by default.** Secrets are dots in the mono face. A deliberate hold (500 ms) reveals. They hide again
   after 15 s. Copy clears the clipboard after 30 s. The UI states these times next to the control.
3. **Prod is loud, the rest is calm.** Only `prod`, danger actions and broken integrity get red. The base palette is
   monochrome. A screen full of red means something is wrong.
4. **Plain-word policy.** Grants read as sentences ("QA runner can read items in shop-frontend, env staging, and I
   approve: never"). Wire words (`ask_once`, `secrets:read`) appear only in mono, as secondary detail.
5. **Every state is designed.** Ready, empty, loading, error and locked exist for every screen. Empty states invite
   the next action. Errors say what happened, what is safe, and what to do, and show the error code in mono.
6. **Keyboard first.** `Ctrl/Cmd+K` palette, `G` + letter navigation, visible focus rings, no hover-only actions.
7. **Quiet motion.** One orchestrated moment: the gate rings open on unlock. Everything else is 120–260 ms state
   feedback. Reduced motion removes movement and keeps meaning.

## 4. Brand idea: the three-ring gate

Cerberus has three heads. We draw them as **three concentric rings**, each with a gap at the bottom. When the gaps
line up, they form a path to the core: the gate is open. When the vault is locked, the rings close.

The three rings are also the three checks every agent request passes, in order:

| Ring | Check | Source |
|---|---|---|
| Outer | Identity | The agent token (`cvt_…`), never the request text |
| Middle | Policy | The grants for that agent (deny wins, then most specific) |
| Inner | You | Approval, when the mode or `prod` needs a person |

Where the motif appears (and nowhere else, so it keeps meaning):

- **Gate mark**: the logo, the unlock screen (closed rings, then open on success), loading states (rings turn).
- **Create vault**: each setup step fills one ring; the recovery key fills the core.
- **Gate trace**: a three-dot row on the dashboard and approval window ("Agent token, Grant, You") showing which
  checks passed and which waits.
- **TTL ring**: the same ring geometry shows time left for leases, sessions, TOTP codes and the auto-lock timer.

Color of the motif: the text color (`ring.gate`), so the rings are the one white shape in the dark theme and read as
"the gate" at a glance. The brand mark itself is a dark glass tile with spectrum light and is drawn separately.

## 5. Look and feel

- **Direction: a monochrome Geist console.** Cerberus shares its look with Hermes and IRIS: near-black or white
  surfaces, 1 px hairlines, dense 13 to 14 px type, no decoration. It replaces the earlier "Obsidian & Brass" look
  (warm ink, brass accent, serif display, guilloche, engraved labels), which read as costume and not as a tool.
- **Palette (dark first).** Canvas `#0A0A0A`, rail `#000000`, raised `#1A1A1A`, hairlines `#FFFFFF24` and `#FFFFFF3D`,
  text `#EDEDED` / `#A1A1A1` / `#8F8F8F`. Light theme: `#FFFFFF`, rail `#FAFAFA`, text `#171717`. The primary button
  is solid foreground ink (`#EDEDED` on dark, `#171717` on light): there is no accent hue, and the `accent.*`
  tokens are that neutral primary. Color is for meaning only: info blue, warning amber, error red, ok green, each
  with a text step, a fill step and a precomputed tint (14% dark, 10% light). Links and the focus ring are blue
  (`#0072F5`). Form-control borders (`border.default`) are the one firm line: they pass 3:1. Full list in
  `tokens.json`; every text pair passes WCAG AA (`a11y-contrast-report.md`).
- **Finish.** Hairline, not heavy: 1 px alpha borders (`line.hair`), flat panels with a faint shadow, popups with a
  ring shadow (`shadow.overlay`). Quiet nav: the current item is a faint fill and a brighter label, never an
  accent. A selected row is a faint fill plus a 2 px inset rule in the text color. Hover and selection never move
  layout. No gradients, no patterns, no uppercase labels.
- **Signature (kept small).** The five spectrum colors (`spectrum.*`, the light of the brand mark) appear in two
  places only: the signal band, a 1 px hairline along the top of the main area with a slow spectrum light (static
  with reduced motion), and a faint 64 px blueprint grid behind the standalone gate screens (unlock, create),
  faded by a radial mask. Nothing else uses them.
- **Type.** Geist Variable for UI text and Geist Mono Variable for secret values, IDs, hashes, fingerprints,
  scopes and code (local woff2, SIL OFL, no CDN). Tabular numbers everywhere. Headings are 600 with negative
  tracking (-0.02em, page title -0.04em); no serif, no italic display, no engraved labels. Scale 12 / 13 / 14 /
  16 / 20 / 24 / 32 px, base 14.
- **Layout.** A 240 px rail (brand lockup with a 24 px mark, navigation with `G` hints that show on hover and
  focus, and the "collar": who unlocked, auto-lock ring, Lock and panic buttons). A 56 px top bar with the page
  title and the palette trigger. Content is left aligned. Panels have a header rule and a quiet body; they are not
  a grid of identical cards. Controls are 32 px tall (28 px compact, 40 px large).
- **Radius by hierarchy.** 4 px chips and keys, 6 px controls, 8 px panels, 12 px dialogs and the approval window,
  full for pills and rings.
- **Untrusted text** has its own surface: dashed amber border (a meaning color: it came from outside), mono face,
  a fixed label above it.

## 6. Voice and tone

Short, plain, active. ASD-STE100 style: one idea per sentence, simple verbs, no idioms. The UI talks about the
vault and the agents, never about itself ("Cerberus cannot reset it", not "We're sorry").

| Do | Do not |
|---|---|
| "Approve for 15 minutes" | "Grant temporary access" |
| "QA runner wants to read a prod login" | "New access request received" |
| "Cannot load items. Your items are safe in the vault file." | "Oops! Something went wrong" |
| "Copied. The clipboard clears in 30 s." | "Copied to clipboard!" |
| "That phrase does not open the slot for Ana Ruiz." | "Invalid credentials" |

Spanish uses "tú", neutral vocabulary (no regional slang), and keeps wire values (`prod`, `admin`, scope names) in
English because agents send them. The prototypes hold the full Spanish set in `prototypes/assets/i18n-es.js`; T16
moves it to `ui/src/locales/es.json`.

Copy samples:

| Place | English | Spanish |
|---|---|---|
| Unlock title | Cerberus is locked | Cerberus está bloqueado |
| Unlock subline | Agents get HTTP 423 until you unlock. | Los agentes reciben HTTP 423 hasta que desbloquees. |
| Back-off | 7 wrong phrases in a row. Wait before the next try. | 7 frases erróneas seguidas. Espera antes del siguiente intento. |
| Approval title | QA runner wants to read a prod login | QA runner quiere leer un acceso de prod |
| Reason label | Reason given by the agent, not verified | Motivo dado por el agente, no verificado |
| Approval note | No answer means deny. | Sin respuesta, se deniega. |
| Grant sentence | … and I approve: never / once / always | … y yo apruebo: nunca / una vez / siempre |
| Empty dashboard | The gate is ready. Nothing passes yet. | La puerta está lista. Aún no pasa nada. |
| Token reveal | Copy the token now. Once you close this, nobody can show it again. | Copia el token ahora. Cuando cierres esto, nadie podrá mostrarlo de nuevo. |
| Recovery warning | Lost phrase and lost key means lost data. | Frase perdida y clave perdida significa datos perdidos. |
| Panic confirm | Hold to lock and revoke | Mantén para bloquear y revocar |
| About | The guard dog keeps the gate. Agents ask. You decide. | El perro guardián vigila la puerta. Los agentes piden. Tú decides. |

## 7. What this brief rules out

- No mascot illustration, no dog head drawing. The rings are the dog.
- No gradients or patterns as decoration. The spectrum signal band and the gate-screen grid are the only signatures.
- No all-caps labels or eyebrows, no "→" on buttons, no emoji, no stock "security shield" hero.
- No secret value in any toast, title, notification, tray badge or event payload.

## Related

- `user-flows.md`, `information-architecture.md`, `components.md`, `tokens.json`, `a11y-contrast-report.md`
- Prototypes: `prototypes/index.html`
