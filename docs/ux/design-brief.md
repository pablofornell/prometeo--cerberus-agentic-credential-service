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
   warm ink black, ivory and brass. A screen full of red means something is wrong.
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

Color of the motif: brass (`ring.gate`). Brass reads as an old lock or a gate fitting: warm, physical, rare. It is
the only warm color in the dark theme besides warnings, so it marks "the gate" at a glance.

## 5. Look and feel

- **Palette, "Obsidian & Brass" (dark first).** Warm ink black, not blue slate: canvas `#0F0F10`, sunken `#0A0A0B`,
  surfaces stepped about 4% (`#151517`, `#1B1B1E`), text `#EDEBE6` ivory. Brass is the only accent and marks the
  gate: primary actions, the current nav item, gate rings and focus (`#C9A45C` solid, `#D9B46A` for text, champagne
  `#E9D7AE` focus ring). Patina green (verdigris, the color brass turns) for success `#7CCBA6`, coral for danger
  `#F2877C`, steel blue for info `#9DB8E0`. Light theme "vellum": ivory paper `#F6F4EF`, white panels, ink
  `#1A1917`, bronze `#7A5410` for brass text and `#8A6118` for buttons. Neutrals are warm in both themes and
  shadows are warm-tinted. Full list in `tokens.json`. Every text pair passes WCAG AA (`a11y-contrast-report.md`).
- **Finish.** Hairline, not heavy: 1px alpha borders (`line.hair`), panels flat on the canvas with a faint inner top
  highlight in dark, like a beveled metal edge. The primary button is polished brass (vertical gradient plus inset
  top highlight), never flat yellow. Brass is used rarely. A very faint concentric "guilloche" of the gate rings
  (2 to 4% opacity) may sit behind the unlock and create screens and the dashboard hero, nowhere else. Scrollbars
  are thin and themed, text selection is a brass tint.
- **Type.** Three families. Instrument Serif (400 and italic, local woff2, SIL OFL) for big moments only: the
  brand wordmark, page titles in the top bar, the unlock and create headlines, the dashboard hero title, dialog
  and drawer titles, empty-state titles. Inter for all UI text (with `cv11`, `ss01`, tabular numbers for timers).
  JetBrains Mono only for secret values, IDs, hashes, fingerprints, scopes and code. Small engraved labels (panel
  and table headers, group labels) are caption size, uppercase, tracking 0.08em, muted. Scale 12 / 13 / 14 / 16 /
  18 / 21 / 24 / 36 / 48 px, base 14; the serif runs about one step larger than Inter because of its small x-height.
- **Layout.** A 232 px rail (brand, navigation with `G` hints, and the "collar": who unlocked, auto-lock ring, Lock
  and panic buttons). A 56 px top bar with the serif page title and the palette trigger. Content is left aligned.
  Panels have a header rule and a quiet body; they are not a grid of identical cards.
- **Radius by hierarchy.** 3 px chips, 6 px controls, 8 px panels, 12 px dialogs and the approval window, full for rings.
- **Untrusted text** has its own surface: dashed brass border, mono face, a fixed label above it.

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
- No gradients as decoration (one soft brass glow behind the dashboard gate band is the only one).
- No all-caps eyebrows, no "→" on buttons, no emoji, no stock "security shield" hero.
- No secret value in any toast, title, notification, tray badge or event payload.

## Related

- `user-flows.md`, `information-architecture.md`, `components.md`, `tokens.json`, `a11y-contrast-report.md`
- Prototypes: `prototypes/index.html`
