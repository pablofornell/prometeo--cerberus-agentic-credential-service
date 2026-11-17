# UI polish report (T21)

Compared: the React app in `pnpm dev` (dev mock) against the prototypes in `docs/ux/prototypes/` and their
screenshots, at 1280x800 and 420 px wide, dark and light. Final screenshots: `docs/ux/screenshots/final/`
(`<screen>[-state]-<theme>[-narrow].png`). Decisions: `docs/decisions.md` DEC-T21-1 to DEC-T21-8.

## Drift found and fixed

| Screen | Drift | Fix |
|---|---|---|
| Shell | Top bar repeated "Unlocked, Auto-lock in 27:42" (also in the rail collar and the dashboard band); it wrapped to three lines on narrow windows. | Removed from the top bar; the collar is the one lock indicator (DEC-T21-1). |
| Shell | While locking, the collar still said "Vault unlocked" with Lock and panic buttons, and the inert rail looked active. | Collar says "Vault locking" / "Vault locked" with a closed gate, no buttons; inert rail is dimmed. |
| Shell | Page actions in the top bar touched each other (no gap). Narrow top bar overflowed onto the rail. | Slot is a flex row with an 8 px gap; narrow top bar wraps. |
| Shell | Rail Vault icon read as a "close" box. | Archive box, as in the prototype; workspaces use layers. |
| Shell, a11y | Palette trigger name "Open the command palette" did not contain its visible text (axe `label-content-name-mismatch` on every screen, WCAG 2.5.3). | Name is the visible text; key cap `aria-hidden`; `aria-keyshortcuts`. |
| Dashboard | "QA runner wants read for 15:00", "wants use SSH"; every request showed a globe icon. | "wants to read for 15 minutes", "wants to use SSH"; icon by permission (the request view has no item kind). |
| Dashboard | Health "Unlock cost" row wrapped into four lines next to its action. | Shorter title and detail, no action (the detail says where to change it). |
| Dashboard | Feed panel used the Dashboard nav icon; item titles in mono. | Activity icon; titles in plain medium text. |
| Vault | Empty 420 px detail column squeezed the list to 444 px and titles were cut ("Chec…"). | Narrower detail column, 280 px placeholder, badges move under the title in a narrow list (DEC-T21-5). |
| Vault | "Export CSV" was a loud red button in the top bar. | Quiet ghost buttons in the top bar; red stays in Settings. |
| Vault | Masked values were 14 small spaced dots. | 12 "●" as in the prototype. |
| Vault, narrow | The facet column stayed beside the list at 420 px (selector specificity). | One column below 760 px. |
| Editor | Kind tiles had two heights ("Browser session" wraps) and boxed icons. | One row height, plain icons. |
| Agents | Key rows had three stacked buttons; "in 70 days" and "2 days ago" wrapped; the row overflowed its panel. | Certificate is an icon button (same accessible name); short columns do not wrap. Suspend uses a pause icon. |
| Policies | "Can create sessions items in workspace …, env any env"; mode buttons had the label at the bottom edge. | Plain sentence rules (DEC-T21-4); buttons centre their label. Simulator says "read items", not `read`. |
| Policies, a11y | Every grant had an "Edit grant" / "Delete grant" button with no hint which grant. | Buttons are described by the grant sentence. |
| Approvals | "Asks for: read, for 15:00", "Asks for: use_ssh"; cards used only the left half of the page. | Words and minutes (DEC-T21-3); cards sit side by side. |
| Leases | "Lock and revoke all" used a warning triangle, the rail uses a siren. "Delete now" had the name "Delete session item …" (2.5.3). | Siren icon; name "Delete now: {title}". |
| Audit | `items.import`, `items.export` and `tls.custom_revert` showed raw type names. | Phrases added; a test checks every type in `docs/reference/audit-events.md`. |
| Audit | A "Details" button on its own line under every event made the timeline loose; item titles in mono; operator node was a shield. | Toggle on the event line with a chevron; plain titles; person node. |
| All screens | Error states printed the raw backend message ("the agent list did not load Your items are safe…"). | A backend message is shown as a sentence (capital, full stop) before "Your items are safe…". |
| Palette | No action for CSV import or for the connect guide (both added after T14). | "Import items from CSV", "Connect an agent" (DEC-T21-6). |

## Accessibility

- axe-core 4.14 (WCAG 2.0/2.1/2.2 A and AA + best practice) in Chromium on 27 screen states (every screen plus empty, error, drawer, viewer and locking states), dark and light, at
  1280x800: before, 2 rules failed (palette trigger on every screen, "Delete now" in Leases); after, 0 violations.
  The vitest axe checks of every screen also pass.
- Contrast: no new token pairs. `docs/ux/check-contrast.mjs`: 154 pairs, 0 failures.
- Keyboard only (Playwright, Tab / Enter / Space / arrows / held Enter, no mouse): create vault (name, generated
  phrase, cost test, recovery key confirm) → Ctrl+L → unlock with Enter → G V → N → new item → save → create
  agent → token dialog (ack, Done) → G P → grant built with the selects and the mode radio (arrows) → save → G R →
  approve once with a 0.6 s held Enter → G U → event details → Ctrl+K "verify". Every step passed; every focused
  control showed a visible focus ring.
- Reduced motion: unchanged and checked (global rule, hold fills jump, shimmer off, gate does not spin).

## Left as is, on purpose

- The editor top bar says "Item editor", not "New item" / "Edit …": the shell title comes from the screen table
  and the form already names the action. Changing the shell title API is not worth the risk now.
- The rail and top bar title say "Leases", the prototype said "Leases and sessions": the rail label must stay short
  and the page shows both sections with headings.
- The audit screen has no free-text search ("Item title or request ID" in the prototype): `audit_query` has no
  text filter. Backend need below.
- The leases table scrolls sideways at 420 px instead of reflowing into cards: it keeps the column headers and
  works with the keyboard.
- Approval card and dashboard queue show no item kind or role label ("Web login in shop-frontend, role admin" in
  the prototype): `AccessRequestView` has no kind or role. Backend need below.

## Backend needs (not done here: no IPC or Rust change in T21)

1. `AccessRequestView`: add `item_kind` and `role_label`, so the queue and the approval card can show the kind
   icon and "Web login in shop-frontend, role admin".
2. `audit_query`: an optional text filter (item title or request ID) for the audit search box of the prototype.
