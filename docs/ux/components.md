# Cerberus components (T14)

Build target: React + shadcn/ui primitives (Radix) + Tailwind v4 with the keys in `tokens.json` → `tailwind`.
Reference rendering: `prototypes/assets/app.css` and `app.js` (same names as below). Icons: lucide-react.

## 1. Tokens in code

- CSS variables come from `tokens.json` (`node docs/ux/build-tokens.mjs` writes the prototype copy). T16 puts the
  same variables in `ui/src/styles/tokens.css` and maps them in `@theme` with the `tailwind` block.
- Theme: `html[data-theme="dark" | "light"]`; no attribute = follow the OS. Dark is the default setting.
- UI scale (Settings > Appearance, `usePrefs().uiScale`, percent 80 to 200, default 100): the desktop app zooms the main
  webview (`setZoom`, capability `core:webview:allow-set-webview-zoom` on `main` only; the approval popup stays at 100%).
  In a plain browser it is the CSS `zoom` of `<html>`, with `data-css-zoom` and `--ui-zoom` (see the end of `extras.css`).
  It is kept in `localStorage` with the other display prefs and applied before the first screen is drawn.
- Use semantic names only (`bg-surface`, `text-fg-muted`, `border-line`). No raw hex in components.

## 2. Component list

States column: `default · hover · focus-visible · active · disabled` apply to every interactive part unless the row
says more.

| Component | Variants | Extra states | Notes |
|---|---|---|---|
| **Button** | primary (brass), secondary, ghost, danger (solid), danger-ghost, icon-only; sizes sm 28 / md 34 / lg 44 | loading (spinner ring, label stays), hold (fill grows) | One primary per view. Labels say the action ("Save item"). |
| **HoldButton** | approve (600 ms), reveal (500 ms), panic (1000 ms) | holding (fill), done | Pointer or Space/Enter. Release before the end cancels. Fill is `currentColor` at 18%. Reduced motion: fill jumps, timing stays. |
| **SecretField** | masked (default), revealed, denied (viewer), loading | auto-hide ring 15 s | Mono value. Eye = HoldButton reveal; copy = `clipboard_copy_secret`. Value only in component state; cleared on hide, unmount, lock (ADR-0010). Never in `title`, `aria-label` or logs. `aria-live="polite"` on the value. |
| **TtlRing** | sizes 20 / 22 / 24 / 28 / 32; tones ok (info), low ≤ 25% (warning), critical ≤ 10% (danger), gate (brass, auto-lock) | live (ticks each second), expired | SVG arc, starts at 12 o'clock. Has `role="img"` and label "4:10 time left". Pair it with text for anything that matters (color is not the only signal). |
| **GateMark** | open, locked, turning (loading) | opening (unlock) | Three rings with bottom gaps. Locked = closed muted rings. Opening is the one orchestrated motion (640 ms, rings stagger 60 ms). |
| **GateTrace** | 3 steps: Agent token, Grant, You | pass, wait, fail per step | Dots + labels; text carries the state, dot colors confirm it. |
| **RoleChip** | preset (admin, normal user, read-only, SAI user), custom (dashed), selectable | pressed | Pill with ring dot. Selectable chips are `button[aria-pressed]`; single-select groups behave as a radio set. |
| **EnvBadge** | prod, staging, dev, other | — | prod = red tint + 1 px red inset + triangle mark, so it reads without color. Always the rightmost badge in a row. |
| **KindIcon** | 10 kinds (web_login globe, api_key key, ssh_key terminal, session_token ticket, browser_session window, database, cloud, certificate badge, env_bundle braces, note file) | prod (red border) | 30 px square, 6 px radius. |
| **AgentMadeBadge** | — | — | Bot icon + agent name in info blue (T-9: shows poisoning risk). |
| **StatusDot** | ok, warn, bad, off (hollow) | — | Always next to a word. |
| **Panel** | default, flush (no body padding) | — | Header rule + body; not a card grid. |
| **Notice** | info, ok, warn, bad, neutral | dismissible | Icon + one bold sentence + detail + up to 2 actions. `role="alert"` only for bad/integrity. |
| **ConfirmDialog** | neutral, danger, hold-to-confirm | open, closing | Radix Dialog. Title is a question with the object ("Delete Shop staging admin?"). Body says the effect and if it can be undone. Focus starts on Cancel for danger dialogs. Esc = cancel. |
| **TokenRevealDialog** | agent token, rotated token, recovery key | stored-ack unchecked (Done disabled), checked | Shows once; clears state on close; copy + save to file; no close by backdrop click. |
| **EmptyState** | with gate mark, with icon, with numbered first steps | — | Title says the situation, body says why it is fine or what to do, one primary action. |
| **ErrorState** | load error, action error, conflict | retry loading | Title "Cannot …", body says what is safe, action "Try again", mono code line `command: code (request id)`. |
| **LockedState** | shared | — | Closed GateMark 72 px, lock reason and time, "Agents get HTTP 423 until you unlock", Unlock button. Rail becomes inert. |
| **Skeleton** | row, box, line, block | — | Shimmer off with reduced motion. Container has `role="status" aria-busy="true"` and a label. |
| **ApprovalCard** | single, burst group, decided, viewer (read only) | expiring (ring low/critical) | See section 3. |
| **UntrustedText** | — | long (scrolls at 120 px) | Dashed brass border, mono, fixed label "Reason given by the agent, not verified". Rendered as plain text only (`textContent`), control chars already removed by the backend, max 500 chars. |
| **GrantBuilder** | new, edit | prod rule notice, owner-only switch disabled | Sentence with inline selects + mode radio (never / once / always / block it). Help line under it changes with the mode. |
| **GrantSentence** | per mode pill: never asks (green), asks once (brass), asks always (amber), blocked (red), no grant (muted) | — | Read form of a grant for lists and the agent page. |
| **SimulatorTable** | — | stale (after edit, before re-run) | Item, env, result pill. |
| **AuditTimeline** | default, filtered, suspect rows (after a chain break) | load more | Rows: time, actor node (agent blue, operator brass, system muted, failure red), sentence, mono event line, seq. |
| **ChainBadge** | ok, broken, checking | — | Seal icon + count + range + checked time; broken names the seq and break kind. |
| **CommandPalette** | — | no results | Radix Dialog + listbox. Groups, `aria-activedescendant`, footer with keys. |
| **SegmentedControl** | sm, lg | — | `aria-pressed` buttons, or radio semantics when single choice. |
| **Switch** | — | checked, disabled (owner only) | Real `input[type=checkbox]`; label is the setting name. |
| **StrengthMeter** | score 0–4 | — | 5 bars + text line; text is the real signal. |
| **RecoveryKeyGrid** | — | print | 15 numbered mono groups (`CRK1` + 14); print stylesheet prints only this. |
| **DropZone** | idle, over, imported, rejected | — | Dashed box with a real "Choose file" button inside (keyboard path). |
| **Toast** | success, info, with TTL ring (clipboard) | — | `role="status"`, bottom right, 5 s (or the ring time, max 8 s). Never holds a secret. |
| **Rail / Collar** | — | locked (inert) | Who unlocked, auto-lock ring + time, Lock, panic icon button with text label for AT. |

## 3. ApprovalCard anatomy (screen 8)

1. GateTrace: Agent token ✓, Grant ✓, You (waiting).
2. Title: "{agent} wants to {permission} a {env} {kind}".
3. Identity line from the token: name, agent ID, key hint, with "Not from the request text".
4. Item box: title, env badge (prod = red edge), kind in workspace and role, permission and requested TTL.
5. UntrustedText with the reason.
6. Expiry: TtlRing + "Request ends in 1:34. No answer means deny."
7. Choices, none preselected: Approve once `A`, For 15 minutes `F`, For this session `S`, Deny `D` (full width, danger-ghost).
8. Key note: "Keys need a 0.6 s hold. Nothing is chosen for you."

Focus order: title → identity → item → reason (scrollable region) → choices in reading order. The window does not
steal focus from a password field in another app on open (T15 checks OS behaviour); it flashes the tray badge.

## 4. Motion rules

| Use | Duration | Easing | Reduced motion |
|---|---|---|---|
| Hover, press, color change | `fast` 120 ms | standard | 0 ms |
| Dialog, toast, palette enter | `base` 180 ms, 6 px rise + scale 0.985 | enter | opacity only, 80 ms |
| Drawer, panel expand | `slow` 260 ms | standard | opacity only, 80 ms |
| Gate opening on unlock | `gate` 640 ms, rings stagger 60 ms | standard | instant swap to the open mark |
| Loading rings turn | 1.2 / 1.8 / 2.4 s loops | linear | static rings + "Loading" text |
| TTL rings | step each second | linear | same (it is information, not decoration) |
| Hold fill | 500 / 600 / 1000 ms | linear | fill shows at once; the hold time stays |
| Skeleton shimmer | 1.6 s | linear | off |

Rules: no entrance animation on page load except the gate; no parallax; nothing moves on its own except timers,
loading rings and the live feed (new rows appear without sliding). Motion never carries meaning alone.

## 5. Accessibility (WCAG 2.2 AA)

- **Contrast**: every text and UI token pair is checked by `check-contrast.mjs` (154 pairs, all pass;
  `a11y-contrast-report.md`). Disabled controls use 50% opacity and are exempt, but they keep a text reason
  ("Owner only").
- **Focus**: 2 px `focus.ring` outline with 2 px offset on every interactive element (`:focus-visible`), 3:1 or more
  against all backgrounds. Focus is never hidden under the sticky top bar (`scroll-padding-top`) (SC 2.4.11).
- **Focus order**: skip link → rail → top bar (page actions, palette) → main content in reading order. Dialogs trap
  focus and return it to the opener. On route change focus moves to `main` (h1 label).
- **Targets**: controls at least 24 × 24 px (SC 2.5.8); small icon buttons are 28 px.
- **Names**: icon-only buttons have `aria-label` with the object ("Copy: Password"). Visible text is part of the
  accessible name (SC 2.5.3).
- **Hold actions**: every hold also works by a single click for pointer users, except panic and reveal, where the
  hold is the safety. Keyboard users get the same hold with Space/Enter. This meets SC 2.5.1 (no path-based gesture)
  and SC 2.5.7 (no drag needed; DropZone has a button).
- **Timing**: auto-hide (15 s), clipboard clear (30 s) and approval timeout are security limits (SC 2.2.1 exception:
  real-time / security). Each shows a visible countdown. The approval timeout is a setting (30–600 s).
- **Live regions**: toasts `status`; approval card and agent feed `polite`; integrity alerts `alert`. Timers do not
  announce every second (`aria-live="off"` on the countdown, label on demand).
- **Color independence**: prod badge has a shape mark; status dots have words; TTL rings have text next to them.
- **Language**: `html lang` follows the UI language; wire values stay English and are marked as code.
- **Reduced motion and forced colors**: see section 4; forced-colors mode adds borders to chips, badges, secrets
  and the untrusted box.
- **Screen readers and secrets**: revealed values are read once by the polite live region; masked state reads
  "Hidden". No secret goes into a notification or the window title.

## 6. Security rules that shape components

| Threat (threat-model.md) | Component rule |
|---|---|
| S-5 reason pretends to be the system | UntrustedText only; identity line from the token comes first; no preselected choice; 600 ms key hold; burst grouping |
| S-6 script injection | Reason and all agent text rendered with `textContent` / React text, never HTML |
| I-9 clipboard history | Copy only on click; 30 s clear; one-time warning toast |
| I-10 shoulder surfing, screen capture | Masked default, hold to reveal, 15 s auto-hide, content protection switch on secret screens |
| I-16 secrets in webview memory | SecretField and TokenRevealDialog keep values in local state only; cleared on hide, close, unmount and lock |
| I-19 titles in tray or events | Tray badge is a count; toasts name the item only after a person action in `main` |
| T-9 vault poisoning | AgentMadeBadge on agent-created items in lists, drawer and candidates |
