# Cerberus accessibility and contrast report (T14)

Date: 2026-11-16. Scope: the design tokens in `tokens.json` and the prototypes in `prototypes/`.

## 1. How to run the checks

```sh
# Contrast of every token pair; exit code 1 on any failure
node docs/ux/check-contrast.mjs          # plain list
node docs/ux/check-contrast.mjs --md     # the table in section 3

# Browser checks: screenshots, axe-core, Spanish coverage, no network, narrow width.
# Needs the npm packages playwright (1.65.1) and axe-core (4.14.0) in any folder:
NODE_PATH=/path/to/node_modules node docs/ux/verify-prototypes.mjs
# --only=NN, --shots, --axe, --i18n run a part. A partial run overwrites verify-report.json, so run the full set last.
```

`verify-prototypes.mjs` serves `prototypes/` on `127.0.0.1` (random port), opens every screen in Chromium with
reduced motion on, and reports any request to another origin as external. Results go to
`screenshots/verify-report.json`.

## 2. Rules

- Text pairs need **4.5:1** (WCAG 2.2 SC 1.4.3). App text is body size or smaller, so the 3:1 large-text rule is
  not used.
- UI pairs (input borders, focus ring, TTL rings on their track, untrusted-text border, solid buttons on the
  canvas) need **3:1** (SC 1.4.11).
- `border.subtle` is decorative (dividers). No control depends on it alone, so it is not checked.
- Disabled controls (50% opacity) are exempt; each has a text reason next to it ("Owner only").
- Color is never the only signal: the `prod` badge has a triangle, status dots have words, TTL rings have text.

## 3. Token pairs (output of `check-contrast.mjs --md`)

| Theme | Kind | Foreground | Background | Ratio | Needs | Result |
|---|---|---|---|---|---|---|
| dark | text | `text.primary` #E9EDF1 | `bg.canvas` #131920 | 15.03:1 | 4.5:1 | pass |
| dark | text | `text.primary` #E9EDF1 | `bg.surface` #19212A | 13.81:1 | 4.5:1 | pass |
| dark | text | `text.primary` #E9EDF1 | `bg.raised` #202A35 | 12.36:1 | 4.5:1 | pass |
| dark | text | `text.primary` #E9EDF1 | `bg.sunken` #0E1318 | 15.87:1 | 4.5:1 | pass |
| dark | text | `text.primary` #E9EDF1 | `bg.hover` #263240 | 11.07:1 | 4.5:1 | pass |
| dark | text | `text.primary` #E9EDF1 | `bg.selected` #2C3B4B | 9.73:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B6C1CC | `bg.canvas` #131920 | 9.67:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B6C1CC | `bg.surface` #19212A | 8.89:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B6C1CC | `bg.raised` #202A35 | 7.96:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B6C1CC | `bg.hover` #263240 | 7.12:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B6C1CC | `bg.selected` #2C3B4B | 6.26:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97A4B1 | `bg.canvas` #131920 | 6.96:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97A4B1 | `bg.surface` #19212A | 6.39:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97A4B1 | `bg.raised` #202A35 | 5.72:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97A4B1 | `bg.sunken` #0E1318 | 7.34:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97A4B1 | `bg.hover` #263240 | 5.12:1 | 4.5:1 | pass |
| dark | text | `text.inverse` #131920 | `text.primary` #E9EDF1 | 15.03:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #E6B866 | `bg.canvas` #131920 | 9.61:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #E6B866 | `bg.surface` #19212A | 8.83:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #E6B866 | `bg.raised` #202A35 | 7.90:1 | 4.5:1 | pass |
| dark | text | `accent.on-solid` #21170A | `accent.solid` #E0AE55 | 8.69:1 | 4.5:1 | pass |
| dark | text | `accent.on-tint` #F2CE8C | `accent.tint` #33291A | 9.49:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF8C82 | `bg.canvas` #131920 | 7.85:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF8C82 | `bg.surface` #19212A | 7.22:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF8C82 | `bg.raised` #202A35 | 6.46:1 | 4.5:1 | pass |
| dark | text | `danger.on-solid` #FFFFFF | `danger.solid` #C3392F | 5.32:1 | 4.5:1 | pass |
| dark | text | `danger.on-tint` #FFB4AC | `danger.tint` #3B1F22 | 8.81:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F5A65F | `bg.canvas` #131920 | 8.84:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F5A65F | `bg.surface` #19212A | 8.13:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F5A65F | `bg.raised` #202A35 | 7.27:1 | 4.5:1 | pass |
| dark | text | `warning.on-solid` #24160A | `warning.solid` #F5A65F | 8.79:1 | 4.5:1 | pass |
| dark | text | `warning.on-tint` #FFCB98 | `warning.tint` #382A1B | 9.40:1 | 4.5:1 | pass |
| dark | text | `success.fg` #71D4A2 | `bg.canvas` #131920 | 9.80:1 | 4.5:1 | pass |
| dark | text | `success.fg` #71D4A2 | `bg.surface` #19212A | 9.01:1 | 4.5:1 | pass |
| dark | text | `success.fg` #71D4A2 | `bg.raised` #202A35 | 8.06:1 | 4.5:1 | pass |
| dark | text | `success.on-solid` #0A1D13 | `success.solid` #45B37D | 6.68:1 | 4.5:1 | pass |
| dark | text | `success.on-tint` #A0E6C2 | `success.tint` #17302A | 9.78:1 | 4.5:1 | pass |
| dark | text | `info.fg` #90BDF6 | `bg.canvas` #131920 | 9.09:1 | 4.5:1 | pass |
| dark | text | `info.fg` #90BDF6 | `bg.surface` #19212A | 8.35:1 | 4.5:1 | pass |
| dark | text | `info.fg` #90BDF6 | `bg.raised` #202A35 | 7.48:1 | 4.5:1 | pass |
| dark | text | `info.on-solid` #0E1A2B | `info.solid` #90BDF6 | 8.99:1 | 4.5:1 | pass |
| dark | text | `info.on-tint` #BBD6FA | `info.tint` #1B2A3D | 9.76:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #E6B866 | `bg.selected` #2C3B4B | 6.22:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF8C82 | `bg.selected` #2C3B4B | 5.08:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F5A65F | `bg.selected` #2C3B4B | 5.73:1 | 4.5:1 | pass |
| dark | text | `success.fg` #71D4A2 | `bg.selected` #2C3B4B | 6.35:1 | 4.5:1 | pass |
| dark | text | `info.fg` #90BDF6 | `bg.selected` #2C3B4B | 5.89:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97A4B1 | `bg.selected` #2C3B4B | 4.50:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #E6B866 | `bg.hover` #263240 | 7.08:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF8C82 | `bg.hover` #263240 | 5.78:1 | 4.5:1 | pass |
| dark | text | `success.fg` #71D4A2 | `bg.hover` #263240 | 7.22:1 | 4.5:1 | pass |
| dark | text | `info.fg` #90BDF6 | `bg.hover` #263240 | 6.69:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B6C1CC | `bg.sunken` #0E1318 | 10.21:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #E6B866 | `bg.sunken` #0E1318 | 10.14:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97A4B1 | `accent.tint` #33291A | 5.61:1 | 4.5:1 | pass |
| dark | text | `untrusted.fg` #E9EDF1 | `untrusted.bg` #1C1F25 | 14.03:1 | 4.5:1 | pass |
| dark | text | `env.prod.fg` #FFB4AC | `env.prod.bg` #3B1F22 | 8.81:1 | 4.5:1 | pass |
| dark | text | `env.staging.fg` #FFCB98 | `env.staging.bg` #382A1B | 9.40:1 | 4.5:1 | pass |
| dark | text | `env.dev.fg` #BBD6FA | `env.dev.bg` #1B2A3D | 9.76:1 | 4.5:1 | pass |
| dark | text | `env.other.fg` #C9D2DB | `env.other.bg` #263240 | 8.51:1 | 4.5:1 | pass |
| dark | ui | `border.default` #64758A | `bg.canvas` #131920 | 3.75:1 | 3:1 | pass |
| dark | ui | `border.default` #64758A | `bg.surface` #19212A | 3.45:1 | 3:1 | pass |
| dark | ui | `border.default` #64758A | `bg.raised` #202A35 | 3.08:1 | 3:1 | pass |
| dark | ui | `border.strong` #8696A8 | `bg.surface` #19212A | 5.37:1 | 3:1 | pass |
| dark | ui | `focus.ring` #9CC8FF | `bg.canvas` #131920 | 10.20:1 | 3:1 | pass |
| dark | ui | `focus.ring` #9CC8FF | `bg.surface` #19212A | 9.38:1 | 3:1 | pass |
| dark | ui | `focus.ring` #9CC8FF | `bg.raised` #202A35 | 8.39:1 | 3:1 | pass |
| dark | ui | `ring.gate` #E0AE55 | `bg.canvas` #131920 | 8.72:1 | 3:1 | pass |
| dark | ui | `ring.gate` #E0AE55 | `bg.surface` #19212A | 8.01:1 | 3:1 | pass |
| dark | ui | `ring.gate` #E0AE55 | `ring.track` #3A4756 | 4.67:1 | 3:1 | pass |
| dark | ui | `accent.solid` #E0AE55 | `bg.canvas` #131920 | 8.72:1 | 3:1 | pass |
| dark | ui | `danger.solid` #C3392F | `bg.surface` #19212A | 3.05:1 | 3:1 | pass |
| dark | ui | `untrusted.border` #B08F55 | `untrusted.bg` #1C1F25 | 5.43:1 | 3:1 | pass |
| dark | ui | `untrusted.border` #B08F55 | `bg.raised` #202A35 | 4.78:1 | 3:1 | pass |
| dark | ui | `warning.fg` #F5A65F | `ring.track` #3A4756 | 4.74:1 | 3:1 | pass |
| dark | ui | `danger.fg` #FF8C82 | `ring.track` #3A4756 | 4.21:1 | 3:1 | pass |
| dark | ui | `info.fg` #90BDF6 | `ring.track` #3A4756 | 4.87:1 | 3:1 | pass |
| light | text | `text.primary` #141B23 | `bg.canvas` #EEF1F4 | 15.30:1 | 4.5:1 | pass |
| light | text | `text.primary` #141B23 | `bg.surface` #FFFFFF | 17.34:1 | 4.5:1 | pass |
| light | text | `text.primary` #141B23 | `bg.raised` #FFFFFF | 17.34:1 | 4.5:1 | pass |
| light | text | `text.primary` #141B23 | `bg.sunken` #E3E8ED | 14.07:1 | 4.5:1 | pass |
| light | text | `text.primary` #141B23 | `bg.hover` #E7ECF1 | 14.59:1 | 4.5:1 | pass |
| light | text | `text.primary` #141B23 | `bg.selected` #DAE4EE | 13.47:1 | 4.5:1 | pass |
| light | text | `text.secondary` #3D4A57 | `bg.canvas` #EEF1F4 | 8.00:1 | 4.5:1 | pass |
| light | text | `text.secondary` #3D4A57 | `bg.surface` #FFFFFF | 9.07:1 | 4.5:1 | pass |
| light | text | `text.secondary` #3D4A57 | `bg.raised` #FFFFFF | 9.07:1 | 4.5:1 | pass |
| light | text | `text.secondary` #3D4A57 | `bg.hover` #E7ECF1 | 7.63:1 | 4.5:1 | pass |
| light | text | `text.secondary` #3D4A57 | `bg.selected` #DAE4EE | 7.04:1 | 4.5:1 | pass |
| light | text | `text.muted` #56636F | `bg.canvas` #EEF1F4 | 5.43:1 | 4.5:1 | pass |
| light | text | `text.muted` #56636F | `bg.surface` #FFFFFF | 6.16:1 | 4.5:1 | pass |
| light | text | `text.muted` #56636F | `bg.raised` #FFFFFF | 6.16:1 | 4.5:1 | pass |
| light | text | `text.muted` #56636F | `bg.sunken` #E3E8ED | 4.99:1 | 4.5:1 | pass |
| light | text | `text.muted` #56636F | `bg.hover` #E7ECF1 | 5.18:1 | 4.5:1 | pass |
| light | text | `text.inverse` #FFFFFF | `text.primary` #141B23 | 17.34:1 | 4.5:1 | pass |
| light | text | `accent.fg` #875800 | `bg.canvas` #EEF1F4 | 5.41:1 | 4.5:1 | pass |
| light | text | `accent.fg` #875800 | `bg.surface` #FFFFFF | 6.13:1 | 4.5:1 | pass |
| light | text | `accent.fg` #875800 | `bg.raised` #FFFFFF | 6.13:1 | 4.5:1 | pass |
| light | text | `accent.on-solid` #FFFFFF | `accent.solid` #93610A | 5.31:1 | 4.5:1 | pass |
| light | text | `accent.on-tint` #6A4400 | `accent.tint` #F6EBD5 | 7.28:1 | 4.5:1 | pass |
| light | text | `danger.fg` #B3261E | `bg.canvas` #EEF1F4 | 5.77:1 | 4.5:1 | pass |
| light | text | `danger.fg` #B3261E | `bg.surface` #FFFFFF | 6.54:1 | 4.5:1 | pass |
| light | text | `danger.fg` #B3261E | `bg.raised` #FFFFFF | 6.54:1 | 4.5:1 | pass |
| light | text | `danger.on-solid` #FFFFFF | `danger.solid` #B3261E | 6.54:1 | 4.5:1 | pass |
| light | text | `danger.on-tint` #8C1D17 | `danger.tint` #FBE4E1 | 7.51:1 | 4.5:1 | pass |
| light | text | `warning.fg` #954C00 | `bg.canvas` #EEF1F4 | 5.59:1 | 4.5:1 | pass |
| light | text | `warning.fg` #954C00 | `bg.surface` #FFFFFF | 6.34:1 | 4.5:1 | pass |
| light | text | `warning.fg` #954C00 | `bg.raised` #FFFFFF | 6.34:1 | 4.5:1 | pass |
| light | text | `warning.on-solid` #2A1600 | `warning.solid` #EFA25A | 8.23:1 | 4.5:1 | pass |
| light | text | `warning.on-tint` #773D00 | `warning.tint` #FCEBDA | 7.36:1 | 4.5:1 | pass |
| light | text | `success.fg` #17683F | `bg.canvas` #EEF1F4 | 6.00:1 | 4.5:1 | pass |
| light | text | `success.fg` #17683F | `bg.surface` #FFFFFF | 6.80:1 | 4.5:1 | pass |
| light | text | `success.fg` #17683F | `bg.raised` #FFFFFF | 6.80:1 | 4.5:1 | pass |
| light | text | `success.on-solid` #FFFFFF | `success.solid` #1C7547 | 5.70:1 | 4.5:1 | pass |
| light | text | `success.on-tint` #155A37 | `success.tint` #DDF3E7 | 7.08:1 | 4.5:1 | pass |
| light | text | `info.fg` #1F5DAA | `bg.canvas` #EEF1F4 | 5.78:1 | 4.5:1 | pass |
| light | text | `info.fg` #1F5DAA | `bg.surface` #FFFFFF | 6.55:1 | 4.5:1 | pass |
| light | text | `info.fg` #1F5DAA | `bg.raised` #FFFFFF | 6.55:1 | 4.5:1 | pass |
| light | text | `info.on-solid` #FFFFFF | `info.solid` #1F5DAA | 6.55:1 | 4.5:1 | pass |
| light | text | `info.on-tint` #184A87 | `info.tint` #E0ECFA | 7.41:1 | 4.5:1 | pass |
| light | text | `accent.fg` #875800 | `bg.selected` #DAE4EE | 4.76:1 | 4.5:1 | pass |
| light | text | `danger.fg` #B3261E | `bg.selected` #DAE4EE | 5.08:1 | 4.5:1 | pass |
| light | text | `warning.fg` #954C00 | `bg.selected` #DAE4EE | 4.93:1 | 4.5:1 | pass |
| light | text | `success.fg` #17683F | `bg.selected` #DAE4EE | 5.28:1 | 4.5:1 | pass |
| light | text | `info.fg` #1F5DAA | `bg.selected` #DAE4EE | 5.09:1 | 4.5:1 | pass |
| light | text | `text.muted` #56636F | `bg.selected` #DAE4EE | 4.78:1 | 4.5:1 | pass |
| light | text | `accent.fg` #875800 | `bg.hover` #E7ECF1 | 5.16:1 | 4.5:1 | pass |
| light | text | `danger.fg` #B3261E | `bg.hover` #E7ECF1 | 5.50:1 | 4.5:1 | pass |
| light | text | `success.fg` #17683F | `bg.hover` #E7ECF1 | 5.72:1 | 4.5:1 | pass |
| light | text | `info.fg` #1F5DAA | `bg.hover` #E7ECF1 | 5.51:1 | 4.5:1 | pass |
| light | text | `text.secondary` #3D4A57 | `bg.sunken` #E3E8ED | 7.36:1 | 4.5:1 | pass |
| light | text | `accent.fg` #875800 | `bg.sunken` #E3E8ED | 4.97:1 | 4.5:1 | pass |
| light | text | `text.muted` #56636F | `accent.tint` #F6EBD5 | 5.21:1 | 4.5:1 | pass |
| light | text | `untrusted.fg` #141B23 | `untrusted.bg` #F7F5F0 | 15.92:1 | 4.5:1 | pass |
| light | text | `env.prod.fg` #8C1D17 | `env.prod.bg` #FBE4E1 | 7.51:1 | 4.5:1 | pass |
| light | text | `env.staging.fg` #773D00 | `env.staging.bg` #FCEBDA | 7.36:1 | 4.5:1 | pass |
| light | text | `env.dev.fg` #184A87 | `env.dev.bg` #E0ECFA | 7.41:1 | 4.5:1 | pass |
| light | text | `env.other.fg` #3D4A57 | `env.other.bg` #E7ECF1 | 7.63:1 | 4.5:1 | pass |
| light | ui | `border.default` #738190 | `bg.canvas` #EEF1F4 | 3.51:1 | 3:1 | pass |
| light | ui | `border.default` #738190 | `bg.surface` #FFFFFF | 3.98:1 | 3:1 | pass |
| light | ui | `border.default` #738190 | `bg.raised` #FFFFFF | 3.98:1 | 3:1 | pass |
| light | ui | `border.strong` #55626E | `bg.surface` #FFFFFF | 6.25:1 | 3:1 | pass |
| light | ui | `focus.ring` #1F5DAA | `bg.canvas` #EEF1F4 | 5.78:1 | 3:1 | pass |
| light | ui | `focus.ring` #1F5DAA | `bg.surface` #FFFFFF | 6.55:1 | 3:1 | pass |
| light | ui | `focus.ring` #1F5DAA | `bg.raised` #FFFFFF | 6.55:1 | 3:1 | pass |
| light | ui | `ring.gate` #A06A0C | `bg.canvas` #EEF1F4 | 4.06:1 | 3:1 | pass |
| light | ui | `ring.gate` #A06A0C | `bg.surface` #FFFFFF | 4.60:1 | 3:1 | pass |
| light | ui | `ring.gate` #A06A0C | `ring.track` #CCD5DE | 3.10:1 | 3:1 | pass |
| light | ui | `accent.solid` #93610A | `bg.canvas` #EEF1F4 | 4.68:1 | 3:1 | pass |
| light | ui | `danger.solid` #B3261E | `bg.surface` #FFFFFF | 6.54:1 | 3:1 | pass |
| light | ui | `untrusted.border` #8A6A2E | `untrusted.bg` #F7F5F0 | 4.61:1 | 3:1 | pass |
| light | ui | `untrusted.border` #8A6A2E | `bg.raised` #FFFFFF | 5.02:1 | 3:1 | pass |
| light | ui | `warning.fg` #954C00 | `ring.track` #CCD5DE | 4.27:1 | 3:1 | pass |
| light | ui | `danger.fg` #B3261E | `ring.track` #CCD5DE | 4.40:1 | 3:1 | pass |
| light | ui | `info.fg` #1F5DAA | `ring.track` #CCD5DE | 4.41:1 | 3:1 | pass |

154 pairs, 0 failures. Lowest text ratio 4.50:1, lowest UI ratio 3.05:1.

## 4. Browser checks (output of `verify-prototypes.mjs`, full run on 2026-11-17)

Tools: Playwright 1.65.1 (Chromium), axe-core 4.14.0, tags `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`
and `best-practice`. Raw results: `screenshots/verify-report.json`. The axe run was also checked against a known bad
page (an image with no `alt` and grey text on grey): axe reported `image-alt` (critical) and `color-contrast`
(serious), so a zero result is real.

What one full run covers, per screen 01–11:

- 5 states (ready, empty, loading, error, locked) × 2 themes (dark, light): screenshot and axe run.
- Every variant (`data-variants`) in both themes: axe run; screenshot in dark.
- Every `<dialog>`, opened with `showModal()`, in both themes: axe run on the dialog; screenshot in dark.
- Width 390 px: every state checked for sideways scroll; screenshot of ready in dark and light.
- Spanish: every state and every variant checked for text with no translation; screenshot of ready in dark.

The index page gets the same checks for its one state.

| Screen | Critical | Serious | Moderate | Minor |
|---|---|---|---|---|
| index | 0 | 0 | 0 | 0 |
| 01 Create vault | 0 | 0 | 0 | 0 |
| 02 Unlock | 0 | 0 | 0 | 0 |
| 03 Dashboard | 0 | 0 | 0 | 0 |
| 04 Vault browser | 0 | 0 | 0 | 0 |
| 05 Item editor | 0 | 0 | 0 | 0 |
| 06 Agents | 0 | 0 | 0 | 0 |
| 07 Policies | 0 | 0 | 0 | 0 |
| 08 Approval prompt | 0 | 0 | 0 | 0 |
| 09 Leases and sessions | 0 | 0 | 0 | 0 |
| 10 Audit | 0 | 0 | 0 | 0 |
| 11 Settings | 0 | 0 | 0 | 0 |

Totals: 224 axe runs (112 state pages, 50 variant pages, 62 dialogs), 0 violations. 204 screenshots in
`screenshots/` (112 states, 25 variants, 31 dialogs, 24 narrow, 12 Spanish). Spanish strings with no translation: 0.
Requests to another origin: 0. Console errors: 0. Sideways scroll at 390 px: none (56 pages checked: 11 screens × 5 states, and the index).

Fixes made in the last pass:

- At 390 px every app screen scrolled sideways by about 440 px. The one-column shell grid used `1fr`, which grows
  to the width of the nav strip. Now `minmax(0, 1fr)`. The dashboard gate band stacks in one column, the
  approval window fits the width, and wide tables keep their hidden labels inside the scroll box.
- Spanish: "0 of 1" lease uses had no translation, and one editor hint used the "vosotros" form against the
  neutral Spanish rule (DEC-040). Both fixed.

Keyboard checks (scripted in the same run, `keyboard` in the report): 11 of 11 pass. Ctrl+K opens the palette
with focus in its field, Esc closes it, `?` opens the shortcut list, G then V goes to the vault, Tab focus shows a
2 px ring, Ctrl+L locks, a short Space press on the eye button does not reveal and a 500 ms hold does, a tap on A
in the approval window does not approve and a 600 ms hold does, D denies at once.

Limits of these checks: axe cannot judge focus order, the meaning of labels, or screen reader speech, and no screen
reader was used. All checks ran in Chromium only. T16 must repeat them in the real app (WebKitGTK on Linux,
WebView2 on Windows, WKWebView on macOS) and test with Orca, NVDA and VoiceOver.
