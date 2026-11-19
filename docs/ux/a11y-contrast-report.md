# Cerberus accessibility and contrast report (T14)

Date: 2026-11-19 (Geist monochrome re-skin; section 4 predates it and covers the prototypes). Scope: the design tokens in `tokens.json` and the prototypes in `prototypes/`.

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
| dark | text | `text.primary` #EDEDED | `bg.canvas` #0A0A0A | 16.91:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEDED | `bg.surface` #0A0A0A | 16.91:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEDED | `bg.raised` #1A1A1A | 14.87:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEDED | `bg.sunken` #000000 | 17.94:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEDED | `bg.hover` #181818 | 15.17:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEDED | `bg.selected` #202020 | 13.92:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEDED | `bg.strong` #1F1F1F | 14.08:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #A1A1A1 | `bg.canvas` #0A0A0A | 7.66:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #A1A1A1 | `bg.surface` #0A0A0A | 7.66:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #A1A1A1 | `bg.raised` #1A1A1A | 6.74:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #A1A1A1 | `bg.sunken` #000000 | 8.13:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #A1A1A1 | `bg.hover` #181818 | 6.87:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #A1A1A1 | `bg.selected` #202020 | 6.31:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #A1A1A1 | `bg.strong` #1F1F1F | 6.38:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `bg.canvas` #0A0A0A | 6.12:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `bg.surface` #0A0A0A | 6.12:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `bg.raised` #1A1A1A | 5.38:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `bg.sunken` #000000 | 6.49:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `bg.hover` #181818 | 5.49:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `bg.selected` #202020 | 5.04:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `bg.strong` #1F1F1F | 5.10:1 | 4.5:1 | pass |
| dark | text | `text.inverse` #0A0A0A | `text.primary` #EDEDED | 16.91:1 | 4.5:1 | pass |
| dark | text | `link.fg` #52A8FF | `bg.canvas` #0A0A0A | 7.92:1 | 4.5:1 | pass |
| dark | text | `link.fg` #52A8FF | `bg.surface` #0A0A0A | 7.92:1 | 4.5:1 | pass |
| dark | text | `link.fg` #52A8FF | `bg.raised` #1A1A1A | 6.96:1 | 4.5:1 | pass |
| dark | text | `link.fg` #52A8FF | `bg.sunken` #000000 | 8.40:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #EDEDED | `bg.canvas` #0A0A0A | 16.91:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #EDEDED | `bg.surface` #0A0A0A | 16.91:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #EDEDED | `bg.raised` #1A1A1A | 14.87:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #EDEDED | `bg.sunken` #000000 | 17.94:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #EDEDED | `bg.selected` #202020 | 13.92:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #EDEDED | `bg.hover` #181818 | 15.17:1 | 4.5:1 | pass |
| dark | text | `accent.on-solid` #0A0A0A | `accent.solid` #EDEDED | 16.91:1 | 4.5:1 | pass |
| dark | text | `accent.on-solid` #0A0A0A | `accent.hi` #CCCCCC | 12.33:1 | 4.5:1 | pass |
| dark | text | `accent.on-solid` #0A0A0A | `accent.lo` #EDEDED | 16.91:1 | 4.5:1 | pass |
| dark | text | `accent.on-tint` #EDEDED | `accent.tint` #1F1F1F | 14.08:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `accent.tint` #1F1F1F | 5.10:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF6166 | `bg.canvas` #0A0A0A | 6.74:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF6166 | `bg.surface` #0A0A0A | 6.74:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF6166 | `bg.raised` #1A1A1A | 5.93:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF6166 | `bg.sunken` #000000 | 7.15:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF6166 | `bg.hover` #181818 | 6.05:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #FF6166 | `bg.selected` #202020 | 5.55:1 | 4.5:1 | pass |
| dark | text | `danger.on-solid` #FFFFFF | `danger.solid` #CB2A2F | 5.37:1 | 4.5:1 | pass |
| dark | text | `danger.on-tint` #FF6166 | `danger.tint` #291313 | 5.98:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F2A20D | `bg.canvas` #0A0A0A | 9.38:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F2A20D | `bg.surface` #0A0A0A | 9.38:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F2A20D | `bg.raised` #1A1A1A | 8.25:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F2A20D | `bg.selected` #202020 | 7.72:1 | 4.5:1 | pass |
| dark | text | `warning.on-solid` #0A0A0A | `warning.solid` #FFB224 | 10.98:1 | 4.5:1 | pass |
| dark | text | `warning.on-tint` #F2A20D | `warning.tint` #2C220E | 7.41:1 | 4.5:1 | pass |
| dark | text | `success.fg` #62C073 | `bg.canvas` #0A0A0A | 8.77:1 | 4.5:1 | pass |
| dark | text | `success.fg` #62C073 | `bg.surface` #0A0A0A | 8.77:1 | 4.5:1 | pass |
| dark | text | `success.fg` #62C073 | `bg.raised` #1A1A1A | 7.71:1 | 4.5:1 | pass |
| dark | text | `success.fg` #62C073 | `bg.selected` #202020 | 7.22:1 | 4.5:1 | pass |
| dark | text | `success.fg` #62C073 | `bg.hover` #181818 | 7.87:1 | 4.5:1 | pass |
| dark | text | `success.on-solid` #0A0A0A | `success.solid` #45A557 | 6.39:1 | 4.5:1 | pass |
| dark | text | `success.on-tint` #62C073 | `success.tint` #122015 | 7.49:1 | 4.5:1 | pass |
| dark | text | `info.fg` #52A8FF | `bg.canvas` #0A0A0A | 7.92:1 | 4.5:1 | pass |
| dark | text | `info.fg` #52A8FF | `bg.surface` #0A0A0A | 7.92:1 | 4.5:1 | pass |
| dark | text | `info.fg` #52A8FF | `bg.raised` #1A1A1A | 6.96:1 | 4.5:1 | pass |
| dark | text | `info.fg` #52A8FF | `bg.selected` #202020 | 6.52:1 | 4.5:1 | pass |
| dark | text | `info.fg` #52A8FF | `bg.hover` #181818 | 7.11:1 | 4.5:1 | pass |
| dark | text | `info.on-solid` #FFFFFF | `info.solid` #0068D6 | 5.31:1 | 4.5:1 | pass |
| dark | text | `info.on-tint` #52A8FF | `info.tint` #09192B | 7.09:1 | 4.5:1 | pass |
| dark | text | `untrusted.fg` #EDEDED | `untrusted.bg` #000000 | 17.94:1 | 4.5:1 | pass |
| dark | text | `text.muted` #8F8F8F | `untrusted.bg` #000000 | 6.49:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #F2A20D | `untrusted.bg` #000000 | 9.95:1 | 4.5:1 | pass |
| dark | text | `env.prod.fg` #FF6166 | `env.prod.bg` #291313 | 5.98:1 | 4.5:1 | pass |
| dark | text | `env.staging.fg` #F2A20D | `env.staging.bg` #2C220E | 7.41:1 | 4.5:1 | pass |
| dark | text | `env.dev.fg` #52A8FF | `env.dev.bg` #09192B | 7.09:1 | 4.5:1 | pass |
| dark | text | `env.other.fg` #A1A1A1 | `env.other.bg` #1F1F1F | 6.38:1 | 4.5:1 | pass |
| dark | ui | `border.default` #666666 | `bg.canvas` #0A0A0A | 3.45:1 | 3:1 | pass |
| dark | ui | `border.default` #666666 | `bg.surface` #0A0A0A | 3.45:1 | 3:1 | pass |
| dark | ui | `border.default` #666666 | `bg.raised` #1A1A1A | 3.03:1 | 3:1 | pass |
| dark | ui | `border.strong` #8F8F8F | `bg.surface` #0A0A0A | 6.12:1 | 3:1 | pass |
| dark | ui | `focus.ring` #0072F5 | `bg.canvas` #0A0A0A | 4.45:1 | 3:1 | pass |
| dark | ui | `focus.ring` #0072F5 | `bg.surface` #0A0A0A | 4.45:1 | 3:1 | pass |
| dark | ui | `focus.ring` #0072F5 | `bg.raised` #1A1A1A | 3.92:1 | 3:1 | pass |
| dark | ui | `ring.gate` #EDEDED | `bg.canvas` #0A0A0A | 16.91:1 | 3:1 | pass |
| dark | ui | `ring.gate` #EDEDED | `bg.surface` #0A0A0A | 16.91:1 | 3:1 | pass |
| dark | ui | `ring.gate` #EDEDED | `ring.track` #2E2E2E | 11.60:1 | 3:1 | pass |
| dark | ui | `accent.solid` #EDEDED | `bg.canvas` #0A0A0A | 16.91:1 | 3:1 | pass |
| dark | ui | `danger.solid` #CB2A2F | `bg.surface` #0A0A0A | 3.69:1 | 3:1 | pass |
| dark | ui | `info.solid` #0068D6 | `bg.surface` #0A0A0A | 3.73:1 | 3:1 | pass |
| dark | ui | `untrusted.border` #F2A20D | `untrusted.bg` #000000 | 9.95:1 | 3:1 | pass |
| dark | ui | `untrusted.border` #F2A20D | `bg.raised` #1A1A1A | 8.25:1 | 3:1 | pass |
| dark | ui | `warning.fg` #F2A20D | `ring.track` #2E2E2E | 6.43:1 | 3:1 | pass |
| dark | ui | `danger.fg` #FF6166 | `ring.track` #2E2E2E | 4.63:1 | 3:1 | pass |
| dark | ui | `info.fg` #52A8FF | `ring.track` #2E2E2E | 5.43:1 | 3:1 | pass |
| light | text | `text.primary` #171717 | `bg.canvas` #FFFFFF | 17.93:1 | 4.5:1 | pass |
| light | text | `text.primary` #171717 | `bg.surface` #FFFFFF | 17.93:1 | 4.5:1 | pass |
| light | text | `text.primary` #171717 | `bg.raised` #F2F2F2 | 16.01:1 | 4.5:1 | pass |
| light | text | `text.primary` #171717 | `bg.sunken` #FAFAFA | 17.18:1 | 4.5:1 | pass |
| light | text | `text.primary` #171717 | `bg.hover` #F2F2F2 | 16.01:1 | 4.5:1 | pass |
| light | text | `text.primary` #171717 | `bg.selected` #EBEBEB | 15.04:1 | 4.5:1 | pass |
| light | text | `text.primary` #171717 | `bg.strong` #EBEBEB | 15.04:1 | 4.5:1 | pass |
| light | text | `text.secondary` #4D4D4D | `bg.canvas` #FFFFFF | 8.45:1 | 4.5:1 | pass |
| light | text | `text.secondary` #4D4D4D | `bg.surface` #FFFFFF | 8.45:1 | 4.5:1 | pass |
| light | text | `text.secondary` #4D4D4D | `bg.raised` #F2F2F2 | 7.55:1 | 4.5:1 | pass |
| light | text | `text.secondary` #4D4D4D | `bg.sunken` #FAFAFA | 8.10:1 | 4.5:1 | pass |
| light | text | `text.secondary` #4D4D4D | `bg.hover` #F2F2F2 | 7.55:1 | 4.5:1 | pass |
| light | text | `text.secondary` #4D4D4D | `bg.selected` #EBEBEB | 7.09:1 | 4.5:1 | pass |
| light | text | `text.secondary` #4D4D4D | `bg.strong` #EBEBEB | 7.09:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `bg.canvas` #FFFFFF | 5.74:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `bg.surface` #FFFFFF | 5.74:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `bg.raised` #F2F2F2 | 5.13:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `bg.sunken` #FAFAFA | 5.50:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `bg.hover` #F2F2F2 | 5.13:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `bg.selected` #EBEBEB | 4.82:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `bg.strong` #EBEBEB | 4.82:1 | 4.5:1 | pass |
| light | text | `text.inverse` #FFFFFF | `text.primary` #171717 | 17.93:1 | 4.5:1 | pass |
| light | text | `link.fg` #0064CC | `bg.canvas` #FFFFFF | 5.68:1 | 4.5:1 | pass |
| light | text | `link.fg` #0064CC | `bg.surface` #FFFFFF | 5.68:1 | 4.5:1 | pass |
| light | text | `link.fg` #0064CC | `bg.raised` #F2F2F2 | 5.08:1 | 4.5:1 | pass |
| light | text | `link.fg` #0064CC | `bg.sunken` #FAFAFA | 5.45:1 | 4.5:1 | pass |
| light | text | `accent.fg` #171717 | `bg.canvas` #FFFFFF | 17.93:1 | 4.5:1 | pass |
| light | text | `accent.fg` #171717 | `bg.surface` #FFFFFF | 17.93:1 | 4.5:1 | pass |
| light | text | `accent.fg` #171717 | `bg.raised` #F2F2F2 | 16.01:1 | 4.5:1 | pass |
| light | text | `accent.fg` #171717 | `bg.sunken` #FAFAFA | 17.18:1 | 4.5:1 | pass |
| light | text | `accent.fg` #171717 | `bg.selected` #EBEBEB | 15.04:1 | 4.5:1 | pass |
| light | text | `accent.fg` #171717 | `bg.hover` #F2F2F2 | 16.01:1 | 4.5:1 | pass |
| light | text | `accent.on-solid` #FFFFFF | `accent.solid` #171717 | 17.93:1 | 4.5:1 | pass |
| light | text | `accent.on-solid` #FFFFFF | `accent.hi` #383838 | 11.73:1 | 4.5:1 | pass |
| light | text | `accent.on-solid` #FFFFFF | `accent.lo` #171717 | 17.93:1 | 4.5:1 | pass |
| light | text | `accent.on-tint` #171717 | `accent.tint` #EBEBEB | 15.04:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `accent.tint` #EBEBEB | 4.82:1 | 4.5:1 | pass |
| light | text | `danger.fg` #CB2A2F | `bg.canvas` #FFFFFF | 5.37:1 | 4.5:1 | pass |
| light | text | `danger.fg` #CB2A2F | `bg.surface` #FFFFFF | 5.37:1 | 4.5:1 | pass |
| light | text | `danger.fg` #CB2A2F | `bg.raised` #F2F2F2 | 4.80:1 | 4.5:1 | pass |
| light | text | `danger.fg` #CB2A2F | `bg.sunken` #FAFAFA | 5.14:1 | 4.5:1 | pass |
| light | text | `danger.fg` #CB2A2F | `bg.hover` #F2F2F2 | 4.80:1 | 4.5:1 | pass |
| light | text | `danger.fg` #CB2A2F | `bg.selected` #EBEBEB | 4.50:1 | 4.5:1 | pass |
| light | text | `danger.on-solid` #FFFFFF | `danger.solid` #CB2A2F | 5.37:1 | 4.5:1 | pass |
| light | text | `danger.on-tint` #CB2A2F | `danger.tint` #FCEDED | 4.72:1 | 4.5:1 | pass |
| light | text | `warning.fg` #A35200 | `bg.canvas` #FFFFFF | 5.58:1 | 4.5:1 | pass |
| light | text | `warning.fg` #A35200 | `bg.surface` #FFFFFF | 5.58:1 | 4.5:1 | pass |
| light | text | `warning.fg` #A35200 | `bg.raised` #F2F2F2 | 4.98:1 | 4.5:1 | pass |
| light | text | `warning.fg` #A35200 | `bg.selected` #EBEBEB | 4.68:1 | 4.5:1 | pass |
| light | text | `warning.on-solid` #0A0A0A | `warning.solid` #CC7700 | 5.85:1 | 4.5:1 | pass |
| light | text | `warning.on-tint` #A35200 | `warning.tint` #FAF1E6 | 4.99:1 | 4.5:1 | pass |
| light | text | `success.fg` #267437 | `bg.canvas` #FFFFFF | 5.78:1 | 4.5:1 | pass |
| light | text | `success.fg` #267437 | `bg.surface` #FFFFFF | 5.78:1 | 4.5:1 | pass |
| light | text | `success.fg` #267437 | `bg.raised` #F2F2F2 | 5.16:1 | 4.5:1 | pass |
| light | text | `success.fg` #267437 | `bg.selected` #EBEBEB | 4.85:1 | 4.5:1 | pass |
| light | text | `success.fg` #267437 | `bg.hover` #F2F2F2 | 5.16:1 | 4.5:1 | pass |
| light | text | `success.on-solid` #FFFFFF | `success.solid` #267437 | 5.78:1 | 4.5:1 | pass |
| light | text | `success.on-tint` #267437 | `success.tint` #EBF4ED | 5.14:1 | 4.5:1 | pass |
| light | text | `info.fg` #0064CC | `bg.canvas` #FFFFFF | 5.68:1 | 4.5:1 | pass |
| light | text | `info.fg` #0064CC | `bg.surface` #FFFFFF | 5.68:1 | 4.5:1 | pass |
| light | text | `info.fg` #0064CC | `bg.raised` #F2F2F2 | 5.08:1 | 4.5:1 | pass |
| light | text | `info.fg` #0064CC | `bg.selected` #EBEBEB | 4.77:1 | 4.5:1 | pass |
| light | text | `info.fg` #0064CC | `bg.hover` #F2F2F2 | 5.08:1 | 4.5:1 | pass |
| light | text | `info.on-solid` #FFFFFF | `info.solid` #0068D6 | 5.31:1 | 4.5:1 | pass |
| light | text | `info.on-tint` #0064CC | `info.tint` #E6F1FE | 4.97:1 | 4.5:1 | pass |
| light | text | `untrusted.fg` #171717 | `untrusted.bg` #FAFAFA | 17.18:1 | 4.5:1 | pass |
| light | text | `text.muted` #666666 | `untrusted.bg` #FAFAFA | 5.50:1 | 4.5:1 | pass |
| light | text | `warning.fg` #A35200 | `untrusted.bg` #FAFAFA | 5.34:1 | 4.5:1 | pass |
| light | text | `env.prod.fg` #CB2A2F | `env.prod.bg` #FCEDED | 4.72:1 | 4.5:1 | pass |
| light | text | `env.staging.fg` #A35200 | `env.staging.bg` #FAF1E6 | 4.99:1 | 4.5:1 | pass |
| light | text | `env.dev.fg` #0064CC | `env.dev.bg` #E6F1FE | 4.97:1 | 4.5:1 | pass |
| light | text | `env.other.fg` #4D4D4D | `env.other.bg` #F2F2F2 | 7.55:1 | 4.5:1 | pass |
| light | ui | `border.default` #858585 | `bg.canvas` #FFFFFF | 3.69:1 | 3:1 | pass |
| light | ui | `border.default` #858585 | `bg.surface` #FFFFFF | 3.69:1 | 3:1 | pass |
| light | ui | `border.default` #858585 | `bg.raised` #F2F2F2 | 3.30:1 | 3:1 | pass |
| light | ui | `border.strong` #595959 | `bg.surface` #FFFFFF | 7.00:1 | 3:1 | pass |
| light | ui | `focus.ring` #0072F5 | `bg.canvas` #FFFFFF | 4.44:1 | 3:1 | pass |
| light | ui | `focus.ring` #0072F5 | `bg.surface` #FFFFFF | 4.44:1 | 3:1 | pass |
| light | ui | `focus.ring` #0072F5 | `bg.raised` #F2F2F2 | 3.97:1 | 3:1 | pass |
| light | ui | `ring.gate` #171717 | `bg.canvas` #FFFFFF | 17.93:1 | 3:1 | pass |
| light | ui | `ring.gate` #171717 | `bg.surface` #FFFFFF | 17.93:1 | 3:1 | pass |
| light | ui | `ring.gate` #171717 | `ring.track` #E0E0E0 | 13.58:1 | 3:1 | pass |
| light | ui | `accent.solid` #171717 | `bg.canvas` #FFFFFF | 17.93:1 | 3:1 | pass |
| light | ui | `danger.solid` #CB2A2F | `bg.surface` #FFFFFF | 5.37:1 | 3:1 | pass |
| light | ui | `info.solid` #0068D6 | `bg.surface` #FFFFFF | 5.31:1 | 3:1 | pass |
| light | ui | `untrusted.border` #A35200 | `untrusted.bg` #FAFAFA | 5.34:1 | 3:1 | pass |
| light | ui | `untrusted.border` #A35200 | `bg.raised` #F2F2F2 | 4.98:1 | 3:1 | pass |
| light | ui | `warning.fg` #A35200 | `ring.track` #E0E0E0 | 4.23:1 | 3:1 | pass |
| light | ui | `danger.fg` #CB2A2F | `ring.track` #E0E0E0 | 4.07:1 | 3:1 | pass |
| light | ui | `info.fg` #0064CC | `ring.track` #E0E0E0 | 4.31:1 | 3:1 | pass |

180 pairs, 0 failures. Lowest text ratio 4.50:1, lowest UI ratio 3.03:1.

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
