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
| dark | text | `text.primary` #EDEBE6 | `bg.canvas` #0F0F10 | 16.08:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEBE6 | `bg.surface` #151517 | 15.31:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEBE6 | `bg.raised` #1B1B1E | 14.42:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEBE6 | `bg.sunken` #0A0A0B | 16.61:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEBE6 | `bg.hover` #222226 | 13.31:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEBE6 | `bg.selected` #2A2A2F | 11.99:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B5B2AA | `bg.canvas` #0F0F10 | 9.04:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B5B2AA | `bg.surface` #151517 | 8.61:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B5B2AA | `bg.raised` #1B1B1E | 8.11:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B5B2AA | `bg.hover` #222226 | 7.48:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B5B2AA | `bg.selected` #2A2A2F | 6.74:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `bg.canvas` #0F0F10 | 6.33:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `bg.surface` #151517 | 6.02:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `bg.raised` #1B1B1E | 5.68:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `bg.sunken` #0A0A0B | 6.54:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `bg.hover` #222226 | 5.24:1 | 4.5:1 | pass |
| dark | text | `text.inverse` #0F0F10 | `text.primary` #EDEBE6 | 16.08:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #D9B46A | `bg.canvas` #0F0F10 | 9.75:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #D9B46A | `bg.surface` #151517 | 9.28:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #D9B46A | `bg.raised` #1B1B1E | 8.74:1 | 4.5:1 | pass |
| dark | text | `accent.on-solid` #1A1408 | `accent.solid` #C9A45C | 7.80:1 | 4.5:1 | pass |
| dark | text | `accent.on-tint` #EBD3A0 | `accent.tint` #2A2416 | 10.54:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #F2877C | `bg.canvas` #0F0F10 | 7.78:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #F2877C | `bg.surface` #151517 | 7.41:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #F2877C | `bg.raised` #1B1B1E | 6.98:1 | 4.5:1 | pass |
| dark | text | `danger.on-solid` #FFFFFF | `danger.solid` #B8382E | 5.76:1 | 4.5:1 | pass |
| dark | text | `danger.on-tint` #F7B4AB | `danger.tint` #2E1A19 | 9.45:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #E8A25C | `bg.canvas` #0F0F10 | 8.90:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #E8A25C | `bg.surface` #151517 | 8.47:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #E8A25C | `bg.raised` #1B1B1E | 7.98:1 | 4.5:1 | pass |
| dark | text | `warning.on-solid` #24160A | `warning.solid` #E8A25C | 8.17:1 | 4.5:1 | pass |
| dark | text | `warning.on-tint` #F5C99A | `warning.tint` #2D2318 | 10.04:1 | 4.5:1 | pass |
| dark | text | `success.fg` #7CCBA6 | `bg.canvas` #0F0F10 | 9.99:1 | 4.5:1 | pass |
| dark | text | `success.fg` #7CCBA6 | `bg.surface` #151517 | 9.51:1 | 4.5:1 | pass |
| dark | text | `success.fg` #7CCBA6 | `bg.raised` #1B1B1E | 8.96:1 | 4.5:1 | pass |
| dark | text | `success.on-solid` #07140E | `success.solid` #3E9C74 | 5.57:1 | 4.5:1 | pass |
| dark | text | `success.on-tint` #A9E0C5 | `success.tint` #15241E | 10.86:1 | 4.5:1 | pass |
| dark | text | `info.fg` #9DB8E0 | `bg.canvas` #0F0F10 | 9.46:1 | 4.5:1 | pass |
| dark | text | `info.fg` #9DB8E0 | `bg.surface` #151517 | 9.00:1 | 4.5:1 | pass |
| dark | text | `info.fg` #9DB8E0 | `bg.raised` #1B1B1E | 8.48:1 | 4.5:1 | pass |
| dark | text | `info.on-solid` #0E1522 | `info.solid` #9DB8E0 | 9.02:1 | 4.5:1 | pass |
| dark | text | `info.on-tint` #C2D4EE | `info.tint` #18202C | 10.88:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #D9B46A | `bg.selected` #2A2A2F | 7.27:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #F2877C | `bg.selected` #2A2A2F | 5.80:1 | 4.5:1 | pass |
| dark | text | `warning.fg` #E8A25C | `bg.selected` #2A2A2F | 6.63:1 | 4.5:1 | pass |
| dark | text | `success.fg` #7CCBA6 | `bg.selected` #2A2A2F | 7.45:1 | 4.5:1 | pass |
| dark | text | `info.fg` #9DB8E0 | `bg.selected` #2A2A2F | 7.05:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `bg.selected` #2A2A2F | 4.72:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #D9B46A | `bg.hover` #222226 | 8.07:1 | 4.5:1 | pass |
| dark | text | `danger.fg` #F2877C | `bg.hover` #222226 | 6.44:1 | 4.5:1 | pass |
| dark | text | `success.fg` #7CCBA6 | `bg.hover` #222226 | 8.27:1 | 4.5:1 | pass |
| dark | text | `info.fg` #9DB8E0 | `bg.hover` #222226 | 7.82:1 | 4.5:1 | pass |
| dark | text | `text.secondary` #B5B2AA | `bg.sunken` #0A0A0B | 9.34:1 | 4.5:1 | pass |
| dark | text | `accent.fg` #D9B46A | `bg.sunken` #0A0A0B | 10.07:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `accent.tint` #2A2416 | 5.09:1 | 4.5:1 | pass |
| dark | text | `untrusted.fg` #EDEBE6 | `untrusted.bg` #141316 | 15.54:1 | 4.5:1 | pass |
| dark | text | `env.prod.fg` #F7B4AB | `env.prod.bg` #2E1A19 | 9.45:1 | 4.5:1 | pass |
| dark | text | `env.staging.fg` #F5C99A | `env.staging.bg` #2D2318 | 10.04:1 | 4.5:1 | pass |
| dark | text | `env.dev.fg` #C2D4EE | `env.dev.bg` #18202C | 10.88:1 | 4.5:1 | pass |
| dark | text | `env.other.fg` #C8C5BE | `env.other.bg` #222226 | 9.20:1 | 4.5:1 | pass |
| dark | text | `accent.on-solid` #1A1408 | `accent.hi` #DDBB78 | 9.98:1 | 4.5:1 | pass |
| dark | text | `accent.on-solid` #1A1408 | `accent.lo` #B8934A | 6.37:1 | 4.5:1 | pass |
| dark | text | `text.primary` #EDEBE6 | `untrusted.bg` #141316 | 15.54:1 | 4.5:1 | pass |
| dark | text | `text.muted` #97948D | `untrusted.bg` #141316 | 6.11:1 | 4.5:1 | pass |
| dark | ui | `border.default` #6B6B74 | `bg.canvas` #0F0F10 | 3.63:1 | 3:1 | pass |
| dark | ui | `border.default` #6B6B74 | `bg.surface` #151517 | 3.46:1 | 3:1 | pass |
| dark | ui | `border.default` #6B6B74 | `bg.raised` #1B1B1E | 3.26:1 | 3:1 | pass |
| dark | ui | `border.strong` #85858E | `bg.surface` #151517 | 4.99:1 | 3:1 | pass |
| dark | ui | `focus.ring` #E9D7AE | `bg.canvas` #0F0F10 | 13.50:1 | 3:1 | pass |
| dark | ui | `focus.ring` #E9D7AE | `bg.surface` #151517 | 12.85:1 | 3:1 | pass |
| dark | ui | `focus.ring` #E9D7AE | `bg.raised` #1B1B1E | 12.11:1 | 3:1 | pass |
| dark | ui | `ring.gate` #C9A45C | `bg.canvas` #0F0F10 | 8.16:1 | 3:1 | pass |
| dark | ui | `ring.gate` #C9A45C | `bg.surface` #151517 | 7.77:1 | 3:1 | pass |
| dark | ui | `ring.gate` #C9A45C | `ring.track` #2E2E33 | 5.76:1 | 3:1 | pass |
| dark | ui | `accent.solid` #C9A45C | `bg.canvas` #0F0F10 | 8.16:1 | 3:1 | pass |
| dark | ui | `danger.solid` #B8382E | `bg.surface` #151517 | 3.16:1 | 3:1 | pass |
| dark | ui | `untrusted.border` #A88A52 | `untrusted.bg` #141316 | 5.66:1 | 3:1 | pass |
| dark | ui | `untrusted.border` #A88A52 | `bg.raised` #1B1B1E | 5.25:1 | 3:1 | pass |
| dark | ui | `warning.fg` #E8A25C | `ring.track` #2E2E33 | 6.27:1 | 3:1 | pass |
| dark | ui | `danger.fg` #F2877C | `ring.track` #2E2E33 | 5.49:1 | 3:1 | pass |
| dark | ui | `info.fg` #9DB8E0 | `ring.track` #2E2E33 | 6.67:1 | 3:1 | pass |
| light | text | `text.primary` #1A1917 | `bg.canvas` #F6F4EF | 15.98:1 | 4.5:1 | pass |
| light | text | `text.primary` #1A1917 | `bg.surface` #FFFFFF | 17.57:1 | 4.5:1 | pass |
| light | text | `text.primary` #1A1917 | `bg.raised` #FFFFFF | 17.57:1 | 4.5:1 | pass |
| light | text | `text.primary` #1A1917 | `bg.sunken` #EEEBE4 | 14.76:1 | 4.5:1 | pass |
| light | text | `text.primary` #1A1917 | `bg.hover` #EFECE5 | 14.89:1 | 4.5:1 | pass |
| light | text | `text.primary` #1A1917 | `bg.selected` #E7E2D7 | 13.60:1 | 4.5:1 | pass |
| light | text | `text.secondary` #45423C | `bg.canvas` #F6F4EF | 9.11:1 | 4.5:1 | pass |
| light | text | `text.secondary` #45423C | `bg.surface` #FFFFFF | 10.01:1 | 4.5:1 | pass |
| light | text | `text.secondary` #45423C | `bg.raised` #FFFFFF | 10.01:1 | 4.5:1 | pass |
| light | text | `text.secondary` #45423C | `bg.hover` #EFECE5 | 8.49:1 | 4.5:1 | pass |
| light | text | `text.secondary` #45423C | `bg.selected` #E7E2D7 | 7.75:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `bg.canvas` #F6F4EF | 6.15:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `bg.surface` #FFFFFF | 6.76:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `bg.raised` #FFFFFF | 6.76:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `bg.sunken` #EEEBE4 | 5.68:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `bg.hover` #EFECE5 | 5.73:1 | 4.5:1 | pass |
| light | text | `text.inverse` #F6F4EF | `text.primary` #1A1917 | 15.98:1 | 4.5:1 | pass |
| light | text | `accent.fg` #7A5410 | `bg.canvas` #F6F4EF | 6.16:1 | 4.5:1 | pass |
| light | text | `accent.fg` #7A5410 | `bg.surface` #FFFFFF | 6.77:1 | 4.5:1 | pass |
| light | text | `accent.fg` #7A5410 | `bg.raised` #FFFFFF | 6.77:1 | 4.5:1 | pass |
| light | text | `accent.on-solid` #FFFFFF | `accent.solid` #8A6118 | 5.52:1 | 4.5:1 | pass |
| light | text | `accent.on-tint` #5E400A | `accent.tint` #F3EAD6 | 7.93:1 | 4.5:1 | pass |
| light | text | `danger.fg` #A8281F | `bg.canvas` #F6F4EF | 6.39:1 | 4.5:1 | pass |
| light | text | `danger.fg` #A8281F | `bg.surface` #FFFFFF | 7.03:1 | 4.5:1 | pass |
| light | text | `danger.fg` #A8281F | `bg.raised` #FFFFFF | 7.03:1 | 4.5:1 | pass |
| light | text | `danger.on-solid` #FFFFFF | `danger.solid` #A8281F | 7.03:1 | 4.5:1 | pass |
| light | text | `danger.on-tint` #7F1C15 | `danger.tint` #F9E3DF | 8.21:1 | 4.5:1 | pass |
| light | text | `warning.fg` #8A4A06 | `bg.canvas` #F6F4EF | 6.24:1 | 4.5:1 | pass |
| light | text | `warning.fg` #8A4A06 | `bg.surface` #FFFFFF | 6.86:1 | 4.5:1 | pass |
| light | text | `warning.fg` #8A4A06 | `bg.raised` #FFFFFF | 6.86:1 | 4.5:1 | pass |
| light | text | `warning.on-solid` #2A1600 | `warning.solid` #E39A4F | 7.42:1 | 4.5:1 | pass |
| light | text | `warning.on-tint` #6E3A02 | `warning.tint` #FAEBD9 | 7.91:1 | 4.5:1 | pass |
| light | text | `success.fg` #1F6B4A | `bg.canvas` #F6F4EF | 5.86:1 | 4.5:1 | pass |
| light | text | `success.fg` #1F6B4A | `bg.surface` #FFFFFF | 6.44:1 | 4.5:1 | pass |
| light | text | `success.fg` #1F6B4A | `bg.raised` #FFFFFF | 6.44:1 | 4.5:1 | pass |
| light | text | `success.on-solid` #FFFFFF | `success.solid` #22714F | 5.93:1 | 4.5:1 | pass |
| light | text | `success.on-tint` #18573C | `success.tint` #DFF0E6 | 7.19:1 | 4.5:1 | pass |
| light | text | `info.fg` #2A5A9A | `bg.canvas` #F6F4EF | 6.31:1 | 4.5:1 | pass |
| light | text | `info.fg` #2A5A9A | `bg.surface` #FFFFFF | 6.94:1 | 4.5:1 | pass |
| light | text | `info.fg` #2A5A9A | `bg.raised` #FFFFFF | 6.94:1 | 4.5:1 | pass |
| light | text | `info.on-solid` #FFFFFF | `info.solid` #2A5A9A | 6.94:1 | 4.5:1 | pass |
| light | text | `info.on-tint` #1F4679 | `info.tint` #E3EBF6 | 7.91:1 | 4.5:1 | pass |
| light | text | `accent.fg` #7A5410 | `bg.selected` #E7E2D7 | 5.24:1 | 4.5:1 | pass |
| light | text | `danger.fg` #A8281F | `bg.selected` #E7E2D7 | 5.44:1 | 4.5:1 | pass |
| light | text | `warning.fg` #8A4A06 | `bg.selected` #E7E2D7 | 5.31:1 | 4.5:1 | pass |
| light | text | `success.fg` #1F6B4A | `bg.selected` #E7E2D7 | 4.99:1 | 4.5:1 | pass |
| light | text | `info.fg` #2A5A9A | `bg.selected` #E7E2D7 | 5.37:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `bg.selected` #E7E2D7 | 5.23:1 | 4.5:1 | pass |
| light | text | `accent.fg` #7A5410 | `bg.hover` #EFECE5 | 5.74:1 | 4.5:1 | pass |
| light | text | `danger.fg` #A8281F | `bg.hover` #EFECE5 | 5.96:1 | 4.5:1 | pass |
| light | text | `success.fg` #1F6B4A | `bg.hover` #EFECE5 | 5.46:1 | 4.5:1 | pass |
| light | text | `info.fg` #2A5A9A | `bg.hover` #EFECE5 | 5.88:1 | 4.5:1 | pass |
| light | text | `text.secondary` #45423C | `bg.sunken` #EEEBE4 | 8.41:1 | 4.5:1 | pass |
| light | text | `accent.fg` #7A5410 | `bg.sunken` #EEEBE4 | 5.68:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `accent.tint` #F3EAD6 | 5.65:1 | 4.5:1 | pass |
| light | text | `untrusted.fg` #1A1917 | `untrusted.bg` #FAF7F0 | 16.42:1 | 4.5:1 | pass |
| light | text | `env.prod.fg` #7F1C15 | `env.prod.bg` #F9E3DF | 8.21:1 | 4.5:1 | pass |
| light | text | `env.staging.fg` #6E3A02 | `env.staging.bg` #FAEBD9 | 7.91:1 | 4.5:1 | pass |
| light | text | `env.dev.fg` #1F4679 | `env.dev.bg` #E3EBF6 | 7.91:1 | 4.5:1 | pass |
| light | text | `env.other.fg` #45423C | `env.other.bg` #EFECE5 | 8.49:1 | 4.5:1 | pass |
| light | text | `accent.on-solid` #FFFFFF | `accent.hi` #93691F | 4.91:1 | 4.5:1 | pass |
| light | text | `accent.on-solid` #FFFFFF | `accent.lo` #7B5512 | 6.67:1 | 4.5:1 | pass |
| light | text | `text.primary` #1A1917 | `untrusted.bg` #FAF7F0 | 16.42:1 | 4.5:1 | pass |
| light | text | `text.muted` #5F5B53 | `untrusted.bg` #FAF7F0 | 6.32:1 | 4.5:1 | pass |
| light | ui | `border.default` #7D786E | `bg.canvas` #F6F4EF | 3.99:1 | 3:1 | pass |
| light | ui | `border.default` #7D786E | `bg.surface` #FFFFFF | 4.39:1 | 3:1 | pass |
| light | ui | `border.default` #7D786E | `bg.raised` #FFFFFF | 4.39:1 | 3:1 | pass |
| light | ui | `border.strong` #5A564E | `bg.surface` #FFFFFF | 7.30:1 | 3:1 | pass |
| light | ui | `focus.ring` #8A6118 | `bg.canvas` #F6F4EF | 5.02:1 | 3:1 | pass |
| light | ui | `focus.ring` #8A6118 | `bg.surface` #FFFFFF | 5.52:1 | 3:1 | pass |
| light | ui | `focus.ring` #8A6118 | `bg.raised` #FFFFFF | 5.52:1 | 3:1 | pass |
| light | ui | `ring.gate` #9A6C1C | `bg.canvas` #F6F4EF | 4.21:1 | 3:1 | pass |
| light | ui | `ring.gate` #9A6C1C | `bg.surface` #FFFFFF | 4.63:1 | 3:1 | pass |
| light | ui | `ring.gate` #9A6C1C | `ring.track` #DAD5CB | 3.17:1 | 3:1 | pass |
| light | ui | `accent.solid` #8A6118 | `bg.canvas` #F6F4EF | 5.02:1 | 3:1 | pass |
| light | ui | `danger.solid` #A8281F | `bg.surface` #FFFFFF | 7.03:1 | 3:1 | pass |
| light | ui | `untrusted.border` #8A6A2E | `untrusted.bg` #FAF7F0 | 4.69:1 | 3:1 | pass |
| light | ui | `untrusted.border` #8A6A2E | `bg.raised` #FFFFFF | 5.02:1 | 3:1 | pass |
| light | ui | `warning.fg` #8A4A06 | `ring.track` #DAD5CB | 4.69:1 | 3:1 | pass |
| light | ui | `danger.fg` #A8281F | `ring.track` #DAD5CB | 4.81:1 | 3:1 | pass |
| light | ui | `info.fg` #2A5A9A | `ring.track` #DAD5CB | 4.74:1 | 3:1 | pass |

162 pairs, 0 failures. Lowest text ratio 4.72:1, lowest UI ratio 3.16:1.

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
