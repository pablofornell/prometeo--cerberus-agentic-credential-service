#!/usr/bin/env node
// Computes WCAG 2.2 contrast ratios for every token pair in tokens.json (both themes).
// Text pairs need 4.5:1 (SC 1.4.3). UI pairs need 3:1 (SC 1.4.11).
// Usage: node docs/ux/check-contrast.mjs [--md]   (exit code 1 if a pair fails)
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const tokens = JSON.parse(readFileSync(join(here, "tokens.json"), "utf8"));

function channel(c) {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}
function luminance(hex) {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) throw new Error(`Not a 6-digit hex color: ${hex}`);
  const n = parseInt(m[1], 16);
  const r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}
export function ratio(a, b) {
  const la = luminance(a), lb = luminance(b);
  const [hi, lo] = la > lb ? [la, lb] : [lb, la];
  return (hi + 0.05) / (lo + 0.05);
}

const rows = [];
let failures = 0;
for (const theme of Object.keys(tokens.color)) {
  const pal = tokens.color[theme];
  for (const [kind, need] of [["text", 4.5], ["ui", 3]]) {
    for (const [fg, bg] of tokens.contrast[kind]) {
      if (!(fg in pal) || !(bg in pal)) throw new Error(`Unknown token in pair ${fg} / ${bg} (${theme})`);
      const r = ratio(pal[fg], pal[bg]);
      const pass = r >= need;
      if (!pass) failures++;
      rows.push({ theme, kind, fg, bg, fgHex: pal[fg], bgHex: pal[bg], r, need, pass });
    }
  }
}

const md = process.argv.includes("--md");
if (md) {
  console.log("| Theme | Kind | Foreground | Background | Ratio | Needs | Result |");
  console.log("|---|---|---|---|---|---|---|");
  for (const x of rows) {
    console.log(`| ${x.theme} | ${x.kind} | \`${x.fg}\` ${x.fgHex} | \`${x.bg}\` ${x.bgHex} | ${x.r.toFixed(2)}:1 | ${x.need}:1 | ${x.pass ? "pass" : "FAIL"} |`);
  }
  const min = (k) => Math.min(...rows.filter((x) => x.kind === k).map((x) => x.r)).toFixed(2);
  console.log(`\n${rows.length} pairs, ${failures} failures. Lowest text ratio ${min("text")}:1, lowest UI ratio ${min("ui")}:1.`);
} else {
  for (const x of rows) {
    console.log(`${x.pass ? "ok  " : "FAIL"} ${x.theme.padEnd(5)} ${x.kind.padEnd(4)} ${x.r.toFixed(2).padStart(6)}:1 (needs ${x.need}) ${x.fg} on ${x.bg}`);
  }
  console.log(`\n${rows.length} pairs checked, ${failures} failures.`);
}
process.exit(failures ? 1 : 0);
