#!/usr/bin/env node
// Opens every prototype screen in Chromium (Playwright), takes screenshots, runs axe-core and lists
// Spanish strings that have no translation. Pages load from a local server on 127.0.0.1; any other
// request is reported as external.
//
// Needs the packages `playwright` and `axe-core` (any folder; pass it with NODE_PATH):
//   NODE_PATH=/path/to/node_modules node docs/ux/verify-prototypes.mjs [--shots] [--axe] [--i18n] [--keys] [--only=03]
import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const require = createRequire(join(process.env.NODE_PATH || ".", "x.js"));
const { chromium } = require("playwright");
const axeSource = require("fs").readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

const here = dirname(fileURLToPath(import.meta.url));
const protoDir = join(here, "prototypes");
const shotDir = join(here, "screenshots");
mkdirSync(shotDir, { recursive: true });
const args = new Set(process.argv.slice(2));
const only = [...args].find((a) => a.startsWith("--only="))?.slice(7);
const all = !args.has("--shots") && !args.has("--axe") && !args.has("--i18n") && !args.has("--keys");

const screens = [
  "index", "01-create-vault", "02-unlock", "03-dashboard", "04-vault-browser", "05-item-editor", "06-agents",
  "07-policies", "08-approval", "09-leases", "10-audit", "11-settings"
].filter((s) => (!only || s.startsWith(only)) && require("fs").existsSync(join(protoDir, `${s}.html`)));
const states = ["ready", "empty", "loading", "error", "locked"];

// Serve the prototypes on 127.0.0.1 so axe can read stylesheets (file:// blocks that).
const http = require("http");
const fs = require("fs");
const types = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".woff2": "font/woff2", ".png": "image/png" };
const server = http.createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  const file = join(protoDir, path === "/" ? "index.html" : path);
  if (!file.startsWith(protoDir) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { "content-type": types[file.slice(file.lastIndexOf("."))] || "application/octet-stream" });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
const external = [];
ctx.on("request", (r) => { if (!r.url().startsWith(origin) && !r.url().startsWith("data:")) external.push(r.url()); });
const page = await ctx.newPage();
const consoleErrors = [];
page.on("pageerror", (e) => consoleErrors.push(`${page.url()}: ${e.message}`));
page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(`${page.url()}: ${m.text()}`); });

const url = (s, q) => `${origin}/${s}.html?` + new URLSearchParams(q);
const axeResults = [];
const missing = new Map();

for (const s of screens) {
  for (const theme of ["dark", "light"]) {
    const list = s === "index" ? ["ready"] : states;
    for (const state of list) {
      await page.goto(url(s, { theme, state, lang: "en" }));
      await page.waitForTimeout(150);
      if (all || args.has("--shots")) {
        await page.screenshot({ path: join(shotDir, `${s}-${state}-${theme}.png`), fullPage: true });
      }
      if (all || args.has("--axe")) {
        await page.addScriptTag({ content: axeSource });
        const r = await page.evaluate(async () => {
          const res = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] } });
          return res.violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length, target: v.nodes.slice(0, 3).map((n) => n.target.join(" ")) }));
        });
        for (const v of r) axeResults.push({ screen: s, theme, state, ...v });
      }
    }
  }
  if (all || args.has("--shots")) {
    // Narrow window check: no sideways scroll at 390 px.
    await page.setViewportSize({ width: 390, height: 844 });
    for (const state of s === "index" ? ["ready"] : states) {
      await page.goto(url(s, { theme: "dark", state }));
      await page.waitForTimeout(100);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (overflow > 1) consoleErrors.push(`${s}/${state}: horizontal overflow ${overflow}px at 390px`);
    }
    await page.goto(url(s, { theme: "dark", state: "ready" }));
    await page.waitForTimeout(150);
    await page.screenshot({ path: join(shotDir, `${s}-ready-dark-narrow.png`), fullPage: false });
    await page.goto(url(s, { theme: "light", state: "ready" }));
    await page.waitForTimeout(150);
    await page.screenshot({ path: join(shotDir, `${s}-ready-light-narrow.png`), fullPage: false });
    await page.setViewportSize({ width: 1440, height: 900 });
  }
  if (all || args.has("--axe")) {
    // Variants (from data-variants) and every dialog, in both themes.
    await page.goto(url(s, { theme: "dark", state: "ready" }));
    const variants = await page.evaluate(() => (document.body.dataset.variants || "").split(",").filter(Boolean).map((v) => v.split(":")[0]));
    const dialogs = await page.evaluate(() => [...document.querySelectorAll("dialog[id]")].map((d) => d.id));
    for (const theme of ["dark", "light"]) {
      for (const variant of variants) {
        await page.goto(url(s, { theme, state: "ready", variant }));
        await page.waitForTimeout(100);
        await page.addScriptTag({ content: axeSource });
        const r = await page.evaluate(async () => (await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa", "best-practice"] } })).violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length, target: v.nodes.slice(0, 3).map((n) => n.target.join(" ")) })));
        for (const v of r) axeResults.push({ screen: s, theme, state: `variant:${variant}`, ...v });
        if ((all || args.has("--shots")) && theme === "dark") await page.screenshot({ path: join(shotDir, `${s}-variant-${variant}-dark.png`), fullPage: true });
      }
      for (const id of dialogs) {
        await page.goto(url(s, { theme, state: "ready" }));
        await page.evaluate((i) => { document.querySelectorAll("dialog[open]").forEach((d) => d.close()); document.getElementById(i).showModal(); }, id);
        await page.waitForTimeout(250);
        await page.addScriptTag({ content: axeSource });
        const r = await page.evaluate(async (i) => (await window.axe.run(document.getElementById(i), { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"] } })).violations.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length, target: v.nodes.slice(0, 3).map((n) => n.target.join(" ")) })), id);
        for (const v of r) axeResults.push({ screen: s, theme, state: `dialog:${id}`, ...v });
        if ((all || args.has("--shots")) && theme === "dark") await page.screenshot({ path: join(shotDir, `${s}-dialog-${id}-dark.png`) });
      }
    }
  }
  if (all || args.has("--i18n")) {
    for (const state of s === "index" ? ["ready"] : states) {
      await page.goto(url(s, { theme: "dark", state, lang: "es" }));
      const m = await page.evaluate(() => window.cerbMissing());
      for (const k of m) missing.set(k, s);
    }
    // Variants change text too, so check them in Spanish as well.
    await page.goto(url(s, { theme: "dark", state: "ready", lang: "es" }));
    const vlist = await page.evaluate(() => (document.body.dataset.variants || "").split(",").filter(Boolean).map((v) => v.split(":")[0]));
    for (const variant of vlist) {
      await page.goto(url(s, { theme: "dark", state: "ready", lang: "es", variant }));
      const m = await page.evaluate(() => window.cerbMissing());
      for (const k of m) missing.set(k, `${s}/${variant}`);
    }
    if (all || args.has("--shots")) {
      await page.goto(url(s, { theme: "dark", state: "ready", lang: "es" }));
      await page.screenshot({ path: join(shotDir, `${s}-ready-dark-es.png`), fullPage: false });
    }
  }
}
// Keyboard checks: palette, shortcut list, go-to keys, lock key, hold to reveal, hold to approve.
const keyboard = [];
if (all || args.has("--keys")) {
  const check = (name, pass, got) => keyboard.push({ name, pass, got });
  const openDialogs = () => page.evaluate(() => [...document.querySelectorAll("dialog[open]")].map((d) => d.id));
  const toastText = () => page.evaluate(() => [...document.querySelectorAll(".toast")].map((x) => x.innerText.trim()).join(" | "));
  await page.goto(url("03-dashboard", { theme: "dark", state: "ready", lang: "en" })); await page.waitForTimeout(150);
  await page.keyboard.press("Control+k"); await page.waitForTimeout(150);
  let d = await openDialogs(); check("Ctrl+K opens the palette with focus in its field", d.includes("palette") && await page.evaluate(() => document.activeElement.id === "pal-q"), d);
  await page.keyboard.press("Escape"); await page.waitForTimeout(150);
  d = await openDialogs(); check("Esc closes the palette", d.length === 0, d);
  await page.keyboard.press("Shift+Slash"); await page.waitForTimeout(150);
  d = await openDialogs(); check("? opens the shortcut list", d.includes("dlg-keys"), d);
  await page.keyboard.press("Escape");
  await page.keyboard.press("g"); await page.keyboard.press("v"); await page.waitForTimeout(400);
  check("G then V goes to the vault", page.url().includes("04-vault-browser"), page.url().split("/").pop());
  await page.goto(url("03-dashboard", { theme: "dark", state: "ready", lang: "en" })); await page.waitForTimeout(150);
  await page.keyboard.press("Tab"); await page.keyboard.press("Tab"); await page.keyboard.press("Tab");
  const ring = await page.evaluate(() => { const st = getComputedStyle(document.activeElement); return `${st.outlineStyle} ${st.outlineWidth}`; });
  check("Tab focus shows a 2 px ring", ring === "solid 2px", ring);
  await page.keyboard.press("Control+l"); await page.waitForTimeout(400);
  check("Ctrl+L locks (goes to unlock)", page.url().includes("02-unlock"), page.url().split("/").pop());
  await page.goto(url("04-vault-browser", { theme: "dark", state: "ready", lang: "en" })); await page.waitForTimeout(200);
  await page.locator(".secret button").first().focus();
  const masked = await page.evaluate(() => document.querySelector(".secret").innerText);
  await page.keyboard.down("Space"); await page.waitForTimeout(200); await page.keyboard.up("Space"); await page.waitForTimeout(100);
  const short = await page.evaluate(() => document.querySelector(".secret").innerText);
  check("A short Space press does not reveal", short === masked, short);
  await page.keyboard.down("Space"); await page.waitForTimeout(650); await page.keyboard.up("Space"); await page.waitForTimeout(100);
  const shown = await page.evaluate(() => document.querySelector(".secret").innerText);
  check("A 500 ms Space hold reveals", shown !== masked, shown === masked ? "still masked" : "revealed");
  await page.goto(url("08-approval", { theme: "dark", state: "ready", lang: "en" })); await page.waitForTimeout(150);
  await page.keyboard.press("a"); await page.waitForTimeout(300);
  check("A tap on A does not approve", (await toastText()) === "", await toastText());
  await page.keyboard.down("a"); await page.waitForTimeout(750); await page.keyboard.up("a"); await page.waitForTimeout(200);
  check("A 600 ms hold on A approves once", (await toastText()).startsWith("Approved once"), await toastText());
  await page.goto(url("08-approval", { theme: "dark", state: "ready", lang: "en" })); await page.waitForTimeout(150);
  await page.keyboard.press("d"); await page.waitForTimeout(200);
  check("D denies at once", (await toastText()).startsWith("Denied"), await toastText());
}
await browser.close();
server.close();

const perScreen = Object.fromEntries(screens.map((s) => {
  const v = axeResults.filter((x) => x.screen === s);
  const n = (imp) => v.filter((x) => x.impact === imp).length;
  return [s, { critical: n("critical"), serious: n("serious"), moderate: n("moderate"), minor: n("minor") }];
}));
const shots = fs.readdirSync(shotDir).filter((f) => f.endsWith(".png")).length;
const summary = {
  screens: screens.length,
  screenshots: shots,
  axePerScreen: perScreen,
  axe: { total: axeResults.length, serious: axeResults.filter((v) => v.impact === "serious" || v.impact === "critical").length },
  keyboard: { checks: keyboard.length, failed: keyboard.filter((k) => !k.pass).length },
  missingSpanish: missing.size,
  externalRequests: external.length,
  consoleErrors: consoleErrors.length
};
writeFileSync(join(here, "screenshots", "verify-report.json"), JSON.stringify({ summary, keyboard, axe: axeResults, missing: [...missing], external, consoleErrors }, null, 2));
console.log(JSON.stringify(summary, null, 2));
const grouped = {};
for (const v of axeResults) { const k = `${v.impact} ${v.id}: ${v.help}`; (grouped[k] ||= new Set()).add(`${v.screen}/${v.state}/${v.theme} ${v.target.join(", ")}`); }
for (const [k, set] of Object.entries(grouped)) console.log(`\n${k}\n  ` + [...set].slice(0, 6).join("\n  "));
if (missing.size) console.log("\nMissing es:\n" + [...missing].map(([k, s]) => `  [${s}] ${k}`).join("\n"));
if (consoleErrors.length) console.log("\nConsole errors (unique):\n  " + [...new Set(consoleErrors.map((e) => e.replace(/^\S+: /, "")))].slice(0, 20).join("\n  "));
if (external.length) console.log("\nExternal requests:\n  " + external.join("\n  "));
