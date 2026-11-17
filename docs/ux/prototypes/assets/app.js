// Cerberus prototype runtime: shell, theme, language, states, palette, shortcuts and shared components.
// Static file, no network. Each screen sets <body data-page data-layout data-title data-variants>.
(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const params = new URLSearchParams(location.search);
  const store = {
    get(k) { try { return localStorage.getItem("cerb-proto-" + k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem("cerb-proto-" + k, v); } catch { /* storage blocked: keep in memory */ } }
  };
  const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const SCREENS = [
    { n: 1, file: "01-create-vault.html", page: "create", title: "Create vault", icon: "plus" },
    { n: 2, file: "02-unlock.html", page: "unlock", title: "Unlock", icon: "unlock" },
    { n: 3, file: "03-dashboard.html", page: "dashboard", title: "Dashboard", icon: "gauge", key: "d" },
    { n: 4, file: "04-vault-browser.html", page: "vault", title: "Vault", icon: "vault", key: "v" },
    { n: 5, file: "05-item-editor.html", page: "editor", title: "Item editor", icon: "edit" },
    { n: 6, file: "06-agents.html", page: "agents", title: "Agents", icon: "bot", key: "a" },
    { n: 7, file: "07-policies.html", page: "policies", title: "Policies", icon: "policy", key: "p" },
    { n: 8, file: "08-approval.html", page: "approval", title: "Approvals", icon: "bell", key: "r" },
    { n: 9, file: "09-leases.html", page: "leases", title: "Leases", icon: "timer", key: "l" },
    { n: 10, file: "10-audit.html", page: "audit", title: "Audit", icon: "audit", key: "u" },
    { n: 11, file: "11-settings.html", page: "settings", title: "Settings", icon: "sliders", key: "s" }
  ];
  const NAV = ["dashboard", "vault", "agents", "policies", "approval", "leases", "audit", "|", "settings"];

  // ---------- i18n: English is the text in the HTML; Spanish comes from i18n-es.js ----------
  const ES = window.CERB_ES || {};
  let lang = params.get("lang") || store.get("lang") || "en";
  const missing = new Set();
  const textOrig = new WeakMap();
  const KEEP = new Set(window.CERB_KEEP || []);
  function t(s) {
    if (lang !== "es") return s;
    const key = s.trim().replace(/\s+/g, " ");
    if (ES[key] !== undefined) return s.match(/^\s*/)[0] + ES[key] + s.match(/\s*$/)[0];
    if (/[a-z]{3,}/i.test(key) && !KEEP.has(key)) missing.add(key);
    return s;
  }
  window.cerbT = t;
  function translateTree(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        if (!n.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const p = n.parentElement;
        if (!p || p.closest("script,style,code,samp,kbd,pre,.mono,.code,.ev,.secret .value,[data-no-i18n]")) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const n of nodes) {
      if (!textOrig.has(n)) textOrig.set(n, n.nodeValue);
      n.nodeValue = t(textOrig.get(n));
    }
    for (const el of $$("[placeholder],[aria-label],[title],[data-label]", root)) {
      if (el.classList.contains("ttl") || el.closest(".secret")) continue; // these build their own translated labels
      for (const a of ["placeholder", "aria-label", "title", "data-label"]) {
        if (!el.hasAttribute(a)) continue;
        const k = "en" + a.replace(/-./g, (m) => m[1].toUpperCase()).replace(/^./, (m) => m.toUpperCase());
        if (el.dataset[k] === undefined) el.dataset[k] = el.getAttribute(a);
        el.setAttribute(a, t(el.dataset[k]));
      }
    }
  }
  window.cerbMissing = () => Array.from(missing);
  function applyLang() {
    document.documentElement.lang = lang;
    translateTree(document.body);
    $$("[data-lang-btn]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.langBtn === lang)));
  }

  // ---------- Theme ----------
  let theme = params.get("theme") || store.get("theme") || "dark";
  function applyTheme() {
    document.documentElement.dataset.theme = theme;
    $$("[data-theme-btn]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeBtn === theme)));
  }

  // ---------- Icons, gate mark, TTL rings ----------
  function icon(name, cls = "") {
    const body = (window.CERB_ICONS || {})[name] || "";
    return `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${body}</svg>`;
  }
  window.cerbIcon = icon;
  function paintIcons(root = document) {
    for (const el of $$("i[data-i]", root)) {
      const span = document.createElement("span");
      span.style.display = "contents";
      span.innerHTML = icon(el.dataset.i, el.className);
      el.replaceWith(span);
    }
  }
  // Three rings with a gap each. Open: the gaps line up at the bottom (the gate). Locked: closed rings.
  function gateSvg(size, mode) {
    const rings = [[10.5, 1.6, "r1"], [7.2, 1.6, "r2"], [3.9, 1.6, "r3"]];
    const parts = rings.map(([r, w, c]) => {
      const len = 2 * Math.PI * r;
      const gap = mode === "locked" ? 0 : len * (c === "r1" ? 0.12 : c === "r2" ? 0.16 : 0.24);
      // The stroke starts at 3 o'clock; offset 3/4 len - gap/2 centres the gap at 6 o'clock (the gate).
      return `<circle class="${c}" cx="12" cy="12" r="${r}" stroke-width="${w}" stroke-dasharray="${(len - gap).toFixed(2)} ${gap.toFixed(2)}" stroke-dashoffset="${(0.75 * len - gap / 2).toFixed(2)}"/>`;
    }).join("");
    const cls = ["gate", mode === "locked" ? "is-locked" : "", mode === "spin" ? "spinning" : ""].join(" ");
    return `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true">${parts}<circle class="core" cx="12" cy="12" r="1.4"/></svg>`;
  }
  window.cerbGate = gateSvg;
  function paintGates(root = document) {
    for (const el of $$("[data-gate]", root)) el.innerHTML = gateSvg(+el.dataset.size || 28, el.dataset.gate);
  }
  function fmtLeft(sec) {
    sec = Math.max(0, Math.round(sec));
    if (sec >= 3600) { const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60); return `${h} h ${String(m).padStart(2, "0")} m`; }
    const m = Math.floor(sec / 60), s = sec % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  }
  window.cerbFmt = fmtLeft;
  function ttlState(left, total) {
    const r = total ? left / total : 1;
    return r <= 0.1 ? "critical" : r <= 0.25 ? "low" : "ok";
  }
  function paintTtl(el) {
    const size = +el.dataset.size || 24, total = +el.dataset.total || 1, left = Math.max(0, +el.dataset.left || 0);
    const sw = size >= 40 ? 4 : size >= 28 ? 3 : 2.5, r = (size - sw) / 2, len = 2 * Math.PI * r;
    const st = el.classList.contains("gate") ? "" : ttlState(left, total);
    el.classList.remove("low", "critical");
    if (st && st !== "ok") el.classList.add(st);
    const label = el.dataset.inner === "1" ? `<span class="lbl">${Math.ceil(left / 60)}</span>` : "";
    el.innerHTML = `<svg width="${size}" height="${size}" aria-hidden="true"><circle class="track" cx="${size / 2}" cy="${size / 2}" r="${r}" stroke-width="${sw}"/><circle class="val" cx="${size / 2}" cy="${size / 2}" r="${r}" stroke-width="${sw}" stroke-dasharray="${len}" stroke-dashoffset="${len * (1 - left / total)}"/></svg>${label}`;
    el.setAttribute("role", "img");
    const words = t("time left");
    el.setAttribute("aria-label", `${fmtLeft(left)} ${words}`);
    const out = el.dataset.out ? document.getElementById(el.dataset.out) : null;
    if (out) { out.textContent = fmtLeft(left); out.classList.remove("low", "critical"); if (st && st !== "ok") out.classList.add(st); }
  }
  function paintTtls(root = document) { $$(".ttl[data-total]", root).forEach(paintTtl); }
  setInterval(() => {
    for (const el of $$(".ttl[data-live]")) { el.dataset.left = Math.max(0, +el.dataset.left - 1); paintTtl(el); }
    for (const el of $$("[data-count-down]")) {
      const v = Math.max(0, +el.dataset.countDown - 1); el.dataset.countDown = v; el.textContent = fmtLeft(v);
    }
  }, 1000);

  // ---------- Toasts ----------
  function toast(msg, opts = {}) {
    let host = $(".toasts");
    if (!host) { host = document.createElement("div"); host.className = "toasts"; host.setAttribute("role", "status"); host.setAttribute("aria-live", "polite"); document.body.append(host); }
    const el = document.createElement("div");
    el.className = "toast";
    const ring = opts.ttl ? `<span class="ttl" data-total="${opts.ttl}" data-left="${opts.ttl}" data-size="20" data-live></span>` : icon(opts.icon || "check");
    el.innerHTML = `${ring}<div class="grow"></div><button class="btn ghost sm icon-only" aria-label="Dismiss">${icon("x")}</button>`;
    el.querySelector(".grow").textContent = t(msg);
    el.querySelector("button").setAttribute("aria-label", t("Dismiss"));
    el.querySelector("button").onclick = () => el.remove();
    host.append(el);
    paintTtls(el);
    setTimeout(() => el.remove(), (opts.ttl ? Math.min(opts.ttl, 8) : 5) * 1000);
  }
  window.cerbToast = toast;

  // ---------- Hold-to-confirm ----------
  function bindHold(btn, ms, done) {
    let timer = null;
    btn.style.setProperty("--hold-ms", ms + "ms");
    const start = (e) => {
      if (timer || btn.disabled) return;
      if (e && e.type === "keydown" && !(e.key === " " || e.key === "Enter")) return;
      if (e) e.preventDefault();
      btn.classList.add("holding");
      timer = setTimeout(() => { timer = null; btn.classList.remove("holding"); done(); }, ms);
    };
    const stop = () => { if (timer) { clearTimeout(timer); timer = null; } btn.classList.remove("holding"); };
    btn.addEventListener("pointerdown", start);
    btn.addEventListener("keydown", start);
    ["pointerup", "pointerleave", "keyup", "blur"].forEach((ev) => btn.addEventListener(ev, stop));
    btn.addEventListener("click", (e) => e.preventDefault());
    return { start, stop };
  }
  window.cerbHold = bindHold;

  // ---------- Secret field ----------
  let clipboardWarned = false;
  function buildSecret(el) {
    const label = el.dataset.label || "Secret";
    const denied = el.dataset.denied === "1";
    el.classList.add("secret");
    el.innerHTML = `
      <span class="value" aria-live="polite"><span class="mask" aria-label="${t("Hidden")}">●●●●●●●●●●●●</span></span>
      <span class="hide-in"><span class="ttl" data-total="15" data-left="15" data-size="20"></span></span>
      <button class="btn ghost sm icon-only hold rev" type="button">${icon("eye")}</button>
      <button class="btn ghost sm icon-only cp" type="button">${icon("copy")}</button>`;
    const rev = $(".rev", el), cp = $(".cp", el), val = $(".value", el), ring = $(".ttl", el);
    rev.setAttribute("aria-label", `${t("Hold to reveal")}: ${t(label)}`);
    rev.title = t("Hold to reveal");
    cp.setAttribute("aria-label", `${t("Copy")}: ${t(label)}`);
    if (denied) {
      el.classList.add("denied");
      val.textContent = t("Viewers cannot reveal secrets");
      rev.disabled = true; cp.disabled = true;
      return;
    }
    let hideTimer = null, tick = null;
    const hide = () => {
      clearTimeout(hideTimer); clearInterval(tick);
      el.classList.remove("revealed");
      val.innerHTML = `<span class="mask" aria-label="${t("Hidden")}">●●●●●●●●●●●●</span>`;
      rev.innerHTML = icon("eye"); rev.setAttribute("aria-label", `${t("Hold to reveal")}: ${t(label)}`);
      rev.dataset.open = "";
    };
    const show = () => {
      el.classList.add("revealed");
      val.textContent = el.dataset.secret; // fake value only, set as text (never HTML)
      rev.innerHTML = icon("eyeOff"); rev.setAttribute("aria-label", `${t("Hide")}: ${t(label)}`);
      rev.dataset.open = "1";
      ring.dataset.left = 15; paintTtl(ring);
      tick = setInterval(() => { ring.dataset.left = +ring.dataset.left - 1; paintTtl(ring); }, 1000);
      hideTimer = setTimeout(hide, 15000);
    };
    bindHold(rev, 500, () => (rev.dataset.open ? hide() : show()));
    rev.addEventListener("click", () => { if (rev.dataset.open) hide(); });
    cp.addEventListener("click", () => {
      toast("Copied. The clipboard clears in 30 s.", { ttl: 30 });
      if (!clipboardWarned) { clipboardWarned = true; setTimeout(() => toast("Clipboard managers can keep a copy. Turn off clipboard history for safety.", { icon: "info" }), 300); }
    });
  }

  // ---------- Tabs ----------
  function bindTabs(root = document) {
    for (const list of $$("[role=tablist]", root)) {
      const tabs = $$("[role=tab]", list);
      const select = (tab, focus) => {
        tabs.forEach((x) => {
          const on = x === tab;
          x.setAttribute("aria-selected", String(on)); x.tabIndex = on ? 0 : -1;
          const p = document.getElementById(x.getAttribute("aria-controls")); if (p) p.hidden = !on;
        });
        if (focus) tab.focus();
        list.dispatchEvent(new CustomEvent("tabchange", { detail: tab }));
      };
      tabs.forEach((tab, i) => {
        tab.addEventListener("click", () => select(tab));
        tab.addEventListener("keydown", (e) => {
          const d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
          if (d) { e.preventDefault(); select(tabs[(i + d + tabs.length) % tabs.length], true); }
        });
      });
      select(tabs.find((x) => x.getAttribute("aria-selected") === "true") || tabs[0]);
    }
  }

  // ---------- Shell ----------
  const body = document.body;
  const page = body.dataset.page;
  const layout = body.dataset.layout || "app";
  const here = SCREENS.find((s) => s.page === page);

  function protoBar() {
    const bar = document.createElement("div");
    bar.className = "proto-bar";
    bar.setAttribute("role", "region");
    bar.setAttribute("aria-label", "Prototype controls");
    const variants = (body.dataset.variants || "").split(",").filter(Boolean).map((v) => v.split(":"));
    bar.innerHTML = `
      <a class="home" href="index.html">${gateSvg(16, "open")}<span>Prototype index</span></a>
      ${here ? `<span class="label">Screen ${here.n} of 11</span>` : ""}
      <span class="spacer"></span>
      ${page && page !== "index" ? `<span class="group"><span class="label" id="st-l">State</span>
      <span class="seg" role="group" aria-labelledby="st-l">
        ${["ready", "empty", "loading", "error", "locked"].map((s) => `<button type="button" data-state-btn="${s}">${s[0].toUpperCase() + s.slice(1)}</button>`).join("")}
      </span></span>` : ""}
      ${variants.length ? `<span class="group"><label class="label" for="variant-sel">Variant</label>
        <select id="variant-sel" class="input" style="height:28px;width:auto"><option value="">Default</option>${variants.map(([k, l]) => `<option value="${k}">${l}</option>`).join("")}</select></span>` : ""}
      <span class="group"><span class="label" id="th-l">Theme</span><span class="seg" role="group" aria-labelledby="th-l">
        <button type="button" data-theme-btn="dark">Dark</button><button type="button" data-theme-btn="light">Light</button></span></span>
      <span class="group"><span class="label" id="lg-l">Language</span><span class="seg" role="group" aria-labelledby="lg-l">
        <button type="button" data-lang-btn="en">EN</button><button type="button" data-lang-btn="es">ES</button></span></span>`;
    return bar;
  }

  function sidebar() {
    const aside = document.createElement("nav");
    aside.className = "sidebar";
    aside.setAttribute("aria-label", "Main");
    const links = NAV.map((p) => {
      if (p === "|") return `<div class="sep" role="presentation"></div>`;
      const s = SCREENS.find((x) => x.page === p);
      const cur = p === page || (page === "editor" && p === "vault");
      const extra = p === "approval" ? `<span class="count" aria-label="2 pending">2</span>` : s.key ? `<kbd aria-hidden="true">G ${s.key.toUpperCase()}</kbd>` : "";
      return `<a href="${s.file}" ${cur ? 'aria-current="page"' : ""}>${icon(s.icon)}<span>${s.title}</span>${extra}</a>`;
    }).join("");
    aside.innerHTML = `
      <a class="brand" href="03-dashboard.html" aria-label="Cerberus, dashboard">${gateSvg(26, "open")}<span class="word">Cerberus</span></a>
      <div class="nav">${links}</div>
      <div class="collar" aria-label="Session">
        <div class="who">
          <span class="ttl gate" data-total="1800" data-left="1661" data-size="30" data-live data-out="collar-left"></span>
          <span class="t"><span class="small">Unlocked by Ana Ruiz</span><span class="small muted">Auto-lock in <span id="collar-left" class="num">27:41</span></span></span>
        </div>
        <div class="row">
          <a class="btn sm" href="02-unlock.html" data-action="lock" title="Lock (Ctrl+L)">${icon("lock")}<span>Lock</span></a>
          <button class="btn sm danger-ghost icon-only" type="button" data-open="dlg-panic" aria-label="Lock and revoke all" title="Lock and revoke all">${icon("siren")}</button>
        </div>
      </div>`;
    return aside;
  }

  function topbar() {
    const bar = document.createElement("header");
    bar.className = "topbar";
    const title = body.dataset.title || (here && here.title) || "";
    const crumb = body.dataset.crumb ? `<span class="crumb">${body.dataset.crumb}</span>${icon("chevR", "")}` : "";
    bar.innerHTML = `${crumb}<h1 id="page-title">${title}</h1>
      <div class="actions">
        <span id="topbar-actions" style="display:contents"></span>
        <button class="palette-trigger" type="button" data-palette title="Command palette (Ctrl+K)">${icon("search")}<span class="ph">Search or run a command</span><kbd>Ctrl K</kbd></button>
      </div>`;
    return bar;
  }

  const panicDialog = `
    <dialog class="dlg" id="dlg-panic" aria-labelledby="panic-h">
      <div class="head"><h2 id="panic-h">Lock and revoke all?</h2>
      <p class="secondary">This locks the vault now, ends every active lease and cancels waiting requests. Agents get HTTP 423 until you unlock.</p></div>
      <div class="body"><div class="notice bad">${icon("alert")}<div class="grow">12 active leases end at once. Running jobs that use them will fail.</div></div></div>
      <div class="foot"><button class="btn" type="button" data-close>Cancel</button>
      <button class="btn danger hold" type="button" id="panic-go" data-hold-ms="1000">${icon("siren")}<span>Hold to lock and revoke</span></button></div>
    </dialog>`;
  const shortcutsDialog = `
    <dialog class="dlg" id="dlg-keys" aria-labelledby="keys-h">
      <div class="head"><h2 id="keys-h">Keyboard shortcuts</h2></div>
      <div class="body"><dl class="kv">
        <dt><kbd>Ctrl K</kbd></dt><dd>Open the command palette</dd>
        <dt><kbd>Ctrl L</kbd></dt><dd>Lock the vault</dd>
        <dt><kbd>G</kbd> then a letter</dt><dd>Go to: D dashboard, V vault, A agents, P policies, R approvals, L leases, U audit, S settings</dd>
        <dt><kbd>/</kbd></dt><dd>Search on this screen</dd>
        <dt><kbd>N</kbd></dt><dd>New item</dd>
        <dt><kbd>Esc</kbd></dt><dd>Close a drawer or dialog</dd>
        <dt><kbd>?</kbd></dt><dd>Show this list</dd>
      </dl></div>
      <div class="foot"><button class="btn" type="button" data-close>Close</button></div>
    </dialog>`;

  function lockedBlock() {
    const d = document.createElement("div");
    d.setAttribute("data-state", "locked");
    d.innerHTML = `<div class="state-block">
      <span data-gate="locked" data-size="72"></span>
      <h2>The vault is locked</h2>
      <p>Locked at 14:02 after 30 minutes without activity. Keys and the search index are erased. Agents get HTTP 423 until you unlock.</p>
      <div class="actions"><a class="btn primary" href="02-unlock.html">${icon("unlock")}<span>Unlock</span></a></div>
      <span class="code">vault_status: sealed</span></div>`;
    return d;
  }

  function mount() {
    const content = $("#page");
    const bar = protoBar();
    body.prepend(bar);
    const skip = document.createElement("a");
    skip.className = "skip-link"; skip.href = "#main"; skip.textContent = "Skip to content";
    body.prepend(skip);
    if (layout === "app") {
      const shell = document.createElement("div");
      shell.className = "shell";
      const work = document.createElement("div");
      work.className = "workarea";
      const main = document.createElement("main");
      main.className = "content"; main.id = "main"; main.tabIndex = -1;
      main.setAttribute("aria-labelledby", "page-title");
      while (content.firstChild) main.append(content.firstChild);
      work.append(topbar(), main);
      shell.append(sidebar(), work);
      content.replaceWith(shell);
      if (!$("[data-state~=locked]", main)) main.append(lockedBlock());
      const ta = $("template#topbar-actions-tpl");
      if (ta) $("#topbar-actions").append(ta.content.cloneNode(true));
    } else if (content) {
      content.id = content.id || "page";
      const main = document.createElement("main");
      main.id = "main"; main.tabIndex = -1;
      content.replaceWith(main); main.append(content);
      if (page !== "index" && !$("[data-state~=locked]", main) && body.dataset.noLocked === undefined) main.append(lockedBlock());
    }
    body.insertAdjacentHTML("beforeend", panicDialog + shortcutsDialog);
  }

  // ---------- States and variants ----------
  let view = params.get("state") || body.dataset.defaultState || "ready";
  function applyView() {
    body.dataset.view = view;
    $$("[data-state]").forEach((el) => el.toggleAttribute("data-off", !el.dataset.state.split(" ").includes(view)));
    $$("[data-state-btn]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.stateBtn === view)));
    const sb = $(".sidebar");
    if (sb) sb.toggleAttribute("inert", view === "locked");
    document.dispatchEvent(new CustomEvent("cerb:view", { detail: view }));
  }
  let variant = params.get("variant") || "";
  function applyVariant() {
    body.dataset.variant = variant;
    $$("[data-variant-show]").forEach((el) => { el.hidden = !el.dataset.variantShow.split(" ").includes(variant); });
    $$("[data-variant-hide]").forEach((el) => { el.hidden = el.dataset.variantHide.split(" ").includes(variant); });
    const sel = $("#variant-sel"); if (sel) sel.value = variant;
    document.dispatchEvent(new CustomEvent("cerb:variant", { detail: variant }));
  }

  // ---------- Command palette ----------
  const ACTIONS = [
    ...SCREENS.filter((s) => s.page !== "create" && s.page !== "unlock").map((s) => ({ g: "Go to", label: s.title, icon: s.icon, href: s.file, keys: s.key ? ["G", s.key.toUpperCase()] : null })),
    { g: "Create", label: "New item", icon: "plus", href: "05-item-editor.html", keys: ["N"] },
    { g: "Create", label: "New agent", icon: "bot", href: "06-agents.html?variant=token" },
    { g: "Create", label: "New grant", icon: "policy", href: "07-policies.html" },
    { g: "Vault", label: "Lock vault", icon: "lock", href: "02-unlock.html", keys: ["Ctrl", "L"] },
    { g: "Vault", label: "Lock and revoke all", icon: "siren", dialog: "dlg-panic", danger: true },
    { g: "Vault", label: "Verify audit chain", icon: "hash", href: "10-audit.html" },
    { g: "Vault", label: "Export CA certificate", icon: "download", href: "11-settings.html#network" },
    { g: "Vault", label: "Create backup", icon: "download", href: "11-settings.html#backup" },
    { g: "View", label: "Switch theme", icon: "moon", run: () => { theme = theme === "dark" ? "light" : "dark"; store.set("theme", theme); applyTheme(); } },
    { g: "View", label: "Switch language", icon: "languages", run: () => { lang = lang === "en" ? "es" : "en"; store.set("lang", lang); applyLang(); } },
    { g: "View", label: "Keyboard shortcuts", icon: "command", dialog: "dlg-keys", keys: ["?"] }
  ];
  function openPalette() {
    let dlg = $("#palette");
    if (!dlg) {
      dlg = document.createElement("dialog");
      dlg.id = "palette"; dlg.className = "dlg palette"; dlg.setAttribute("aria-label", "Command palette");
      dlg.innerHTML = `<div class="search">${icon("search", "lg")}<input id="pal-q" role="combobox" aria-expanded="true" aria-controls="pal-list" aria-autocomplete="list" placeholder="Type a command or a screen" autocomplete="off"></div>
        <ul id="pal-list" role="listbox" aria-label="Commands"></ul>
        <div class="foot"><span><kbd>↑</kbd> <kbd>↓</kbd> move</span><span><kbd>Enter</kbd> run</span><span><kbd>Esc</kbd> close</span></div>`;
      document.body.append(dlg);
      const q = $("#pal-q", dlg), list = $("#pal-list", dlg);
      let sel = 0, shown = [];
      const render = () => {
        const term = q.value.trim().toLowerCase();
        shown = ACTIONS.filter((a) => !term || t(a.label).toLowerCase().includes(term) || a.label.toLowerCase().includes(term));
        sel = Math.min(sel, Math.max(0, shown.length - 1));
        let lastG = "", html = "";
        shown.forEach((a, i) => {
          if (a.g !== lastG) { html += `<li class="group" role="presentation">${t(a.g)}</li>`; lastG = a.g; }
          html += `<li role="option" id="pal-${i}" aria-selected="${i === sel}" class="${a.danger ? "danger" : ""}" data-i="${i}">${icon(a.icon)}<span>${t(a.label)}</span>${a.keys ? `<span class="hint">${a.keys.map((k) => `<kbd>${k}</kbd>`).join("")}</span>` : ""}</li>`;
        });
        list.innerHTML = html || `<li class="group" role="presentation">${t("No command matches. Try a screen name.")}</li>`;
        q.setAttribute("aria-activedescendant", shown.length ? `pal-${sel}` : "");
        const cur = $(`#pal-${sel}`, list); if (cur) cur.scrollIntoView({ block: "nearest" });
      };
      const run = (a) => {
        dlg.close();
        if (!a) return;
        if (a.href) location.href = a.href;
        else if (a.dialog) document.getElementById(a.dialog).showModal();
        else if (a.run) a.run();
      };
      q.addEventListener("input", () => { sel = 0; render(); });
      q.addEventListener("keydown", (e) => {
        if (e.key === "ArrowDown") { e.preventDefault(); sel = (sel + 1) % Math.max(1, shown.length); render(); }
        if (e.key === "ArrowUp") { e.preventDefault(); sel = (sel - 1 + shown.length) % Math.max(1, shown.length); render(); }
        if (e.key === "Enter") { e.preventDefault(); run(shown[sel]); }
      });
      list.addEventListener("click", (e) => { const li = e.target.closest("[data-i]"); if (li) run(shown[+li.dataset.i]); });
      dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
      dlg._render = render;
    }
    $("#pal-q", dlg).value = "";
    dlg._render();
    dlg.showModal();
    $("#pal-q", dlg).focus();
  }
  window.cerbPalette = openPalette;

  // ---------- Keyboard map ----------
  let gPending = 0;
  document.addEventListener("keydown", (e) => {
    const mod = e.ctrlKey || e.metaKey;
    const typing = e.target.closest && e.target.closest("input,textarea,select,[contenteditable]");
    if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); return; }
    if (mod && e.key.toLowerCase() === "l" && layout === "app") { e.preventDefault(); location.href = "02-unlock.html"; return; }
    if (typing || mod || e.altKey || $("dialog[open]")) return;
    if (gPending && Date.now() - gPending < 1200) {
      gPending = 0;
      const s = SCREENS.find((x) => x.key === e.key.toLowerCase());
      if (s) { e.preventDefault(); location.href = s.file; }
      return;
    }
    if (e.key === "g") { gPending = Date.now(); return; }
    if (e.key === "/") { const s = $("[data-search]"); if (s) { e.preventDefault(); s.focus(); } return; }
    if (e.key === "?") { e.preventDefault(); $("#dlg-keys").showModal(); return; }
    if (e.key === "n" && layout === "app") { location.href = "05-item-editor.html"; }
  });

  // ---------- Generic wiring ----------
  function wire() {
    document.addEventListener("click", (e) => {
      const st = e.target.closest("[data-state-btn]");
      if (st) { view = st.dataset.stateBtn; applyView(); return; }
      const th = e.target.closest("[data-theme-btn]");
      if (th) { theme = th.dataset.themeBtn; store.set("theme", theme); applyTheme(); return; }
      const lg = e.target.closest("[data-lang-btn]");
      if (lg) { lang = lg.dataset.langBtn; store.set("lang", lang); applyLang(); return; }
      const cl = e.target.closest("[data-close]");
      if (cl && cl.closest("dialog")) cl.closest("dialog").close();
      const op = e.target.closest("[data-open]");
      if (op) { const d = document.getElementById(op.dataset.open); if (d) { e.preventDefault(); d.showModal(); } }
      const pt = e.target.closest("[data-palette]");
      if (pt) { openPalette(); return; }
      const ts = e.target.closest("[data-toast]");
      if (ts) { toast(ts.dataset.toast, { icon: ts.dataset.toastIcon || "check" }); }
      const sv = e.target.closest("[data-set-view]");
      if (sv) { view = sv.dataset.setView; applyView(); }
    });
    const vs = $("#variant-sel");
    if (vs) vs.addEventListener("change", () => { variant = vs.value; applyVariant(); });
    for (const b of $$(".btn.hold[data-hold-ms]")) {
      bindHold(b, +b.dataset.holdMs, () => {
        if (b.id === "panic-go") { location.href = "02-unlock.html?variant=panic"; return; }
        b.dispatchEvent(new CustomEvent("hold-done", { bubbles: true }));
      });
    }
    $$("[data-secret]").forEach(buildSecret);
    bindTabs();
    for (const p of $$("button[aria-pressed]:not([data-state-btn]):not([data-theme-btn]):not([data-lang-btn])")) {
      if (p.closest("[data-single]")) {
        p.addEventListener("click", () => {
          $$("button[aria-pressed]", p.closest("[data-single]")).forEach((x) => x.setAttribute("aria-pressed", String(x === p)));
        });
      } else if (p.classList.contains("chip")) {
        p.addEventListener("click", () => p.setAttribute("aria-pressed", String(p.getAttribute("aria-pressed") !== "true")));
      }
    }
  }

  // Public helpers for screen scripts.
  window.Cerb = { $, $$, icon, toast, paintIcons, paintTtls, paintGates, translate: () => applyLang(), t, fmt: fmtLeft, reduced, setView: (v) => { view = v; applyView(); } };

  mount();
  paintIcons(); paintGates(); paintTtls();
  wire();
  applyTheme(); applyView(); applyVariant(); applyLang();
  document.dispatchEvent(new CustomEvent("cerb:ready"));
})();
