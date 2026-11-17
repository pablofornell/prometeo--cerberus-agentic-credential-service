import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import type { VaultStatusView_Serialize } from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { handlers as auditHandlers, brokenReport } from "../audit/mock";
import { cliSnippets, mcpSnippets, restSnippets, serverUrl } from "./snippets";

const base: MockHandlers = auditHandlers;
const UNLOCKED: VaultStatusView_Serialize = {
  state: "unlocked",
  operator: "op-ana",
  role: "owner",
  idle_seconds_left: 100,
  hard_lock_at: null,
  memlock_ok: true,
  os_hook_ok: true,
  header_ok: true,
  kdf: { m_cost_kib: 262_144, t_cost: 3, p_cost: 4 },
  last_lock_reason: null,
  failed_unlocks: 0,
  free_unlock_tries_left: 5,
  retry_after_seconds: null,
  stranded_restore: [],
};
const open = (extra: MockHandlers = {}, options: { role?: "owner" | "operator" | "viewer" } = {}) =>
  renderApp({ path: "/dashboard", handlers: { ...base, ...extra }, ...options });

describe("dashboard ready", () => {
  it("shows the lock band, approvals, health, feed and expiring items", async () => {
    open();
    expect(await screen.findByRole("heading", { name: "Vault unlocked" })).toBeInTheDocument();
    expect(await screen.findByText("2 requests wait for you", {})).toBeInTheDocument();
    expect(screen.getByText("3 agents active")).toBeInTheDocument();
    const queue = screen.getByRole("region", { name: "Waiting for you" });
    expect(within(queue).getByText("Shop admin login")).toBeInTheDocument();
    expect(within(queue).getByText("prod")).toBeInTheDocument();
    const health = screen.getByRole("region", { name: "Health" });
    expect(await within(health).findByText("Audit chain OK", {})).toBeInTheDocument();
    expect(within(health).getByText(/TLS certificate valid for 8\d days/)).toBeInTheDocument();
    expect(within(health).getByText("Memory lock on")).toBeInTheDocument();
    expect(within(health).getByText("Unlock cost 256 MiB, 3 passes")).toBeInTheDocument();
    const feed = screen.getByRole("region", { name: "Live agent feed" });
    expect(await within(feed).findAllByText("QA runner", {})).not.toHaveLength(0);
    const expires = screen.getByRole("region", { name: "Expires soon" });
    expect(within(expires).getByText("Checkout session token")).toBeInTheDocument();
    expect(screen.getAllByText(/Auto-lock in/).length).toBeGreaterThan(0);
  });

  it("has no axe violations", async () => {
    const { container } = open();
    await screen.findByText("2 requests wait for you");
    await screen.findByText("Audit chain OK");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("adds a live agent event to the feed and raises a mass-read alert", async () => {
    const { mock } = open({ audit_query: () => [] });
    await screen.findByText("No agent calls yet. They show here as they happen.");
    await act(async () => {
      await mock.emit("agent-activity", { agent_id: "agent-rel", event_type: "item.reveal", item_id: "it-deploy", at: new Date().toISOString() });
      await mock.emit("mass-read-alert", { agent_id: "agent-qa", distinct_items: 31 });
    });
    const feed = screen.getByRole("region", { name: "Live agent feed" });
    expect(await within(feed).findByText("Release bot")).toBeInTheDocument();
    expect(within(feed).getByText("build-01 deploy key")).toBeInTheDocument();
    expect(await screen.findByRole("alert")).toHaveTextContent("QA runner read 31 different items in the last hour.");
  });

  it("shows the quiet parts as plain lines", async () => {
    open({ lease_list: () => [], request_list_pending: () => [], audit_query: () => [] });
    expect(await screen.findByText(/Nothing waits for you/)).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Expires soon" })).toHaveTextContent("Checkout session token");
  });

  it("warns when the certificate ends soon", async () => {
    window.history.replaceState(null, "", "/?scenario=cert-soon");
    open();
    expect(await screen.findByText(/TLS certificate ends in 1\d days/)).toBeInTheDocument();
    window.history.replaceState(null, "", "/");
  });
});

describe("dashboard integrity", () => {
  it("shows the broken chain at its position, in the alert and in health", async () => {
    open({ audit_verify: () => brokenReport(3977) });
    const alerts = await screen.findAllByRole("alert");
    expect(alerts.some((a) => a.textContent?.includes("The audit chain is broken at event 3,977."))).toBe(true);
    const health = screen.getByRole("region", { name: "Health" });
    expect(await within(health).findByText("Audit chain broken at event 3,977")).toBeInTheDocument();
  });

  it("shows a header alert when the vault header check failed", async () => {
    open({
      vault_status: () => ({ ...UNLOCKED, memlock_ok: false, os_hook_ok: false, header_ok: false }),
    });
    expect(await screen.findByText("The vault header check failed at unlock.")).toBeInTheDocument();
    expect(screen.getByText("Memory lock off")).toBeInTheDocument();
    expect(screen.getByText("Screen lock hook off")).toBeInTheDocument();
  });
});

describe("dashboard unlock cost", () => {
  it("says so when the session has no passphrase cost", async () => {
    open({ vault_status: () => ({ ...UNLOCKED, kdf: null }) });
    const health = await screen.findByRole("region", { name: "Health" });
    expect(within(health).getByText("Unlock cost not shown")).toBeInTheDocument();
    expect(within(health).queryByText(/Unlock cost: /)).not.toBeInTheDocument();
  });
});

describe("dashboard states", () => {
  it("shows the empty state with first steps and the guide link", async () => {
    const { container } = open({ agent_list: () => [], item_list: () => [] });
    expect(await screen.findByRole("heading", { name: "The gate is ready. Nothing passes yet." })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New agent" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Read how to connect an agent" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows a loading state first", async () => {
    open({ agent_list: () => new Promise(() => undefined) });
    expect((await screen.findAllByRole("status", { name: "Loading the dashboard" })).length).toBeGreaterThan(0);
  });

  it("shows an error with a retry and the command line", async () => {
    let fail = true;
    open({
      agent_list: () => {
        if (fail) throw mockError("internal", "boom");
        return [];
      },
    });
    expect(await screen.findByRole("heading", { name: "Cannot load the dashboard" })).toBeInTheDocument();
    expect(screen.getByText("agent_list: internal")).toBeInTheDocument();
    fail = false;
    await userEvent.setup().click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Cannot load the dashboard" })).toBeNull());
  });

  it("is locked: the guard shows the locked state while locking", async () => {
    renderApp({ state: "locking", path: "/dashboard", handlers: base });
    expect(await screen.findByText("Cerberus is locked")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Vault unlocked" })).toBeNull();
  });

  it("viewer: reads everything, sees a note, and cannot create a token", async () => {
    const user = userEvent.setup();
    open({}, { role: "viewer" });
    expect(await screen.findByText(/signed in as a viewer/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Connect an agent" }));
    const dialog = await screen.findByRole("dialog", { name: "Connect an agent" });
    expect(await within(dialog).findByRole("button", { name: "Open Agents and create a token" })).toBeDisabled();
  });
});

describe("connect an agent guide", () => {
  it("opens at once from the palette deep link ?connect=1", async () => {
    renderApp({ path: "/dashboard?connect=1", handlers: base });
    expect(await screen.findByRole("dialog", { name: "Connect an agent" })).toBeInTheDocument();
  });

  it("shows the kind of each waiting item (T21)", async () => {
    open();
    const queue = await screen.findByRole("region", { name: "Waiting for you" });
    await within(queue).findByText("Shop admin login");
    expect(within(queue).getAllByText(/^(Web login|API key|SSH key|Session token|Browser session|Database|Cloud|Certificate|Env bundle|Note)(, role .+)?$/).length).toBeGreaterThan(0);
  });

  it("says what each waiting request wants in plain words", async () => {
    open();
    const queue = await screen.findByRole("region", { name: "Waiting for you" });
    expect(await within(queue).findByText(/QA runner wants to read for 15 minutes/)).toBeInTheDocument();
  });

  it("shows the address, CA fingerprint and MCP, REST and CLI snippets without a token", async () => {
    const user = userEvent.setup();
    const { location } = open();
    await screen.findByText("2 requests wait for you");
    await user.click(screen.getByRole("button", { name: "Connect an agent" }));
    const dialog = await screen.findByRole("dialog", { name: "Connect an agent" });
    expect(await within(dialog).findByText("https://127.0.0.1:7373")).toBeInTheDocument();
    expect(within(dialog).getByText(/3f9a1c0be2d74a86/)).toBeInTheDocument();
    expect(within(dialog).getByText(/"command": "cerberus-mcp"/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("tab", { name: "REST" }));
    expect(within(dialog).getAllByText(/Bearer \$CERBERUS_TOKEN/).length).toBeGreaterThan(0);
    await user.click(within(dialog).getByRole("tab", { name: "CLI" }));
    expect(within(dialog).getByText(/cerberus run --app shop/)).toBeInTheDocument();
    expect(dialog.textContent).not.toMatch(/cvt_/);
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Open Agents and create a token" }));
    await waitFor(() => expect(location.history?.at(-1)).toBe("/agents?new=1"));
  });

  it("shows an error when the server address cannot be read", async () => {
    const user = userEvent.setup();
    open({ network_status: () => { throw mockError("internal", "x"); } });
    await user.click(await screen.findByRole("button", { name: "Connect an agent" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByRole("heading", { name: "Cannot read the server address" })).toBeInTheDocument();
  });
});

describe("snippets", () => {
  it("builds addresses, brackets IPv6 and never holds a token", () => {
    expect(serverUrl({ bind: ["0.0.0.0"], port: 9000 })).toBe("https://127.0.0.1:9000");
    expect(serverUrl({ bind: ["::1"], port: 7373 })).toBe("https://[::1]:7373");
    const all = [...mcpSnippets("https://127.0.0.1:7373", "sha256/x"), ...restSnippets("https://127.0.0.1:7373"), ...cliSnippets("https://127.0.0.1:7373", "sha256/x")];
    expect(all.map((s) => s.code).join("\n")).not.toMatch(/cvt_/);
    expect(JSON.parse(mcpSnippets("https://127.0.0.1:7373", "sha256/x")[0]?.code ?? "{}").mcpServers.cerberus.command).toBe("cerberus-mcp");
  });
});
