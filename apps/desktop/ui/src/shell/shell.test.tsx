import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import { renderApp } from "../test/renderApp";
import { watchZoom } from "../test/zoom";
import { handlers as auditHandlers } from "../screens/audit/mock";
import { createFlowStore } from "./createFlow";
import { buildCommands, filterCommands } from "./commands";
import { resolveRoute } from "./guard";
import { normalizeHash, splitQuery } from "./location";
import { screenForPath, SCREENS } from "./screens";

describe("route guard", () => {
  const vault = screenForPath("/vault");
  const unlock = screenForPath("/unlock");
  const create = screenForPath("/create");
  it("routes each vault state (IA section 1)", () => {
    expect(resolveRoute("no_vault", vault)).toBe("/create");
    expect(resolveRoute("no_vault", create)).toBeNull();
    expect(resolveRoute("no_vault", unlock)).toBeNull();
    expect(resolveRoute("sealed", vault)).toBe("/unlock");
    expect(resolveRoute("sealed", create)).toBe("/unlock");
    expect(resolveRoute("sealed", unlock)).toBeNull();
    expect(resolveRoute("unlocked", unlock)).toBe("/dashboard");
    expect(resolveRoute("unlocked", vault)).toBeNull();
    expect(resolveRoute("unlocked", null)).toBe("/dashboard");
    expect(resolveRoute("locking", vault)).toBeNull();
  });
  it("closes the create screen while a failed restore stranded the vault (T27-G)", () => {
    expect(resolveRoute("no_vault", create, false, true)).toBe("/unlock");
    expect(resolveRoute("no_vault", vault, false, true)).toBe("/unlock");
    expect(resolveRoute("no_vault", null, false, true)).toBe("/unlock");
    expect(resolveRoute("no_vault", unlock, false, true)).toBeNull();
  });
  it("keeps create on an open vault only while the create flow runs", () => {
    expect(resolveRoute("unlocked", create)).toBe("/dashboard");
    expect(resolveRoute("unlocked", create, false)).toBe("/dashboard");
    expect(resolveRoute("unlocked", create, true)).toBeNull();
    expect(resolveRoute("unlocked", vault, true)).toBeNull();
    expect(resolveRoute("unlocked", unlock, true)).toBe("/dashboard");
    expect(resolveRoute("sealed", create, true)).toBe("/unlock");
  });
  it("owns sub-paths and knows all 11 screens", () => {
    expect(screenForPath("/vault/anything")?.id).toBe("vault");
    expect(screenForPath("/editor/new")?.id).toBe("editor");
    expect(SCREENS).toHaveLength(11);
    expect(normalizeHash("#approval")).toBe("/approval");
    expect(normalizeHash("")).toBe("/");
  });
  it("matches a screen with a query in the location", () => {
    expect(screenForPath("/agents?new=1")?.id).toBe("agents");
    expect(screenForPath("/vault?item=it_1")?.id).toBe("vault");
    expect(screenForPath("/vault/x?item=it_1")?.id).toBe("vault");
    expect(screenForPath("/agentsx?new=1")).toBeNull();
    expect(splitQuery("/agents?agent=a&new=1")).toEqual({ path: "/agents", query: "agent=a&new=1" });
    expect(splitQuery("/agents")).toEqual({ path: "/agents", query: "" });
  });
});

describe("lock routing in the app", () => {
  it("unlocked goes to the dashboard inside the shell", async () => {
    const { location } = renderApp({ state: "unlocked", handlers: auditHandlers });
    expect(await screen.findByRole("heading", { level: 1, name: "Dashboard" })).toBeInTheDocument();
    expect(location.history?.at(-1)).toBe("/dashboard");
    expect(screen.getByRole("region", { name: "Dashboard" })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Vault unlocked" })).toBeInTheDocument();
    expect(await screen.findByText("Unlocked by Ana Ruiz")).toBeInTheDocument();
  });

  it("sealed goes to the unlock screen with no rail", async () => {
    const { location } = renderApp({ state: "sealed", path: "/vault" });
    expect(await screen.findByRole("heading", { level: 1, name: "Cerberus is locked" })).toBeInTheDocument();
    expect(location.history?.at(-1)).toBe("/unlock");
    expect(screen.queryByRole("navigation", { name: "Main" })).toBeNull();
  });

  it("no vault goes to create", async () => {
    const { location } = renderApp({ state: "no_vault", path: "/dashboard" });
    expect(await screen.findByRole("heading", { level: 1, name: "Create your vault" })).toBeInTheDocument();
    expect(location.history?.at(-1)).toBe("/create");
  });

  it("keeps a deep link with a query instead of redirecting", async () => {
    const { location } = renderApp({ state: "unlocked", path: "/vault?item=it_1" });
    expect(await screen.findByRole("heading", { level: 1, name: "Vault" })).toBeInTheDocument();
    expect(location.history).toEqual(["/vault?item=it_1"]);
  });

  it("keeps the create screen on an open vault while the create flow runs, then leaves", async () => {
    const { location } = renderApp({ state: "unlocked", path: "/create" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    expect(location.history?.at(-1)).toBe("/dashboard");
    await act(async () => {
      createFlowStore.set(true);
      location.navigate("/create");
    });
    expect(await screen.findByRole("heading", { level: 1, name: "Create your vault" })).toBeInTheDocument();
    expect(location.history?.at(-1)).toBe("/create");
    await act(async () => createFlowStore.set(false));
    await waitFor(() => expect(location.history?.at(-1)).toBe("/dashboard"));
  });

  it("locks at once when the backend says the vault sealed, and drops cached data", async () => {
    const { mock, location, queryClient } = renderApp({ state: "unlocked", path: "/agents" });
    await screen.findByRole("heading", { level: 1, name: "Agents" });
    queryClient.setQueryData(["agents", "x"], ["cached"]);
    await act(async () => {
      await mock.setState("sealed");
    });
    await waitFor(() => expect(location.history?.at(-1)).toBe("/unlock"));
    expect(queryClient.getQueryData(["agents", "x"])).toBeUndefined();
  });

  it("shows the locked state while locking", async () => {
    renderApp({ state: "locking", path: "/dashboard" });
    expect(await screen.findByText("Cerberus is locked")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unlock" })).toBeInTheDocument();
  });

  it("the collar says the vault is locking and hides Lock and panic", async () => {
    renderApp({ state: "locking", path: "/dashboard" });
    const collar = await screen.findByRole("group", { name: "Session" });
    expect(within(collar).getByText("Vault locking")).toBeInTheDocument();
    expect(within(collar).queryByRole("button", { name: "Lock" })).toBeNull();
    expect(within(collar).queryByRole("button", { name: "Lock and revoke all" })).toBeNull();
  });

  it("shows the auto-lock countdown once, in the collar", async () => {
    renderApp({ state: "unlocked", path: "/agents" });
    await screen.findByRole("heading", { level: 1, name: "Agents" });
    const collar = screen.getByRole("group", { name: "Session" });
    await waitFor(() => expect(within(collar).getByText(/Auto-lock/)).toBeInTheDocument());
    expect(screen.getAllByText(/Auto-lock/)).toHaveLength(1);
  });

  it("the Lock button calls vault_lock and the guard moves to unlock", async () => {
    const user = userEvent.setup();
    const { location } = renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.click(screen.getByRole("button", { name: "Lock" }));
    await waitFor(() => expect(location.history?.at(-1)).toBe("/unlock"));
  });

  it("shows the pending count on Approvals", async () => {
    renderApp({
      handlers: { request_list_pending: () => [{ id: "r1" }, { id: "r2" }] },
    });
    const link = await screen.findByRole("link", { name: /Approvals/ });
    await waitFor(() => expect(within(link).getByLabelText("2")).toBeInTheDocument());
  });

  it("an unreadable status gives an error state with retry", async () => {
    renderApp({ handlers: { vault_status: () => { throw { code: "internal", message: "x", retry_after_seconds: null, fields: [] }; } } });
    expect(await screen.findByRole("heading", { name: "Cannot read the vault status" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});

describe("navigation", () => {
  it("G then V goes to the vault; keys are ignored in a field", async () => {
    const user = userEvent.setup();
    const { location } = renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.keyboard("gv");
    await waitFor(() => expect(location.history?.at(-1)).toBe("/vault"));
    await user.keyboard("{Control>}k{/Control}");
    const box = await screen.findByRole("combobox");
    await user.type(box, "ga");
    expect(location.history?.at(-1)).toBe("/vault");
  });

  it("the rail marks the current screen and the editor marks Vault", async () => {
    renderApp({ path: "/editor/new" });
    await screen.findByRole("heading", { level: 1, name: "Item editor" });
    expect(screen.getByRole("link", { name: /^Vault/ })).toHaveAttribute("aria-current", "page");
  });
});

describe("command palette", () => {
  it("opens with Ctrl+K, filters, moves with arrows and runs with Enter", async () => {
    const user = userEvent.setup();
    const { location } = renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.keyboard("{Control>}k{/Control}");
    const box = await screen.findByRole("combobox");
    expect(box).toHaveFocus();
    expect(screen.getAllByRole("option").length).toBeGreaterThan(10);

    await user.type(box, "leases");
    expect(screen.getAllByRole("option")).toHaveLength(1);
    expect(box).toHaveAttribute("aria-activedescendant", screen.getByRole("option").id);
    await user.keyboard("{Enter}");
    await waitFor(() => expect(location.history?.at(-1)).toBe("/leases"));
    expect(screen.queryByRole("combobox", { name: "Search items, agents and actions" })).toBeNull();
  });

  it("ArrowDown moves the active option and Esc closes", async () => {
    const user = userEvent.setup();
    renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.keyboard("{Control>}k{/Control}");
    await screen.findByRole("combobox");
    const options = screen.getAllByRole("option");
    expect(options[0]).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{ArrowDown}");
    expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("combobox")).toBeNull());
  });

  it("has actions for CSV import and the connect guide", async () => {
    const user = userEvent.setup();
    const { location } = renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.keyboard("{Control>}k{/Control}");
    await user.type(await screen.findByRole("combobox"), "bitwarden");
    expect(screen.getByRole("option", { name: /Import items from CSV/ })).toBeInTheDocument();
    await user.clear(screen.getByRole("combobox"));
    await user.type(screen.getByRole("combobox"), "connect an agent");
    await user.keyboard("{Enter}");
    await waitFor(() => expect(location.history?.at(-1)).toBe("/dashboard?connect=1"));
  });

  it("the search button is named by its visible text", async () => {
    renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    expect(screen.getByRole("button", { name: "Search or run a command" })).toHaveAttribute("aria-keyshortcuts", "Control+K Meta+K");
  });

  it("shows no results text", async () => {
    const user = userEvent.setup();
    renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.keyboard("{Control>}k{/Control}");
    await user.type(await screen.findByRole("combobox"), "zzzzzz");
    expect(screen.getByText("No results")).toBeInTheDocument();
  });

  it("panic is a palette action that opens the hold dialog and has no shortcut", async () => {
    const user = userEvent.setup();
    renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.keyboard("{Control>}k{/Control}");
    await user.type(await screen.findByRole("combobox"), "revoke");
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("dialog", { name: "Lock and revoke all?" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Hold to lock and revoke" })).toBeInTheDocument();
  });

  it("the shortcut list shows the zoom keys, and the zoom keys leave Ctrl+K and Ctrl+L alone", async () => {
    const user = userEvent.setup();
    const zoom = watchZoom();
    try {
      renderApp({ state: "unlocked" });
      await screen.findByRole("heading", { level: 1, name: "Dashboard" });
      await user.keyboard("?");
      const dialog = await screen.findByRole("dialog", { name: "Keyboard shortcuts" });
      for (const label of ["Zoom in", "Zoom out", "Reset zoom to 100%"]) expect(within(dialog).getByText(label)).toBeInTheDocument();
      expect(within(dialog).getAllByText("+")).toHaveLength(1);
      await user.keyboard("{Escape}");
      await user.keyboard("{Control>}={/Control}");
      expect(zoom.value).toBe("1.1");
      await user.keyboard("{Control>}k{/Control}");
      expect(await screen.findByRole("combobox")).toBeInTheDocument();
    } finally {
      zoom.stop();
    }
  });

  it("command list helpers", () => {
    const cmds = buildCommands({ navigate: () => undefined, lock: () => undefined, panic: () => undefined, verifyAudit: () => undefined, exportCa: () => undefined, createBackup: () => undefined, cycleTheme: () => undefined, showShortcuts: () => undefined, themeLabel: "Theme: dark" });
    expect(filterCommands(cmds, "ca cert").map((c) => c.id)).toEqual(["export-ca"]);
    expect(cmds.find((c) => c.id === "panic")?.keys).toBeUndefined();
  });
});

describe("accessibility", () => {
  it("the unlocked shell has no axe violations", async () => {
    const { container } = renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    expect(await axe(container)).toHaveNoViolations();
  });

  it("the open palette has no axe violations", async () => {
    const user = userEvent.setup();
    renderApp({ state: "unlocked" });
    await screen.findByRole("heading", { level: 1, name: "Dashboard" });
    await user.keyboard("{Control>}k{/Control}");
    await screen.findByRole("combobox");
    expect(await axe(document.body)).toHaveNoViolations();
  });

  it("the unlock screen has no axe violations", async () => {
    const { container } = renderApp({ state: "sealed" });
    await screen.findByRole("heading", { level: 1, name: "Cerberus is locked" });
    expect(await axe(container)).toHaveNoViolations();
  });
});
