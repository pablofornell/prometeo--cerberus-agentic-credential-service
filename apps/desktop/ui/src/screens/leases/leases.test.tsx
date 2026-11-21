import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import { mockError } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { recordedHandlers } from "../agents/testkit";

describe("Leases screen", () => {
  it("lists leases with agent, item, source and time, and has no axe violations", async () => {
    const { handlers } = recordedHandlers();
    const { container } = renderApp({ path: "/leases", handlers });
    expect(await screen.findByRole("heading", { name: "6 active leases" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Active leases" });
    const first = within(table).getAllByRole("row")[1] as HTMLElement;
    expect(within(first).getByText("QA runner")).toBeInTheDocument();
    expect(within(first).getByText("Shop staging admin")).toBeInTheDocument();
    expect(within(table).getByText("Your approval", { selector: "td" })).toBeInTheDocument();
    // Five end first; the rest wait behind "Show all".
    expect(within(table).getAllByRole("row")).toHaveLength(6);
    await userEvent.setup().click(screen.getByRole("button", { name: "Show all 6" }));
    expect(within(table).getAllByRole("row")).toHaveLength(7);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("revokes one lease", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/leases", handlers });
    await user.click(await screen.findByRole("button", { name: "Revoke lease of QA runner for Shop staging admin" }));
    await waitFor(() => expect(calls.lease_revoke).toEqual([{ lease: "lse_1" }]));
    expect(await screen.findByRole("heading", { name: "5 active leases" })).toBeInTheDocument();
  });

  it("revokes all leases only after a confirm", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/leases", handlers });
    await user.click(await screen.findByRole("button", { name: "Revoke all leases" }));
    const dialog = await screen.findByRole("dialog", { name: "Revoke all 6 leases?" });
    expect(calls.lease_revoke_all).toBeUndefined();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.click(within(dialog).getByRole("button", { name: "Revoke all leases" }));
    await waitFor(() => expect(calls.lease_revoke_all).toHaveLength(1));
    expect(await screen.findByText("6 leases revoked.")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "No agent holds access now" })).toBeInTheDocument();
  });

  it("Lock and revoke all needs a hold before it calls vault_panic", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers({ vault_panic: async (_args, ctl) => { await ctl.setState("sealed"); return null; } });
    renderApp({ path: "/leases", handlers });
    const band = within(await screen.findByRole("region", { name: "Stop all access now" }));
    await user.click(band.getByRole("button", { name: "Lock and revoke all" }));
    const dialog = await screen.findByRole("dialog", { name: "Lock and revoke all?" });
    const hold = within(dialog).getByRole("button", { name: "Hold to lock and revoke" });
    await user.click(hold);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 300));
    });
    expect(calls.vault_panic).toBeUndefined();
    hold.focus();
    await user.keyboard("{Enter>}");
    await waitFor(() => expect(calls.vault_panic).toHaveLength(1));
  });

  it("shows session items and deletes one after a confirm", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/leases", handlers });
    const list = await screen.findByRole("list", { name: "Session items" });
    expect(within(list).getByText("Checkout session token")).toBeInTheDocument();
    expect(within(list).getByText(/Stored by Docs writer, ends in/)).toBeInTheDocument();
    await user.click(within(list).getByRole("button", { name: "Delete now: Checkout session token" }));
    await user.click(within(await screen.findByRole("dialog", { name: "Delete this session item?" })).getByRole("button", { name: "Delete session item" }));
    await waitFor(() => expect(calls.item_delete).toEqual([{ item: "it-session" }]));
  });

  it("context menu: a lease row revokes, a session item deletes through the same confirm", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/leases", handlers });
    const table = await screen.findByRole("table", { name: "Active leases" });
    fireEvent.contextMenu(within(table).getAllByRole("row")[1] as HTMLElement, { clientX: 20, clientY: 20 });
    await user.click(await screen.findByRole("menuitem", { name: "Revoke" }));
    await waitFor(() => expect(calls.lease_revoke).toEqual([{ lease: "lse_1" }]));

    const list = await screen.findByRole("list", { name: "Session items" });
    fireEvent.contextMenu(within(list).getAllByRole("listitem")[0] as HTMLElement, { clientX: 20, clientY: 20 });
    await user.click(await screen.findByRole("menuitem", { name: "Delete now" }));
    expect(calls.item_delete).toBeUndefined();
    await user.click(within(await screen.findByRole("dialog", { name: "Delete this session item?" })).getByRole("button", { name: "Delete session item" }));
    await waitFor(() => expect(calls.item_delete).toEqual([{ item: "it-session" }]));
  });

  it("lets a viewer revoke leases and lock, but not delete session items", async () => {
    const { handlers } = recordedHandlers();
    renderApp({ path: "/leases", role: "viewer", handlers });
    expect(await screen.findByRole("heading", { name: "6 active leases" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Revoke lease of/ }).length).toBeGreaterThan(0);
    expect(within(screen.getByRole("region", { name: "Stop all access now" })).getByRole("button", { name: "Lock and revoke all" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: /^Delete now/ })).toBeNull();
    expect(screen.getByText(/You are a viewer/)).toBeInTheDocument();
  });

  it("covers empty, loading and error states, and keeps the stop band in each", async () => {
    const empty = recordedHandlers({ lease_list: () => [] });
    const a = renderApp({ path: "/leases", handlers: empty.handlers });
    expect(await screen.findByRole("heading", { name: "No agent holds access now" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke all leases" })).toBeDisabled();
    expect(await axe(a.container)).toHaveNoViolations();
    a.unmount();

    const slow = recordedHandlers({ lease_list: () => new Promise(() => undefined) });
    const b = renderApp({ path: "/leases", handlers: slow.handlers });
    expect(await screen.findByRole("status", { name: "Loading leases" })).toBeInTheDocument();
    b.unmount();

    const broken = recordedHandlers({
      lease_list: () => {
        throw mockError("internal", "boom");
      },
    });
    renderApp({ path: "/leases", handlers: broken.handlers });
    expect(await screen.findByRole("heading", { name: "Cannot load leases" })).toBeInTheDocument();
    expect(screen.getByText("lease_list: internal")).toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "Stop all access now" })).getByRole("button", { name: "Lock and revoke all" })).toBeInTheDocument();
  });

  it("refreshes when a lease changes", async () => {
    const { handlers, calls } = recordedHandlers();
    const view = renderApp({ path: "/leases", handlers });
    expect(await screen.findByRole("heading", { name: "6 active leases" })).toBeInTheDocument();
    const before = calls.lease_list?.length ?? 0;
    await act(async () => view.mock.emit("lease-changed", { id: "lse_9" }));
    await waitFor(() => expect(calls.lease_list?.length ?? 0).toBeGreaterThan(before));
  });
});
