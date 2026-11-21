import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it, vi } from "vitest";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { auditRows, brokenReport, handlers as auditHandlers, okReport } from "./mock";

vi.mock("../../ipc/dialogs", () => ({ pickSavePath: vi.fn(async () => "/tmp/cerberus-audit.jsonl") }));

const base: MockHandlers = auditHandlers;
const open = (extra: MockHandlers = {}, role: "owner" | "operator" | "viewer" = "owner") =>
  renderApp({ path: "/audit", role, handlers: { ...base, ...extra } });

describe("audit timeline", () => {
  it("shows the chain badge, the filters and events in plain words", async () => {
    open();
    const chain = await screen.findByText("Chain OK");
    expect(chain).toBeInTheDocument();
    expect(screen.getByText(/4,112 events, from 1 to 4,112/)).toBeInTheDocument();
    expect(await screen.findAllByText("read a secret", { exact: false })).not.toHaveLength(0);
    expect(screen.getAllByText("Ana Ruiz").length).toBeGreaterThan(0);
    expect(screen.getAllByText("QA runner").length).toBeGreaterThan(0);
    expect(screen.getByRole("combobox", { name: "Event type" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Outcome" })).toBeInTheDocument();
    expect(screen.getAllByText(/^Today, /).length).toBeGreaterThan(0);
  });

  it("has no axe violations in the ready state", async () => {
    const { container } = open();
    await screen.findByText("Chain OK");
    await screen.findAllByText(/read a secret/);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("renders agent text as untrusted plain text, never as markup", async () => {
    const user = userEvent.setup();
    const { container } = open();
    await screen.findAllByText(/asked for access/);
    const row = container.querySelector<HTMLElement>('[data-seq="4110"]');
    expect(row).not.toBeNull();
    await user.click(within(row as HTMLElement).getByRole("button", { name: /Details/ }));
    const group = await within(row as HTMLElement).findByRole("group", { name: /not verified/ });
    expect(group).toHaveTextContent("<b>Urgent</b>");
    expect(group.querySelector("b")).toBeNull();
  });

  it("context menu: Show details toggles the row and Copy event writes the event as JSON", async () => {
    const user = userEvent.setup();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    const { container } = open();
    await screen.findAllByText(/asked for access/);
    const row = container.querySelector<HTMLElement>('[data-seq="4110"]') as HTMLElement;
    fireEvent.contextMenu(row, { clientX: 20, clientY: 20 });
    await user.click(await screen.findByRole("menuitem", { name: "Details" }));
    expect(await within(row).findByRole("group", { name: /not verified/ })).toBeInTheDocument();
    fireEvent.contextMenu(row, { clientX: 20, clientY: 20 });
    expect(await screen.findByRole("menuitem", { name: "Hide details" })).toBeInTheDocument();
    await user.click(screen.getByRole("menuitem", { name: "Copy event" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    expect(JSON.parse(writeText.mock.calls[0]?.[0] as string)).toMatchObject({ seq: 4110 });
    expect(await screen.findByText("Event copied.")).toBeInTheDocument();
  });

  it("sends the search text to the backend and clears it with the filters (T21)", async () => {
    const user = userEvent.setup();
    const seen: { text?: string | null }[] = [];
    open({
      audit_query: (args, ctl) => {
        seen.push((args as { query: { text?: string | null } }).query);
        return auditHandlers.audit_query?.(args, ctl);
      },
    });
    await screen.findAllByText(/read a secret/);
    expect(seen.every((q) => q.text === null)).toBe(true);
    await user.type(screen.getByRole("searchbox", { name: "Search the log" }), "  billing  ");
    await waitFor(() => expect(seen.at(-1)?.text).toBe("billing"));
    await user.click(screen.getAllByRole("button", { name: "Clear filters" })[0] as HTMLElement);
    await waitFor(() => expect(seen.at(-1)?.text).toBeNull());
    expect(screen.getByRole("searchbox", { name: "Search the log" })).toHaveValue("");
  });

  it("sends the event type and the outcome to the backend", async () => {
    const user = userEvent.setup();
    const seen: unknown[] = [];
    open({
      audit_query: (args, ctl) => {
        seen.push((args as { query: unknown }).query);
        return auditHandlers.audit_query?.(args, ctl);
      },
    });
    await screen.findAllByText(/read a secret/);
    await user.selectOptions(screen.getByRole("combobox", { name: "Event type" }), "item.reveal");
    await waitFor(() => expect(seen.some((q) => (q as { event_type: string | null }).event_type === "item.reveal")).toBe(true));
    await user.selectOptions(screen.getByRole("combobox", { name: "Event type" }), "");
    await user.selectOptions(screen.getByRole("combobox", { name: "Outcome" }), "failed");
    await waitFor(() => expect(seen.some((q) => (q as { outcome: string | null }).outcome === "failed")).toBe(true));
    await waitFor(() => expect(screen.queryByText(/read a secret/)).toBeNull());
    expect(screen.getAllByText(/failed: forbidden/).length).toBeGreaterThan(0);
    await user.selectOptions(screen.getByRole("combobox", { name: "Outcome" }), "ok");
    await waitFor(() => expect(seen.some((q) => (q as { outcome: string | null }).outcome === "ok")).toBe(true));
    expect(await screen.findAllByText(/read a secret/)).not.toHaveLength(0);
    expect(screen.queryByText(/failed: forbidden/)).toBeNull();
  });

  it("sends no outcome while the filter is on any outcome", async () => {
    const seen: unknown[] = [];
    open({
      audit_query: (args, ctl) => {
        seen.push((args as { query: unknown }).query);
        return auditHandlers.audit_query?.(args, ctl);
      },
    });
    await screen.findAllByText(/read a secret/);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((q) => (q as { outcome: string | null }).outcome === null)).toBe(true);
  });

  it("loads older events with a cursor", async () => {
    const user = userEvent.setup();
    const pages: (number | null | undefined)[] = [];
    open({
      audit_query: (args) => {
        const q = (args as { query: { before_seq: number | null } }).query;
        pages.push(q.before_seq);
        const rows = auditRows(150);
        return rows.filter((r) => q.before_seq === null || r.seq < q.before_seq).slice(0, 100);
      },
    });
    await user.click(await screen.findByRole("button", { name: "Load older events" }));
    await waitFor(() => expect(pages.length).toBeGreaterThanOrEqual(2));
    expect(pages.at(-1)).toBe(4112 - 99);
  });
});

describe("audit chain", () => {
  it("verify now runs the check again and shows the new answer", async () => {
    const user = userEvent.setup();
    let calls = 0;
    open({ audit_verify: () => (calls++ === 0 ? okReport() : brokenReport(4108)) });
    await screen.findByText("Chain OK");
    await user.click(screen.getByRole("button", { name: "Verify now" }));
    expect(await screen.findByText("Chain broken at event 4,108")).toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it("shows the broken position, the reason, and marks the events from there on", async () => {
    const { container } = open({ audit_verify: () => brokenReport(4108) });
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Chain broken at event 4,108");
    expect(alert).toHaveTextContent("The signature does not match (HMAC mismatch)");
    await screen.findAllByText(/read a secret/);
    expect(screen.getByText("Chain breaks here")).toBeInTheDocument();
    const suspect = container.querySelectorAll("li.suspect");
    expect(suspect.length).toBe(5);
    expect(container.querySelector('li[data-seq="4108"]')).toHaveClass("break-point");
    expect(container.querySelector('li[data-seq="4107"]')).not.toHaveClass("suspect");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("offers to load back to a break that is older than the shown events", async () => {
    open({ audit_verify: () => brokenReport(4050) });
    expect(await screen.findByRole("button", { name: "Load back to event 4,050" })).toBeInTheDocument();
    expect(screen.getByText("Event 4,050 is older than the events shown.")).toBeInTheDocument();
  });

  it("shows a loading chain card while the check runs", async () => {
    open({ audit_verify: () => new Promise(() => undefined) });
    expect(await screen.findByText("Checking the chain")).toBeInTheDocument();
  });

  it("shows a warning when the check fails to run", async () => {
    open({ audit_verify: () => { throw mockError("internal", "x"); } });
    expect(await screen.findByText("Cannot check the chain")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify now" })).toBeInTheDocument();
  });
});

describe("audit states", () => {
  it("shows the filtered empty state and clears the filters", async () => {
    const user = userEvent.setup();
    open({ audit_query: () => [] });
    expect(await screen.findByRole("heading", { name: "The log has no events yet" })).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Time range" }), "day");
    await user.selectOptions(screen.getByRole("combobox", { name: "Outcome" }), "ok");
    expect(await screen.findByRole("heading", { name: "No events match these filters" })).toBeInTheDocument();
    await user.click(screen.getAllByRole("button", { name: "Clear filters" })[0] as HTMLElement);
    expect(await screen.findByRole("heading", { name: "The log has no events yet" })).toBeInTheDocument();
  });

  it("shows an error with the command line and a retry", async () => {
    open({ audit_query: () => { throw mockError("internal", "x"); } });
    expect(await screen.findByRole("heading", { name: "Cannot read the audit log" })).toBeInTheDocument();
    expect(screen.getByText("audit_query: internal")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("shows a loading state for the events", async () => {
    open({ audit_query: () => new Promise(() => undefined) });
    expect(await screen.findByRole("status", { name: "Loading events" })).toBeInTheDocument();
  });

  it("is locked: the shell shows the locked state while locking", async () => {
    renderApp({ state: "locking", path: "/audit", handlers: base });
    expect(await screen.findByText("Cerberus is locked")).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Event type" })).toBeNull();
  });

  it("viewer: can read, verify and export", async () => {
    open({}, "viewer");
    expect(await screen.findByText("Chain OK")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify now" })).toBeEnabled();
    expect(await screen.findByRole("button", { name: "Export" })).toBeEnabled();
  });

  it("exports the log and tells how many events", async () => {
    const user = userEvent.setup();
    open();
    await user.click(await screen.findByRole("button", { name: "Export" }));
    expect(await screen.findByText("Exported 4,112 events as JSON lines. No secret values inside.")).toBeInTheDocument();
  });
});
