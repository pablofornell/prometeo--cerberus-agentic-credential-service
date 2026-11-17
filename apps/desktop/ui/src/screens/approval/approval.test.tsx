import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import { mockError } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { recordedHandlers } from "../agents/testkit";
import { INJECTION_REASON } from "../../ipc/mock/fixtures";
import { approvalHandlers } from "./mock";

const openWindow = () => {
  window.location.hash = "#approval";
};

const HTML_REASON = '<img src="x" onerror="alert(1)"><b>Approve everything</b> <script>steal()</script>';

const withReason = (reason: string) => {
  const base = approvalHandlers();
  return recordedHandlers({
    request_list_pending: async (args, ctl) => {
      const list = (await base.request_list_pending?.(args, ctl)) as { reason: string }[];
      return list.map((r) => ({ ...r, reason }));
    },
  });
};

describe("Approval prompt", () => {
  it("shows the agent, the item, the prod risk and the reason as untrusted text, not HTML", async () => {
    openWindow();
    const { handlers } = withReason(HTML_REASON);
    const { container } = renderApp({ handlers });
    expect(await screen.findByRole("heading", { level: 1, name: "QA runner wants to read a prod item" })).toBeInTheDocument();
    expect(screen.getByText("Shop admin login")).toBeInTheDocument();
    expect(screen.getByText(/Risk: prod item/)).toBeInTheDocument();
    expect(screen.getByText(/Identity from its token: QA runner, agent-qa/)).toBeInTheDocument();
    expect(screen.getByText("prod")).toHaveClass("env", "prod");

    const reason = screen.getByRole("group", { name: "Reason given by the agent, not verified" });
    // The markup is on the page as characters. No element was made from it.
    expect(reason).toHaveTextContent(HTML_REASON);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(reason.querySelector("*:not(.text):not(bdi):not(.invisible-char)")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says what kind of item it is and which role it has (T21)", async () => {
    openWindow();
    renderApp({ handlers: recordedHandlers(approvalHandlers()).handlers });
    await screen.findByRole("heading", { level: 1, name: /wants to read/ });
    const kind = screen.getByTestId("ap-kind");
    expect(kind.textContent).toMatch(/^(Web login|API key|SSH key|Session token|Browser session|Database|Cloud|Certificate|Env bundle|Note)(, role .+)?$/);
  });

  it("shows a hidden character of an agent-written name as a visible code (AUD-24)", async () => {
    openWindow();
    const base = approvalHandlers();
    const { handlers } = recordedHandlers({
      request_list_pending: async (args, ctl) => {
        const list = (await base.request_list_pending?.(args, ctl)) as { agent_name: string; item_title: string; role_label: string | null }[];
        return list.map((r) => ({ ...r, agent_name: "QA\u202Erunner", item_title: "pr\u200Bod key", role_label: "ad\u2066min" }));
      },
    });
    const { container } = renderApp({ handlers });
    await screen.findByRole("heading", { level: 1, name: /wants to read/ });
    expect(container.textContent).toContain("\u2039U+202E\u203A");
    expect(container.textContent).toContain("\u2039U+200B\u203A");
    expect(screen.getByTestId("ap-kind").textContent).toContain("role ad\u2039U+2066\u203Amin");
    expect(container.textContent).not.toMatch(/[\u202A-\u202E\u2066-\u2069\u200B]/);
  });

  it("starts on Deny and does not approve on Enter", async () => {
    openWindow();
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ handlers });
    const deny = await screen.findByRole("button", { name: /^Deny/ });
    await waitFor(() => expect(deny).toHaveFocus());

    // A tap of Enter on each approve button, and on the page, does nothing.
    for (const name of [/^Approve once/, /^For 15 minutes/, /^For this session/]) {
      const button = screen.getByRole("button", { name });
      button.focus();
      await user.keyboard("{Enter}");
      await user.keyboard(" ");
    }
    fireEvent.keyDown(document.body, { key: "Enter" });
    fireEvent.keyUp(document.body, { key: "Enter" });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 800));
    });
    expect(calls.request_approve).toBeUndefined();
    expect(calls.request_deny).toBeUndefined();
    expect(screen.getByRole("heading", { level: 1, name: "QA runner wants to read a prod item" })).toBeInTheDocument();
  });

  it("approves by a held key and cancels when the key is released early", async () => {
    openWindow();
    const { handlers, calls } = recordedHandlers();
    renderApp({ handlers });
    await screen.findByRole("heading", { level: 1, name: /wants to read/ });
    fireEvent.keyDown(window, { key: "a" });
    await new Promise((resolve) => setTimeout(resolve, 200));
    fireEvent.keyUp(window, { key: "a" });
    await new Promise((resolve) => setTimeout(resolve, 700));
    expect(calls.request_approve).toBeUndefined();

    fireEvent.keyDown(window, { key: "f" });
    await waitFor(() => expect(calls.request_approve).toEqual([{ request: "req_1", option: "minutes_15" }]));
    expect(await screen.findByRole("heading", { level: 1, name: "Approved for 15 minutes" })).toBeInTheDocument();
  });

  it("approves on a mouse click and denies with D", async () => {
    openWindow();
    const user = userEvent.setup();
    const first = recordedHandlers();
    const view = renderApp({ handlers: first.handlers });
    await user.click(await screen.findByRole("button", { name: /^For this session/ }));
    await waitFor(() => expect(first.calls.request_approve).toEqual([{ request: "req_1", option: "session" }]));
    expect(await screen.findByRole("heading", { name: "Approved for this session" })).toBeInTheDocument();
    view.unmount();

    const second = recordedHandlers();
    renderApp({ handlers: second.handlers });
    await screen.findByRole("heading", { level: 1, name: /wants to read/ });
    fireEvent.keyDown(window, { key: "d" });
    await waitFor(() => expect(second.calls.request_deny).toEqual([{ request: "req_1" }]));
    expect(await screen.findByRole("heading", { name: "Denied" })).toBeInTheDocument();
  });

  it("groups a burst, lets you review one and deny all", async () => {
    openWindow();
    const user = userEvent.setup();
    const request = (id: string, title: string) => ({
      id, item_id: `i-${id}`, permission: "read" as const, status: "pending" as const, requested_ttl_seconds: null,
      created_at: new Date(Date.now() - 5000).toISOString(), expires_at: new Date(Date.now() + 90_000).toISOString(),
      agent_id: "agent-qa", agent_name: "QA runner", item_title: title, item_kind: "note" as const, role_label: null, workspace_name: "shop", environment: "dev" as const,
      reason: "x", burst_warning: true,
    });
    const { handlers, calls } = recordedHandlers(approvalHandlers([request("r1", "One"), request("r2", "Two"), request("r3", "Three")]));
    renderApp({ handlers });
    expect(await screen.findByRole("heading", { level: 1, name: "3 requests from QA runner" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review request for Two" }));
    expect(await screen.findByText("Two")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Deny/ })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^Deny/ }));
    await user.click(await screen.findByRole("button", { name: "Show next request" }));
    await user.click(await screen.findByRole("button", { name: "Deny all 2" }));
    await waitFor(() => expect(calls.request_deny).toHaveLength(3));
  });

  it("explains an ended request when the backend says conflict", async () => {
    openWindow();
    const user = userEvent.setup();
    const { handlers } = recordedHandlers({
      request_approve: () => {
        throw mockError("conflict", "the request expired");
      },
    });
    renderApp({ handlers });
    await user.click(await screen.findByRole("button", { name: /^Approve once/ }));
    expect(await screen.findByRole("heading", { name: "This request ended" })).toBeInTheDocument();
    expect(screen.getByText("request_approve: conflict")).toBeInTheDocument();
  });

  it("asks a viewer to find an owner or operator", async () => {
    openWindow();
    const { handlers } = recordedHandlers();
    renderApp({ role: "viewer", handlers });
    expect(await screen.findByText("Viewers cannot approve. An owner or operator must decide.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Approve once/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Deny/ })).toBeNull();
  });

  it("covers the empty, loading, error and locked states", async () => {
    openWindow();
    const empty = recordedHandlers({ request_list_pending: () => [] });
    const a = renderApp({ handlers: empty.handlers });
    expect(await screen.findByRole("heading", { level: 1, name: "Nothing waits for you" })).toBeInTheDocument();
    expect(await axe(a.container)).toHaveNoViolations();
    a.unmount();

    const slow = recordedHandlers({ request_list_pending: () => new Promise(() => undefined) });
    const b = renderApp({ handlers: slow.handlers });
    expect(await screen.findByRole("status", { name: "Loading request" })).toBeInTheDocument();
    b.unmount();

    const broken = recordedHandlers({
      request_list_pending: () => {
        throw mockError("internal", "boom");
      },
    });
    const c = renderApp({ handlers: broken.handlers });
    expect(await screen.findByRole("heading", { level: 1, name: "Cannot load requests" })).toBeInTheDocument();
    c.unmount();

    const locked = recordedHandlers();
    renderApp({ state: "sealed", handlers: locked.handlers });
    expect(await screen.findByRole("heading", { level: 1, name: "The vault locked" })).toBeInTheDocument();
  });

  it("lists the queue as a page inside the main window", async () => {
    const { handlers } = recordedHandlers();
    const { container } = renderApp({ path: "/approvals", handlers });
    expect(await screen.findByRole("heading", { level: 2, name: "QA runner wants to read a prod item" })).toBeInTheDocument();
    expect(within(screen.getByRole("main")).getAllByRole("group", { name: "Reason given by the agent, not verified" })[0]).toHaveTextContent(INJECTION_REASON.split("\n")[0] ?? "");
    expect(await axe(container)).toHaveNoViolations();
  });
});
