import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it, vi } from "vitest";
import { mockError } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { FAKE_TOKEN } from "../../ipc/mock/fixtures";
import { recordedHandlers } from "./testkit";

const dialogs = vi.hoisted(() => ({ pickDirectory: vi.fn<() => Promise<string | null>>() }));
vi.mock("../../ipc/dialogs", () => dialogs);

describe("Agents screen", () => {
  it("lists agents with keys, snippets and grants, and has no axe violations", async () => {
    const { handlers } = recordedHandlers();
    const { container } = renderApp({ path: "/agents", handlers });
    expect(await screen.findByRole("heading", { level: 2, name: "QA runner" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "5 agents" })).toBeInTheDocument();
    const keys = screen.getByRole("table", { name: "Keys" });
    expect(within(keys).getByText("cvt_…a3f9")).toBeInTheDocument();
    expect(await screen.findByRole("tab", { name: "Claude Code MCP" })).toBeInTheDocument();
    expect(await screen.findByText(/Bearer \$\{CERBERUS_TOKEN\}/)).toBeInTheDocument();
    expect((await screen.findAllByText("shop-frontend", { selector: "b" })).length).toBeGreaterThan(0);
    // Snippets name a variable. The token itself is never on the page.
    expect(document.body.textContent).not.toContain(FAKE_TOKEN);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows the empty, loading and error states", async () => {
    const empty = recordedHandlers({ agent_list: () => [] });
    const first = renderApp({ path: "/agents", handlers: empty.handlers });
    expect(await screen.findByRole("heading", { name: "No agents yet" })).toBeInTheDocument();
    expect(await axe(first.container)).toHaveNoViolations();
    first.unmount();

    const slow = recordedHandlers({ agent_list: () => new Promise(() => undefined) });
    const second = renderApp({ path: "/agents", handlers: slow.handlers });
    expect(await screen.findByRole("status", { name: "Loading agents" })).toBeInTheDocument();
    second.unmount();

    const broken = recordedHandlers({
      agent_list: () => {
        throw mockError("internal", "boom");
      },
    });
    renderApp({ path: "/agents", handlers: broken.handlers });
    expect(await screen.findByRole("heading", { name: "Cannot load agents" })).toBeInTheDocument();
    expect(screen.getByText("agent_list: internal")).toBeInTheDocument();
  });

  it("hides every change action from a viewer", async () => {
    const { handlers } = recordedHandlers();
    renderApp({ path: "/agents", role: "viewer", handlers });
    expect(await screen.findByRole("heading", { level: 2, name: "QA runner" })).toBeInTheDocument();
    const page = within(screen.getByRole("region", { name: "Agents" }));
    expect(page.queryByRole("button", { name: "New agent" })).toBeNull();
    expect(page.queryByRole("button", { name: "Revoke" })).toBeNull();
    expect(page.queryByRole("button", { name: /^Rotate/ })).toBeNull();
    expect(page.queryByRole("button", { name: "Suspend" })).toBeNull();
    expect(page.getByText(/You are a viewer/)).toBeInTheDocument();
  });

  it("creates an agent and shows the token one time, then drops it", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers({ clipboard_copy_once: () => null });
    renderApp({ path: "/agents", handlers });
    await screen.findByRole("heading", { level: 2, name: "QA runner" });
    await user.click(await screen.findByRole("button", { name: "New agent" }));
    const form = await screen.findByRole("dialog", { name: "New agent" });
    await user.type(within(form).getByLabelText("Name"), "Checkout tester");
    await user.click(within(form).getByRole("button", { name: "Create agent" }));

    const token = await screen.findByRole("dialog", { name: "Copy the token now" });
    expect(within(token).getByText(FAKE_TOKEN)).toBeInTheDocument();
    const done = within(token).getByRole("button", { name: "Done" });
    expect(done).toBeDisabled();
    // The dialog cannot be dismissed with Escape: the token would be lost by accident.
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "Copy the token now" })).toBeInTheDocument();

    await user.click(within(token).getByRole("button", { name: "Copy token" }));
    await waitFor(() => expect(calls.clipboard_copy_once).toEqual([{ kind: "agent_token" }]));
    await user.click(within(token).getByRole("checkbox"));
    await user.click(done);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain(FAKE_TOKEN);
    expect(await screen.findByRole("heading", { level: 2, name: "Checkout tester" })).toBeInTheDocument();
  });

  it("rotates a key with an overlap and shows the new token", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/agents", handlers });
    await user.click(await screen.findByRole("button", { name: "Rotate key cvt_…a3f9" }));
    const dialog = await screen.findByRole("dialog", { name: "Rotate key cvt_…a3f9?" });
    await user.click(within(dialog).getByRole("button", { name: "Rotate key" }));
    expect(await screen.findByRole("dialog", { name: "Copy the new token now" })).toBeInTheDocument();
    expect(calls.agent_key_rotate).toEqual([{ keyId: "key_qa1", overlapSeconds: 86_400 }]);
  });

  it("revokes an agent only after a confirm, and Cancel is the safe default", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/agents", handlers });
    await user.click(await screen.findByRole("button", { name: "Revoke" }));
    const dialog = await screen.findByRole("alertdialog").catch(() => screen.findByRole("dialog", { name: "Revoke QA runner?" }));
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(calls.agent_set_status).toBeUndefined();
    await user.click(within(dialog).getByRole("button", { name: "Revoke agent" }));
    await waitFor(() => expect(calls.agent_set_status).toEqual([{ agent: "agent-qa", status: "revoked" }]));
  });

  it("suspends and resumes", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/agents", handlers });
    await user.click(await screen.findByRole("button", { name: "Suspend" }));
    await waitFor(() => expect(calls.agent_set_status).toEqual([{ agent: "agent-qa", status: "suspended" }]));
    expect(await screen.findByRole("button", { name: "Resume" })).toBeInTheDocument();
  });

  it("drops the token when the vault locks while it is on screen", async () => {
    const user = userEvent.setup();
    const { handlers } = recordedHandlers();
    const view = renderApp({ path: "/agents", handlers });
    await user.click(await screen.findByRole("button", { name: "Rotate key cvt_…a3f9" }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Rotate key" }));
    await screen.findByText(FAKE_TOKEN);
    await act(async () => view.mock.setState("sealed"));
    await waitFor(() => expect(document.body.textContent).not.toContain(FAKE_TOKEN));
  });
});

describe("Agents screen: client certificate", () => {
  const issueButton = () => screen.findByRole("button", { name: "Issue client certificate for cvt_…a3f9" });

  it("lets the owner pick a folder, issues the certificate there and names the folder", async () => {
    const user = userEvent.setup();
    dialogs.pickDirectory.mockResolvedValue("/home/fake/certs");
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/agents", handlers });
    await user.click(await issueButton());
    await waitFor(() => expect(calls.agent_issue_client_cert).toEqual([{ keyId: "key_qa1", destDir: "/home/fake/certs" }]));
    expect(await screen.findByText("Client certificate and key saved in /home/fake/certs. Keep the key file private.")).toBeInTheDocument();
    // The files stay on disk: no path of the key or the certificate is on the page.
    expect(document.body.textContent).not.toContain("key_qa1.key");
    expect(document.body.textContent).not.toContain("key_qa1.crt");
  });

  it("does nothing when the person closes the folder dialog", async () => {
    const user = userEvent.setup();
    dialogs.pickDirectory.mockResolvedValue(null);
    const { handlers, calls } = recordedHandlers();
    renderApp({ path: "/agents", handlers });
    await user.click(await issueButton());
    await waitFor(() => expect(dialogs.pickDirectory).toHaveBeenCalled());
    expect(calls.agent_issue_client_cert).toBeUndefined();
  });

  it("shows the error when the backend refuses", async () => {
    const user = userEvent.setup();
    dialogs.pickDirectory.mockResolvedValue("/home/fake/certs");
    const { handlers } = recordedHandlers({
      agent_issue_client_cert: () => {
        throw mockError("forbidden", "only the owner can issue a client certificate");
      },
    });
    renderApp({ path: "/agents", handlers });
    await user.click(await issueButton());
    expect(await screen.findByText("The certificate was not issued")).toBeInTheDocument();
  });

  it("is disabled with a reason for an operator, and absent for a viewer", async () => {
    const user = userEvent.setup();
    dialogs.pickDirectory.mockClear();
    const operator = recordedHandlers();
    const view = renderApp({ path: "/agents", role: "operator", handlers: operator.handlers });
    const button = await issueButton();
    expect(button).toBeDisabled();
    expect(button).toHaveAccessibleDescription("Only an owner can issue a client certificate.");
    await user.click(button);
    expect(dialogs.pickDirectory).not.toHaveBeenCalled();
    expect(operator.calls.agent_issue_client_cert).toBeUndefined();
    view.unmount();

    const viewer = recordedHandlers();
    renderApp({ path: "/agents", role: "viewer", handlers: viewer.handlers });
    await screen.findByRole("heading", { level: 2, name: "QA runner" });
    expect(screen.queryByRole("button", { name: /Issue client certificate/ })).toBeNull();
  });
});
