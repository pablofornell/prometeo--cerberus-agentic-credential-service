// Remote mode in the UI (ADR-0034, plan step 9): the connect flow, the remote unlock, an unreachable or revoked server,
// the Remote server settings, the shell indicator, and the "Not available for a remote server" states. Fake data only.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import { mockError, type MockHandlers } from "../ipc/mock/core";
import { MOCK_PROFILE, MOCK_PROFILE_2 } from "../ipc/mock/fixtures";
import { handlers as auditHandlers } from "../screens/audit/mock";
import { handlers as unlockHandlers, MOCK_PHRASE } from "../screens/unlock/mock";
import { renderApp } from "../test/renderApp";

/** Wraps handlers so a test can see the calls and their arguments. */
function spy(names: string[], base: MockHandlers = {}): { handlers: MockHandlers; calls: Record<string, unknown[]> } {
  const calls: Record<string, unknown[]> = {};
  const handlers: MockHandlers = { ...base };
  for (const name of names) {
    const inner = base[name];
    handlers[name] = (args, ctl) => {
      (calls[name] ??= []).push(args);
      return inner ? inner(args, ctl) : null;
    };
  }
  return { handlers, calls };
}

describe("connect to a remote server (local mode)", () => {
  it("keeps the unlock card as it is: the link comes last in the tab order", async () => {
    const user = userEvent.setup();
    renderApp({ state: "sealed", path: "/unlock", handlers: unlockHandlers });
    await user.click(await screen.findByRole("radio", { name: /Ben Ortiz/ }));
    await user.tab();
    expect(screen.getByLabelText("Master phrase")).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Unlock" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Use recovery key" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Connect to a remote server" })).toHaveFocus();
  });

  it("imports a bundle, shows what to compare with cerberusd status, and connects", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "sealed", path: "/unlock", handlers: unlockHandlers });
    await user.click(await screen.findByRole("button", { name: "Connect to a remote server" }));
    const dialog = await screen.findByRole("dialog", { name: "Connect to a remote server" });
    await user.click(within(dialog).getByRole("button", { name: "Choose bundle file" }));
    expect(await within(dialog).findByText("Compare before you connect")).toBeInTheDocument();
    expect(within(dialog).getByTestId("remote-pin")).toHaveTextContent(MOCK_PROFILE.ca_pin);
    expect(within(dialog).getByTestId("remote-sha")).toHaveTextContent(MOCK_PROFILE.ca_sha256);
    expect(within(dialog).getByText(MOCK_PROFILE.url)).toBeInTheDocument();
    // The labels are the ones cerberusd status prints.
    expect(within(dialog).getByText("CA pin")).toBeInTheDocument();
    expect(within(dialog).getByText("CA SHA-256")).toBeInTheDocument();
    // Nothing secret is on the page.
    expect(document.body.textContent).not.toContain("PRIVATE KEY");
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    // The mock "restarts" in remote mode: the unlock card is now the server's.
    expect(await screen.findByRole("heading", { level: 1, name: "Connect to build-server" })).toBeInTheDocument();
    expect(mock.activated).toBe(MOCK_PROFILE.id);
  });

  it("says when a file is not a bundle, and forgets a bundle that was imported and then cancelled", async () => {
    const user = userEvent.setup();
    let path = "/home/demo/notes.txt";
    const { handlers, calls } = spy(["remote_forget"], {
      ...unlockHandlers,
      file_pick_open: () => path,
      remote_forget: (_args, ctl) => {
        ctl.profiles = [];
        return null;
      },
    });
    renderApp({ state: "sealed", path: "/unlock", handlers });
    await user.click(await screen.findByRole("button", { name: "Connect to a remote server" }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Choose bundle file" }));
    expect(await within(dialog).findByText("That file is not a valid Cerberus admin bundle.")).toBeInTheDocument();
    path = "/home/demo/build-server.cerberus-admin";
    await user.click(within(dialog).getByRole("button", { name: "Choose bundle file" }));
    await within(dialog).findByText("Compare before you connect");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(calls.remote_forget).toEqual([{ profile: MOCK_PROFILE.id }]));
  });
});

describe("remote unlock", () => {
  it("offers the bound operator only, no recovery key, and connects to the open server vault", async () => {
    const user = userEvent.setup();
    const { container } = renderApp({ state: "sealed", path: "/unlock", handlers: unlockHandlers, remote: true });
    expect(await screen.findByRole("heading", { level: 1, name: "Connect to build-server" })).toBeInTheDocument();
    expect(screen.getByText("vault.example.test:8443")).toBeInTheDocument();
    expect(await screen.findByRole("radio", { name: /Ana Ruiz/ })).toBeChecked();
    expect(screen.queryByRole("radio", { name: /Ben Ortiz/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Use recovery key" })).not.toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    // Tab order: operator, phrase, Connect, then the way back to the local vault.
    await user.click(screen.getByRole("radio", { name: /Ana Ruiz/ }));
    await user.tab();
    expect(screen.getByLabelText("Master phrase")).toHaveFocus();
    await user.keyboard(MOCK_PHRASE);
    await user.tab();
    expect(screen.getByRole("button", { name: "Connect" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Use the local vault" })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "Connect" }));
    // The shell names the server in use.
    const badge = await screen.findByTestId("remote-badge");
    expect(badge).toHaveTextContent("Remote: build-server");
    expect(screen.getByRole("button", { name: "Disconnect" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lock" })).not.toBeInTheDocument();
  });

  it("says that a locked server vault is unlocked for its agents too", async () => {
    renderApp({ state: "sealed", path: "/unlock", handlers: unlockHandlers, remote: { server_state: "sealed" } });
    expect(await screen.findByText("The server vault is locked. Your phrase unlocks it, for its agents too.")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Unlock" })).toBeInTheDocument();
  });

  it("explains a session the server refuses because another operator has the vault open", async () => {
    const user = userEvent.setup();
    renderApp({
      state: "sealed",
      path: "/unlock",
      remote: true,
      handlers: { vault_unlock: () => { throw mockError("conflict", "unlocked by another operator"); } },
    });
    await user.type(await screen.findByLabelText("Master phrase"), "anything");
    await user.click(screen.getByRole("button", { name: "Connect" }));
    expect(await screen.findByText("Another operator has the server vault unlocked. Only that operator can connect now.")).toBeInTheDocument();
  });

  it("shows an unreachable server with Try again and the way back to the local vault", async () => {
    const user = userEvent.setup();
    const { mock, container } = renderApp({ state: "sealed", path: "/unlock", remote: { reachable: false, problem: "remote_unreachable" } });
    expect(await screen.findByRole("heading", { level: 1, name: "Cannot reach build-server" })).toBeInTheDocument();
    expect(screen.getByText("Cannot reach the server. Check the network or the SSH tunnel.")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    mock.remote = mock.remote && { ...mock.remote, reachable: true, problem: null };
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Connect to build-server" })).toBeInTheDocument();
  });

  it("goes back to the local vault", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "sealed", path: "/unlock", handlers: unlockHandlers, remote: { reachable: false, problem: "remote_unreachable" } });
    await user.click(await screen.findByRole("button", { name: "Use the local vault" }));
    await waitFor(() => expect(mock.activated).toBeNull());
    expect(await screen.findByRole("heading", { level: 1, name: "Cerberus is locked" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Use recovery key" })).toBeInTheDocument();
  });

  it("says when the server no longer accepts this desktop", async () => {
    renderApp({ state: "sealed", path: "/unlock", remote: { problem: "admin_cert_required" } });
    expect(await screen.findByRole("heading", { level: 1, name: "The server no longer accepts this desktop" })).toBeInTheDocument();
    expect(screen.getByText(/Enrol it again on the server/)).toBeInTheDocument();
  });

  it("names a pin mismatch, and never offers to connect past it", async () => {
    renderApp({ state: "sealed", path: "/unlock", remote: { reachable: false, problem: "remote_pin_mismatch" } });
    expect(await screen.findByRole("heading", { level: 1, name: "The server is not the one you enrolled with" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Master phrase")).not.toBeInTheDocument();
  });
});

describe("remote server settings", () => {
  it("shows the server, tests it, disconnects, and locks the server vault only after a confirm", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = spy(["remote_disconnect", "vault_lock", "settings_get"], {
      remote_disconnect: async (_args, ctl) => {
        await ctl.setState("sealed");
        return null;
      },
      vault_lock: async (_args, ctl) => {
        await ctl.setState("sealed");
        return null;
      },
    });
    const { container } = renderApp({ state: "unlocked", path: "/settings", remote: true, profiles: [{ ...MOCK_PROFILE, active: true }, MOCK_PROFILE_2], handlers });
    const section = await screen.findByRole("region", { name: "Remote server" });
    expect(await within(section).findByText("Connected to build-server")).toBeInTheDocument();
    expect(await within(section).findByTestId("remote-pin")).toHaveTextContent(MOCK_PROFILE.ca_pin);
    expect(within(section).getByText("staging-box")).toBeInTheDocument();
    // The sections of a local vault say that they do not apply; their controls are not there.
    for (const name of ["Security", "Network", "Remote desktop", "Backup and restore"]) {
      expect(within(screen.getByRole("region", { name })).getByTestId("local-only")).toBeInTheDocument();
    }
    expect(screen.getByRole("region", { name: "Appearance" })).toBeInTheDocument();
    expect(calls.settings_get).toBeUndefined();
    expect(await axe(container)).toHaveNoViolations();

    await user.click(within(section).getByRole("button", { name: "Test connection" }));
    expect(await within(section).findByText("The server answered. Version 0.3.0.")).toBeInTheDocument();

    await user.click(within(section).getByRole("button", { name: "Lock the server vault" }));
    const confirm = await screen.findByRole("dialog", { name: "Lock the vault on build-server?" });
    expect(calls.vault_lock).toBeUndefined();
    await user.click(within(confirm).getByRole("button", { name: "Cancel" }));
    await user.click(within(section).getByRole("button", { name: "Disconnect" }));
    await waitFor(() => expect(calls.remote_disconnect).toHaveLength(1));
    expect(calls.vault_lock).toBeUndefined();
  });

  it("in local mode offers to connect and lists the imported servers", async () => {
    const user = userEvent.setup();
    const { handlers, calls } = spy(["remote_forget"], {
      remote_forget: (_args, ctl) => {
        ctl.profiles = [];
        return null;
      },
    });
    renderApp({ state: "unlocked", path: "/settings", profiles: [MOCK_PROFILE_2], handlers });
    const section = await screen.findByRole("region", { name: "Remote server" });
    expect(within(section).getByText("This desktop uses its own vault")).toBeInTheDocument();
    expect(await within(section).findByText("staging-box")).toBeInTheDocument();
    expect(within(section).getByRole("button", { name: "Lock and connect" })).toBeInTheDocument();
    await user.click(within(section).getByRole("button", { name: "Forget staging-box" }));
    await waitFor(() => expect(calls.remote_forget).toEqual([{ profile: MOCK_PROFILE_2.id }]));
    expect(await screen.findByText("Server forgotten. Its certificate and key were deleted from this device.")).toBeInTheDocument();
  });
});

describe("local-only actions in remote mode", () => {
  it("the panic dialog names the server vault", async () => {
    const user = userEvent.setup();
    renderApp({ state: "unlocked", path: "/leases", remote: true });
    await user.click(await screen.findByRole("button", { name: "Lock the server vault and revoke all" }));
    expect(await screen.findByRole("dialog", { name: "Lock the server vault and revoke all?" })).toHaveTextContent("This locks the vault on build-server");
  });

  it("leases keep the panic button but have no revoke all (local mode has it)", async () => {
    const local = renderApp({ state: "unlocked", path: "/leases" });
    await screen.findByRole("heading", { level: 2, name: "Stop all access now" });
    expect(screen.getByRole("button", { name: "Revoke all leases" })).toBeInTheDocument();
    local.unmount();
    renderApp({ state: "unlocked", path: "/leases", remote: true });
    await screen.findByRole("heading", { level: 2, name: "Stop all access now" });
    expect(screen.queryByRole("button", { name: "Revoke all leases" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Lock and revoke all" })).toBeInTheDocument();
  });

  it("agents are read-only and say why", async () => {
    renderApp({ state: "unlocked", path: "/agents", remote: true });
    expect(await screen.findByTestId("local-only")).toHaveTextContent("Agents are read-only on a remote server for now.");
    expect(screen.queryByRole("button", { name: "New agent" })).not.toBeInTheDocument();
  });

  it("the audit log shows the server's events without the chain check or the export", async () => {
    renderApp({ state: "unlocked", path: "/audit", remote: true, handlers: auditHandlers });
    expect(await screen.findByTestId("local-only")).toHaveTextContent("The chain check and the export run on the local vault.");
    expect(screen.queryByRole("button", { name: /Export/ })).not.toBeInTheDocument();
  });

  it("the dashboard health names the server instead of the local chain and TLS checks", async () => {
    renderApp({ state: "unlocked", path: "/dashboard", remote: true });
    expect(await screen.findByText("The audit chain check and the TLS listener belong to the server. Run cerberusd status there.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Connect an agent" })).not.toBeInTheDocument();
  });
});
