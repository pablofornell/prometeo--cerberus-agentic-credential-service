import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { OperatorRole } from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { watchZoom } from "../../test/zoom";
import { handlers as createHandlers, MOCK_RECOVERY_KEY } from "../create/mock";
import { handlers, resetSettingsMock } from "./mock";

// Fake values only.
type Calls = Record<string, unknown[]>;

function renderSettings(opts: { role?: OperatorRole; extra?: MockHandlers; spy?: string[] } = {}) {
  const calls: Calls = {};
  const wrapped: MockHandlers = { ...createHandlers, ...handlers };
  for (const name of opts.spy ?? []) {
    const inner = handlers[name];
    wrapped[name] = (args, ctl) => {
      (calls[name] ??= []).push(args);
      return inner ? inner(args, ctl) : null;
    };
  }
  const view = renderApp({ state: "unlocked", role: opts.role ?? "owner", path: "/settings", handlers: { ...wrapped, ...opts.extra } });
  return { ...view, calls };
}

const ready = () => screen.findByRole("heading", { level: 2, name: "Security" });
const section = (name: string) => screen.getByRole("region", { name });


describe("settings", () => {
  beforeEach(() => resetSettingsMock());

  it("shows every section with no axe violations", async () => {
    const { container } = renderSettings();
    await ready();
    for (const name of ["Security", "Network", "Appearance", "Backup and restore", "About"]) {
      expect(screen.getByRole("heading", { level: 2, name })).toBeInTheDocument();
    }
    expect(await screen.findByText("Cerberus 0.1.0")).toBeInTheDocument();
    expect(await screen.findByText("sha256/DEMOPINDEMOPINDEMOPINDEMOPIN0000000000000=")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows a skeleton while loading and an error with retry when the settings fail", async () => {
    const user = userEvent.setup();
    let fail = true;
    renderSettings({
      extra: {
        settings_get: (a, c) => {
          if (fail) throw mockError("internal", "internal error");
          return handlers.settings_get?.(a, c);
        },
      },
    });
    expect(await screen.findByText("Cannot load the settings")).toBeInTheDocument();
    expect(screen.getByText("settings_get: internal")).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await ready();
  });

  it("shows the defaults notice when no setting exists", async () => {
    renderSettings({ extra: { settings_get: () => ({ values: {} }) } });
    expect(await screen.findByText("Defaults are in use")).toBeInTheDocument();
  });

  it("saves the idle lock time", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["settings_set"] });
    await ready();
    const select = await screen.findByLabelText("Idle time");
    expect(select).toHaveValue("1800");
    await user.selectOptions(select, "15 minutes");
    await waitFor(() => expect(calls.settings_set).toEqual([{ key: "idle_lock_seconds", value: 900 }]));
    await waitFor(() => expect(screen.getByLabelText("Idle time")).toHaveValue("900"));
    await user.selectOptions(screen.getByLabelText("Idle time"), "Off");
    await waitFor(() => expect(calls.settings_set?.at(-1)).toEqual({ key: "idle_lock_seconds", value: null }));
  });

  it("saves a switch", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["settings_set"] });
    await ready();
    await user.click(await screen.findByRole("switch", { name: "Start Cerberus at login" }));
    await waitFor(() => expect(calls.settings_set).toEqual([{ key: "autostart", value: true }]));
  });

  it("shows a save error with the code line and leaves the value alone", async () => {
    const user = userEvent.setup();
    renderSettings({
      extra: {
        settings_set: () => {
          throw mockError("forbidden", "owner role needed");
        },
      },
    });
    await ready();
    await user.selectOptions(await screen.findByLabelText("Hard limit"), "4 hours");
    expect(await screen.findByText("The setting was not saved")).toBeInTheDocument();
    expect(screen.getByText("settings_set: forbidden")).toBeInTheDocument();
    expect(screen.getByLabelText("Hard limit")).toHaveValue("43200");
  });

  it("makes owner-only settings read only for an operator", async () => {
    renderSettings({ role: "operator" });
    await ready();
    expect(await screen.findByText(/You are an operator/)).toBeInTheDocument();
    expect(screen.getByLabelText("Idle time")).toBeEnabled();
    expect(screen.getByLabelText("Default session time")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Rotate recovery key" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Restore a backup" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Change" })).toBeDisabled();
  });

  it("makes everything read only for a viewer", async () => {
    renderSettings({ role: "viewer" });
    await ready();
    expect(await screen.findByText(/You are a viewer/)).toBeInTheDocument();
    expect(screen.getByLabelText("Idle time")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Create backup" })).toBeDisabled();
  });

  it("tests the unlock cost and offers to apply it with a phrase change", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["phrase_change"] });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Test this device" }));
    expect(await screen.findByText(/256 MiB memory, 3 passes, 4 lanes, 0.71 s/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Use this cost" }));
    const dialog = await screen.findByRole("dialog", { name: "Change your master phrase" });
    expect(within(dialog).getByLabelText(/Also use the unlock cost I tested/)).toBeChecked();
    await user.type(within(dialog).getByLabelText("Current phrase"), "current phrase here ok");
    await user.type(within(dialog).getByLabelText("New phrase"), "correct horse battery staple");
    await user.type(within(dialog).getByLabelText("New phrase again"), "correct horse battery staple");
    await waitFor(() => expect(within(dialog).queryByText(/too weak/)).toBeNull());
    await user.click(within(dialog).getByRole("button", { name: "Change phrase" }));
    await waitFor(() => expect(calls.phrase_change).toHaveLength(1));
    expect((calls.phrase_change?.[0] as { kdf: unknown }).kdf).toEqual({ m_cost_kib: 262_144, t_cost: 3, p_cost: 4 });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(await screen.findByText("Phrase changed")).toBeInTheDocument();
  });

  it("shows the unlock cost of the vault from its status", async () => {
    renderSettings();
    await ready();
    expect(await screen.findByText(/Your passphrase uses 256 MiB, 3 passes, 4 lanes\./)).toBeInTheDocument();
  });

  it("says a recovery session has no passphrase cost to show", async () => {
    renderSettings({
      extra: {
        vault_status: (_args, ctl) => ({
          state: "unlocked",
          operator: null,
          role: ctl.role,
          idle_seconds_left: 100,
          hard_lock_at: null,
          memlock_ok: true,
          os_hook_ok: true,
          header_ok: true,
          kdf: null,
          last_lock_reason: null,
          failed_unlocks: 0,
          free_unlock_tries_left: 5,
          retry_after_seconds: null,
          stranded_restore: [],
        }),
      },
    });
    await ready();
    expect(await screen.findByText(/A recovery session has no passphrase cost to show\./)).toBeInTheDocument();
    expect(screen.queryByText(/Your passphrase uses/)).not.toBeInTheDocument();
  });

  it("checks the new phrase and the current phrase", async () => {
    const user = userEvent.setup();
    renderSettings();
    await ready();
    await user.click(await screen.findByRole("button", { name: "Change phrase" }));
    const dialog = await screen.findByRole("dialog");
    expect(await axe(dialog)).toHaveNoViolations();
    await user.type(within(dialog).getByLabelText("Current phrase"), "wrong current phrase");
    await user.type(within(dialog).getByLabelText("New phrase"), "short");
    await user.type(within(dialog).getByLabelText("New phrase again"), "other");
    await user.click(within(dialog).getByRole("button", { name: "Change phrase" }));
    expect(await within(dialog).findByText("Use at least 12 characters.")).toBeInTheDocument();
    expect(within(dialog).getByText("The two phrases are not the same.")).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText("New phrase"));
    await user.clear(within(dialog).getByLabelText("New phrase again"));
    await user.type(within(dialog).getByLabelText("New phrase"), "correct horse battery staple");
    await user.type(within(dialog).getByLabelText("New phrase again"), "correct horse battery staple");
    await waitFor(() => expect(within(dialog).queryByText(/too weak/)).toBeNull());
    await user.click(within(dialog).getByRole("button", { name: "Change phrase" }));
    expect(await within(dialog).findByText("That is not your current phrase.")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Current phrase")).toHaveValue("");
  });

  it("rotates the recovery key with a one-time reveal", async () => {
    const user = userEvent.setup();
    renderSettings();
    await ready();
    await user.click(await screen.findByRole("button", { name: "Rotate recovery key" }));
    const confirm = await screen.findByRole("dialog", { name: "Make a new recovery key?" });
    expect(within(confirm).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.click(within(confirm).getByRole("button", { name: "Make new key" }));
    const reveal = await screen.findByRole("dialog", { name: "Your new recovery key" });
    expect(within(reveal).getAllByRole("listitem")).toHaveLength(15);
    expect(await axe(reveal)).toHaveNoViolations();
    const done = within(reveal).getByRole("button", { name: "Done" });
    expect(done).toBeDisabled();
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog", { name: "Your new recovery key" })).toBeInTheDocument();
    await user.click(within(reveal).getByLabelText("I stored the new recovery key away from this computer."));
    await user.click(done);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain(MOCK_RECOVERY_KEY);
    expect(document.body.textContent).not.toContain("DEMO-AAAA");
  });

  it("shows an error when the rotation fails", async () => {
    const user = userEvent.setup();
    renderSettings({
      extra: {
        recovery_rotate: () => {
          throw mockError("forbidden", "owner role needed");
        },
      },
    });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Rotate recovery key" }));
    await user.click(await screen.findByRole("button", { name: "Make new key" }));
    expect(await screen.findByText("Cannot make a new recovery key")).toBeInTheDocument();
  });

  it("lists operators, keeps the last owner, changes a role and removes an operator", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["operator_set_role", "operator_remove"] });
    await ready();
    expect(await screen.findByText("Ana Ruiz")).toBeInTheDocument();
    const role = screen.getByLabelText("Role of Ben Ortiz");
    await user.selectOptions(role, "Viewer");
    await waitFor(() => expect(calls.operator_set_role).toEqual([{ operator: "op-ben", role: "viewer" }]));
    await user.click(await screen.findByRole("button", { name: "Remove Ben Ortiz" }));
    const confirm = await screen.findByRole("dialog", { name: "Remove Ben Ortiz?" });
    await user.click(within(confirm).getByRole("button", { name: "Remove operator" }));
    await waitFor(() => expect(calls.operator_remove).toEqual([{ operator: "op-ben" }]));
    expect(await screen.findByText(/Only you can unlock this vault/)).toBeInTheDocument();
  });

  it("adds an operator after it checks the phrase", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["operator_add"] });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Add operator" }));
    const dialog = await screen.findByRole("dialog", { name: "Add an operator" });
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Add operator" }));
    expect(await within(dialog).findByText("Enter a name.")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Name"), "Luis Mora");
    await user.type(within(dialog).getByLabelText("Phrase for this operator"), "correct horse battery staple");
    await user.type(within(dialog).getByLabelText("Phrase again"), "correct horse battery staple");
    await waitFor(() => expect(within(dialog).queryByText(/too weak/)).toBeNull());
    await user.click(within(dialog).getByRole("button", { name: "Add operator" }));
    await waitFor(() => expect(calls.operator_add).toHaveLength(1));
    expect(await screen.findByText("Luis Mora")).toBeInTheDocument();
  });

  it("changes the listen address and validates it", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["network_set_bind"] });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Change" }));
    const dialog = await screen.findByRole("dialog", { name: "Change where Cerberus listens" });
    await user.clear(within(dialog).getByLabelText("Port"));
    await user.type(within(dialog).getByLabelText("Port"), "80");
    await user.click(within(dialog).getByRole("button", { name: "Save address" }));
    expect(await within(dialog).findByText("Use a port from 1024 to 65535.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("radio", { name: "Other devices on the network" }));
    await user.click(within(dialog).getByRole("button", { name: "Save address" }));
    expect(await within(dialog).findByText("Enter a valid IPv4 or IPv6 address.")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Address to listen on"), "192.168.1.20");
    await user.clear(within(dialog).getByLabelText("Port"));
    await user.type(within(dialog).getByLabelText("Port"), "7400");
    await user.click(within(dialog).getByRole("button", { name: "Save address" }));
    // The backend refuses a LAN address with open keys: the reason shows in the dialog.
    expect((await within(dialog).findAllByText(/needs a client certificate/)).length).toBeGreaterThan(0);
    await user.click(within(dialog).getByRole("radio", { name: "This computer only" }));
    await user.click(within(dialog).getByRole("button", { name: "Save address" }));
    await waitFor(() => expect(calls.network_set_bind?.at(-1)).toEqual({ addrs: ["127.0.0.1", "::1"], port: 7400 }));
    expect(await screen.findByText("port 7400")).toBeInTheDocument();
  });

  it("copies the public pin and exports the CA through the save dialog", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["tls_export_ca"] });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Export CA" }));
    await waitFor(() => expect(calls.tls_export_ca).toEqual([{ dest: "/tmp/cerberus-demo.cerb" }]));
    expect(await screen.findByText("CA certificate saved")).toBeInTheDocument();
  });

  it("loads your own certificate, warns about pinned clients and goes back to the local CA", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["tls_load_custom", "tls_use_local_ca"] });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Load my own certificate" }));
    const dialog = await screen.findByRole("dialog", { name: "Load your own certificate" });
    expect(within(dialog).getByText(/Agents that pin the local CA stop matching/)).toBeInTheDocument();
    // AUD-31: the pin moves to the top certificate of the chain, and that can be a public CA.
    expect(within(dialog).getByText("The pin moves to the top of your chain.")).toBeInTheDocument();
    expect(within(dialog).getByText(/a public intermediate CA/)).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Load certificate" }));
    expect(await within(dialog).findAllByText("Choose a file.")).toHaveLength(2);
    // A bad certificate shows its reason on the chain field.
    await user.type(within(dialog).getByLabelText(/Certificate chain/), "/tmp/bad-chain.pem");
    await user.type(within(dialog).getByLabelText(/Private key/), "/tmp/key.pem");
    await user.click(within(dialog).getByRole("button", { name: "Load certificate" }));
    expect(await within(dialog).findByText("the certificate has expired")).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText(/Certificate chain/));
    await user.type(within(dialog).getByLabelText(/Certificate chain/), "/tmp/chain.pem");
    await user.click(within(dialog).getByRole("button", { name: "Load certificate" }));
    await waitFor(() => expect(calls.tls_load_custom?.at(-1)).toEqual({ chainPath: "/tmp/chain.pem", keyPath: "/tmp/key.pem" }));
    expect(await screen.findByText("Your own certificate is in use.")).toBeInTheDocument();
    expect(screen.getByText(/the pin below is the top certificate of your chain/)).toBeInTheDocument();
    expect(screen.getByText("sha256/DEMOCUSTOMDEMOCUSTOMDEMOCUSTOM00000000000=")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Use the local CA again" }));
    const confirm = await screen.findByRole("dialog", { name: "Use the local CA again?" });
    await user.click(within(confirm).getByRole("button", { name: "Use local CA" }));
    await waitFor(() => expect(calls.tls_use_local_ca).toHaveLength(1));
    await waitFor(() => expect(screen.queryByText("Your own certificate is in use.")).toBeNull());
  });

  it("fills the certificate paths from the file dialog", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["tls_load_custom"] });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Load my own certificate" }));
    const dialog = await screen.findByRole("dialog", { name: "Load your own certificate" });
    const choose = within(dialog).getAllByRole("button", { name: "Choose file" });
    expect(choose).toHaveLength(2);
    for (const button of choose) await user.click(button);
    await waitFor(() => expect(within(dialog).getByLabelText(/Certificate chain/)).toHaveValue("/tmp/cerberus-demo.cerb"));
    expect(within(dialog).getByLabelText(/Private key/)).toHaveValue("/tmp/cerberus-demo.cerb");
    await user.click(within(dialog).getByRole("button", { name: "Load certificate" }));
    await waitFor(() => expect(calls.tls_load_custom).toEqual([{ chainPath: "/tmp/cerberus-demo.cerb", keyPath: "/tmp/cerberus-demo.cerb" }]));
  });

  it("keeps the custom certificate controls owner only", async () => {
    renderSettings({ role: "operator" });
    await ready();
    expect(await screen.findByRole("button", { name: "Load my own certificate" })).toBeDisabled();
  });

  it("changes theme and density, and offers English only", async () => {
    const user = userEvent.setup();
    renderSettings();
    await ready();
    const appearance = within(section("Appearance"));
    await user.click(appearance.getByRole("radio", { name: "Light" }));
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    await user.click(appearance.getByRole("radio", { name: "Compact" }));
    expect(document.documentElement.getAttribute("data-density")).toBe("compact");
    expect(appearance.getAllByRole("radio", { name: "English" })).toHaveLength(1);
    expect(appearance.queryByRole("radio", { name: /Espa/ })).toBeNull();
  });

  describe("UI scale", () => {
    const stored = () => (JSON.parse(window.localStorage.getItem("cerberus-prefs") ?? "{}") as { uiScale?: number }).uiScale;
    const open = async () => {
      renderSettings();
      await ready();
      return within(section("Appearance"));
    };
    let zoom: ReturnType<typeof watchZoom>;
    beforeEach(() => {
      zoom = watchZoom();
    });
    afterEach(() => zoom.stop());

    it("shows 100% and Reset is off", async () => {
      const appearance = await open();
      expect(appearance.getByRole("slider", { name: "UI scale" })).toHaveValue("100");
      expect(appearance.getByText("100%")).toBeInTheDocument();
      expect(appearance.getByRole("button", { name: "Reset to 100%" })).toHaveAttribute("aria-disabled", "true");
      expect(appearance.getByText(/Zooms the whole window/)).toHaveTextContent(/(Ctrl|Cmd) \+ \(zoom in\)/);
    });

    it("the - and + buttons step by 10, show it at once, apply once, and stop at the limits", async () => {
      const user = userEvent.setup();
      const appearance = await open();
      await user.click(appearance.getByRole("button", { name: "Increase UI scale" }));
      expect(appearance.getByText("110%")).toBeInTheDocument();
      expect(zoom.value).toBe("");
      expect(stored()).toBe(100);
      await waitFor(() => expect(zoom.value).toBe("1.1")); // no further click: applied after the wait
      expect(stored()).toBe(110);
      await user.click(appearance.getByRole("button", { name: "Decrease UI scale" }));
      await user.click(appearance.getByRole("button", { name: "Decrease UI scale" }));
      expect(appearance.getByText("90%")).toBeInTheDocument();
      for (let i = 0; i < 3; i++) await user.click(appearance.getByRole("button", { name: "Decrease UI scale" }));
      expect(appearance.getByText("80%")).toBeInTheDocument();
      expect(appearance.getByRole("button", { name: "Decrease UI scale" })).toHaveAttribute("aria-disabled", "true");
      expect(stored()).toBe(110);
      fireEvent.pointerLeave(appearance.getByRole("slider", { name: "UI scale" }).closest(".scale-ctl")!, { pointerType: "mouse" });
      expect(stored()).toBe(80);
      expect(zoom.value).toBe("0.8");
    });

    it("a button that goes off at a limit keeps the keyboard focus and does nothing", async () => {
      const user = userEvent.setup();
      const appearance = await open();
      const reset = appearance.getByRole("button", { name: "Reset to 100%" });
      reset.focus();
      expect(reset).toHaveFocus();
      await user.keyboard("{Enter}");
      expect(reset).toHaveFocus();
      expect(appearance.getByText("100%")).toBeInTheDocument();
      // at the limit: the button that was just used goes off while it has the focus
      const inc = appearance.getByRole("button", { name: "Increase UI scale" });
      inc.focus();
      for (let i = 0; i < 10; i++) await user.keyboard("{Enter}");
      expect(appearance.getByText("200%")).toBeInTheDocument();
      expect(inc).toHaveAttribute("aria-disabled", "true");
      expect(inc).toHaveFocus();
      await user.keyboard("{Enter}");
      expect(appearance.getByText("200%")).toBeInTheDocument();
      expect(inc).toHaveFocus();
    });

    it("a slider drag only previews; the scale applies once, on release", async () => {
      const appearance = await open();
      const slider = appearance.getByRole("slider", { name: "UI scale" });
      fireEvent.pointerDown(slider, { button: 0, clientX: 10, clientY: 10 });
      fireEvent.change(slider, { target: { value: "130" } });
      fireEvent.change(slider, { target: { value: "150" } });
      expect(appearance.getByText("150%")).toBeInTheDocument();
      expect(slider).toHaveAttribute("aria-valuetext", "150%");
      expect(zoom.value).toBe("");
      expect(stored()).toBe(100);
      fireEvent.pointerUp(slider);
      await waitFor(() => expect(zoom.value).toBe("1.5"));
      expect(stored()).toBe(150);
    });

    it("a lost drag goes back to the stored value", async () => {
      const appearance = await open();
      const slider = appearance.getByRole("slider", { name: "UI scale" });
      fireEvent.pointerDown(slider, { button: 0 });
      fireEvent.change(slider, { target: { value: "170" } });
      expect(appearance.getByText("170%")).toBeInTheDocument();
      fireEvent.pointerCancel(slider);
      expect(appearance.getByText("100%")).toBeInTheDocument();
      expect(zoom.value).toBe("");
    });

    it("an arrow key on the slider applies at once", async () => {
      const appearance = await open();
      fireEvent.change(appearance.getByRole("slider", { name: "UI scale" }), { target: { value: "110" } });
      expect(zoom.value).toBe("1.1");
      expect(appearance.getByText("110%")).toBeInTheDocument();
    });

    it("Reset goes back to 100% and the keys work on this screen too", async () => {
      const user = userEvent.setup();
      const appearance = await open();
      await user.keyboard("{Control>}={/Control}");
      await user.keyboard("{Control>}={/Control}");
      expect(appearance.getByText("120%")).toBeInTheDocument();
      await user.click(appearance.getByRole("button", { name: "Reset to 100%" }));
      expect(appearance.getByText("100%")).toBeInTheDocument();
      expect(zoom.value).toBe("");
      expect(stored()).toBe(100);
    });

    it("has no axe violations", async () => {
      await open();
      expect(await axe(section("Appearance"))).toHaveNoViolations();
    });
  });

  it("creates a backup in the chosen file", async () => {
    const user = userEvent.setup();
    const { calls } = renderSettings({ spy: ["backup_create"] });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Create backup" }));
    await waitFor(() => expect(calls.backup_create).toEqual([{ dest: "/tmp/cerberus-demo.cerb" }]));
    expect(await screen.findByText("Backup saved")).toBeInTheDocument();
  });

  it("opens the CSV import and export dialogs from the backup section", async () => {
    const user = userEvent.setup();
    renderSettings({ extra: { workspace_list: () => [{ id: "ws-shop", slug: "shop", name: "Shop", description: "", aliases: [], item_count: 0 }] } });
    await ready();
    await user.click(await screen.findByRole("button", { name: "Import CSV" }));
    expect(await screen.findByRole("dialog", { name: "Import from CSV" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.click(screen.getByRole("button", { name: "Export CSV" }));
    expect(await screen.findByRole("dialog", { name: "Export to CSV" })).toBeInTheDocument();
  });

  it("limits CSV import to operators and export to owners", async () => {
    renderSettings({ role: "operator" });
    await ready();
    expect(await screen.findByRole("button", { name: "Import CSV" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Export CSV" })).toBeDisabled();
  });

  it("restores a backup: a wrong key shows a problem, a right one seals the vault", async () => {
    const user = userEvent.setup();
    const { mock, container } = renderSettings();
    await ready();
    await user.click(await screen.findByRole("button", { name: "Restore a backup" }));
    const dialog = await screen.findByRole("dialog", { name: "Restore a backup" });
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Restore backup" }));
    expect(await within(dialog).findByText("Choose a backup file.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Choose file" }));
    await waitFor(() => expect(within(dialog).getByLabelText(/Backup file/)).toHaveValue("/tmp/cerberus-demo.cerb"));
    await user.type(within(dialog).getByLabelText("Recovery key of the backup"), "CRK1-WRONG");
    await user.click(within(dialog).getByRole("button", { name: "Restore backup" }));
    expect(await within(dialog).findByText("That does not open this backup.")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Recovery key of the backup"), "CRK1-DEMO");
    await user.click(within(dialog).getByRole("button", { name: "Restore backup" }));
    await waitFor(() => expect(mock.state).toBe("sealed"));
    await waitFor(() => expect(screen.getByRole("heading", { level: 1, name: "Cerberus is locked" })).toBeInTheDocument());
    expect(container).toBeTruthy();
  });

  it("shows the licenses dialog", async () => {
    const user = userEvent.setup();
    renderSettings();
    await ready();
    await user.click(await screen.findByRole("button", { name: "Show licenses" }));
    const dialog = await screen.findByRole("dialog", { name: "Open source licenses" });
    expect(within(dialog).getAllByText(/SIL Open Font License/)).toHaveLength(2);
  });
});
