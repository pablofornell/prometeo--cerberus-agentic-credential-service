// Set up a new server (DEC-SRV-3): the dialog that makes the vault on a cerberusd with no vault, from the unlock screen
// and from Settings. The mock reads the end of a setup code as a scenario (see `MOCK_SETUP_CODE`). Fake data only.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import type { MockHandlers } from "../ipc/mock/core";
import { MOCK_PROFILE, MOCK_SETUP_CODE, MOCK_SETUP_RECOVERY_KEY } from "../ipc/mock/fixtures";
import { handlers as createHandlers } from "../screens/create/mock";
import { handlers as unlockHandlers } from "../screens/unlock/mock";
import { renderApp } from "../test/renderApp";

type User = ReturnType<typeof userEvent.setup>;

const PHRASE = "correct horse battery staple";
const codeFor = (scenario: string) => `cerberus-setup:1:${scenario}`;

const all: MockHandlers = { ...unlockHandlers, ...createHandlers };

async function openDialog(user: User) {
  await user.click(await screen.findByRole("button", { name: "Set up a new server" }));
  return screen.findByRole("dialog", { name: "Set up a new server" });
}

/** Pastes a code and checks the server. Pasting is a single change, so a long code is not typed key by key. */
async function check(user: User, dialog: HTMLElement, code: string) {
  const field = within(dialog).getByLabelText("Setup code");
  await user.click(field);
  await user.paste(code);
  await user.click(within(dialog).getByRole("button", { name: /^Check/ }));
}

async function toOwnerStep(user: User, dialog: HTMLElement, code = MOCK_SETUP_CODE) {
  await check(user, dialog, code);
  await within(dialog).findByText("Server found. It waits for its first client.");
  await user.click(within(dialog).getByRole("button", { name: "Continue" }));
  await within(dialog).findByRole("heading", { name: "Create the first owner" });
}

async function fillOwner(user: User, dialog: HTMLElement, name = "Ana Ruiz", phrase = PHRASE) {
  await user.type(within(dialog).getByLabelText("Your name on this vault"), name);
  await user.type(within(dialog).getByLabelText("Master phrase"), phrase);
  await user.type(within(dialog).getByLabelText("Type the phrase again"), phrase);
  const create = within(dialog).getByRole("button", { name: "Create vault on the server" });
  await waitFor(() => expect(create).toBeEnabled());
  return create;
}

/** Types back the two groups that the check asks for, and ticks the box. */
async function passProof(user: User, dialog: HTMLElement) {
  const parts = MOCK_SETUP_RECOVERY_KEY.split("-");
  for (const input of within(dialog).getAllByLabelText(/^Type group \d+$/)) {
    const n = Number(/\d+/.exec((input as HTMLInputElement).labels?.[0]?.textContent ?? "")?.[0]);
    await user.type(input, parts[n - 1]);
  }
  await user.click(within(dialog).getByLabelText("I stored the recovery key away from this computer."));
}

describe("set up a new server: the code step", () => {
  it("sits next to the connect link on the unlock screen, and opens a labelled dialog with no axe violations", async () => {
    const user = userEvent.setup();
    renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    expect(await screen.findByRole("button", { name: "Connect to a remote server" })).toBeInTheDocument();
    const dialog = await openDialog(user);
    expect(within(dialog).getByRole("heading", { name: "Connect to the server" })).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Setup steps")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Setup code")).toHaveFocus();
    // Nothing to check yet: the button waits for a code.
    expect(within(dialog).getByRole("button", { name: "Check server" })).toBeDisabled();
    expect(await axe(dialog)).toHaveNoViolations();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("says when the text is not a setup code, and when the address is not an https address", async () => {
    const user = userEvent.setup();
    renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await check(user, dialog, "https://example.test/not-a-code");
    expect(await within(dialog).findByText(/This is not a Cerberus setup code/)).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText("Setup code"));
    await user.click(within(dialog).getByText("Reach the server at another address"));
    await user.type(within(dialog).getByLabelText("Address"), "http://localhost:7373");
    await user.click(within(dialog).getByLabelText("Setup code"));
    await user.paste(MOCK_SETUP_CODE);
    await user.click(within(dialog).getByRole("button", { name: "Check server" }));
    expect(await within(dialog).findByText("Use https://host or https://host:port, with no path.")).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
  });

  it("shows the server that waits, with its address, status and version, and sends the chosen address", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await user.click(within(dialog).getByText("Reach the server at another address"));
    await user.type(within(dialog).getByLabelText("Address"), "https://localhost:7373");
    await check(user, dialog, MOCK_SETUP_CODE);
    expect(await within(dialog).findByText("Server found. It waits for its first client.")).toBeInTheDocument();
    expect(within(dialog).getByText("https://localhost:7373")).toBeInTheDocument();
    expect(within(dialog).getByText("Waiting for setup")).toBeInTheDocument();
    expect(within(dialog).getByText("0.4.0")).toBeInTheDocument();
    expect(mock.calls.remote_setup_check).toEqual([{ code: MOCK_SETUP_CODE, url: "https://localhost:7373" }]);
    expect(await axe(dialog)).toHaveNoViolations();
    // A changed code drops the result: the person has to check the new one.
    await user.type(within(dialog).getByLabelText("Setup code"), "x");
    expect(within(dialog).queryByText("Server found. It waits for its first client.")).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Check server" })).toBeInTheDocument();
  });

  it.each([
    ["down", "Cannot reach the server", /Behind SSH, open the tunnel/, "remote_unreachable"],
    ["wrong", "This is not the server of that code", /cerberusd restarted and made a new one/, "setup_wrong_server"],
    ["exists", "This server already has a vault", /cerberusd admin enroll/, "conflict"],
  ])("explains a server that is %s", async (scenario, title, body, code) => {
    const user = userEvent.setup();
    renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await check(user, dialog, codeFor(scenario));
    const alert = await within(dialog).findByRole("alert");
    expect(within(alert).getByText(title)).toBeInTheDocument();
    expect(alert).toHaveTextContent(body);
    expect(alert).toHaveTextContent(`remote_setup_check: ${code}`);
    expect(within(dialog).queryByRole("button", { name: "Continue" })).toBeNull();
    expect(await axe(dialog)).toHaveNoViolations();
  });

  it("tells an address that has to wait that the code stays valid, and offers a new check", async () => {
    const user = userEvent.setup();
    renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await check(user, dialog, codeFor("locked"));
    expect(await within(dialog).findByText("This address has to wait")).toBeInTheDocument();
    expect(dialog).toHaveTextContent(/The code stays valid and the server needs no restart/);
    expect(dialog).not.toHaveTextContent(/systemctl restart/);
    expect(within(dialog).queryByRole("button", { name: "Continue" })).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Check again" })).toBeEnabled();
    expect(await axe(dialog)).toHaveNoViolations();
  });
});

describe("set up a new server: the whole flow", () => {
  it("creates the vault, checks the recovery key and connects in remote mode", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog);
    expect(within(dialog).getByText("Setting up https://vault.example.test:7373")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Your name on this vault")).toHaveFocus();
    // The policy of the create flow: a weak phrase keeps the button off.
    await user.type(within(dialog).getByLabelText("Master phrase"), "abc");
    expect(await within(dialog).findByText(/^Too weak\./)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Create vault on the server" })).toBeDisabled();
    await user.clear(within(dialog).getByLabelText("Master phrase"));
    expect(await axe(dialog)).toHaveNoViolations();

    await user.click(within(dialog).getByText("Name of this computer on the server"));
    await user.type(within(dialog).getByLabelText("Computer name"), "ana-laptop");
    const create = await fillOwner(user, dialog);
    await user.click(create);

    // The long call has its own state, and the dialog cannot be dismissed while it runs.
    expect(await within(dialog).findByText("Creating the vault on the server")).toBeInTheDocument();
    expect(within(dialog).getByRole("status")).toHaveAttribute("aria-busy", "true");
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    expect(await within(dialog).findByRole("heading", { name: "Save your recovery key" })).toBeInTheDocument();
    expect(mock.calls.remote_setup).toEqual([
      { code: MOCK_SETUP_CODE, ownerLabel: "Ana Ruiz", passphrase: PHRASE, deviceLabel: "ana-laptop", url: null },
    ]);
    const groups = within(within(dialog).getByRole("list", { name: /Recovery key, 15 groups/ })).getAllByRole("listitem");
    expect(groups).toHaveLength(15);
    expect(await axe(dialog)).toHaveNoViolations();
    // No way out before the key is saved: Escape does nothing and there is no Cancel.
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Cancel" })).toBeNull();

    const connect = within(dialog).getByRole("button", { name: "Connect to the server" });
    await user.click(connect);
    const inputs = within(dialog).getAllByLabelText(/^Type group \d+$/);
    expect(inputs).toHaveLength(2);
    expect(mock.calls.remote_activate).toBeUndefined();
    const parts = MOCK_SETUP_RECOVERY_KEY.split("-");
    const numbers = inputs.map((input) => Number(/\d+/.exec((input as HTMLInputElement).labels?.[0]?.textContent ?? "")?.[0]));
    for (const [i, input] of inputs.entries()) await user.type(input, parts[numbers[i] - 1].toLowerCase());
    await user.click(within(dialog).getByLabelText("I stored the recovery key away from this computer."));
    await user.click(connect);

    await waitFor(() => expect(mock.calls.remote_activate).toHaveLength(1));
    expect(mock.calls.remote_activate).toEqual([{ profile: mock.profiles[0].id, lockLocal: false }]);
    expect(mock.activated).toBe(mock.profiles[0].id);
    // The mock "restarts" in remote mode: the unlock card is the server's.
    expect(await screen.findByRole("heading", { level: 1, name: "Connect to ana-laptop" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
    // Nothing of the key, the phrase or the code stays on the page.
    for (const secret of [MOCK_SETUP_RECOVERY_KEY, PHRASE, "CRK1-SRVA"]) expect(document.body.textContent).not.toContain(secret);
  });

  it("copies the recovery key with the backend clipboard command of the setup", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog);
    await user.click(await fillOwner(user, dialog));
    await within(dialog).findByRole("heading", { name: "Save your recovery key" });
    await user.click(within(dialog).getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(mock.calls.remote_setup_copy_key).toHaveLength(1));
    // The server key has its own command: the one-time value of a local vault is never asked.
    expect(mock.calls.clipboard_copy_once).toBeUndefined();
  });

  it("takes the person back to the first step to use another code, and the old one is gone", async () => {
    const user = userEvent.setup();
    renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog, codeFor("badtoken"));
    await user.click(await fillOwner(user, dialog));
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent(/did not accept the setup code/);
    expect(alert).toHaveTextContent("remote_setup: unauthenticated");
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(alert).getByRole("button", { name: "Use another code" }));
    expect(await within(dialog).findByRole("heading", { name: "Connect to the server" })).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Setup code")).toHaveValue("");
    expect(within(dialog).getByRole("button", { name: "Check server" })).toBeDisabled();
  });

  it("keeps what was typed when the server refuses a field, and lists the fields", async () => {
    const user = userEvent.setup();
    renderApp({
      state: "no_vault",
      path: "/unlock",
      handlers: {
        ...all,
        remote_setup: () => {
          throw {
            code: "validation_failed",
            message: "validation failed",
            retry_after_seconds: null,
            fields: [{ field: "owner_label", problem: "must not hold control characters" }],
          };
        },
      },
    });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog);
    await user.click(await fillOwner(user, dialog));
    const alert = await within(dialog).findByRole("alert");
    expect(within(alert).getByText("Cannot create the vault")).toBeInTheDocument();
    expect(within(alert).getByLabelText("The server did not accept these fields")).toHaveTextContent("owner_label must not hold control characters");
    expect(within(dialog).getByLabelText("Your name on this vault")).toHaveValue("Ana Ruiz");
    expect(within(dialog).getByRole("button", { name: "Create vault on the server" })).toBeEnabled();
  });

  it("counts down the wait that the server asks for, keeps the code and the typed values, and tries again after it", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog, codeFor("toomany"));
    const create = await fillOwner(user, dialog);
    await user.click(create);
    const alert = await within(dialog).findByRole("alert");
    expect(within(alert).getByText("Wait before you try again")).toBeInTheDocument();
    expect(alert).toHaveTextContent(/The code stays valid, and the server needs no restart/);
    expect(alert).toHaveTextContent("remote_setup: too_many_failures");
    // The count is visible, the screen readers get one fixed sentence, and the button waits.
    expect(within(alert).getByText(/^Try again in \d s\.$/)).toHaveAttribute("aria-hidden", "true");
    expect(within(alert).getByText("Try again in 2 seconds.")).toHaveClass("sr-only");
    expect(within(alert).queryByRole("button", { name: "Use another code" })).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Create vault on the server" })).toBeDisabled();
    expect(await axe(dialog)).toHaveNoViolations();
    // After the wait the same notice stays (no jump) and says so; the button works again with the same values.
    expect(await within(dialog).findByText("You can try again now.")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Your name on this vault")).toHaveValue("Ana Ruiz");
    const again = within(dialog).getByRole("button", { name: "Create vault on the server" });
    expect(again).toBeEnabled();
    await user.click(again);
    expect(await within(dialog).findByRole("heading", { name: "Save your recovery key" })).toBeInTheDocument();
    expect(mock.calls.remote_setup).toHaveLength(2);
    expect((mock.calls.remote_setup as { code: string }[])[1].code).toBe(codeFor("toomany"));
  });

  it("says that the vault may exist when the answer never arrived", async () => {
    const user = userEvent.setup();
    renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog, codeFor("lost"));
    await user.click(await fillOwner(user, dialog));
    const alert = await within(dialog).findByRole("alert");
    expect(within(alert).getByText("The answer of the server did not arrive")).toBeInTheDocument();
    expect(alert).toHaveTextContent(/cerberusd status/);
    expect(alert).toHaveTextContent(/nobody can show it again/);
    expect(within(alert).queryByRole("button", { name: "Use another code" })).toBeNull();
  });

  it("keeps the recovery step and says why when the switch is refused", async () => {
    const user = userEvent.setup();
    renderApp({
      state: "no_vault",
      path: "/unlock",
      handlers: {
        ...all,
        remote_activate: () => {
          throw { code: "unavailable", message: "a file of the remote profile is missing", retry_after_seconds: null, fields: [] };
        },
      },
    });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog);
    await user.click(await fillOwner(user, dialog));
    await within(dialog).findByRole("heading", { name: "Save your recovery key" });
    const parts = MOCK_SETUP_RECOVERY_KEY.split("-");
    for (const input of within(dialog).getAllByLabelText(/^Type group \d+$/)) {
      const n = Number(/\d+/.exec((input as HTMLInputElement).labels?.[0]?.textContent ?? "")?.[0]);
      await user.type(input, parts[n - 1]);
    }
    await user.click(within(dialog).getByLabelText("I stored the recovery key away from this computer."));
    await user.click(within(dialog).getByRole("button", { name: "Connect to the server" }));
    expect(await within(dialog).findByText("Cannot connect")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Connect to the server" })).toBeEnabled();
    expect(within(dialog).getByRole("heading", { name: "Save your recovery key" })).toBeInTheDocument();
  });
});

describe("set up a new server from Settings", () => {
  it("is offered in local mode, and locks the local vault with the switch", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "unlocked", path: "/settings", handlers: all });
    const section = await screen.findByRole("region", { name: "Remote server" });
    await user.click(within(section).getByRole("button", { name: "Set up a new server" }));
    const dialog = await screen.findByRole("dialog", { name: "Set up a new server" });
    await toOwnerStep(user, dialog);
    await user.click(await fillOwner(user, dialog));
    await within(dialog).findByRole("heading", { name: "Save your recovery key" });
    const parts = MOCK_SETUP_RECOVERY_KEY.split("-");
    for (const input of within(dialog).getAllByLabelText(/^Type group \d+$/)) {
      const n = Number(/\d+/.exec((input as HTMLInputElement).labels?.[0]?.textContent ?? "")?.[0]);
      await user.type(input, parts[n - 1]);
    }
    await user.click(within(dialog).getByLabelText("I stored the recovery key away from this computer."));
    await user.click(within(dialog).getByRole("button", { name: "Connect to the server" }));
    await waitFor(() => expect(mock.calls.remote_activate).toEqual([{ profile: mock.profiles[0].id, lockLocal: true }]));
  });

  it("is not offered while the desktop is connected to a server", async () => {
    renderApp({ state: "unlocked", path: "/settings", remote: true });
    const section = await screen.findByRole("region", { name: "Remote server" });
    await within(section).findByText("Connected to build-server");
    expect(within(section).queryByRole("button", { name: "Set up a new server" })).toBeNull();
  });
});

describe("set up a new server: nothing is lost after the vault exists", () => {
  it("shows the key and offers to save the connection again when the profile was not stored", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog, codeFor("nostore"));
    await user.click(await fillOwner(user, dialog));
    expect(await within(dialog).findByRole("heading", { name: "Save your recovery key" })).toBeInTheDocument();
    expect(within(dialog).getByText("The connection was not saved")).toBeInTheDocument();
    expect(within(dialog).getByRole("list", { name: /Recovery key, 15 groups/ })).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Connect to the server" })).toBeNull();
    expect(await axe(dialog)).toHaveNoViolations();

    await passProof(user, dialog);
    const save = within(dialog).getByRole("button", { name: "Save the connection" });
    // The first save fails like the first try, and the key stays on the screen.
    await user.click(save);
    await waitFor(() => expect(mock.calls.remote_setup_save).toHaveLength(1));
    expect(await within(dialog).findByText(/remote_setup_save: internal/)).toBeInTheDocument();
    expect(within(dialog).getByRole("list", { name: /Recovery key, 15 groups/ })).toBeInTheDocument();
    await user.click(save);
    expect(await within(dialog).findByRole("button", { name: "Connect to the server" })).toBeInTheDocument();
    expect(within(dialog).queryByText("The connection was not saved")).toBeNull();
    expect(mock.profiles).toHaveLength(1);
  });

  it("lets the person leave without a saved connection once the key is checked", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({ state: "no_vault", path: "/unlock", handlers: all });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog, codeFor("nostore"));
    await user.click(await fillOwner(user, dialog));
    await within(dialog).findByRole("heading", { name: "Save your recovery key" });
    const leave = within(dialog).getByRole("button", { name: "Close without saving" });
    // Not before the key is checked.
    await user.click(leave);
    expect(mock.calls.remote_setup_finish).toBeUndefined();
    await passProof(user, dialog);
    await user.click(leave);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mock.calls.remote_setup_finish).toHaveLength(1);
    expect(document.body.textContent).not.toContain("CRK1-SRVA");
  });

  it("is not a dead end: when the switch keeps failing the person can close and connect later", async () => {
    const user = userEvent.setup();
    const { mock } = renderApp({
      state: "no_vault",
      path: "/unlock",
      handlers: {
        ...all,
        remote_activate: () => {
          throw { code: "unavailable", message: "a file of the remote profile is missing", retry_after_seconds: null, fields: [] };
        },
      },
    });
    const dialog = await openDialog(user);
    await toOwnerStep(user, dialog);
    await user.click(await fillOwner(user, dialog));
    await within(dialog).findByRole("heading", { name: "Save your recovery key" });
    await passProof(user, dialog);
    await user.click(within(dialog).getByRole("button", { name: "Connect to the server" }));
    expect(await within(dialog).findByText("Cannot connect")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Close, connect later" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mock.calls.remote_setup_finish).toHaveLength(1);
    // The profile stays, so Settings can connect to it.
    expect(mock.profiles).toHaveLength(1);
  });

  it("keeps the long call and its answer when the screen that started it goes away", async () => {
    const user = userEvent.setup();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { mock, location } = renderApp({
      state: "unlocked",
      path: "/settings",
      handlers: {
        ...all,
        remote_setup: async (_args, ctl) => {
          await gate;
          const profile = { ...MOCK_PROFILE, id: "0196d7a0-1c2e-7c3a-9f00-00000000b001", active: false };
          ctl.profiles = [...ctl.profiles, profile];
          return { profile, store_error: null, recovery_key: MOCK_SETUP_RECOVERY_KEY };
        },
      },
    });
    const section = await screen.findByRole("region", { name: "Remote server" });
    await user.click(within(section).getByRole("button", { name: "Set up a new server" }));
    const dialog = await screen.findByRole("dialog", { name: "Set up a new server" });
    await toOwnerStep(user, dialog);
    await user.click(await fillOwner(user, dialog));
    expect(await within(dialog).findByText("Creating the vault on the server")).toBeInTheDocument();

    // The local vault locks (idle lock, sleep): Settings goes away and the unlock screen comes.
    await mock.setState("sealed");
    await waitFor(() => expect(location.history?.at(-1)).toBe("/unlock"));
    expect(screen.queryByRole("region", { name: "Remote server" })).toBeNull();
    expect(screen.getByRole("dialog", { name: "Set up a new server" })).toBeInTheDocument();
    expect(screen.getByText("Creating the vault on the server")).toBeInTheDocument();

    release();
    const after = await screen.findByRole("dialog", { name: "Set up a new server" });
    expect(await within(after).findByRole("heading", { name: "Save your recovery key" })).toBeInTheDocument();
    await user.click(within(after).getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(mock.calls.remote_setup_copy_key).toHaveLength(1));
    await passProof(user, after);
    await user.click(within(after).getByRole("button", { name: "Connect to the server" }));
    // Started from Settings: the switch locks the local vault first.
    await waitFor(() => expect(mock.calls.remote_activate).toEqual([{ profile: "0196d7a0-1c2e-7c3a-9f00-00000000b001", lockLocal: true }]));
  });
});
