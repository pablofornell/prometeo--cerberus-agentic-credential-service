import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import type { LockReasonView, VaultStatusView_Serialize } from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { handlers, MOCK_PHRASE } from "./mock";

// Fake values only.
const WRONG = "not the right phrase";

function renderUnlock(extra: MockHandlers = {}, state: "sealed" | "no_vault" = "sealed", lockReason?: LockReasonView) {
  return renderApp({ state, path: "/unlock", lockReason, handlers: { ...handlers, ...extra } });
}

/** A sealed `vault_status` with the unlock counters of the backend. */
const sealed = (counters: Partial<VaultStatusView_Serialize> = {}): VaultStatusView_Serialize => ({
  state: "sealed",
  operator: null,
  role: null,
  idle_seconds_left: null,
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
  ...counters,
});

describe("unlock", () => {
  it("shows the operators and the phrase field with no axe violations", async () => {
    const { container } = renderUnlock();
    expect(await screen.findByRole("heading", { level: 1, name: "Cerberus is locked" })).toBeInTheDocument();
    expect(await screen.findByRole("radio", { name: /Ana Ruiz/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: /Ben Ortiz/ })).not.toBeChecked();
    expect(screen.getByText("No failed tries.")).toBeInTheDocument();
    // The head is the mark and the title only: no line about HTTP 423 under it.
    expect(screen.queryByText(/HTTP 423/)).not.toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows a skeleton while the operators load, and an error with retry when they fail", async () => {
    const user = userEvent.setup();
    let fail = true;
    renderUnlock({
      vault_list_operators: () => {
        if (fail) throw mockError("internal", "internal error");
        return [{ id: "op-ana", label: "Ana Ruiz", role: "owner", last_unlock_at: null }];
      },
    });
    expect(await screen.findByText("Cannot load the operators")).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("radio", { name: /Ana Ruiz/ })).toBeInTheDocument();
  });

  it("counts a wrong phrase, clears the field and says which slot failed", async () => {
    const user = userEvent.setup();
    const { container } = renderUnlock();
    const field = await screen.findByLabelText("Master phrase");
    await user.type(field, WRONG);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("That phrase does not open the slot for Ana Ruiz.")).toBeInTheDocument();
    expect(await screen.findByText("1 failed try. 4 more before Cerberus makes you wait.")).toBeInTheDocument();
    expect(screen.getByLabelText("Master phrase")).toHaveValue("");
    expect(document.body.textContent).not.toContain(WRONG);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("tabs from the operators to the phrase, then to Unlock, and only then to the recovery switch", async () => {
    const user = userEvent.setup();
    renderUnlock();
    await user.click(await screen.findByRole("radio", { name: /Ben Ortiz/ }));
    expect(screen.getByRole("radio", { name: /Ben Ortiz/ })).toHaveFocus();
    await user.tab();
    expect(screen.getByLabelText("Master phrase")).toHaveFocus();
    // A phrase with spaces stays in the field: the space never reaches the switch.
    await user.keyboard("two words");
    expect(screen.getByLabelText("Master phrase")).toHaveValue("two words");
    await user.tab();
    expect(screen.getByRole("button", { name: "Unlock" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Use recovery key" })).toHaveFocus();
  });

  it("asks for a phrase before it calls the backend", async () => {
    const user = userEvent.setup();
    let calls = 0;
    renderUnlock({
      vault_unlock: () => {
        calls += 1;
        return null;
      },
    });
    await user.click(await screen.findByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("Enter your master phrase.")).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it("takes the phrase out of the field while the key is derived and allows one call only", async () => {
    const user = userEvent.setup();
    let calls = 0;
    let release: () => void = () => {};
    renderUnlock({
      vault_unlock: async () => {
        calls += 1;
        await new Promise<void>((resolve) => (release = resolve));
        throw mockError("bad_credentials", "wrong phrase");
      },
    });
    const input = await screen.findByLabelText("Master phrase");
    await user.type(input, WRONG);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    await waitFor(() => expect(calls).toBe(1));
    expect(screen.getByLabelText(/Master phrase/)).toHaveValue("");
    expect(screen.getByLabelText(/Master phrase/)).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(calls).toBe(1);
    release();
    expect(await screen.findByText("That phrase does not open the slot for Ana Ruiz.")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText("Master phrase")).toHaveFocus());
  });

  it("shows the back-off countdown, disables the input and then lets the person try again", async () => {
    const user = userEvent.setup();
    const { container } = renderUnlock({
      vault_unlock: (_args, ctl) => {
        ctl.failedUnlocks = 5;
        ctl.retryUntil = Date.now() + 2000;
        throw mockError("too_many_failures", "wait", { retry_after_seconds: 2 });
      },
    });
    await user.type(await screen.findByLabelText("Master phrase"), WRONG);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByRole("heading", { name: "Too many failed tries" })).toBeInTheDocument();
    expect(screen.getByRole("timer", { name: "Time to wait" })).toHaveTextContent(/0:0[12]/);
    expect(screen.getByText("Wait before the next try. Restarting the app does not reset this timer.")).toBeInTheDocument();
    // The timer is drawn over the operator list, which stays in place (so nothing moves) but cannot be used.
    const ops = container.querySelector("fieldset.ops");
    expect(ops).toHaveAttribute("inert");
    expect(screen.getByLabelText("Master phrase, disabled while you wait")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Unlock" })).toBeDisabled();
    expect(await axe(container)).toHaveNoViolations();
    expect(await screen.findByText("You can try again.", {})).toBeInTheDocument();
    expect(screen.getByLabelText("Master phrase")).toBeEnabled();
    expect(container.querySelector("fieldset.ops")).not.toHaveAttribute("inert");
  });

  it("waits after five free tries (mock backend)", async () => {
    const user = userEvent.setup();
    renderUnlock();
    for (let i = 0; i < 6; i++) {
      await user.type(await screen.findByLabelText("Master phrase"), WRONG);
      await user.click(screen.getByRole("button", { name: "Unlock" }));
      // The field empties as soon as the key is derived, so wait for the try to end, not for the empty field.
      await waitFor(() => expect(screen.queryByText(/Deriving the key/)).not.toBeInTheDocument());
    }
    expect(await screen.findByRole("heading", { name: "Too many failed tries" })).toBeInTheDocument();
  });

  it("reads the failed tries from the backend, not from the window", async () => {
    const user = userEvent.setup();
    let reads = 0;
    renderUnlock({
      vault_status: () => {
        reads += 1;
        return sealed({ failed_unlocks: 3, free_unlock_tries_left: 2 });
      },
    });
    expect(await screen.findByText("3 failed tries in a row. 2 more before Cerberus makes you wait.")).toBeInTheDocument();
    const before = reads;
    await user.type(screen.getByLabelText("Master phrase"), WRONG);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("That phrase does not open the slot for Ana Ruiz.")).toBeInTheDocument();
    await waitFor(() => expect(reads).toBeGreaterThan(before));
    expect(screen.getByText("3 failed tries in a row. 2 more before Cerberus makes you wait.")).toBeInTheDocument();
  });

  it("starts the wait from the backend when the screen opens during a wait", async () => {
    const { container } = renderUnlock({ vault_status: () => sealed({ failed_unlocks: 6, free_unlock_tries_left: 0, retry_after_seconds: 90 }) });
    expect(await screen.findByRole("heading", { name: "Too many failed tries" })).toBeInTheDocument();
    expect(screen.getByRole("timer", { name: "Time to wait" })).toHaveTextContent(/1:(29|30)/);
    expect(screen.getByText("6 failed tries in a row. Cerberus makes you wait between tries.")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("draws the wait over the recovery key box, which stays disabled", async () => {
    const user = userEvent.setup();
    const { container } = renderUnlock({ vault_status: () => sealed({ failed_unlocks: 6, free_unlock_tries_left: 0, retry_after_seconds: 90 }) });
    await user.click(await screen.findByRole("button", { name: "Use recovery key" }));
    const timer = screen.getByRole("timer", { name: "Time to wait" });
    // Inside the field, over the key box and its hint (unlock.css), so the card keeps its height.
    expect(timer.closest(".field")).toHaveClass("waiting");
    expect(screen.getByLabelText("Recovery key")).toBeDisabled();
    expect(await axe(container)).toHaveNoViolations();
  });

  it.each<[LockReasonView, string]>([
    ["manual", "You locked the vault."],
    ["idle", "The vault locked after a time with no activity."],
    ["max_unlocked", "The vault locked because it reached the longest time it may stay unlocked."],
    ["os", "The vault locked when the screen locked or the device went to sleep."],
    ["quit", "The vault locked when Cerberus quit."],
    ["panic", "The vault locked with the panic button, or Cerberus stopped on an error. Check the audit log."],
    ["restore", "The vault locked after a backup was restored."],
  ])("says why the vault locked: %s", async (reason, sentence) => {
    renderUnlock({}, "sealed", reason);
    expect(await screen.findByText(sentence)).toBeInTheDocument();
  });

  it("shows no reason when the vault was not locked in this run", async () => {
    renderUnlock();
    await screen.findByLabelText("Master phrase");
    expect(screen.queryByText(/The vault locked|You locked the vault/)).not.toBeInTheDocument();
  });

  it("explains an unsupported unlock cost", async () => {
    const user = userEvent.setup();
    const { container } = renderUnlock();
    await user.type(await screen.findByLabelText("Master phrase"), "cost too high for this device");
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("This device cannot run the unlock cost")).toBeInTheDocument();
    expect(screen.getByText("vault_unlock: unavailable")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows other failures with the code line", async () => {
    const user = userEvent.setup();
    renderUnlock({
      vault_unlock: () => {
        throw mockError("vault_corrupt", "bad file");
      },
    });
    await user.type(await screen.findByLabelText("Master phrase"), WRONG);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("vault_unlock: vault_corrupt")).toBeInTheDocument();
  });

  it("unlocks with the right phrase and leaves the screen", async () => {
    const user = userEvent.setup();
    const { mock, location } = renderUnlock();
    await user.type(await screen.findByLabelText("Master phrase"), MOCK_PHRASE);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    await waitFor(() => expect(mock.state).toBe("unlocked"));
    await waitFor(() => expect(location.history?.at(-1)).toBe("/dashboard"));
  });

  it("says it is opening the vault on the footer status line, under the same head", async () => {
    const user = userEvent.setup();
    // The unlock succeeds but the status stays sealed, so the screen stays on "opening".
    renderUnlock({ vault_unlock: () => ({ operator_id: "op-ana", role: "owner", unlocked_at: new Date().toISOString(), via_recovery: false }) });
    await user.type(await screen.findByLabelText("Master phrase"), MOCK_PHRASE);
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("Unlocked. Opening the vault.")).toHaveAttribute("role", "status");
    expect(screen.getByRole("heading", { level: 1, name: "Cerberus is locked" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Use recovery key" })).toBeDisabled();
  });

  it("uses the recovery key: a format error is not a failed try", async () => {
    const user = userEvent.setup();
    const { container } = renderUnlock();
    await user.click(await screen.findByRole("button", { name: "Use recovery key" }));
    const field = screen.getByLabelText("Recovery key");
    expect(screen.queryByRole("radio")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await user.type(field, "garbage");
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("That is not a recovery key. Check for typing errors.")).toBeInTheDocument();
    expect(screen.getByText("No failed tries.")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Recovery key"), "CRK1-DEMO-AAAA");
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    await waitFor(() => expect(screen.queryByLabelText("Recovery key")).toBeNull());
  });

  it("goes back to the phrase from the recovery path", async () => {
    const user = userEvent.setup();
    renderUnlock();
    await user.click(await screen.findByRole("button", { name: "Use recovery key" }));
    await user.click(screen.getByRole("button", { name: "Use master phrase" }));
    expect(await screen.findByLabelText("Master phrase")).toBeInTheDocument();
  });

  it("offers create and restore when there is no vault", async () => {
    const user = userEvent.setup();
    const { container, location } = renderUnlock({}, "no_vault");
    expect(await screen.findByRole("heading", { level: 1, name: "No vault on this device" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await user.click(screen.getByRole("button", { name: "Restore a backup" }));
    expect(await screen.findByRole("dialog", { name: "Restore a backup" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "Create vault" }));
    await waitFor(() => expect(location.history?.at(-1)).toBe("/create"));
  });

  it("says where a stranded vault is and puts it back instead of offering a new one (T27-G)", async () => {
    const user = userEvent.setup();
    const old = "/data/vault.cerberus.pre-restore-20260101T000000Z";
    const { container, location } = renderApp({
      state: "no_vault",
      stranded: [old, "/data/vault.cerberus.pre-restore-20250101T000000Z"],
      path: "/create",
      handlers,
    });
    expect(await screen.findByRole("heading", { level: 1, name: "Your vault was found, but it is not in place" })).toBeInTheDocument();
    expect(location.history?.at(-1)).toBe("/unlock");
    expect(screen.getByTestId("stranded-path")).toHaveTextContent(old);
    expect(screen.getByText("Older files of earlier restores are next to it (1). They are left alone.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Create vault" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await user.click(screen.getByRole("button", { name: "Put the vault back" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Cerberus is locked" })).toBeInTheDocument();
  });

  it("shows the error when the stranded vault cannot be put back", async () => {
    const user = userEvent.setup();
    renderApp({
      state: "no_vault",
      stranded: ["/data/vault.cerberus.pre-restore-20260101T000000Z"],
      path: "/unlock",
      handlers: {
        vault_recover_stranded: () => {
          throw mockError("conflict", "a vault file already exists; nothing was moved");
        },
      },
    });
    await user.click(await screen.findByRole("button", { name: "Put the vault back" }));
    expect(await screen.findByText("Cannot put the vault back")).toBeInTheDocument();
    expect(screen.getByText(/A vault file is already at the vault path/)).toBeInTheDocument();
    expect(screen.getByText("vault_recover_stranded: conflict")).toBeInTheDocument();
  });
});
