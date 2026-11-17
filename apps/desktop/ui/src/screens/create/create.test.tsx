import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { beforeEach, describe, expect, it } from "vitest";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { renderApp } from "../../test/renderApp";
import { handlers, MOCK_RECOVERY_KEY } from "./mock";

// Fake values only. They are not real phrases or keys.
const PHRASE = "correct horse battery staple";

function renderCreate(extra: MockHandlers = {}) {
  return renderApp({ state: "no_vault", path: "/create", handlers: { ...handlers, ...extra } });
}

async function toPhraseStep(user: ReturnType<typeof userEvent.setup>, name = "Ana Ruiz") {
  await user.type(await screen.findByLabelText("Your name on this vault"), name);
  await user.click(screen.getByRole("button", { name: "Continue" }));
  await screen.findByRole("heading", { name: "Choose a master phrase" });
}

async function toCostStep(user: ReturnType<typeof userEvent.setup>, name?: string) {
  await toPhraseStep(user, name);
  await user.type(screen.getByLabelText("Master phrase"), PHRASE);
  await user.type(screen.getByLabelText("Type the phrase again"), PHRASE);
  await waitFor(() => expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Continue" }));
  await screen.findByRole("heading", { name: "Test the unlock cost" });
}

async function createVault(user: ReturnType<typeof userEvent.setup>) {
  const button = screen.getByRole("button", { name: "Create vault" });
  await waitFor(() => expect(button).toBeEnabled());
  await user.click(button);
}


describe("create vault", () => {
  beforeEach(() => window.localStorage.clear());

  it("starts on the name step with no axe violations", async () => {
    const { container } = renderCreate();
    expect(await screen.findByRole("heading", { name: "Create your vault" })).toBeInTheDocument();
    expect(screen.getByLabelText("Setup steps")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("asks for a name before it continues", async () => {
    const user = userEvent.setup();
    renderCreate();
    await user.click(await screen.findByRole("button", { name: "Continue" }));
    expect(await screen.findByText("Enter a name.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Create your vault" })).toBeInTheDocument();
  });

  it("adds and removes an extra network name, and rejects a bad one", async () => {
    const user = userEvent.setup();
    renderCreate();
    await user.click(await screen.findByText("Network names for the local certificate"));
    const input = screen.getByLabelText("Another network name");
    await user.type(input, "bad name/");
    await user.click(screen.getByRole("button", { name: "Add name" }));
    expect(await screen.findByText(/plain host name/)).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "ana-laptop{Enter}");
    expect(await screen.findByText("ana-laptop")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Remove ana-laptop" }));
    expect(screen.queryByText("ana-laptop")).toBeNull();
  });

  it("blocks a weak phrase and shows the strength", async () => {
    const user = userEvent.setup();
    const { container } = renderCreate();
    await toPhraseStep(user);
    await user.type(screen.getByLabelText("Master phrase"), "abc");
    await user.type(screen.getByLabelText("Type the phrase again"), "abc");
    expect(await screen.findByText(/^Too weak\./)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
    expect(screen.getByText("At least 12 characters")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("asks for the same phrase twice", async () => {
    const user = userEvent.setup();
    renderCreate();
    await toPhraseStep(user);
    await user.type(screen.getByLabelText("Master phrase"), PHRASE);
    await user.type(screen.getByLabelText("Type the phrase again"), "something else here");
    expect(await screen.findByText("The two phrases are not the same.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();
  });

  it("generates a word phrase and fills both fields", async () => {
    const user = userEvent.setup();
    renderCreate();
    await toPhraseStep(user);
    await user.click(screen.getByRole("button", { name: "Generate" }));
    expect(await screen.findByText(/7 words from the EFF list/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Continue" })).toBeEnabled());
    await user.click(screen.getByLabelText("Show phrase"));
    expect((screen.getByLabelText("Master phrase") as HTMLInputElement).type).toBe("text");
  });

  it("shows the cost test result and lets the person run it again", async () => {
    const user = userEvent.setup();
    const { container } = renderCreate();
    await toCostStep(user);
    expect(await screen.findByText("256 MiB")).toBeInTheDocument();
    expect(screen.getByText("0.71 s")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await user.click(screen.getByRole("button", { name: "Run the test again" }));
    expect(await screen.findByText("256 MiB")).toBeInTheDocument();
  });

  it("shows an error when the cost test fails, and creates nothing", async () => {
    const user = userEvent.setup();
    renderCreate({
      kdf_benchmark: () => {
        throw mockError("internal", "internal error");
      },
    });
    await toCostStep(user);
    expect(await screen.findByText("Cannot measure this device")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create vault" })).toBeDisabled();
  });

  it("creates the vault, keeps the screen while the vault is open, and checks the recovery key", async () => {
    const user = userEvent.setup();
    const { mock, container, location } = renderCreate();
    await toCostStep(user);
    await createVault(user);
    expect(await screen.findByText("Creating your vault")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Save your recovery key" })).toBeInTheDocument();
    // The backend now says unlocked, but the screen stays until the key is saved.
    expect(mock.state).toBe("unlocked");
    expect(location.history?.at(-1)).toBe("/create");
    const groups = within(screen.getByRole("list", { name: /Recovery key, 15 groups/ })).getAllByRole("listitem");
    expect(groups).toHaveLength(15);
    expect(await axe(container)).toHaveNoViolations();

    const open = screen.getByRole("button", { name: "Open the vault" });
    await user.click(open);
    expect(await screen.findByText("Group 3 does not match.")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Type group 3"), "aaaa");
    await user.type(screen.getByLabelText("Type group 11"), "jjjj");
    await user.click(screen.getByLabelText("I stored the recovery key away from this computer."));
    await user.click(open);
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Save your recovery key" })).toBeNull());
    await waitFor(() => expect(location.history?.at(-1)).toBe("/dashboard"));
    // Nothing of the key stays on the page.
    expect(document.body.textContent).not.toContain("DEMO-AAAA");
    expect(document.body.textContent).not.toContain(MOCK_RECOVERY_KEY);
  });

  it("copies the key with the backend one-time clipboard, not with the page", async () => {
    const user = userEvent.setup();
    const calls: string[] = [];
    renderCreate({
      clipboard_copy_once: (args) => {
        calls.push(String((args as { kind: string }).kind));
        return null;
      },
    });
    await toCostStep(user);
    await createVault(user);
    await screen.findByRole("heading", { name: "Save your recovery key" });
    await user.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(calls).toEqual(["recovery_key"]));
    expect(await screen.findByText("Recovery key copied")).toBeInTheDocument();
  });

  it("shows what failed and goes back to the cost step", async () => {
    const user = userEvent.setup();
    const { container } = renderCreate();
    await toCostStep(user, "fail");
    await createVault(user);
    expect(await screen.findByRole("heading", { name: "Cannot create the vault" })).toBeInTheDocument();
    expect(screen.getByText("vault_create: internal")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByRole("heading", { name: "Test the unlock cost" })).toBeInTheDocument();
  });

  it("lists field problems of a rejected create", async () => {
    const user = userEvent.setup();
    renderCreate();
    await toCostStep(user, "invalid");
    await createVault(user);
    expect(await screen.findByText("must not hold control characters", { exact: false })).toBeInTheDocument();
  });

  it("goes back to an earlier step from the step list", async () => {
    const user = userEvent.setup();
    renderCreate();
    await toPhraseStep(user);
    await user.click(screen.getByRole("button", { name: /Your name/ }));
    expect(await screen.findByRole("heading", { name: "Create your vault" })).toBeInTheDocument();
    expect(screen.getByLabelText("Your name on this vault")).toHaveValue("Ana Ruiz");
  });
});
