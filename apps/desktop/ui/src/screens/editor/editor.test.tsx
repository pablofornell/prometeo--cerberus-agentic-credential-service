import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import type { OperatorRole } from "../../bindings";
import { renderApp } from "../../test/renderApp";
import { createVaultMock, FAKE_PEM, type VaultMockOptions } from "../vault/mockData";

function open(path: string, options: VaultMockOptions & { role?: OperatorRole } = {}) {
  const fake = createVaultMock(options);
  const view = renderApp({ path, role: options.role, handlers: fake.handlers });
  return { fake, ...view };
}

const form = async () => {
  await screen.findByLabelText("Title");
};
const pickWorkspace = async (slug = "shop-frontend") => userEvent.selectOptions(screen.getByLabelText("Workspace"), slug);
const saveButton = () => screen.getByRole("button", { name: "Save item" });

describe("item editor: new item", () => {
  // One axe run per test: four runs in one test passed the time limit on a busy machine.
  it.each(["Web login", "SSH key", "Database", "Env bundle"])("has no axe violations (%s)", async (kind) => {
    const { container } = open("/editor/new");
    await form();
    await userEvent.click(screen.getByRole("radio", { name: kind }));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("changes the secret panel with the kind and the default category", async () => {
    open("/editor/new");
    await form();
    expect(screen.getByRole("group", { name: "Login" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("radio", { name: "API key" }));
    expect(screen.getByRole("group", { name: "API key" })).toBeInTheDocument();
    expect(screen.getByLabelText("Category")).toHaveValue("API key");
    await userEvent.click(screen.getByRole("radio", { name: "Certificate" }));
    expect(screen.getByLabelText("Certificate (PEM)")).toBeInTheDocument();
    expect(screen.getByLabelText("Category")).toHaveValue("Certificate");
  });

  it("saves a web login and sends the typed payload", async () => {
    const { fake } = open("/editor/new");
    await form();
    await userEvent.type(screen.getByLabelText("Title"), "Fake shop login");
    await pickWorkspace();
    await userEvent.click(screen.getByRole("radio", { name: "staging" }));
    await userEvent.click(screen.getByRole("button", { name: "admin" }));
    await userEvent.type(screen.getByLabelText("Tags"), "e2e, #checkout, E2E");
    await userEvent.type(screen.getByLabelText("Username"), "fake-user@example.test");
    await userEvent.type(screen.getByLabelText("Password"), "fake-password-0000");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.created).toHaveLength(1));
    const input = fake.calls.created[0];
    expect(input).toMatchObject({
      workspace_id: "ws-shop",
      title: "Fake shop login",
      role_label: "admin",
      environment: "staging",
      category: "Web login",
      tags: ["e2e", "checkout"],
      expires_at: null,
      payload: { kind: "web_login", username: "fake-user@example.test", password: "fake-password-0000", url: null, totp: null },
    });
  });

  it("shows the prod note and a custom role label", async () => {
    const { fake } = open("/editor/new");
    await form();
    expect(screen.queryByText(/ask you every time/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("radio", { name: "prod" }));
    expect(screen.getByText(/ask you every time/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Custom role"), "release bot");
    expect(await screen.findByText(/role: "release bot"/, { selector: "pre" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Title"), "Fake");
    await pickWorkspace();
    await userEvent.type(screen.getByLabelText("Password"), "fake-password-0000");
    await userEvent.type(screen.getByLabelText("Username"), "u");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.created[0]?.role_label).toBe("release bot"));
  });

  it("local check: an empty title and workspace stop the save, count in the banner and focus the title", async () => {
    const { fake } = open("/editor/new");
    await form();
    await userEvent.click(saveButton());
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("2 fields need a fix before you can save.");
    expect(alert).toHaveTextContent("Nothing was saved.");
    expect(screen.getByLabelText("Title")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Title")).toHaveFocus();
    expect(screen.getByLabelText("Title")).toHaveAccessibleDescription(/Add a title/);
    expect(fake.calls.created).toHaveLength(0);
  });

  it("maps field problems from the backend onto the fields", async () => {
    const { fake } = open("/editor/new");
    await form();
    await userEvent.type(screen.getByLabelText("Title"), "Fake");
    await pickWorkspace();
    await userEvent.type(screen.getByLabelText("Sign-in URL"), "not-a-url");
    await userEvent.click(saveButton());
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("2 fields need a fix");
    expect(screen.getByLabelText("Sign-in URL")).toHaveAccessibleDescription("must be an http or https URL");
    expect(screen.getByLabelText("Password")).toHaveAccessibleDescription("must be 1..1024 characters");
    expect(fake.calls.created).toHaveLength(0);
  });

  it("generates a password with the IPC command", async () => {
    open("/editor/new");
    await form();
    await userEvent.click(screen.getByRole("button", { name: "Generator" }));
    expect(screen.getByRole("button", { name: "Generator" })).toHaveAttribute("aria-expanded", "true");
    fireEvent.change(screen.getByLabelText("Length"), { target: { value: "16" } });
    await userEvent.click(screen.getByRole("button", { name: "Generate password" }));
    await waitFor(() => expect((screen.getByLabelText("Password") as HTMLInputElement).value).toHaveLength(16));
    await userEvent.click(screen.getByRole("button", { name: "Show Password" }));
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "text");
  });

  it("previews the TOTP code of a seed, and warns about a bad seed", async () => {
    open("/editor/new");
    await form();
    await userEvent.type(screen.getByLabelText("TOTP seed (optional)"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    const code = await screen.findByLabelText("Preview code");
    await waitFor(() => expect(code.textContent).toMatch(/^\d{3} \d{3}$/));
    expect(within(code.parentElement as HTMLElement).getByRole("img", { name: /time left/ })).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("TOTP seed (optional)"));
    await userEvent.type(screen.getByLabelText("TOTP seed (optional)"), "no!");
    expect(await screen.findByText(/not valid Base32/)).toBeInTheDocument();
  });

  it("session kinds always expire and offer a time to live", async () => {
    const { fake } = open("/editor/new");
    await form();
    await userEvent.click(screen.getByRole("radio", { name: "Session token" }));
    const ttl = screen.getByLabelText("Time to live");
    expect(ttl).toHaveValue("3600");
    expect(within(ttl).queryByRole("option", { name: "Never" })).not.toBeInTheDocument();
    expect(within(ttl).getByRole("option", { name: "In 24 hours (maximum)" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Title"), "Fake token");
    await pickWorkspace();
    await userEvent.type(screen.getByLabelText("Token"), "fake-session-token-0000");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.created).toHaveLength(1));
    const at = Date.parse(fake.calls.created[0]?.expires_at ?? "");
    expect(at - Date.now()).toBeGreaterThan(3_500_000);
  });

  it("edits env bundle rows", async () => {
    open("/editor/new");
    await form();
    await userEvent.click(screen.getByRole("radio", { name: "Env bundle" }));
    await userEvent.type(screen.getByLabelText("Name of row 1"), "api_url");
    expect(screen.getByLabelText("Name of row 1")).toHaveValue("API_URL");
    await userEvent.click(screen.getByRole("button", { name: "Add value" }));
    expect(screen.getByLabelText("Name of row 2")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove this row" }));
    expect(screen.queryByLabelText("Name of row 2")).not.toBeInTheDocument();
  });
});

describe("item editor: ssh key", () => {
  const toSsh = async () => {
    await form();
    await userEvent.click(screen.getByRole("radio", { name: "SSH key" }));
  };

  it("generates ed25519, shows public key and fingerprint, saves by draft ID", async () => {
    const { fake } = open("/editor/new");
    await toSsh();
    await userEvent.type(screen.getByLabelText("Title"), "build deploy");
    await pickWorkspace("build-infra");
    await userEvent.click(screen.getByRole("button", { name: "Generate ed25519" }));
    expect(await screen.findByText(/^ssh-ed25519 AAAAFAKEGENERATED build deploy/)).toBeInTheDocument();
    expect(screen.getByText(/^SHA256:/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Host"), "build-01.internal");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.created).toHaveLength(1));
    const input = fake.calls.created[0];
    expect(input?.payload.kind).toBe("ssh_key_draft");
    expect(input?.custom).toMatchObject({ host: "build-01.internal", port: "22" });
    expect(JSON.stringify(input)).not.toContain("PRIVATE KEY");
  });

  it("imports a key from a chosen file (browser fallback) and refuses a bad file", async () => {
    open("/editor/new");
    await toSsh();
    const input = screen.getByTestId("ssh-file-input");
    await userEvent.upload(input, new File(["not a key"], "notes.txt", { type: "text/plain" }));
    expect(await screen.findByText("is not an OpenSSH private key")).toBeInTheDocument();
    await userEvent.upload(input, new File([FAKE_PEM], "id_fake", { type: "text/plain" }));
    expect(await screen.findByText(/^ssh-ed25519 AAAAFAKEIMPORTED/)).toBeInTheDocument();
  });

  it("imports a key dropped on the drop zone and marks the zone while a file is over it", async () => {
    open("/editor/new");
    await toSsh();
    const zone = screen.getByRole("group", { name: "Key file drop zone" });
    fireEvent.dragOver(zone);
    expect(zone).toHaveClass("over");
    const file = new File([FAKE_PEM], "id_fake", { type: "text/plain" });
    await act(async () => {
      fireEvent.drop(zone, { dataTransfer: { files: [file] } });
    });
    expect(await screen.findByText(/^ssh-ed25519 AAAAFAKEIMPORTED/)).toBeInTheDocument();
    expect(zone).not.toHaveClass("over");
  });

  it("refuses a file that is too large before any IPC call", async () => {
    const { fake } = open("/editor/new");
    await toSsh();
    const big = new File(["x".repeat(70 * 1024)], "big.bin");
    await userEvent.upload(screen.getByTestId("ssh-file-input"), big);
    expect(await screen.findByText(/larger than 64 KiB/)).toBeInTheDocument();
    expect(fake.calls.created).toHaveLength(0);
  });

  it("asks for a key when none is set", async () => {
    open("/editor/new");
    await toSsh();
    await userEvent.type(screen.getByLabelText("Title"), "x");
    await pickWorkspace();
    await userEvent.click(saveButton());
    expect(await screen.findByText("Add a key: drop a file, choose one, or generate a new one.")).toBeInTheDocument();
  });
});

describe("item editor: edit", () => {
  it("loads the item without reading the secret, locks the kind, and saves with keep", async () => {
    const { fake } = open("/editor/it-stage");
    expect(await screen.findByDisplayValue("Shop staging admin")).toBeInTheDocument();
    expect(screen.getByText(/The secret is unchanged/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Username")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "API key" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "admin" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("radio", { name: "staging" })).toBeChecked();
    expect(screen.getByLabelText("Workspace")).toHaveValue("ws-shop");
    await userEvent.clear(screen.getByLabelText("Title"));
    await userEvent.type(screen.getByLabelText("Title"), "Shop staging admin 2");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]).toMatchObject({ item: "it-stage", input: { title: "Shop staging admin 2", payload: { kind: "keep" } } });
    expect(fake.calls.revealed).toEqual([]);
  });

  it("replaces the secret only after Replace, and sends the new payload", async () => {
    const { fake } = open("/editor/it-stage");
    await userEvent.click(await screen.findByRole("button", { name: "Replace secret" }));
    expect(screen.getByText("You are replacing the secret")).toBeInTheDocument();
    expect(screen.getByLabelText("Username")).toHaveValue("");
    await userEvent.type(screen.getByLabelText("Username"), "new-user@example.test");
    await userEvent.type(screen.getByLabelText("Password"), "new-fake-password-0000");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]?.input.payload).toEqual({
      kind: "web_login",
      username: "new-user@example.test",
      password: "new-fake-password-0000",
      url: null,
      totp: null,
    });
    expect(fake.calls.revealed).toEqual([]);
  });

  it("goes back to keep when the person cancels the replace", async () => {
    const { fake } = open("/editor/it-stage");
    await userEvent.click(await screen.findByRole("button", { name: "Replace secret" }));
    await userEvent.type(screen.getByLabelText("Password"), "typed-then-dropped");
    await userEvent.click(screen.getByRole("button", { name: "Keep the current secret" }));
    expect(screen.getByText(/The secret is unchanged/)).toBeInTheDocument();
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]?.input.payload).toEqual({ kind: "keep" });
  });

  it("keeps an env bundle it does not read", async () => {
    const { fake } = open("/editor/it-env");
    await userEvent.click(await screen.findByRole("button", { name: "Save item" }));
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]?.input.payload).toEqual({ kind: "keep" });
  });

  it("replaces an env bundle with the typed rows", async () => {
    const { fake } = open("/editor/it-env");
    await userEvent.click(await screen.findByRole("button", { name: "Replace secret" }));
    await userEvent.type(screen.getByLabelText("Name of row 1"), "api_url");
    await userEvent.type(screen.getByLabelText("Value of row 1"), "https://api.shop.example");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]?.input.payload).toEqual({ kind: "env_bundle", vars: { API_URL: "https://api.shop.example" } });
  });

  it("sends the custom values of the item back on save", async () => {
    const { fake } = open("/editor/it-db");
    await screen.findByDisplayValue("Billing database");
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]?.input).toMatchObject({ custom: { cluster: "billing-staging" }, payload: { kind: "keep" } });
  });

  it("keeps the current ssh key and its host details", async () => {
    const { fake } = open("/editor/it-deploy");
    expect(await screen.findByLabelText("Host")).toHaveValue("build-01.internal");
    expect(screen.getByText(/keeps its current key/)).toBeInTheDocument();
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]?.input).toMatchObject({
      custom: { machine: "build-01", host: "build-01.internal", port: "22", user: "deploy" },
      payload: { kind: "keep" },
    });
    expect(fake.calls.revealed).toEqual([]);
  });

  it("replaces the ssh key when a new one is generated", async () => {
    const { fake } = open("/editor/it-deploy");
    await userEvent.click(await screen.findByRole("button", { name: "Generate ed25519" }));
    expect(await screen.findByText(/^ssh-ed25519 AAAAFAKEGENERATED/)).toBeInTheDocument();
    await userEvent.click(saveButton());
    await waitFor(() => expect(fake.calls.updated).toHaveLength(1));
    expect(fake.calls.updated[0]?.input.payload.kind).toBe("ssh_key_draft");
    expect(fake.calls.revealed).toEqual([]);
  });

  it("not found: error state with the code line", async () => {
    open("/editor/nope");
    expect(await screen.findByRole("heading", { name: "Cannot load the item" })).toBeInTheDocument();
    expect(screen.getByText("item_get: not_found")).toBeInTheDocument();
  });

  it("shows a skeleton while the item loads", async () => {
    const fake = createVaultMock();
    fake.handlers.item_get = () => new Promise(() => undefined);
    renderApp({ path: "/editor/it-stage", handlers: fake.handlers });
    expect(await screen.findByRole("status", { name: "Loading the item" })).toBeInTheDocument();
  });

  it("opens an item with a reveal limit at once, because editing is not a reveal", async () => {
    const fake = createVaultMock();
    const base = fake.handlers.item_get;
    fake.handlers.item_get = (args, ctl) => {
      const detail = base?.(args, ctl) as { max_uses: number | null };
      return { ...detail, max_uses: 3 };
    };
    renderApp({ path: "/editor/it-stage", handlers: fake.handlers });
    expect(await screen.findByLabelText("Reveal limit")).toHaveValue("3");
    expect(screen.queryByText("Editing reads the secret")).not.toBeInTheDocument();
    expect(fake.calls.revealed).toEqual([]);
  });
});

describe("item editor: other states", () => {
  it("viewer sees no form and no edit action", async () => {
    open("/editor/new", { role: "viewer" });
    expect(await screen.findByRole("heading", { name: "Your role cannot add or edit items" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Title")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save item" })).not.toBeInTheDocument();
  });

  it("no workspace yet: asks for one first", async () => {
    const { container } = open("/editor/new", { mode: "empty" });
    expect(await screen.findByRole("heading", { name: "Add a workspace first" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("the bare path shows the empty state", async () => {
    open("/editor");
    expect(await screen.findByRole("heading", { name: "No item open" })).toBeInTheDocument();
  });

  it("a lock leaves the form", async () => {
    const { mock } = open("/editor/new");
    await form();
    await act(async () => mock.setState("sealed"));
    await waitFor(() => expect(screen.queryByLabelText("Title")).not.toBeInTheDocument());
  });
});
