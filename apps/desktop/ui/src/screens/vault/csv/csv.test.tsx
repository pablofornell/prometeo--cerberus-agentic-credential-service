import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { describe, expect, it } from "vitest";
import type { OperatorRole } from "../../../bindings";
import type { MockHandlers } from "../../../ipc/mock/core";
import { renderApp } from "../../../test/renderApp";
import { createVaultMock } from "../mockData";
import { guessMapping } from "./fields";
import { handlers as csvHandlers } from "./mock";

// Fake values only.
function open(role: OperatorRole = "owner", extra: MockHandlers = {}) {
  const calls: Record<string, unknown[]> = {};
  const spy = (name: string): MockHandlers[string] => (args, ctl) => {
    (calls[name] ??= []).push(args);
    return (extra[name] ?? csvHandlers[name])?.(args, ctl);
  };
  const handlers: MockHandlers = {
    ...createVaultMock({}).handlers,
    ...csvHandlers,
    "plugin:dialog|save": () => "/tmp/cerberus-export.csv",
    file_pick_open: () => "/tmp/bitwarden.csv",
    ...extra,
    csv_preview: spy("csv_preview"),
    csv_import: spy("csv_import"),
    csv_export: spy("csv_export"),
  };
  return { calls, ...renderApp({ path: "/vault", role, handlers }) };
}

const importButton = () => screen.findByRole("button", { name: "Import CSV" });

async function toPreview(user: ReturnType<typeof userEvent.setup>, path: string) {
  await user.click(await importButton());
  const dialog = await screen.findByRole("dialog", { name: "Import from CSV" });
  await user.type(within(dialog).getByLabelText("CSV file"), path);
  await user.click(within(dialog).getByRole("button", { name: "Read file" }));
  await within(dialog).findByText(/Step 2 of 5/);
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  await within(dialog).findByText(/Step 3 of 5/);
  await user.click(within(dialog).getByRole("button", { name: "Next" }));
  await within(dialog).findByText(/Step 4 of 5/);
  return dialog;
}

describe("import deep link", () => {
  it("opens the wizard from ?import=1 (the command palette action)", async () => {
    renderApp({ path: "/vault?import=1", handlers: { ...createVaultMock({}).handlers, ...csvHandlers } });
    expect(await screen.findByRole("dialog", { name: "Import from CSV" })).toBeInTheDocument();
  });
});

describe("csv import wizard", () => {
  it("walks file, format, target, preview and result, and sends the choices", async () => {
    const user = userEvent.setup();
    const { calls, container } = open();
    await user.click(await importButton());
    const dialog = await screen.findByRole("dialog", { name: "Import from CSV" });
    expect(await axe(dialog)).toHaveNoViolations();
    expect(within(dialog).getByText(/Step 1 of 5/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Read file" }));
    expect(await within(dialog).findByText("Choose a file first")).toBeInTheDocument();

    await user.type(within(dialog).getByLabelText("CSV file"), "/tmp/bitwarden.csv");
    await user.click(within(dialog).getByRole("button", { name: "Read file" }));
    expect(await within(dialog).findByText(/The header looks like Bitwarden\. 14 rows found\./)).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Next" }));

    await within(dialog).findByText(/Step 3 of 5/);
    await user.selectOptions(within(dialog).getByLabelText("Environment for rows that have none"), "staging");
    await user.type(within(dialog).getByLabelText("Role label for rows that have none"), "admin");
    await user.click(within(dialog).getByRole("radio", { name: "Add a number" }));
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Next" }));

    await within(dialog).findByText(/Step 4 of 5/);
    expect(within(dialog).getByText("14 rows: 12 will be imported, 0 cannot be, 0 have a title that is already used.")).toBeInTheDocument();
    expect(within(dialog).getByText("Web login 10")).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Import 12 items" }));

    expect(await within(dialog).findByText("Import finished")).toBeInTheDocument();
    expect(within(dialog).getByText(/12 items added/)).toBeInTheDocument();
    const sent = calls["csv_import"]?.[0] as { request: { source: string; environment: string; role_label: string; duplicates: string; path: string } };
    expect(sent.request).toMatchObject({ source: "auto", environment: "staging", role_label: "admin", duplicates: "rename", path: "/tmp/bitwarden.csv" });
    expect(await axe(container)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("shows problems and duplicates in the preview, with no secret", async () => {
    const user = userEvent.setup();
    open();
    const dialog = await toPreview(user, "/tmp/bad.csv");
    expect(within(dialog).getByText("Row 3")).toBeInTheDocument();
    expect(within(dialog).getByText(/not imported \(cards, identities, keys\)/)).toBeInTheDocument();
    expect(within(dialog).getByText(/A value is not valid: payload\.username/)).toBeInTheDocument();
    expect(within(dialog).getByText("Staging admin")).toBeInTheDocument();
    expect(within(dialog).getByText(/3 logins have notes/)).toBeInTheDocument();
    expect(within(dialog).getByText(/if anything fails, nothing is added/)).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
  });

  it("asks for a column mapping when the header is unknown", async () => {
    const user = userEvent.setup();
    const { calls } = open();
    await user.click(await importButton());
    const dialog = await screen.findByRole("dialog", { name: "Import from CSV" });
    await user.type(within(dialog).getByLabelText("CSV file"), "/tmp/unknown.csv");
    await user.click(within(dialog).getByRole("button", { name: "Read file" }));
    expect(await within(dialog).findByText(/not a known format/)).toBeInTheDocument();
    expect(within(dialog).getByRole("group", { name: "Column mapping" })).toBeInTheDocument();
    // The guess fills title, user name, password and kind from the header names.
    expect(within(dialog).getByLabelText("Title")).toHaveValue("Label");
    expect(within(dialog).getByLabelText("Password")).toHaveValue("Pass");
    expect(await axe(dialog)).toHaveNoViolations();
    await user.selectOptions(within(dialog).getByLabelText("Title"), "");
    await user.click(within(dialog).getByRole("button", { name: "Next" }));
    expect(await within(dialog).findByText("Choose the title column")).toBeInTheDocument();
    await user.selectOptions(within(dialog).getByLabelText("Title"), "Label");
    await user.click(within(dialog).getByRole("button", { name: "Next" }));
    await user.click(await within(dialog).findByRole("button", { name: "Next" }));
    await within(dialog).findByText(/Step 4 of 5/);
    const last = calls["csv_preview"]?.at(-1) as { request: { source: string; mapping: { columns: Record<string, string> } } };
    expect(last.request.source).toBe("generic");
    expect(last.request.mapping.columns).toMatchObject({ title: "Label", username: "User name", password: "Pass", kind: "Type" });
  });

  it("shows the reason of a failed read, and of a failed import with nothing added", async () => {
    const user = userEvent.setup();
    open();
    await user.click(await importButton());
    let dialog = await screen.findByRole("dialog", { name: "Import from CSV" });
    await user.type(within(dialog).getByLabelText("CSV file"), "/tmp/utf8.csv");
    await user.click(within(dialog).getByRole("button", { name: "Read file" }));
    expect(await within(dialog).findByText("Cannot read the file")).toBeInTheDocument();
    expect(within(dialog).getByText(/is not UTF-8 text/)).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    dialog = await toPreview(user, "/tmp/fail.csv");
    await user.click(within(dialog).getByRole("button", { name: "Import 12 items" }));
    expect(await within(dialog).findByText("Cannot import the file")).toBeInTheDocument();
    expect(within(dialog).getByText("Nothing was added.")).toBeInTheDocument();
  });

  it("disables the import when no row can be imported", async () => {
    const user = userEvent.setup();
    open();
    const dialog = await toPreview(user, "/tmp/empty.csv");
    expect(within(dialog).getByText(/No row can be imported/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Import 0 items" })).toHaveAttribute("disabled");
  });

  it("is hidden for viewers", async () => {
    open("viewer");
    await screen.findByRole("listbox", { name: "Items" });
    expect(screen.queryByRole("button", { name: "Import CSV" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Export CSV" })).toBeNull();
  });
});

describe("csv export dialog", () => {
  it("warns about plain text, needs the confirmation, and writes through the save dialog", async () => {
    const user = userEvent.setup();
    const { calls } = open();
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    const dialog = await screen.findByRole("dialog", { name: "Export to CSV" });
    expect(within(dialog).getByText("The file holds your secrets in plain text")).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await user.click(within(dialog).getByRole("button", { name: "Choose file and export" }));
    expect(await within(dialog).findByText("Tick the box to continue")).toBeInTheDocument();
    expect(calls["csv_export"]).toBeUndefined();
    expect(await axe(dialog)).toHaveNoViolations();
    await user.selectOptions(within(dialog).getByLabelText("What to export"), within(dialog).getAllByRole("option")[1] as HTMLElement);
    await user.click(within(dialog).getByLabelText("I understand that the file is not encrypted"));
    await user.click(within(dialog).getByRole("button", { name: "Choose file and export" }));
    expect(await screen.findByText("Export written")).toBeInTheDocument();
    const args = calls["csv_export"]?.[0] as { dest: string; workspaceId: string | null };
    expect(args.dest).toBe("/tmp/cerberus-export.csv");
    expect(args.workspaceId).not.toBeNull();
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Export to CSV" })).toBeNull());
  });

  it("shows a failed export, and is hidden for operators", async () => {
    const user = userEvent.setup();
    const { unmount } = open("owner", {
      csv_export: () => {
        throw { code: "role_not_allowed", message: "role not allowed", retry_after_seconds: null, fields: [] };
      },
    });
    await user.click(await screen.findByRole("button", { name: "Export CSV" }));
    const dialog = await screen.findByRole("dialog", { name: "Export to CSV" });
    await user.click(within(dialog).getByLabelText("I understand that the file is not encrypted"));
    await user.click(within(dialog).getByRole("button", { name: "Choose file and export" }));
    expect(await within(dialog).findByText("Cannot export")).toBeInTheDocument();
    unmount();
    open("operator");
    await importButton();
    expect(screen.queryByRole("button", { name: "Export CSV" })).toBeNull();
  });
});

describe("guessMapping", () => {
  it("matches header names without case or spacing", () => {
    expect(guessMapping(["Label", " User Name ", "PASS", "Type", "Other"])).toEqual({ title: "Label", username: " User Name ", password: "PASS", kind: "Type" });
  });
});
