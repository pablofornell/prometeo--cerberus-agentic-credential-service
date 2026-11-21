import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OperatorRole } from "../../bindings";
import { renderApp } from "../../test/renderApp";
import { createVaultMock, type VaultMockOptions } from "./mockData";

function open(options: VaultMockOptions & { role?: OperatorRole } = {}) {
  const fake = createVaultMock(options);
  const view = renderApp({ path: "/vault", role: options.role, handlers: fake.handlers });
  return { fake, ...view };
}

/** Holds the eye button of a secret for the full reveal time. */
async function hold(button: HTMLElement) {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  fireEvent.keyDown(button, { key: "Enter" });
  await act(async () => vi.advanceTimersByTimeAsync(600));
  fireEvent.keyUp(button, { key: "Enter" });
  vi.useRealTimers();
}

afterEach(() => vi.useRealTimers());

/** The item options. The selects of the toolbar have `option` elements too, so look inside the list. */
const rows = () => within(screen.getByRole("listbox", { name: "Items" })).getAllByRole("option");
const firstRow = async () => {
  await screen.findByRole("listbox", { name: "Items" });
  return rows()[0] as HTMLElement;
};

describe("vault browser", () => {
  it("lists items with prod badges, role chips and TTL rings for session items", async () => {
    open();
    const list = await screen.findByRole("listbox", { name: "Items" });
    expect(rows()).toHaveLength(13);
    expect(within(list).getAllByText("prod")).toHaveLength(2);
    expect(within(list).getAllByRole("img", { name: /time left/ }).length).toBe(2);
    expect(screen.getByText("13 items in all workspaces")).toBeInTheDocument();
  });

  it("has no axe violations in the ready state (list and grid)", async () => {
    const { container } = open();
    await screen.findByRole("listbox", { name: "Items" });
    expect(await axe(container)).toHaveNoViolations();
    await userEvent.click(screen.getByRole("radio", { name: "Grid" }));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("filters by environment, kind, role, workspace, category and tag", async () => {
    open();
    await screen.findByRole("listbox", { name: "Items" });
    const count = () => rows().length;
    await userEvent.selectOptions(screen.getByLabelText("Environment"), "prod");
    expect(count()).toBe(2);
    await userEvent.selectOptions(screen.getByLabelText("Environment"), "");
    await userEvent.selectOptions(screen.getByLabelText("Kind"), "ssh_key");
    expect(count()).toBe(1);
    await userEvent.selectOptions(screen.getByLabelText("Kind"), "");
    await userEvent.selectOptions(screen.getByLabelText("Role"), "admin");
    expect(count()).toBe(3);
    await userEvent.selectOptions(screen.getByLabelText("Role"), "");
    await userEvent.click(screen.getByRole("button", { name: /^billing-api/ }));
    expect(count()).toBe(2);
    expect(screen.getByText("2 items in billing-api")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /^All workspaces/ }));
    await userEvent.click(screen.getByRole("button", { name: /^Cloud/ }));
    expect(count()).toBe(1);
    await userEvent.click(screen.getByRole("button", { name: /^Cloud/ }));
    await userEvent.click(screen.getByRole("button", { name: "#deploy" }));
    expect(count()).toBe(2);
  });

  it("searches through the backend and shows the empty match state", async () => {
    open();
    await screen.findByRole("listbox", { name: "Items" });
    await userEvent.type(screen.getByRole("searchbox"), "runbook");
    await waitFor(() => expect(rows()).toHaveLength(1));
    await userEvent.clear(screen.getByRole("searchbox"));
    await userEvent.type(screen.getByRole("searchbox"), "zzzz");
    expect(await screen.findByRole("heading", { name: "No items match these filters" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await waitFor(() => expect(rows()).toHaveLength(13));
  });

  it("moves the selection with the arrow keys and opens the details", async () => {
    open();
    const first = await firstRow();
    first.focus();
    await userEvent.keyboard("{ArrowDown}");
    const options = rows();
    expect(options[1]).toHaveAttribute("aria-selected", "true");
    expect(options[1]).toHaveFocus();
    expect(await screen.findByRole("heading", { name: "Shop admin login" })).toBeInTheDocument();
  });

  it("reveals a secret only after the hold, and copies by the IPC command", async () => {
    const { fake } = open();
    await userEvent.click(await firstRow());
    await screen.findByRole("heading", { name: "Shop staging admin" });
    const eye = screen.getByRole("button", { name: "Hold to reveal: Password" });
    fireEvent.click(eye);
    expect(fake.calls.revealed).toEqual([]);
    await hold(eye);
    expect(await screen.findByText("fake-password-0000")).toBeInTheDocument();
    expect(fake.calls.revealed).toEqual(["it-stage"]);
    await userEvent.click(screen.getByRole("button", { name: "Copy: Password" }));
    await waitFor(() => expect(fake.calls.copied).toEqual([{ item: "it-stage", field: "password" }]));
  });

  it("shows the one-time code of an item with a seed", async () => {
    const { fake } = open();
    await userEvent.click(await firstRow());
    const eye = await screen.findByRole("button", { name: "Hold to reveal: One-time code" });
    await hold(eye);
    expect(await screen.findByText("492 113")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Copy: One-time code" }));
    await waitFor(() => expect(fake.calls.copied).toEqual([{ item: "it-stage", field: "totp" }]));
  });

  it("shows use details and the version history with restore", async () => {
    open();
    await userEvent.click(await firstRow());
    expect(await screen.findByText(/^QA runner, /)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "History" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("Version 3")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Restore version 2" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("deletes after a confirm and Cancel is first", async () => {
    const { fake } = open();
    await userEvent.click((await firstRow(), rows()[2] as HTMLElement));
    await userEvent.click(await screen.findByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete item" }));
    await waitFor(() => expect(fake.calls.deleted).toEqual(["it-user"]));
    await waitFor(() => expect(rows()).toHaveLength(12));
  });

  it("viewer: no New item, no Edit or Delete, values denied, no reveal call", async () => {
    const { fake } = open({ role: "viewer" });
    await userEvent.click(await firstRow());
    await screen.findByRole("heading", { name: "Shop staging admin" });
    expect(screen.queryByRole("button", { name: /New item/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Hold to reveal/ })).not.toBeInTheDocument();
    expect(screen.getAllByText("Your role cannot see this value.").length).toBeGreaterThan(0);
    expect(fake.calls.revealed).toEqual([]);
  });

  it("empty vault: explains, offers a workspace first, no placeholder import button", async () => {
    const { container } = open({ mode: "empty" });
    expect(await screen.findByRole("heading", { name: "Add a workspace first" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New workspace" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /import/i })).not.toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("creates a workspace from the empty state", async () => {
    open({ mode: "empty" });
    await userEvent.click(await screen.findByRole("button", { name: "New workspace" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText("Display name"), "Shop frontend");
    expect(within(dialog).getByLabelText("Slug")).toHaveValue("shop-frontend");
    await userEvent.click(within(dialog).getByRole("button", { name: "Create workspace" }));
    expect(await screen.findByRole("heading", { name: "No items in this vault" })).toBeInTheDocument();
  });

  it("error state: says what failed, keeps the code line, and retries", async () => {
    const { container } = open({ mode: "error" });
    expect(await screen.findByRole("heading", { name: "Cannot load items" })).toBeInTheDocument();
    expect(screen.getByText("item_list: internal")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("loading state is announced", async () => {
    open({ mode: "slow" });
    expect(await screen.findByRole("status", { name: "Loading items" })).toHaveAttribute("aria-busy", "true");
  });

  describe("RustDesk item", () => {
    const LINK = "rustdesk://connect/123456789@rd.example.test?key=FAKE%2BKEY%2FFAKE%3D";
    const openLaptop = async (options: VaultMockOptions & { role?: OperatorRole } = {}) => {
      const writeText = vi.fn<(text: string) => Promise<void>>().mockResolvedValue(undefined);
      Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
      const view = open(options);
      await screen.findByRole("listbox", { name: "Items" });
      await userEvent.click(screen.getByRole("option", { name: /Build laptop \(RustDesk\)/ }));
      await screen.findByRole("heading", { name: "Build laptop (RustDesk)" });
      return { ...view, writeText };
    };

    it("shows what to share without the password, with no axe violations", async () => {
      const { container, writeText } = await openLaptop();
      const card = screen.getByRole("region", { name: "Connection" });
      expect(within(card).getByText("123456789")).toBeInTheDocument();
      expect(within(card).getByText("rd.example.test:21117")).toBeInTheDocument();
      expect(within(card).getByText(LINK)).toBeInTheDocument();
      expect(within(card).getByText(/RustDesk gets the relay from the ID server/)).toBeInTheDocument();
      expect(within(card).getByText(/it can misread a key that has a \+/)).toBeInTheDocument();
      await userEvent.click(within(card).getByRole("button", { name: "Copy the RustDesk link" }));
      await userEvent.click(within(card).getByRole("button", { name: "Copy all" }));
      expect(writeText.mock.calls.map(([text]) => text)).toEqual([
        LINK,
        ["RustDesk ID: 123456789", "ID server: rd.example.test", "Relay server: rd.example.test:21117", "Key: FAKE+KEY/FAKE=", `Link: ${LINK}`].join("\n"),
      ]);
      expect(writeText.mock.calls.flat().join("")).not.toContain("fake-rd-password");
      expect(await axe(container)).toHaveNoViolations();
    });

    it("connects and copies the password through the backend, with a toast", async () => {
      const { fake, writeText } = await openLaptop();
      await userEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(fake.calls.connected).toEqual([{ item: "it-laptop", copyPassword: true }]));
      expect(await screen.findByText("Password copied — paste it in RustDesk")).toBeInTheDocument();
      expect(screen.getByText("RustDesk is opening 123456789.")).toBeInTheDocument();
      expect(writeText).not.toHaveBeenCalled();
      // The password row uses the backend copy with auto-clear, as for every other secret.
      await userEvent.click(screen.getByRole("button", { name: "Copy: Password" }));
      await waitFor(() => expect(fake.calls.copied).toEqual([{ item: "it-laptop", field: "password" }]));
    });

    it("viewer: connects without asking for the password", async () => {
      const { fake } = await openLaptop({ role: "viewer" });
      expect(screen.getByText("Opens RustDesk on this ID. Your role cannot copy the password.")).toBeInTheDocument();
      await userEvent.click(screen.getByRole("button", { name: "Connect" }));
      await waitFor(() => expect(fake.calls.connected).toEqual([{ item: "it-laptop", copyPassword: false }]));
      expect(await screen.findByText("RustDesk is opening 123456789.")).toBeInTheDocument();
    });

    it("asks to set an IPv6 ID server in the client, and links the ID alone", async () => {
      await openLaptop({ laptopCustom: { rustdesk_id: "123456789", id_server: "[2001:db8::1]:21116", server_key: "FAKE=" } });
      const card = screen.getByRole("region", { name: "Connection" });
      expect(within(card).getByText("Set this ID server in the RustDesk client")).toBeInTheDocument();
      expect(within(card).getByText("rustdesk://123456789")).toBeInTheDocument();
    });

    it("says how to get RustDesk when it is not installed", async () => {
      const { fake } = await openLaptop({ rustdesk: "missing" });
      expect(await screen.findByText("RustDesk was not found on this computer")).toBeInTheDocument();
      expect(screen.getByText(/Install it from rustdesk.com/)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();
      expect(fake.calls.connected).toEqual([]);
    });
  });

  it("locked: a lock while the list is open leaves the screen", async () => {
    const { mock } = open();
    await screen.findByRole("listbox", { name: "Items" });
    await act(async () => mock.setState("sealed"));
    await waitFor(() => expect(screen.queryByRole("listbox", { name: "Items" })).not.toBeInTheDocument());
  });
});

describe("vault item context menu", () => {
  const menuItems = () => within(screen.getByRole("menu")).getAllByRole("menuitem").map((el) => el.textContent);

  it("right click selects the item and offers open, copy, edit and delete", async () => {
    open();
    const row = await firstRow();
    fireEvent.contextMenu(row, { clientX: 40, clientY: 60 });
    expect(await screen.findByRole("menu", { name: "Actions for Shop staging admin" })).toBeInTheDocument();
    expect(menuItems()).toEqual(["Open details", "Copy: Username", "Copy: Password", "Copy: One-time code", "Edit", "Delete"]);
    expect(row).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByRole("heading", { name: "Shop staging admin" })).toBeInTheDocument();
  });

  it("copy uses the clipboard command of the drawer, with its toast", async () => {
    const { fake } = open();
    fireEvent.contextMenu(await firstRow(), { clientX: 40, clientY: 60 });
    await userEvent.click(await screen.findByRole("menuitem", { name: "Copy: Password" }));
    await waitFor(() => expect(fake.calls.copied).toEqual([{ item: "it-stage", field: "password" }]));
    expect(await screen.findByText(/Copied\. The clipboard clears/)).toBeInTheDocument();
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("delete asks for the same confirm as the drawer and Cancel is first", async () => {
    const { fake } = open();
    await firstRow();
    fireEvent.contextMenu(rows()[2] as HTMLElement, { clientX: 40, clientY: 60 });
    await userEvent.click(await screen.findByRole("menuitem", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog", { name: /^Delete / });
    expect(fake.calls.deleted).toEqual([]);
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    await userEvent.click(within(dialog).getByRole("button", { name: "Delete item" }));
    await waitFor(() => expect(fake.calls.deleted).toEqual(["it-user"]));
    await waitFor(() => expect(rows()).toHaveLength(12));
  });

  it("the Menu key opens it on the focused item, Escape closes it and gives the focus back", async () => {
    open();
    const row = await firstRow();
    row.focus();
    fireEvent.keyDown(row, { key: "ContextMenu" });
    const first = await screen.findByRole("menuitem", { name: "Open details" });
    expect(first).toHaveFocus();
    fireEvent.keyDown(first, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
    expect(row).toHaveFocus();
  });

  it("viewer: open only, no copy, no edit, no delete", async () => {
    open({ role: "viewer" });
    fireEvent.contextMenu(await firstRow(), { clientX: 40, clientY: 60 });
    await screen.findByRole("menu");
    expect(menuItems()).toEqual(["Open details"]);
  });
});
