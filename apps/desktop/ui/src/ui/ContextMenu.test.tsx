import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { axe } from "vitest-axe";
import { Router } from "wouter";
import { memoryLocation } from "wouter/memory-location";
import { vaultStateStore } from "../state/live";
import { ContextMenu, ContextMenuProvider, useContextMenu, type MenuEntry } from ".";

// jsdom has no layout. Give the window a size and the menu one, so the position maths has something to work on.
const sizes = { w: 200, h: 100 };
beforeEach(() => {
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, get: () => sizes.w });
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, get: () => sizes.h });
  vi.spyOn(document.documentElement, "clientWidth", "get").mockReturnValue(800);
  vi.spyOn(document.documentElement, "clientHeight", "get").mockReturnValue(600);
});
afterEach(() => {
  Reflect.deleteProperty(HTMLElement.prototype, "offsetWidth");
  Reflect.deleteProperty(HTMLElement.prototype, "offsetHeight");
  vi.restoreAllMocks();
});

const entries = (spy = vi.fn()): MenuEntry[] => [
  { id: "a", label: "Alpha", icon: "copy", shortcut: "Ctrl+A", onSelect: () => spy("a") },
  { id: "b", label: "Beta", disabled: true, onSelect: () => spy("b") },
  { id: "sep", separator: true },
  { id: "c", label: "Gamma", icon: "edit", onSelect: () => spy("c") },
  { id: "d", label: "Delta", icon: "trash", danger: true, onSelect: () => spy("d") },
];

describe("ContextMenu", () => {
  it("is a named menu with items, a separator, a shortcut hint and a danger item", async () => {
    const { baseElement } = render(<ContextMenu entries={entries()} x={10} y={10} label="Actions" onClose={() => undefined} />);
    const menu = screen.getByRole("menu", { name: "Actions" });
    expect(menu.parentElement).toBe(document.body);
    expect(screen.getAllByRole("menuitem").map((e) => e.textContent)).toEqual(["AlphaCtrl+A", "Beta", "Gamma", "Delta"]);
    expect(screen.getByRole("separator")).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Beta" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("menuitem", { name: "Delta" })).toHaveClass("danger");
    // The menu is a floating layer, not page content: the landmark rule does not apply to it alone.
    expect(await axe(baseElement, { rules: { region: { enabled: false } } })).toHaveNoViolations();
  });

  it("a click runs the item, closes with focus back on the trigger; a disabled item does nothing", async () => {
    const spy = vi.fn();
    const onClose = vi.fn();
    const trigger = document.createElement("button");
    document.body.append(trigger);
    render(<ContextMenu entries={entries(spy)} x={0} y={0} label="Actions" returnFocusTo={trigger} onClose={onClose} />);
    await userEvent.click(screen.getByRole("menuitem", { name: "Beta" }));
    expect(spy).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("menuitem", { name: "Gamma" }));
    expect(spy).toHaveBeenCalledWith("c");
    expect(onClose).toHaveBeenCalledWith("select");
    expect(trigger).toHaveFocus();
    trigger.remove();
  });

  it("keyboard: focus starts on the menu, Down and Up wrap and skip the disabled item, Home and End jump, Enter runs", () => {
    const spy = vi.fn();
    render(<ContextMenu entries={entries(spy)} x={0} y={0} label="Actions" onClose={() => undefined} />);
    const key = (k: string) => fireEvent.keyDown(window, { key: k });
    expect(screen.getByRole("menu")).toHaveFocus();
    key("ArrowDown");
    expect(screen.getByRole("menuitem", { name: /^Alpha/ })).toHaveFocus();
    key("ArrowDown");
    expect(screen.getByRole("menuitem", { name: "Gamma" })).toHaveFocus();
    key("ArrowDown");
    key("ArrowDown");
    expect(screen.getByRole("menuitem", { name: /^Alpha/ })).toHaveFocus();
    key("ArrowUp");
    expect(screen.getByRole("menuitem", { name: "Delta" })).toHaveFocus();
    key("Home");
    expect(screen.getByRole("menuitem", { name: /^Alpha/ })).toHaveFocus();
    key("End");
    expect(screen.getByRole("menuitem", { name: "Delta" })).toHaveFocus();
    key("Enter");
    expect(spy).toHaveBeenCalledWith("d");
  });

  it("focusFirst puts the focus on the first item", () => {
    render(<ContextMenu entries={entries()} x={0} y={0} label="Actions" focusFirst onClose={() => undefined} />);
    expect(screen.getByRole("menuitem", { name: /^Alpha/ })).toHaveFocus();
  });

  it("Escape closes it before a dialog under it sees the key, and the focus goes back", () => {
    const onClose = vi.fn();
    const underneath = vi.fn();
    document.addEventListener("keydown", underneath, true);
    const trigger = document.createElement("button");
    document.body.append(trigger);
    render(<ContextMenu entries={entries()} x={0} y={0} label="Actions" returnFocusTo={trigger} onClose={onClose} />);
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    expect(onClose).toHaveBeenCalledWith("escape");
    expect(trigger).toHaveFocus();
    expect(underneath).not.toHaveBeenCalled();
    document.removeEventListener("keydown", underneath, true);
    trigger.remove();
  });

  it.each([
    ["a click outside", () => fireEvent.pointerDown(document.body), "outside"],
    ["a scroll", () => fireEvent.scroll(document), "scroll"],
    ["a resize", () => fireEvent(window, new Event("resize")), "resize"],
    ["the window losing focus", () => fireEvent(window, new Event("blur")), "blur"],
    ["Tab", () => fireEvent.keyDown(window, { key: "Tab" }), "tab"],
  ] as const)("closes on %s", (_name, act, reason) => {
    const onClose = vi.fn();
    render(<ContextMenu entries={entries()} x={0} y={0} label="Actions" onClose={onClose} />);
    act();
    expect(onClose).toHaveBeenCalledWith(reason);
  });

  it.each([
    ["Ctrl+L", { key: "l", ctrlKey: true }],
    ["Ctrl+K", { key: "k", metaKey: true }],
    ["Alt+Left", { key: "ArrowLeft", altKey: true }],
    ["a letter (n, g)", { key: "n" }],
  ])("%s closes it and does not swallow the key", (_name, init) => {
    const onClose = vi.fn();
    const later = vi.fn();
    document.addEventListener("keydown", later);
    render(<ContextMenu entries={entries()} x={0} y={0} label="Actions" onClose={onClose} />);
    const event = new KeyboardEvent("keydown", { ...init, bubbles: true, cancelable: true });
    document.body.dispatchEvent(event);
    expect(onClose).toHaveBeenCalledWith("key");
    expect(event.defaultPrevented).toBe(false);
    expect(later).toHaveBeenCalled();
    document.removeEventListener("keydown", later);
  });

  it("a bare modifier key does not close it", () => {
    const onClose = vi.fn();
    render(<ContextMenu entries={entries()} x={0} y={0} label="Actions" onClose={onClose} />);
    fireEvent.keyDown(window, { key: "Shift", shiftKey: true });
    fireEvent.keyDown(window, { key: "Control", ctrlKey: true });
    expect(onClose).not.toHaveBeenCalled();
  });

  it("a pointer down or a scroll inside the menu does not close it", () => {
    const onClose = vi.fn();
    render(<ContextMenu entries={entries()} x={0} y={0} label="Actions" onClose={onClose} />);
    fireEvent.pointerDown(screen.getByRole("menuitem", { name: "Gamma" }));
    fireEvent.scroll(screen.getByRole("menu"));
    expect(onClose).not.toHaveBeenCalled();
  });

  describe("position", () => {
    const place = (x: number, y: number) => {
      render(<ContextMenu entries={entries()} x={x} y={y} label="Actions" onClose={() => undefined} />);
      const menu = screen.getByRole("menu");
      return { left: parseFloat(menu.style.left), top: parseFloat(menu.style.top), ready: "ready" in menu.dataset };
    };

    it("opens at the cursor", () => {
      expect(place(100, 120)).toEqual({ left: 100, top: 120, ready: true });
    });
    it("flips to the left and up when it would leave the window", () => {
      expect(place(700, 550)).toMatchObject({ left: 500, top: 450 });
    });
    it("clamps inside the window when a flip does not fit either", () => {
      sizes.w = 900;
      expect(place(300, 10).left).toBe(8);
      sizes.w = 200;
    });
  });
});

function Target({ build }: { build: () => MenuEntry[] | null }) {
  const menu = useContextMenu();
  return (
    <div>
      <div tabIndex={0} data-testid="target" {...menu.targetProps(build, "Target actions")}>
        Row
      </div>
      <p data-testid="plain">Some text</p>
      <input aria-label="Name" defaultValue="hello world" />
      <input aria-label="Secret" type="password" defaultValue="hunter2" />
      <input aria-label="Agree" type="checkbox" />
      <textarea aria-label="Note" readOnly defaultValue="read only" />
    </div>
  );
}

describe("ContextMenuProvider", () => {
  const open = (build: () => MenuEntry[] | null = () => entries()) => render(<ContextMenuProvider><Target build={build} /></ContextMenuProvider>);

  it("hides the webview menu everywhere and shows nothing where there is no target", () => {
    open();
    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 5, clientY: 5 });
    screen.getByTestId("plain").dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("a checkbox is not a text field: no menu", () => {
    open();
    fireEvent.contextMenu(screen.getByRole("checkbox"), { clientX: 5, clientY: 5 });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("a target opens its menu at the pointer and closes it after a choice", async () => {
    const spy = vi.fn();
    open(() => entries(spy));
    const target = screen.getByTestId("target");
    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 30, clientY: 40 });
    target.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
    const menu = await screen.findByRole("menu", { name: "Target actions" });
    expect(menu.style.left).toBe("30px");
    await userEvent.click(screen.getByRole("menuitem", { name: "Gamma" }));
    expect(spy).toHaveBeenCalledWith("c");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("a target with no entries gets no menu", () => {
    open(() => null);
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 5, clientY: 5 });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it.each([
    ["the Menu key", { key: "ContextMenu" }],
    ["Shift+F10", { key: "F10", shiftKey: true }],
  ])("%s opens the menu on the focused target, first item focused", async (_name, init) => {
    open();
    const target = screen.getByTestId("target");
    target.focus();
    fireEvent.keyDown(target, init);
    expect(await screen.findByRole("menuitem", { name: /^Alpha/ })).toHaveFocus();
    fireEvent.keyDown(window, { key: "Escape" });
    expect(target).toHaveFocus();
  });

  it("a contextmenu event after the Menu key opens on the element, first item focused, wherever WebKit put it", async () => {
    open();
    const target = screen.getByTestId("target");
    fireEvent.keyDown(window, { key: "ContextMenu" });
    fireEvent.contextMenu(target, { clientX: 140, clientY: 90 });
    expect(await screen.findByRole("menuitem", { name: /^Alpha/ })).toHaveFocus();
    expect(parseFloat(screen.getByRole("menu").style.left)).not.toBe(140);
  });

  it("a text field opened with Shift+F10 focuses the first item of the text menu", async () => {
    open();
    const input = screen.getByRole("textbox", { name: "Name" });
    input.focus();
    fireEvent.keyDown(input, { key: "F10", shiftKey: true });
    fireEvent.contextMenu(input, { clientX: 60, clientY: 70 });
    await screen.findByRole("menu", { name: "Text" });
    expect(screen.getByRole("menuitem", { name: /^Paste/ })).toBeInTheDocument();
    // Cut and Copy are disabled without a selection, so Paste is the first enabled item.
    expect(screen.getByRole("menuitem", { name: /^Paste/ })).toHaveFocus();
  });

  it("a right click after the Menu key is a pointer open: at the pointer, the menu takes the focus", async () => {
    open();
    fireEvent.keyDown(window, { key: "ContextMenu" });
    fireEvent.pointerDown(screen.getByTestId("target"), { button: 2 });
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 30, clientY: 40 });
    const menu = await screen.findByRole("menu");
    expect(menu.style.left).toBe("30px");
    expect(menu).toHaveFocus();
  });

  it("a pointer right click at (0, 0) is not a keyboard open", async () => {
    open();
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 0, clientY: 0 });
    expect(await screen.findByRole("menu")).toHaveFocus();
  });

  it("a contextmenu event long after the Menu key is not a keyboard open", async () => {
    open();
    const now = vi.spyOn(performance, "now");
    now.mockReturnValue(1000);
    fireEvent.keyDown(window, { key: "ContextMenu" });
    now.mockReturnValue(5000);
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 30, clientY: 40 });
    expect(await screen.findByRole("menu")).toHaveFocus();
  });

  it("closes the menu when the screen changes", async () => {
    const { hook, navigate } = memoryLocation({ path: "/vault" });
    render(
      <Router hook={hook}>
        <ContextMenuProvider>
          <Target build={() => entries()} />
        </ContextMenuProvider>
      </Router>,
    );
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 30, clientY: 40 });
    await screen.findByRole("menu");
    await act(async () => navigate("/audit"));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("closes the menu when the vault locks", async () => {
    act(() => vaultStateStore.set("unlocked"));
    open();
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 30, clientY: 40 });
    await screen.findByRole("menu");
    act(() => vaultStateStore.set("sealed"));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("Ctrl+L closes the menu and the shortcut still sees the key", async () => {
    open();
    const shortcut = vi.fn();
    document.addEventListener("keydown", shortcut);
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 30, clientY: 40 });
    await screen.findByRole("menu");
    fireEvent.keyDown(screen.getByRole("menu"), { key: "l", ctrlKey: true });
    await vi.waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
    expect(shortcut).toHaveBeenCalled();
    document.removeEventListener("keydown", shortcut);
  });

  it("a text field gets the text menu, with Cut and Copy off without a selection", async () => {
    open();
    const input = screen.getByRole("textbox", { name: "Name" }) as HTMLInputElement;
    fireEvent.contextMenu(input, { clientX: 20, clientY: 20 });
    const menu = await screen.findByRole("menu", { name: "Text" });
    expect(screen.getAllByRole("menuitem").map((e) => e.textContent?.replace(/(Ctrl|Cmd)\+.$/, ""))).toEqual(["Cut", "Copy", "Paste", "Select all"]);
    expect(screen.getByRole("menuitem", { name: /^Cut/ })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("menuitem", { name: /^Paste/ })).not.toHaveAttribute("aria-disabled");
    expect(menu).toBeInTheDocument();
  });

  it("Select all selects the field and Copy writes the selection", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    open();
    const input = screen.getByRole("textbox", { name: "Name" }) as HTMLInputElement;
    input.setSelectionRange(0, 5);
    fireEvent.contextMenu(input, { clientX: 20, clientY: 20 });
    await userEvent.click(await screen.findByRole("menuitem", { name: /^Copy/ }));
    expect(writeText).toHaveBeenCalledWith("hello");
    expect(input).toHaveFocus();
    fireEvent.contextMenu(input, { clientX: 20, clientY: 20 });
    await userEvent.click(await screen.findByRole("menuitem", { name: /^Select all/ }));
    expect(input.selectionStart).toBe(0);
    expect(input.selectionEnd).toBe(input.value.length);
  });

  it("Paste inserts the clipboard text at the caret", async () => {
    const execCommand = vi.fn().mockReturnValue(true);
    Object.defineProperty(document, "execCommand", { value: execCommand, configurable: true });
    Object.defineProperty(navigator, "clipboard", { value: { readText: vi.fn().mockResolvedValue("pasted") }, configurable: true });
    open();
    fireEvent.contextMenu(screen.getByRole("textbox", { name: "Name" }), { clientX: 20, clientY: 20 });
    await userEvent.click(await screen.findByRole("menuitem", { name: /^Paste/ }));
    await vi.waitFor(() => expect(execCommand).toHaveBeenCalledWith("insertText", false, "pasted"));
    Reflect.deleteProperty(document, "execCommand");
  });

  it("a password field never offers Cut or Copy", async () => {
    open();
    const input = screen.getByLabelText("Secret") as HTMLInputElement;
    input.setSelectionRange(0, 3);
    fireEvent.contextMenu(input, { clientX: 20, clientY: 20 });
    await screen.findByRole("menu");
    expect(screen.getByRole("menuitem", { name: /^Cut/ })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("menuitem", { name: /^Copy/ })).toHaveAttribute("aria-disabled", "true");
  });

  it("a read-only field cannot be cut into or pasted over", async () => {
    open();
    fireEvent.contextMenu(screen.getByLabelText("Note"), { clientX: 20, clientY: 20 });
    await screen.findByRole("menu");
    expect(screen.getByRole("menuitem", { name: /^Paste/ })).toHaveAttribute("aria-disabled", "true");
  });

  it("selected plain text gets Copy only; no selection gets nothing", async () => {
    open();
    fireEvent.contextMenu(screen.getByTestId("plain"), { clientX: 5, clientY: 5 });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    const text = screen.getByTestId("plain").firstChild as Text;
    const range = document.createRange();
    range.setStart(text, 0);
    range.setEnd(text, 4);
    window.getSelection()?.removeAllRanges();
    window.getSelection()?.addRange(range);
    fireEvent.contextMenu(screen.getByTestId("plain"), { clientX: 5, clientY: 5 });
    await screen.findByRole("menu");
    expect(screen.getAllByRole("menuitem").map((e) => e.textContent?.replace(/(Ctrl|Cmd)\+.$/, ""))).toEqual(["Copy"]);
    window.getSelection()?.removeAllRanges();
  });

  it("in a dev build Shift+right click reaches the native menu (Inspect)", () => {
    open();
    const event = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 5, clientY: 5, shiftKey: true });
    screen.getByTestId("target").dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("a second right click replaces the open menu", async () => {
    open();
    fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 30, clientY: 40 });
    await screen.findByRole("menu");
    fireEvent.pointerDown(screen.getByTestId("target"));
    await act(async () => fireEvent.contextMenu(screen.getByTestId("target"), { clientX: 90, clientY: 90 }));
    expect(screen.getAllByRole("menu")).toHaveLength(1);
    expect(screen.getByRole("menu").style.left).toBe("90px");
  });
});
