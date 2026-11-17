import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { axe } from "vitest-axe";
import { describe, expect, it, vi } from "vitest";
import { renderUi } from "../test/renderUi";
import { Button, ConfirmDialog, DataTable, EmptyState, EnvBadge, ErrorState, Field, HoldButton, Input, RoleChip, SegmentedControl, Switch, Tabs, TtlRing, ttlTone } from ".";
import { IpcFailure } from "../ipc/client";

describe("HoldButton", () => {
  it("runs only after the full hold, and also by keyboard", async () => {
    vi.useFakeTimers();
    const onHold = vi.fn();
    render(<HoldButton holdMs={600} onHold={onHold}>Approve once</HoldButton>);
    const button = screen.getByRole("button", { name: "Approve once" });
    fireEvent.keyDown(button, { key: " " });
    await act(async () => vi.advanceTimersByTimeAsync(500));
    fireEvent.keyUp(button, { key: " " });
    await act(async () => vi.advanceTimersByTimeAsync(500));
    expect(onHold).not.toHaveBeenCalled();

    fireEvent.keyDown(button, { key: "Enter" });
    await act(async () => vi.advanceTimersByTimeAsync(600));
    expect(onHold).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });

  it("a plain click does nothing unless allowClick is set", () => {
    const onHold = vi.fn();
    const { rerender } = render(<HoldButton holdMs={600} onHold={onHold}>Go</HoldButton>);
    const click = () => {
      const b = screen.getByRole("button", { name: "Go" });
      fireEvent.pointerDown(b, { button: 0 });
      fireEvent.pointerUp(b);
      fireEvent.click(b);
    };
    click();
    expect(onHold).not.toHaveBeenCalled();
    rerender(<HoldButton holdMs={600} onHold={onHold} allowClick>Go</HoldButton>);
    click();
    expect(onHold).toHaveBeenCalledTimes(1);
  });
});

describe("TtlRing", () => {
  it("picks the tone from the time left", () => {
    expect(ttlTone(100, 100)).toBe("ok");
    expect(ttlTone(25, 100)).toBe("low");
    expect(ttlTone(10, 100)).toBe("critical");
  });
  it("has an image role with the time as text", () => {
    render(<TtlRing total={300} left={250} />);
    expect(screen.getByRole("img", { name: "4:10 time left" })).toBeInTheDocument();
  });
});

describe("badges", () => {
  it("shows prod and role chips as text", () => {
    render(
      <>
        <EnvBadge env="prod" />
        <RoleChip role="admin" />
        <RoleChip role="deploy bot" />
      </>,
    );
    expect(screen.getByText("prod")).toHaveClass("env", "prod");
    expect(screen.getByText("deploy bot")).toHaveClass("custom");
    expect(screen.getByText("admin")).not.toHaveClass("custom");
  });
});

describe("form controls", () => {
  it("links label, hint and problem to the input", () => {
    render(<Field label="Name" hint="Shown in lists" problem="Required">{(p) => <Input {...p} />}</Field>);
    const input = screen.getByLabelText("Name");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription("Shown in lists Required");
  });

  it("switch is a real checkbox named by its label", async () => {
    const user = userEvent.setup();
    const Demo = () => {
      const [on, setOn] = useState(false);
      return <Switch label="Auto-start" checked={on} onChange={(e) => setOn(e.target.checked)} />;
    };
    render(<Demo />);
    await user.click(screen.getByRole("switch", { name: "Auto-start" }));
    expect(screen.getByRole("switch", { name: "Auto-start" })).toBeChecked();
  });

  it("segmented control moves with arrow keys", async () => {
    const user = userEvent.setup();
    const Demo = () => {
      const [v, setV] = useState("dark");
      return <SegmentedControl label="Theme" value={v} onChange={setV} options={[{ value: "dark", label: "Dark" }, { value: "light", label: "Light" }]} />;
    };
    render(<Demo />);
    screen.getByRole("radio", { name: "Dark" }).focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("radio", { name: "Light" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "Light" })).toHaveFocus();
  });

  it("tabs select with arrow keys and show one panel", async () => {
    const user = userEvent.setup();
    const Demo = () => {
      const [v, setV] = useState<"a" | "b">("a");
      return <Tabs label="Sections" value={v} onChange={setV} tabs={[{ id: "a", label: "Keys", panel: "keys panel" }, { id: "b", label: "Snippets", panel: "snippets panel" }]} />;
    };
    render(<Demo />);
    screen.getByRole("tab", { name: "Keys" }).focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Snippets" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("snippets panel")).toBeInTheDocument();
    expect(screen.queryByText("keys panel")).toBeNull();
  });
});

describe("dialogs and states", () => {
  it("danger confirm dialog focuses Cancel and Esc never confirms", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onOpenChange = vi.fn();
    renderUi(<ConfirmDialog open onOpenChange={onOpenChange} title="Delete Shop staging admin?" description="This cannot be undone." confirmLabel="Delete item" tone="danger" onConfirm={onConfirm} />);
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("error state shows the mono code line and retries", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    const error = new IpcFailure({ code: "vault_corrupt", message: "bad", command: "item_list", retryAfterSeconds: null, fields: [] });
    render(<ErrorState action="load items" error={error} onRetry={onRetry} />);
    expect(screen.getByRole("heading", { name: "Cannot load items" })).toBeInTheDocument();
    expect(screen.getByText("item_list: vault_corrupt")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalled();
  });

  it("error state writes a backend message as a sentence", () => {
    const error = new IpcFailure({ code: "internal", message: "the agent list did not load", command: "agent_list", retryAfterSeconds: null, fields: [] });
    render(<ErrorState action="load agents" error={error} />);
    expect(screen.getByText("The agent list did not load. Your items are safe in the vault file.")).toBeInTheDocument();
  });

  it("table and empty state have no axe violations", async () => {
    const { container } = render(
      <main>
        <h1>Page</h1>
        <EmptyState title="Nothing waits for you" body="Requests show here." icon="bell" action={<Button variant="primary">Open</Button>} />
        <DataTable caption="Agents" columns={[{ id: "n", header: "Name", cell: (r: { n: string }) => r.n }]} rows={[{ n: "QA runner" }]} rowKey={(r) => r.n} />
      </main>,
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
