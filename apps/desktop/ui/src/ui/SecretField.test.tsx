import { act, fireEvent, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { vaultStateStore } from "../state/live";
import { renderUi } from "../test/renderUi";
import { SecretField } from "./SecretField";

const FAKE = "fake-value-1234";

async function holdReveal(ms: number) {
  const eye = screen.getByRole("button", { name: /Hold to reveal: Password/ });
  fireEvent.pointerDown(eye, { button: 0 });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
  fireEvent.pointerUp(eye);
}

describe("SecretField", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("is masked by default and never shows the value", () => {
    renderUi(<SecretField label="Password" onReveal={async () => FAKE} />);
    expect(screen.getByText("Hidden")).toBeInTheDocument();
    expect(screen.queryByText(FAKE)).toBeNull();
  });

  it("does not reveal when the hold is released early", async () => {
    const onReveal = vi.fn(async () => FAKE);
    renderUi(<SecretField label="Password" onReveal={onReveal} />);
    await holdReveal(400);
    expect(onReveal).not.toHaveBeenCalled();
    expect(screen.queryByText(FAKE)).toBeNull();
  });

  it("reveals after a 500 ms hold and hides after 15 s", async () => {
    const onReveal = vi.fn(async () => FAKE);
    renderUi(<SecretField label="Password" onReveal={onReveal} />);
    await holdReveal(500);
    expect(onReveal).toHaveBeenCalledTimes(1);
    expect(screen.getByText(FAKE)).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(14_900);
    });
    expect(screen.getByText(FAKE)).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(200);
    });
    expect(screen.queryByText(FAKE)).toBeNull();
    expect(screen.getByText("Hidden")).toBeInTheDocument();
  });

  it("hides on request and when the vault locks", async () => {
    renderUi(<SecretField label="Password" onReveal={async () => FAKE} />);
    await holdReveal(500);
    fireEvent.click(screen.getByRole("button", { name: "Hide: Password" }));
    expect(screen.queryByText(FAKE)).toBeNull();

    await holdReveal(500);
    expect(screen.getByText(FAKE)).toBeInTheDocument();
    act(() => vaultStateStore.set("sealed"));
    expect(screen.queryByText(FAKE)).toBeNull();
  });

  it("copies through the IPC command and tells the clipboard clears in 30 s", async () => {
    const onCopy = vi.fn(async () => null);
    renderUi(<SecretField label="Password" onReveal={async () => FAKE} onCopy={onCopy} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy: Password" }));
    });
    expect(onCopy).toHaveBeenCalledTimes(1);
    expect(screen.getByText("Copied. The clipboard clears in 30 s.")).toBeInTheDocument();
    expect(screen.queryByText(FAKE)).toBeNull();
  });

  it("never puts the value in an accessible name", async () => {
    renderUi(<SecretField label="Password" onReveal={async () => FAKE} onCopy={async () => null} />);
    await holdReveal(500);
    expect(document.body.innerHTML.split(FAKE).length - 1).toBe(1);
  });

  it("shows the denied state for a viewer", () => {
    renderUi(<SecretField label="Password" onReveal={async () => FAKE} denied />);
    expect(screen.getByText("Your role cannot see this value.")).toBeInTheDocument();
    expect(screen.queryByRole("button")).toBeNull();
  });
});
