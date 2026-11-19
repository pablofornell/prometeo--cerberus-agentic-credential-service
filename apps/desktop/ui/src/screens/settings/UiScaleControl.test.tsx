import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PrefsProvider } from "../../state/prefs";
import * as uiScale from "../../state/uiScale";
import { COMMIT_DELAY_MS } from "./sizeControl";
import { UiScaleControl } from "./UiScaleControl";

vi.mock("../../state/uiScale", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../state/uiScale")>();
  return { ...actual, applyUiScale: vi.fn(async () => {}) };
});

// A pointer click has `detail` 1; Enter or Space on a button gives a click with `detail` 0.
const inc = () => screen.getByRole("button", { name: "Increase UI scale" });
const dec = () => screen.getByRole("button", { name: "Decrease UI scale" });
const slider = () => screen.getByRole("slider", { name: "UI scale" });
const ctl = () => slider().closest(".scale-ctl")!;
const click = (el: Element) => fireEvent.click(el, { detail: 1, clientX: 20, clientY: 20 });
const shown = () => screen.getByRole("status").textContent;
const applied = () => vi.mocked(uiScale.applyUiScale).mock.calls.map((c) => c[0]);
const wait = (ms: number) => act(() => vi.advanceTimersByTime(ms));

describe("UiScaleControl: pending value of the - and + buttons", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    window.localStorage.clear();
    vi.mocked(uiScale.applyUiScale).mockClear();
  });
  afterEach(() => vi.useRealTimers());

  const setup = () => {
    const view = render(
      <PrefsProvider>
        <UiScaleControl />
      </PrefsProvider>,
    );
    vi.mocked(uiScale.applyUiScale).mockClear(); // the one of the start
    return view;
  };

  it("three quick clicks show 110, 120, 130 at once and apply 130 once, after the wait", () => {
    setup();
    click(inc());
    expect(shown()).toBe("110%");
    expect(slider()).toHaveValue("110");
    expect(slider()).toHaveAttribute("aria-valuetext", "110%");
    wait(300);
    click(inc());
    expect(shown()).toBe("120%");
    wait(300);
    click(inc());
    expect(shown()).toBe("130%");
    expect(slider()).toHaveValue("130");
    expect(applied()).toEqual([]);
    wait(COMMIT_DELAY_MS - 1);
    expect(applied()).toEqual([]);
    wait(1);
    expect(applied()).toEqual([130]);
    expect(shown()).toBe("130%");
    wait(5000);
    expect(applied()).toEqual([130]);
  });

  it("each click restarts the wait", () => {
    setup();
    click(inc());
    wait(COMMIT_DELAY_MS - 100);
    click(inc());
    wait(COMMIT_DELAY_MS - 100);
    expect(applied()).toEqual([]);
    wait(100);
    expect(applied()).toEqual([120]);
  });

  it("the pointer leaving the control applies at once, and only once", () => {
    setup();
    click(inc());
    click(inc());
    fireEvent.pointerLeave(ctl(), { pointerType: "mouse" });
    expect(applied()).toEqual([120]);
    wait(5000);
    expect(applied()).toEqual([120]);
  });

  it("a touch or pen pointer leaving does not apply: it fires between taps, so the timer applies", () => {
    setup();
    click(inc());
    fireEvent.pointerLeave(ctl(), { pointerType: "touch" });
    click(inc());
    fireEvent.pointerLeave(ctl(), { pointerType: "pen" });
    click(inc());
    fireEvent.pointerLeave(ctl(), { pointerType: "touch" });
    expect(shown()).toBe("130%");
    expect(applied()).toEqual([]);
    wait(COMMIT_DELAY_MS);
    expect(applied()).toEqual([130]);
  });

  it("the window losing the focus applies at once", () => {
    setup();
    click(dec());
    expect(applied()).toEqual([]);
    act(() => void window.dispatchEvent(new Event("blur")));
    expect(applied()).toEqual([90]);
    wait(5000);
    expect(applied()).toEqual([90]);
  });

  it("Enter on a button applies at once and keeps the focus", () => {
    setup();
    inc().focus();
    fireEvent.click(inc(), { detail: 0 });
    expect(shown()).toBe("110%");
    expect(applied()).toEqual([110]);
    expect(inc()).toHaveFocus();
    wait(5000);
    expect(applied()).toEqual([110]);
  });

  it("Enter after pointer clicks steps from the pending value and applies it", () => {
    setup();
    click(inc());
    click(inc());
    fireEvent.click(inc(), { detail: 0 });
    expect(applied()).toEqual([130]);
    wait(5000);
    expect(applied()).toEqual([130]);
  });

  it("the limits follow the pending value", () => {
    setup();
    for (let i = 0; i < 10; i++) click(inc());
    expect(shown()).toBe("200%");
    expect(inc()).toHaveAttribute("aria-disabled", "true");
    expect(dec()).not.toHaveAttribute("aria-disabled");
    click(inc()); // at the limit: nothing
    expect(shown()).toBe("200%");
    expect(applied()).toEqual([]);
    for (let i = 0; i < 12; i++) click(dec());
    expect(shown()).toBe("80%");
    expect(dec()).toHaveAttribute("aria-disabled", "true");
    wait(COMMIT_DELAY_MS);
    expect(applied()).toEqual([80]);
  });

  it("Reset follows the pending value, applies at once and cancels it", () => {
    setup();
    const reset = () => screen.getByRole("button", { name: "Reset to 100%" });
    expect(reset()).toHaveAttribute("aria-disabled", "true");
    click(inc());
    click(inc());
    expect(reset()).not.toHaveAttribute("aria-disabled");
    click(reset());
    expect(shown()).toBe("100%");
    wait(5000);
    expect(applied()).toEqual([]); // the stored scale was 100 all along
    click(inc());
    wait(COMMIT_DELAY_MS);
    expect(applied()).toEqual([110]);
    click(dec());
    click(dec());
    click(reset());
    expect(applied()).toEqual([110, 100]);
    wait(5000);
    expect(applied()).toEqual([110, 100]);
  });

  it("stepping back to the stored value applies nothing", () => {
    setup();
    click(inc());
    click(dec());
    expect(shown()).toBe("100%");
    wait(5000);
    expect(applied()).toEqual([]);
  });

  it("unmounting the control applies the pending value (the prefs stay mounted, as when the screen changes)", () => {
    const Host = ({ open }: { open: boolean }) => <PrefsProvider>{open ? <UiScaleControl /> : null}</PrefsProvider>;
    const { rerender } = render(<Host open />);
    vi.mocked(uiScale.applyUiScale).mockClear();
    click(inc());
    click(inc());
    click(inc());
    expect(applied()).toEqual([]);
    rerender(<Host open={false} />);
    expect(applied()).toEqual([130]);
    wait(5000);
    expect(applied()).toEqual([130]);
  });

  it("an arrow key on the slider applies at once and replaces the pending value", () => {
    setup();
    click(inc());
    click(inc());
    fireEvent.change(slider(), { target: { value: "100" } });
    expect(shown()).toBe("100%");
    wait(5000);
    expect(applied()).toEqual([]);
    click(inc());
    fireEvent.change(slider(), { target: { value: "120" } });
    expect(applied()).toEqual([120]);
    wait(5000);
    expect(applied()).toEqual([120]);
  });

  it("a slider drag after clicks applies the dragged value once and drops the pending one", () => {
    setup();
    click(inc());
    fireEvent.pointerDown(slider(), { button: 0 });
    wait(5000); // the drag has the pointer: nothing is applied during it
    fireEvent.change(slider(), { target: { value: "160" } });
    expect(shown()).toBe("160%");
    expect(applied()).toEqual([]);
    fireEvent.pointerUp(slider());
    expect(applied()).toEqual([160]);
    wait(5000);
    expect(applied()).toEqual([160]);
  });

  it("a lost drag goes back to the pending value, which is then applied", () => {
    setup();
    click(inc());
    fireEvent.pointerDown(slider(), { button: 0 });
    fireEvent.change(slider(), { target: { value: "160" } });
    fireEvent.pointerCancel(slider());
    expect(shown()).toBe("110%");
    expect(applied()).toEqual([]);
    wait(COMMIT_DELAY_MS);
    expect(applied()).toEqual([110]);
  });

  describe("zoom keys act on the shown (pending) value and always consume it", () => {
    const key = (k: string) => fireEvent.keyDown(window, { key: k, ctrlKey: true });

    it("Ctrl+= with 120 pending gives 130", () => {
      setup();
      click(inc());
      click(inc());
      key("=");
      expect(shown()).toBe("130%");
      expect(applied()).toEqual([130]);
      wait(5000);
      expect(applied()).toEqual([130]);
    });

    it("Ctrl+- with 120 pending gives 110", () => {
      setup();
      click(inc());
      click(inc());
      key("-");
      expect(shown()).toBe("110%");
      wait(5000);
      expect(applied()).toEqual([110]);
    });

    it("Ctrl+0 with 120 pending gives 100 although the stored scale is 100: the pending value is dropped", () => {
      setup();
      click(inc());
      click(inc());
      key("0");
      expect(shown()).toBe("100%");
      wait(5000);
      expect(applied()).not.toContain(120); // the key may re-apply 100 (the prefs object is new), never the dropped 120
      expect(shown()).toBe("100%");
    });

    it("Ctrl+= without a pending value steps from the stored one", () => {
      setup();
      key("=");
      expect(shown()).toBe("110%");
      expect(applied()).toEqual([110]);
    });

    it("a click right after the pending value applied steps from the applied value", () => {
      setup();
      click(inc());
      wait(COMMIT_DELAY_MS); // the timer applies 110; the click comes before the next render could update anything
      act(() => {
        vi.mocked(uiScale.applyUiScale).mockClear();
      });
      click(inc());
      expect(shown()).toBe("120%");
      wait(COMMIT_DELAY_MS);
      expect(applied()).toEqual([120]);
    });
  });

  describe("a slider drag whose pointer capture fails", () => {
    // jsdom has no pointer capture at all; give the slider one that throws, as a pointer that is no longer active does.
    const failCapture = () => {
      Object.defineProperty(slider(), "setPointerCapture", {
        configurable: true,
        value: () => {
          throw new DOMException("not active", "NotFoundError");
        },
      });
    };

    it("ends on a release anywhere in the window, and the slider takes new presses", () => {
      setup();
      failCapture();
      click(inc());
      fireEvent.pointerDown(slider(), { button: 0 });
      fireEvent.change(slider(), { target: { value: "160" } });
      expect(shown()).toBe("160%");
      fireEvent.pointerUp(window); // released off the slider
      expect(applied()).toEqual([160]);
      expect(shown()).toBe("160%");
      // not locked: a second press starts a new drag, which also ends
      fireEvent.pointerDown(slider(), { button: 0 });
      fireEvent.change(slider(), { target: { value: "140" } });
      fireEvent.pointerUp(window);
      expect(applied()).toEqual([160, 140]);
    });

    it("ends on a pointercancel anywhere in the window and the pending value is applied again", () => {
      setup();
      failCapture();
      click(inc());
      fireEvent.pointerDown(slider(), { button: 0 });
      fireEvent.pointerCancel(window);
      expect(shown()).toBe("110%");
      wait(COMMIT_DELAY_MS);
      expect(applied()).toEqual([110]);
    });
  });
});
