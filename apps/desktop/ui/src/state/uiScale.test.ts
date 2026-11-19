import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const setZoom = vi.fn<(factor: number) => Promise<void>>();
vi.mock("@tauri-apps/api/webview", () => ({ getCurrentWebview: () => ({ setZoom }) }));

import { watchZoom } from "../test/zoom";
import { applyUiScale, applyUiScaleEarly, modLabel, sanitizeUiScale, stepUiScale, zoomKeyAction } from "./uiScale";

const key = (init: Partial<Parameters<typeof zoomKeyAction>[0]>) => ({ key: "", code: "", ctrlKey: false, metaKey: false, altKey: false, ...init });

describe("sanitizeUiScale", () => {
  it("rounds to the step and stays inside 80..200", () => {
    expect(sanitizeUiScale(100)).toBe(100);
    expect(sanitizeUiScale(105)).toBe(110);
    expect(sanitizeUiScale(104)).toBe(100);
    expect(sanitizeUiScale(3)).toBe(80);
    expect(sanitizeUiScale(999)).toBe(200);
    expect(sanitizeUiScale(-40)).toBe(80);
  });
  it("falls back to 100 for anything that is not a finite number", () => {
    for (const bad of [undefined, null, "150", NaN, Infinity, {}, [], true]) expect(sanitizeUiScale(bad)).toBe(100);
  });
});

describe("stepUiScale", () => {
  it("moves by 10 and stops at the limits", () => {
    expect(stepUiScale(100, 1)).toBe(110);
    expect(stepUiScale(100, -1)).toBe(90);
    expect(stepUiScale(200, 1)).toBe(200);
    expect(stepUiScale(80, -1)).toBe(80);
  });
});

describe("zoomKeyAction", () => {
  it("matches Ctrl+= and Ctrl++ (also with Shift, also the numpad) as zoom in", () => {
    expect(zoomKeyAction(key({ key: "=", code: "Equal", ctrlKey: true }), false)).toBe("in");
    expect(zoomKeyAction(key({ key: "+", code: "Equal", ctrlKey: true }), false)).toBe("in");
    expect(zoomKeyAction(key({ key: "+", code: "NumpadAdd", ctrlKey: true }), false)).toBe("in");
    // Spanish layout: "+" is the key left of Enter, not Shift+Equal
    expect(zoomKeyAction(key({ key: "+", code: "BracketRight", ctrlKey: true }), false)).toBe("in");
  });
  it("matches Ctrl+- (any layout, numpad too) as zoom out and Ctrl+0 as reset", () => {
    expect(zoomKeyAction(key({ key: "-", code: "Minus", ctrlKey: true }), false)).toBe("out");
    expect(zoomKeyAction(key({ key: "-", code: "Slash", ctrlKey: true }), false)).toBe("out");
    expect(zoomKeyAction(key({ key: "-", code: "NumpadSubtract", ctrlKey: true }), false)).toBe("out");
    expect(zoomKeyAction(key({ key: "0", code: "Digit0", ctrlKey: true }), false)).toBe("reset");
    expect(zoomKeyAction(key({ key: "0", code: "Numpad0", ctrlKey: true }), false)).toBe("reset");
  });
  it("leaves Ctrl+Insert (numpad 0 with NumLock off) alone: it is copy", () => {
    expect(zoomKeyAction(key({ key: "Insert", code: "Numpad0", ctrlKey: true }), false)).toBeNull();
  });
  it("needs the modifier of the platform: Cmd on macOS, Ctrl elsewhere, never the other one", () => {
    expect(zoomKeyAction(key({ key: "=", metaKey: true }), true)).toBe("in");
    expect(zoomKeyAction(key({ key: "=", ctrlKey: true }), true)).toBeNull();
    expect(zoomKeyAction(key({ key: "=", metaKey: true }), false)).toBeNull();
    expect(zoomKeyAction(key({ key: "=", ctrlKey: true, metaKey: true }), false)).toBeNull();
  });
  it("ignores plain keys, other chords and AltGr (Ctrl+Alt)", () => {
    expect(zoomKeyAction(key({ key: "=" }), false)).toBeNull();
    expect(zoomKeyAction(key({ key: "k", ctrlKey: true }), false)).toBeNull();
    expect(zoomKeyAction(key({ key: "l", ctrlKey: true }), false)).toBeNull();
    expect(zoomKeyAction(key({ key: "1", ctrlKey: true }), false)).toBeNull();
    expect(zoomKeyAction(key({ key: "-", ctrlKey: true, altKey: true }), false)).toBeNull();
  });
  it("names the modifier for the labels", () => expect(["Ctrl", "Cmd"]).toContain(modLabel()));
});

describe("applyUiScale", () => {
  const root = document.documentElement;
  let zoom: ReturnType<typeof watchZoom>;
  beforeEach(() => {
    zoom = watchZoom();
    setZoom.mockReset();
    setZoom.mockResolvedValue();
  });
  afterEach(() => {
    zoom.stop();
    Reflect.deleteProperty(globalThis, "isTauri");
  });

  it("in a browser it is the CSS zoom of <html>, and 100% removes it", async () => {
    await applyUiScale(150);
    expect(zoom.value).toBe("1.5");
    await applyUiScale(80);
    expect(zoom.value).toBe("0.8");
    expect(root.getAttribute("data-css-zoom")).toBe("");
    expect(root.style.getPropertyValue("--ui-zoom")).toBe("0.8");
    await applyUiScale(100);
    expect(zoom.value).toBe("");
    expect(root.hasAttribute("data-css-zoom")).toBe(false);
    expect(root.style.getPropertyValue("--ui-zoom")).toBe("");
    expect(setZoom).not.toHaveBeenCalled();
  });

  it("in the desktop app it is the webview zoom, once per change, and no CSS zoom", async () => {
    Object.defineProperty(globalThis, "isTauri", { value: true, configurable: true });
    root.style.setProperty("zoom", "2");
    root.setAttribute("data-css-zoom", "");
    await applyUiScale(110);
    expect(zoom.value).toBe("");
    expect(root.hasAttribute("data-css-zoom")).toBe(false);
    expect(setZoom).toHaveBeenLastCalledWith(1.1);
    const calls = setZoom.mock.calls.length;
    await applyUiScale(110);
    expect(setZoom).toHaveBeenCalledTimes(calls);
    await applyUiScale(100);
    expect(setZoom).toHaveBeenLastCalledWith(1);
  });

  it("a webview error is swallowed and the same zoom is tried again next time", async () => {
    Object.defineProperty(globalThis, "isTauri", { value: true, configurable: true });
    await applyUiScale(130);
    setZoom.mockRejectedValueOnce(new Error("denied"));
    await expect(applyUiScale(140)).resolves.toBeUndefined();
    await applyUiScale(140);
    expect(setZoom).toHaveBeenLastCalledWith(1.4);
    expect(setZoom).toHaveBeenCalledTimes(3);
  });

  it("sends one setZoom at a time and ends on the last request", async () => {
    Object.defineProperty(globalThis, "isTauri", { value: true, configurable: true });
    const pending: Array<() => void> = [];
    setZoom.mockImplementation(() => new Promise<void>((resolve) => pending.push(resolve)));
    const first = applyUiScale(150);
    const second = applyUiScale(160);
    const third = applyUiScale(170);
    expect(setZoom.mock.calls.map((c) => c[0])).toEqual([1.5]);
    pending.shift()?.();
    await vi.waitFor(() => expect(setZoom).toHaveBeenCalledTimes(2));
    // 160 was overtaken by 170: only the newest wish follows the first call
    expect(setZoom).toHaveBeenLastCalledWith(1.7);
    pending.shift()?.();
    await Promise.all([first, second, third]);
    expect(setZoom.mock.calls.map((c) => c[0])).toEqual([1.5, 1.7]);
    // the zoom the webview has is the last request: asking for it again sends nothing
    await applyUiScale(170);
    expect(setZoom).toHaveBeenCalledTimes(2);
  });

  it("does not send a wish that the webview already has once the call settles", async () => {
    Object.defineProperty(globalThis, "isTauri", { value: true, configurable: true });
    let release: () => void = () => undefined;
    setZoom.mockImplementation(() => new Promise<void>((resolve) => (release = resolve)));
    const a = applyUiScale(180);
    const b = applyUiScale(170);
    const c = applyUiScale(180);
    release();
    await Promise.all([a, b, c]);
    expect(setZoom).toHaveBeenCalledTimes(1);
    expect(setZoom).toHaveBeenLastCalledWith(1.8);
  });

  it("the approval window never calls setZoom", async () => {
    Object.defineProperty(globalThis, "isTauri", { value: true, configurable: true });
    window.location.hash = "#approval";
    try {
      await applyUiScale(150);
      await applyUiScaleEarly(150);
      expect(setZoom).not.toHaveBeenCalled();
    } finally {
      window.location.hash = "";
    }
  });

  it("the start waits for the webview, but not for ever", async () => {
    vi.useFakeTimers();
    try {
      Object.defineProperty(globalThis, "isTauri", { value: true, configurable: true });
      setZoom.mockReturnValue(new Promise(() => undefined));
      let done = false;
      void applyUiScaleEarly(170).then(() => {
        done = true;
      });
      await vi.advanceTimersByTimeAsync(100);
      expect(done).toBe(false);
      await vi.advanceTimersByTimeAsync(400);
      expect(done).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
