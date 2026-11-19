import { act, fireEvent, render, renderHook, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IpcFailure, isLockError, toUiError } from "../ipc/client";
import { format } from "../i18n";
import { watchZoom } from "../test/zoom";
import { applyPrefs, DEFAULT_PREFS, effectiveUiScale, PrefsProvider, readPrefs, usePrefs } from "./prefs";
import { formatLeft, useCountdown } from "./time";

describe("ipc error mapping", () => {
  it("maps the Rust error shape", () => {
    const e = toUiError("vault_unlock", { code: "too_many_failures", message: "wait", retry_after_seconds: 30, fields: [{ field: "phrase", problem: "x" }] });
    expect(e).toEqual({ code: "too_many_failures", message: "wait", command: "vault_unlock", retryAfterSeconds: 30, fields: [{ field: "phrase", problem: "x" }] });
  });
  it("maps a transport failure to ipc_unreachable", () => {
    expect(toUiError("vault_status", new TypeError("no runtime")).code).toBe("ipc_unreachable");
  });
  it("detects lock errors", () => {
    expect(isLockError(new IpcFailure(toUiError("x", { code: "vault_locked", message: "", retry_after_seconds: null, fields: [] })))).toBe(true);
    expect(isLockError(new Error("x"))).toBe(false);
  });
});

describe("format and time", () => {
  it("fills slots", () => expect(format("Hi {name} {missing}", { name: "Ana" })).toBe("Hi Ana {missing}"));
  it("formats time left", () => {
    expect(formatLeft(250)).toBe("4:10");
    expect(formatLeft(4 * 3600 + 16 * 60)).toBe("4 h 16 m");
    expect(formatLeft(-3)).toBe("0:00");
  });
  it("counts down each second", () => {
    vi.useFakeTimers();
    const end = Date.now() + 5000;
    const { result } = renderHook(() => useCountdown(end));
    expect(result.current).toBe(5);
    act(() => void vi.advanceTimersByTime(2000));
    expect(result.current).toBe(3);
    vi.useRealTimers();
  });
});

describe("theme and density", () => {
  it("applies to <html> and persists", () => {
    const Probe = () => {
      const p = usePrefs();
      return (
        <>
          <button onClick={() => p.setTheme("light")}>light</button>
          <button onClick={() => p.setDensity("compact")}>compact</button>
          <button onClick={p.cycleTheme}>cycle</button>
        </>
      );
    };
    render(<PrefsProvider><Probe /></PrefsProvider>);
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    act(() => screen.getByText("light").click());
    act(() => screen.getByText("compact").click());
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    expect(document.documentElement).toHaveAttribute("data-density", "compact");
    expect(JSON.parse(window.localStorage.getItem("cerberus-prefs") ?? "{}")).toMatchObject({ theme: "light", density: "compact" });
    act(() => screen.getByText("cycle").click());
    expect(document.documentElement).not.toHaveAttribute("data-theme");
  });
  it("system follows the OS (no attribute)", () => {
    applyPrefs({ ...DEFAULT_PREFS, theme: "system" });
    expect(document.documentElement).not.toHaveAttribute("data-theme");
  });
  it("the approval window is compact on <html> whatever the pref is, so its toasts are too", () => {
    window.location.hash = "#approval";
    try {
      applyPrefs({ ...DEFAULT_PREFS, density: "comfortable" });
      expect(document.documentElement).toHaveAttribute("data-density", "compact");
    } finally {
      window.location.hash = "";
    }
    applyPrefs({ ...DEFAULT_PREFS, density: "comfortable" });
    expect(document.documentElement).toHaveAttribute("data-density", "comfortable");
  });
});

describe("UI scale pref", () => {
  const stored = () => JSON.parse(window.localStorage.getItem("cerberus-prefs") ?? "{}") as { uiScale?: number };
  const Probe = () => {
    const p = usePrefs();
    return (
      <>
        <output data-testid="scale">{p.uiScale}</output>
        <button onClick={() => p.setUiScale(133)}>set</button>
      </>
    );
  };
  const shown = () => screen.getByTestId("scale").textContent;
  const zoomKey = (init: KeyboardEventInit, target: Element | Window = window) => fireEvent.keyDown(target, init);
  let zoom: ReturnType<typeof watchZoom>;
  beforeEach(() => {
    zoom = watchZoom();
  });
  afterEach(() => zoom.stop());

  it("defaults to 100% and is sanitized on load", () => {
    expect(readPrefs().uiScale).toBe(100);
    for (const [raw, want] of [[150, 150], [155, 160], [5, 80], [900, 200], ["big", 100], [null, 100]] as const) {
      window.localStorage.setItem("cerberus-prefs", JSON.stringify({ theme: "dark", uiScale: raw }));
      expect(readPrefs().uiScale).toBe(want);
    }
    window.localStorage.setItem("cerberus-prefs", "not json");
    expect(readPrefs().uiScale).toBe(100);
  });

  it("is applied to <html> and persisted, rounded to the step", () => {
    render(<PrefsProvider><Probe /></PrefsProvider>);
    expect(zoom.value).toBe("");
    act(() => screen.getByText("set").click());
    expect(shown()).toBe("130");
    expect(zoom.value).toBe("1.3");
    expect(stored().uiScale).toBe(130);
  });

  it("starts from the saved value, so the first draw is already zoomed", () => {
    window.localStorage.setItem("cerberus-prefs", JSON.stringify({ uiScale: 150 }));
    render(<PrefsProvider><Probe /></PrefsProvider>);
    expect(shown()).toBe("150");
    expect(zoom.value).toBe("1.5");
  });

  it("Ctrl+= / Ctrl++ / Ctrl+- / Ctrl+0 zoom in, out and reset, also in a text field", () => {
    render(<PrefsProvider><Probe /><input aria-label="field" /></PrefsProvider>);
    zoomKey({ key: "=", ctrlKey: true });
    expect(shown()).toBe("110");
    zoomKey({ key: "+", code: "NumpadAdd", ctrlKey: true });
    expect(shown()).toBe("120");
    zoomKey({ key: "-", ctrlKey: true }, screen.getByLabelText("field"));
    expect(shown()).toBe("110");
    zoomKey({ key: "-", ctrlKey: true });
    zoomKey({ key: "-", ctrlKey: true });
    expect(shown()).toBe("90");
    expect(zoom.value).toBe("0.9");
    zoomKey({ key: "0", ctrlKey: true }, screen.getByLabelText("field"));
    expect(shown()).toBe("100");
    expect(stored().uiScale).toBe(100);
  });

  it("stops at 80% and 200%, and a held key is one step", () => {
    window.localStorage.setItem("cerberus-prefs", JSON.stringify({ uiScale: 200 }));
    render(<PrefsProvider><Probe /></PrefsProvider>);
    zoomKey({ key: "=", ctrlKey: true });
    expect(shown()).toBe("200");
    zoomKey({ key: "-", ctrlKey: true });
    zoomKey({ key: "-", ctrlKey: true, repeat: true });
    expect(shown()).toBe("190");
  });

  it("prevents the browser zoom and leaves other chords alone", () => {
    render(<PrefsProvider><Probe /></PrefsProvider>);
    expect(fireEvent.keyDown(window, { key: "=", ctrlKey: true })).toBe(false);
    expect(fireEvent.keyDown(window, { key: "k", ctrlKey: true })).toBe(true);
    expect(fireEvent.keyDown(window, { key: "=" })).toBe(true);
    expect(shown()).toBe("110");
  });

  it("the approval window stays at 100% and ignores the keys", () => {
    window.location.hash = "#approval";
    try {
      window.localStorage.setItem("cerberus-prefs", JSON.stringify({ uiScale: 150 }));
      expect(effectiveUiScale(readPrefs())).toBe(100);
      render(<PrefsProvider><Probe /></PrefsProvider>);
      expect(zoom.value).toBe("");
      zoomKey({ key: "=", ctrlKey: true });
      expect(shown()).toBe("150");
      expect(zoom.value).toBe("");
    } finally {
      window.location.hash = "";
    }
    expect(effectiveUiScale({ ...DEFAULT_PREFS, uiScale: 150 })).toBe(150);
  });
});
