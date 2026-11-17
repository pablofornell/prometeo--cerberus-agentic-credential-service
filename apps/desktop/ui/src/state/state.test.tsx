import { act, render, renderHook, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { IpcFailure, isLockError, toUiError } from "../ipc/client";
import { format } from "../i18n";
import { applyPrefs, DEFAULT_PREFS, PrefsProvider, usePrefs } from "./prefs";
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
});
