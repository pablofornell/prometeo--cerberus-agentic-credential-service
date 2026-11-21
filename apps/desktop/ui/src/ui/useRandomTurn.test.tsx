import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useRandomTurn } from "./useRandomTurn";

const reduceMotion = (on: boolean) => {
  window.matchMedia = ((query: string) => ({ matches: on && query.includes("reduce"), media: query }) as MediaQueryList) as typeof window.matchMedia;
};

describe("useRandomTurn", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    reduceMotion(false);
  });
  afterEach(() => {
    vi.useRealTimers();
    // @ts-expect-error jsdom has no matchMedia; remove the stub again
    delete window.matchMedia;
  });

  it("turns after a random delay inside the window, for turnMs, then waits again", () => {
    const random = vi.fn().mockReturnValueOnce(0.5).mockReturnValueOnce(0);
    const { result } = renderHook(() => useRandomTurn({ minMs: 1000, maxMs: 3000, turnMs: 500, random }));
    expect(result.current).toBe(false);
    act(() => vi.advanceTimersByTime(1999));
    expect(result.current).toBe(false);
    act(() => vi.advanceTimersByTime(1));
    expect(result.current).toBe(true);
    act(() => vi.advanceTimersByTime(500));
    expect(result.current).toBe(false);
    // The second wait uses the next random value (0 -> minMs).
    act(() => vi.advanceTimersByTime(1000));
    expect(result.current).toBe(true);
  });

  it("keeps the default window at 20 to 60 seconds", () => {
    const random = vi.fn().mockReturnValue(0);
    const { result } = renderHook(() => useRandomTurn({ random }));
    act(() => vi.advanceTimersByTime(19_999));
    expect(result.current).toBe(false);
    act(() => vi.advanceTimersByTime(1));
    expect(result.current).toBe(true);
  });

  it("never turns under prefers-reduced-motion", () => {
    reduceMotion(true);
    const { result } = renderHook(() => useRandomTurn({ minMs: 100, maxMs: 200, turnMs: 50, random: () => 0 }));
    act(() => vi.advanceTimersByTime(10_000));
    expect(result.current).toBe(false);
  });

  it("clears its timers on unmount", () => {
    const { unmount } = renderHook(() => useRandomTurn({ minMs: 100, maxMs: 200, turnMs: 50, random: () => 0 }));
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
