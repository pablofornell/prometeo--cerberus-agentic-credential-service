import { describe, expect, it } from "vitest";
import { formatDuration, formatLeft } from "./time";

describe("time formats", () => {
  it("says a span of time in words", () => {
    expect(formatDuration(45)).toBe("45 seconds");
    expect(formatDuration(60)).toBe("1 minute");
    expect(formatDuration(900)).toBe("15 minutes");
    expect(formatDuration(3600)).toBe("1 hour");
    expect(formatDuration(8 * 3600)).toBe("8 hours");
    expect(formatDuration(9000)).toBe("2 h 30 min");
  });

  it("keeps the countdown format for time left", () => {
    expect(formatLeft(900)).toBe("15:00");
    expect(formatLeft(15_360)).toBe("4 h 16 m");
  });
});
