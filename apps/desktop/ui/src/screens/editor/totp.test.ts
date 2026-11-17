import { describe, expect, it } from "vitest";
import { decodeBase32, groupCode, secondsLeft, totpCode } from "./totp";

// RFC 6238 appendix B test seed (public, not a real credential): "12345678901234567890" in Base32.
const RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("totp", () => {
  it("matches the RFC 6238 vectors", async () => {
    expect(await totpCode({ secret: RFC_SEED, algorithm: "SHA1", digits: 8, period: 30 }, 59_000)).toBe("94287082");
    expect(await totpCode({ secret: RFC_SEED, algorithm: "SHA1", digits: 8, period: 30 }, 1_111_111_109_000)).toBe("07081804");
  });

  it("accepts groups, dashes and lower case, and refuses bad characters", () => {
    expect(decodeBase32("gezd gnbv-GY3T")).not.toBeNull();
    expect(decodeBase32("not base32!")).toBeNull();
    expect(decodeBase32("")).toBeNull();
  });

  it("counts the seconds left and groups the code", () => {
    expect(secondsLeft(30, 59_000)).toBe(1);
    expect(secondsLeft(30, 60_000)).toBe(30);
    expect(groupCode("492113")).toBe("492 113");
    expect(groupCode("07081804")).toBe("0708 1804");
  });
});
