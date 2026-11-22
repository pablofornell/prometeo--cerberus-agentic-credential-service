import { describe, expect, it } from "vitest";
import { pickCheckGroups, recoveryGroups } from "./RecoveryKeyGrid";
import { MOCK_RECOVERY_KEY } from "./mock";

describe("pickCheckGroups", () => {
  const groups = recoveryGroups(MOCK_RECOVERY_KEY);

  it("picks two different body groups in ascending order, never the CRK1 prefix", () => {
    for (let run = 0; run < 500; run++) {
      const [a, b, ...rest] = pickCheckGroups(groups);
      expect(rest).toHaveLength(0);
      expect(a).toBeGreaterThanOrEqual(2);
      expect(b).toBeGreaterThan(a!);
      expect(b).toBeLessThanOrEqual(groups.length);
    }
  });

  it("is not always the same pair (the old check always asked for 3 and 11)", () => {
    const pairs = new Set(Array.from({ length: 200 }, () => pickCheckGroups(groups).join(",")));
    expect(pairs.size).toBeGreaterThan(10);
  });

  it("reaches every body group", () => {
    const seen = new Set(Array.from({ length: 2000 }, () => pickCheckGroups(groups)).flat());
    expect([...seen].sort((x, y) => x - y)).toEqual(Array.from({ length: groups.length - 1 }, (_, i) => i + 2));
  });

  it("checks every group of a short key", () => {
    expect(pickCheckGroups(["ABCD", "EFGH"])).toEqual([1, 2]);
    expect(pickCheckGroups(["ABCD"])).toEqual([1]);
    expect(pickCheckGroups([])).toEqual([]);
  });
});
