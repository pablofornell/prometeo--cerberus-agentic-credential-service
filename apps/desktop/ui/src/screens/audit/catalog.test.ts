import { describe, expect, it } from "vitest";
import reference from "../../../../../../docs/reference/audit-events.md?raw";
import { EVENT_PHRASES, EVENT_TYPES, phraseFor } from "./catalog";

/** Event types of the catalog table: a code name, then a target kind in code or `none`. The alias table is left out. */
function documentedTypes(markdown: string): string[] {
  const types = new Set<string>();
  for (const line of markdown.split("\n")) {
    const match = /^\| `([a-z_]+\.[a-z_.]+)` \| (?:`[a-z_]+`|none) \|/.exec(line);
    if (match?.[1]) types.add(match[1]);
  }
  return [...types].sort();
}

describe("audit catalog", () => {
  it("has a phrase for every event type in docs/reference/audit-events.md", () => {
    const documented = documentedTypes(reference);
    expect(documented.length).toBeGreaterThan(60);
    expect(documented.filter((type) => !(type in EVENT_PHRASES))).toEqual([]);
    expect(EVENT_TYPES.filter((type) => !documented.includes(type))).toEqual([]);
  });

  it("says CSV import and export in plain words", () => {
    expect(phraseFor("items.import")).toBe("imported items from a CSV file");
    expect(phraseFor("items.export")).toBe("exported items to a CSV file, secrets in plain text");
  });
});
