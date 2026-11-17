import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { InlineUntrusted, UntrustedText, showInvisible } from "./Untrusted";

describe("invisible and bidi characters in agent text (AUD-24)", () => {
  it("writes each one as a visible code, and leaves normal text and line breaks alone", () => {
    expect(showInvisible("pr‮od")).toBe("pr‹U+202E›od");
    expect(showInvisible("a​b⁦c⁩d﻿")).toBe("a‹U+200B›b‹U+2066›c‹U+2069›d‹U+FEFF›");
    expect(showInvisible("line one\nline two\tend ünï")).toBe("line one\nline two\tend ünï");
  });

  it("shows the codes in the untrusted block, so the text cannot hide a reordering", () => {
    render(<UntrustedText text={"deploy to ‮prod"} />);
    const block = screen.getByRole("group");
    expect(block.textContent).toContain("deploy to ‹U+202E›prod");
    expect(block.textContent).not.toContain("‮");
    expect(block.querySelector("bdi")).not.toBeNull();
  });

  it("isolates inline agent text so it cannot reorder the text around it", () => {
    const { container } = render(<p>Name: <InlineUntrusted text={"bot‮gnp"} /> end</p>);
    const bdi = container.querySelector("bdi");
    expect(bdi?.textContent).toBe("bot‹U+202E›gnp");
    expect(container.textContent).not.toContain("‮");
  });
});
