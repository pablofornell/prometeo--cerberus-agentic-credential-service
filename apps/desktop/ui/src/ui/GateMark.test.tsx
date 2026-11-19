import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GateMark } from "./GateMark";

describe("GateMark", () => {
  it("draws three solid rings and a core, with no blur, glow or radial shading", () => {
    const { container } = render(<GateMark size={120} />);
    expect(container.querySelectorAll("circle.gate-mark__ring")).toHaveLength(3);
    expect(container.querySelector("filter, radialGradient, mask, feGaussianBlur")).toBeNull();
    expect(container.querySelector("circle:not(.gate-mark__ring)")).toHaveAttribute("fill", "currentColor");
  });

  it("open puts the spectrum on the innermost ring only; locked is monochrome", () => {
    const { container, rerender } = render(<GateMark mode="open" />);
    const strokes = () => Array.from(container.querySelectorAll("circle.gate-mark__ring")).map((c) => c.getAttribute("stroke"));
    const [outer, middle, inner] = strokes();
    expect(outer).toBe("currentColor");
    expect(middle).toBe("currentColor");
    expect(inner).toMatch(/^url\(#/);
    // Five sharp bands (two stops each), colored by the --c-spectrum-* tokens through gate-mark.css, never by hex.
    const stops = Array.from(container.querySelectorAll("stop"));
    expect(stops).toHaveLength(10);
    expect(stops.map((s) => s.getAttribute("class"))).toEqual(
      ["red", "red", "amber", "amber", "green", "green", "blue", "blue", "violet", "violet"].map((c) => `gate-mark__band gate-mark__band--${c}`),
    );
    expect(container.querySelector("stop[stop-color], style")).toBeNull();
    rerender(<GateMark mode="locked" />);
    expect(strokes()).toEqual(["currentColor", "currentColor", "currentColor"]);
    expect(container.querySelector("linearGradient")).toBeNull();
  });

  it("gives every instance its own gradient id", () => {
    const { container } = render(
      <>
        <GateMark />
        <GateMark />
      </>,
    );
    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);
  });

  it("open leaves gaps in the rings, locked closes them", () => {
    const { container, rerender } = render(<GateMark mode="open" />);
    const hole = () => container.querySelector("circle.gate-mark__ring--r1")?.getAttribute("stroke-dasharray")?.split(" ")[1];
    expect(hole()).not.toBe("0.00");
    rerender(<GateMark mode="locked" />);
    expect(hole()).toBe("0.00");
  });

  it("marks the mode with its own class and stays decorative", () => {
    const { container, rerender } = render(<GateMark mode="locked" />);
    const svg = container.querySelector("svg");
    expect(svg).toHaveClass("gate-mark", "gate-mark--locked");
    expect(svg).toHaveAttribute("aria-hidden", "true");
    rerender(<GateMark mode="spin" />);
    expect(container.querySelector("svg")).toHaveClass("gate-mark--spin");
    expect(container.querySelector("svg")).not.toHaveClass("gate-mark--locked");
  });
});
