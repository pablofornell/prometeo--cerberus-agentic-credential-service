import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { GateMark } from "./GateMark";

describe("GateMark", () => {
  it("draws three solid rings in the ink color, with no blur, glow or mask", () => {
    const { container } = render(<GateMark size={120} />);
    const rings = Array.from(container.querySelectorAll("circle.gate-mark__ring"));
    expect(rings).toHaveLength(3);
    // No band or gradient on any ring: all three are plain currentColor.
    expect(rings.map((c) => c.getAttribute("stroke"))).toEqual(["currentColor", "currentColor", "currentColor"]);
    expect(container.querySelector("filter, mask, feGaussianBlur")).toBeNull();
  });

  it("open puts the spectrum in the core, a crisp disc clipped to its edge; locked is flat and monochrome", () => {
    const { container, rerender } = render(<GateMark mode="open" />);
    // The core is clipped to a disc, so the colors never spill past its edge.
    const clip = container.querySelector("clipPath");
    expect(clip).not.toBeNull();
    const clipped = container.querySelector(`g[clip-path="url(#${clip?.id})"]`);
    expect(clipped).not.toBeNull();
    // All five spectrum colors are present at once, each a radial pool fading to transparent, colored by the
    // --c-spectrum-* tokens through gate-mark.css, never by hex or inline style.
    const gradients = Array.from(container.querySelectorAll("radialGradient"));
    expect(gradients).toHaveLength(5);
    for (const g of gradients) {
      const stops = Array.from(g.querySelectorAll("stop"));
      expect(stops.at(0)).toHaveAttribute("stop-opacity", "1");
      expect(stops.at(-1)).toHaveAttribute("stop-opacity", "0");
    }
    const hues = Array.from(container.querySelectorAll("stop")).map((s) => /gate-mark__hue--(\w+)/.exec(s.getAttribute("class") ?? "")?.[1]);
    expect(new Set(hues)).toEqual(new Set(["red", "amber", "green", "blue", "violet"]));
    expect(container.querySelector("stop[stop-color], style")).toBeNull();
    // The aurora circles are drawn inside the clip; each is painted by one of the gradients.
    const fills = Array.from(clipped?.querySelectorAll(".gate-mark__aurora circle") ?? []).map((c) => c.getAttribute("fill"));
    expect(fills).toHaveLength(5);
    expect(fills.every((f) => /^url\(#/.test(f ?? ""))).toBe(true);

    rerender(<GateMark mode="locked" />);
    expect(container.querySelector("radialGradient, linearGradient, clipPath, defs")).toBeNull();
    const core = container.querySelector("circle:not(.gate-mark__ring)");
    expect(core).toHaveAttribute("fill", "currentColor");
    expect(Array.from(container.querySelectorAll("circle.gate-mark__ring")).map((c) => c.getAttribute("stroke"))).toEqual([
      "currentColor",
      "currentColor",
      "currentColor",
    ]);
  });

  it("makes the core larger than the gaps between rings need, keeping it inside the innermost ring", () => {
    const { container } = render(<GateMark mode="locked" />);
    const core = Number(container.querySelector("circle:not(.gate-mark__ring)")?.getAttribute("r"));
    const inner = container.querySelector("circle.gate-mark__ring--r3");
    const innerEdge = Number(inner?.getAttribute("r")) - Number(inner?.getAttribute("stroke-width")) / 2;
    expect(core).toBeGreaterThan(2);
    expect(innerEdge - core).toBeGreaterThan(0.5);
  });

  it("gives every instance its own gradient and clip ids", () => {
    const { container } = render(
      <>
        <GateMark />
        <GateMark />
      </>,
    );
    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(ids).toHaveLength(12);
    expect(new Set(ids).size).toBe(12);
    // Every url(#id) reference resolves to an id of the same instance.
    const refs = Array.from(container.querySelectorAll("*")).flatMap((el) =>
      ["fill", "clip-path"].flatMap((attr) => /^url\(#(.+)\)$/.exec(el.getAttribute(attr) ?? "")?.slice(1) ?? []),
    );
    expect(refs.length).toBeGreaterThan(0);
    for (const r of refs) expect(ids).toContain(r);
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
