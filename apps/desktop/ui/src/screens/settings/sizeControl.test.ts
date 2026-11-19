import { describe, expect, it } from "vitest";
import { dragEnd, pinScrollDelta, SLIDER_IDLE, sliderStep, type SliderEvent, type SliderState } from "./sizeControl";

/** Runs the events in order from idle and returns every value that was applied. */
function run(events: SliderEvent[], committed = 100): number[] {
  let state: SliderState = SLIDER_IDLE;
  const applied: number[] = [];
  for (const event of events) {
    const r = sliderStep(state, event, committed);
    state = r.state;
    if (r.apply !== null) applied.push(r.apply);
  }
  return applied;
}

describe("sliderStep", () => {
  it("a drag previews and applies once, on release", () => {
    const events: SliderEvent[] = [{ type: "down" }, { type: "input", value: 110 }, { type: "input", value: 130 }];
    expect(run(events)).toEqual([]);
    expect(run([...events, { type: "release", value: 150 }])).toEqual([150]);
    expect(run([...events, { type: "release" }])).toEqual([130]);
  });
  it("shows the preview while dragging", () => {
    const r = sliderStep({ dragging: true, preview: null }, { type: "input", value: 120 }, 100);
    expect(r.state).toEqual({ dragging: true, preview: 120 });
  });
  it("an arrow key (no pointer down) applies at once, one step per key", () => {
    expect(run([{ type: "input", value: 110 }, { type: "input", value: 120 }])).toEqual([110, 120]);
  });
  it("a second release does nothing", () => {
    expect(run([{ type: "down" }, { type: "input", value: 140 }, { type: "release", value: 140 }, { type: "release", value: 140 }])).toEqual([140]);
  });
  it("releasing on the value that is already set applies nothing", () => {
    expect(run([{ type: "down" }, { type: "input", value: 120 }, { type: "input", value: 100 }, { type: "release", value: 100 }])).toEqual([]);
  });
  it("a lost drag applies nothing and a later release cannot apply the stale preview", () => {
    expect(run([{ type: "down" }, { type: "input", value: 160 }, { type: "cancel" }, { type: "release" }])).toEqual([]);
    expect(sliderStep({ dragging: true, preview: 160 }, { type: "cancel" }, 100).state).toEqual(SLIDER_IDLE);
  });
});

describe("dragEnd", () => {
  it("pointerup is the release with the slider value; the rest lose the drag", () => {
    expect(dragEnd("pointerup", false, 150)).toEqual({ type: "release", value: 150 });
    for (const signal of ["pointercancel", "blur", "hidden"] as const) expect(dragEnd(signal)).toEqual({ type: "cancel" });
    expect(dragEnd("lostpointercapture", false)).toEqual({ type: "cancel" });
  });
  it("a capture that ends while the button is still down is not the end of the drag", () => {
    expect(dragEnd("lostpointercapture", true)).toBeNull();
  });
});

describe("pinScrollDelta", () => {
  const box = (top: number) => ({ left: 900, top, width: 28, height: 28 });
  it("scrolls by what the control moved when the zoom does not change client coordinates", () => {
    expect(pinScrollDelta(box(500), box(530), { x: 910, y: 510 }, 100, 100)).toBe(30);
    expect(pinScrollDelta(box(500), box(500), { x: 910, y: 510 }, 100, 100)).toBe(0);
  });
  it("accounts for the client coordinates of the fixed screen point at the new zoom", () => {
    // 100% -> 200%: the screen point at client y 510 is client y 255 now; the control (28 high) is at 240
    expect(pinScrollDelta(box(500), box(240), { x: 910, y: 514 }, 100, 200)).toBe(240 + 0.5 * 28 - 257);
  });
  it("uses the middle of the control without a pointer, and the nearest point when the pointer is off it", () => {
    expect(pinScrollDelta(box(500), box(520), null, 100, 100)).toBe(20);
    expect(pinScrollDelta(box(500), box(520), { x: 0, y: 900 }, 100, 100)).toBe(20);
    expect(pinScrollDelta(box(500), box(520), { x: 0, y: 0 }, 100, 100)).toBe(20);
  });
  it("is the same again when `now` already holds the first scroll", () => {
    const first = pinScrollDelta(box(500), box(530), { x: 910, y: 510 }, 100, 100);
    const after = box(530 - first);
    expect(pinScrollDelta(box(500), after, { x: 910, y: 510 }, 100, 100)).toBe(0);
  });
});
