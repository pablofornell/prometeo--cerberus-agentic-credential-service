// Pure logic of the UI scale control (`UiScaleControl.tsx`): number steps, the slider gesture and the "stay under the
// pointer" geometry. No DOM, so it is tested without one.
//
// Why it exists: the scale resizes the whole window, so the control moves under a pressed pointer. A slider that applies
// its value while it moves would read a new value from the same pointer position, apply it, and move again. The rules
// here make one user action give exactly one change:
//  - a pointer drag only previews; the value is applied once, on release (`sliderStep`);
//  - `-` / `+` clicks with a pointer are collected: each is one step from the pending value, and the sum is applied
//    once, after `COMMIT_DELAY_MS` without a click (or earlier, see `UiScaleControl.tsx`). No press-and-hold repeat;
//  - after the change the page is scrolled so that the control is still under the pointer (`pinScrollDelta`).

/** How long the `-` / `+` buttons wait for one more click before the pending scale is applied. */
export const COMMIT_DELAY_MS = 700;

// ---------------------------------------------------------------- slider gesture

export interface SliderState {
  /** A pointer is down on the slider. */
  dragging: boolean;
  /** The value under the pointer, shown but not applied; null when there is no drag. */
  preview: number | null;
}

export const SLIDER_IDLE: SliderState = { dragging: false, preview: null };

export type SliderEvent =
  /** Pointer pressed on the slider. */
  | { type: "down" }
  /** The slider reports a value (pointer move, or an arrow key when no pointer is down). */
  | { type: "input"; value: number }
  /** Pointer released. `value` is the slider value at that moment, when known. */
  | { type: "release"; value?: number }
  /**
   * The drag was lost: it ended without a release on the slider (`pointercancel`, the pointer capture ended with the
   * button up, the window lost the focus, the page was hidden). Nothing is applied; the slider shows the stored value.
   */
  | { type: "cancel" };

export interface SliderStepResult {
  state: SliderState;
  /** The value to apply now, or null. At most one per gesture. */
  apply: number | null;
}

/**
 * The slider state machine. `committed` is the value the setting has now.
 *
 *   down, input 130, input 140, input 150, release   ->  apply 150 once (on release)
 *   input 130 (no pointer down: an arrow key)         ->  apply 130 at once
 *   release, release                                  ->  the second one does nothing
 */
export function sliderStep(state: SliderState, event: SliderEvent, committed: number): SliderStepResult {
  switch (event.type) {
    case "down":
      return { state: { dragging: true, preview: state.preview }, apply: null };
    case "input":
      if (state.dragging) return { state: { dragging: true, preview: event.value }, apply: null };
      return { state: SLIDER_IDLE, apply: event.value === committed ? null : event.value };
    case "release": {
      if (!state.dragging) return { state: SLIDER_IDLE, apply: null };
      const value = event.value ?? state.preview;
      return { state: SLIDER_IDLE, apply: value === null || value === committed ? null : value };
    }
    case "cancel":
      return { state: SLIDER_IDLE, apply: null };
  }
}

/** A DOM event that can end a pointer drag of the slider. `hidden`: `visibilitychange` to a hidden page. */
export type DragSignal = "pointerup" | "pointercancel" | "lostpointercapture" | "blur" | "hidden";

/**
 * What `signal` means for a drag in progress: `pointerup` is the release (with the slider value at that moment); every
 * other one means the drag is lost (`cancel`), so a later pointerup cannot apply a stale preview. A capture that ends
 * while the button is still `pressed` is not the end of the drag (the slider still gets the pointer): null.
 */
export function dragEnd(signal: DragSignal, pressed = false, value?: number): SliderEvent | null {
  switch (signal) {
    case "pointerup":
      return { type: "release", value };
    case "lostpointercapture":
      return pressed ? null : { type: "cancel" };
    case "pointercancel":
    case "blur":
    case "hidden":
      return { type: "cancel" };
  }
}

// ---------------------------------------------------------------- stay under the pointer

export interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

export interface Point {
  x: number;
  y: number;
}

/**
 * How far to scroll the page down so that the control is under the pointer again after a zoom from `from` to `to`
 * percent. `before` is the control's box before the change (client coordinates), `now` its box after it, `pointer`
 * where the pointer was (null: the middle of the control). A pointer outside the control counts as the nearest point of
 * it, so a drag that ended away from the slider does not pull the page. That point keeps its relative place on the
 * control (the same fraction of its height).
 *
 * Client coordinates are CSS px, so a fixed screen point has client coordinates that change with the zoom: it is
 * `from / to` times what it was. The result is the same for any number of calls with the same `before`, because `now`
 * already has the scroll of the earlier calls in it.
 */
export function pinScrollDelta(before: Box, now: Box, pointer: Point | null, from: number, to: number): number {
  const y = pointer ? Math.min(before.top + before.height, Math.max(before.top, pointer.y)) : before.top + before.height / 2;
  const fraction = before.height > 0 ? (y - before.top) / before.height : 0.5;
  const target = y * (from / to);
  return Math.round(now.top + fraction * now.height - target);
}
