import { useEffect, useRef, useState, type CSSProperties, type MouseEvent as ReactMouseEvent, type PointerEvent as ReactPointerEvent } from "react";
import { useScreenT } from "../../i18n";
import { usePrefs } from "../../state/prefs";
import { inTauri, stepUiScale, UI_SCALE_DEFAULT, UI_SCALE_MAX, UI_SCALE_MIN, UI_SCALE_STEP } from "../../state/uiScale";
import { Button, IconButton } from "../../ui";
import { messages } from "./messages";
import { COMMIT_DELAY_MS, dragEnd, pinScrollDelta, SLIDER_IDLE, sliderStep, type Box, type DragSignal, type Point, type SliderEvent } from "./sizeControl";

/** The keys that move a slider: holding one gives one step, not a run of them (each step resizes the whole window). */
const STEP_KEYS = new Set(["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "PageUp", "PageDown", "Home", "End"]);

const boxOf = (el: HTMLElement): Box => {
  const r = el.getBoundingClientRect();
  return { left: r.left, top: r.top, width: r.width, height: r.height };
};

interface Pin {
  anchor: HTMLElement;
  before: Box;
  pointer: Point;
  from: number;
  to: number;
}

/** The one scroll that waits for a webview zoom, and what ends it. Quick clicks share it, so the page scrolls once. */
let pin: Pin | null = null;
let pinTimer: ReturnType<typeof setTimeout> | undefined;
let pinFrame = 0;

function endPin(): void {
  clearTimeout(pinTimer);
  cancelAnimationFrame(pinFrame);
  window.removeEventListener("resize", onZoomResize);
  pin = null;
}

/** The webview applied the zoom: next frame, scroll so that the control is back under the pointer. */
function onZoomResize(): void {
  cancelAnimationFrame(pinFrame);
  pinFrame = requestAnimationFrame(() => {
    if (!pin?.anchor.isConnected) return;
    const dy = pinScrollDelta(pin.before, boxOf(pin.anchor), pin.pointer, pin.from, pin.to);
    if (dy !== 0) window.scrollBy(0, dy);
  });
  clearTimeout(pinTimer);
  pinTimer = setTimeout(endPin, 400);
}

/**
 * Asks to keep `anchor` under `pointer` through a zoom from `from` to `to` percent. The webview applies the zoom a
 * moment after the setting changes, so the scroll waits for the `resize` it causes. Only the desktop app does this: in a
 * browser the zoom is the CSS `zoom` of `<html>`, which has no `resize` and other client coordinates. It corrects the
 * vertical place only: a zoom also moves the control sideways (x scales with it), and no scroll can undo that.
 */
function keepUnderPointer(anchor: HTMLElement, pointer: Point, from: number, to: number): void {
  if (!inTauri()) return;
  if (pin && pin.anchor !== anchor) endPin();
  if (pin) {
    pin = { ...pin, to };
  } else {
    pin = { anchor, before: boxOf(anchor), pointer, from, to };
    window.addEventListener("resize", onZoomResize);
  }
  cancelAnimationFrame(pinFrame);
  clearTimeout(pinTimer);
  pinTimer = setTimeout(endPin, 1500);
}

/** A `-` / `+` button the pointer clicked: where it is, so the page can be scrolled back to it when the zoom lands. */
interface Held {
  anchor: HTMLElement;
  at: Point;
}

/**
 * UI scale: `-` and `+` buttons, the value, a slider and Reset. The scale resizes the whole window, so a zoom moves the
 * button the pointer is on, and the next click would land beside it. Therefore a pointer click on `-` / `+` does not
 * zoom at once: it sets a pending value that the value, the slider and the limits show, and that the next click steps
 * from. The pending value is applied once, by the first of: `COMMIT_DELAY_MS` with no click, the pointer leaving the
 * control, the window losing the focus, the control unmounting (the user asked for it: it is applied, not dropped).
 * Only a mouse leaving applies it (touch and pen fire a leave after every tap).
 * Other ways to change the scale never wait: Enter or Space on a button (there is no pointer to keep), Reset, an arrow
 * key on the slider, the end of a slider drag (`sliderStep`: a drag only previews). They replace a pending value. The
 * zoom keys (Ctrl+=) are handled by the prefs: they take the pending value (`registerPendingScale`), step from it and
 * replace it, so a key acts on the scale that is shown.
 */
export function UiScaleControl() {
  const t = useScreenT(messages);
  const { uiScale, setUiScale, registerPendingScale } = usePrefs();
  const slider = useRef<HTMLInputElement>(null);
  const gesture = useRef(SLIDER_IDLE);
  const pointer = useRef<Point | null>(null);
  const stopTracking = useRef<(() => void) | null>(null);
  /** The value under a slider drag, shown but not applied. */
  const [preview, setPreview] = useState<number | null>(null);
  /** The value of the `-` / `+` clicks that is not applied yet. `pendingRef` is the same value, for the handlers. */
  const [pending, setPending] = useState<number | null>(null);
  const pendingRef = useRef<number | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const held = useRef<Held | null>(null);
  /** The scale the user sees now, as far as the buttons are concerned: the pending value, else the stored one. */
  const base = pending ?? uiScale;
  const shown = preview ?? base;

  const latest = useRef({ uiScale, setUiScale, flush: () => {}, takePending: () => null as number | null });

  /** Gives the pending value away and drops it: a zoom key steps from it (`prefs.tsx`), so it is never applied after it. */
  const takePending = () => {
    const value = pendingRef.current;
    clearPending();
    return value;
  };

  const clearPending = () => {
    clearTimeout(timer.current);
    pendingRef.current = null;
    held.current = null;
    setPending(null);
  };

  /** Applies a value now (any pending one is replaced by it). */
  const change = (next: number, anchor: HTMLElement | null, at: Point | null) => {
    clearPending();
    const { uiScale: current, setUiScale: set } = latest.current;
    if (next === current) return;
    if (anchor && at) keepUnderPointer(anchor, at, current, next);
    latest.current.uiScale = next; // now, not after the render: the next click may come before it
    set(next);
  };

  /** Applies the pending value, if there is one. Not during a slider drag: that one ends first and then restarts the wait. */
  const flush = () => {
    const value = pendingRef.current;
    if (value === null || gesture.current.dragging) return;
    const h = held.current;
    change(value, h?.anchor ?? null, h?.at ?? null);
  };

  useEffect(() => {
    latest.current = { uiScale, setUiScale, flush, takePending };
  });

  const wait = () => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => latest.current.flush(), COMMIT_DELAY_MS);
  };

  useEffect(() => {
    const onBlur = () => latest.current.flush();
    window.addEventListener("blur", onBlur);
    return () => {
      window.removeEventListener("blur", onBlur);
      stopTracking.current?.();
      gesture.current = SLIDER_IDLE; // a drag in progress is lost with the control; the pending value still counts
      held.current = null; // the button is gone: nothing to keep under the pointer
      latest.current.flush();
    };
  }, []);

  // The zoom keys are handled by the prefs: they take the pending value, step from it and replace it.
  useEffect(() => registerPendingScale(() => latest.current.takePending()), [registerPendingScale]);

  const dispatch = (event: SliderEvent) => {
    const wasDragging = gesture.current.dragging;
    if (event.type === "down") clearTimeout(timer.current);
    const result = sliderStep(gesture.current, event, pendingRef.current ?? latest.current.uiScale);
    gesture.current = result.state;
    setPreview(result.state.preview);
    if (result.apply !== null) change(result.apply, slider.current, wasDragging ? pointer.current : null);
    else if (!result.state.dragging && pendingRef.current !== null) wait();
  };

  /**
   * A pointer went down on the slider. It captures the pointer, so it gets the moves and the release also outside its
   * box. The drag ends on the release, or is lost (the stored value comes back) when the capture ends without one, the
   * window loses the focus (alt-tab) or the page is hidden.
   */
  const begin = (e: ReactPointerEvent<HTMLInputElement>) => {
    const el = slider.current;
    if (e.button !== 0 || gesture.current.dragging || !el) return;
    pointer.current = { x: e.clientX, y: e.clientY };
    dispatch({ type: "down" });
    let captured = true;
    try {
      el.setPointerCapture(e.pointerId);
    } catch {
      captured = false; // not an active pointer any more: the release may come anywhere, so the window listens for it
    }
    const move = (ev: PointerEvent) => {
      pointer.current = { x: ev.clientX, y: ev.clientY };
    };
    const end = (signal: DragSignal, pressed = false) => {
      const event = dragEnd(signal, pressed, Number(el.value));
      if (!event) return;
      stop();
      dispatch(event);
    };
    const up = () => end("pointerup");
    const cancel = () => end("pointercancel");
    const lost = (ev: PointerEvent) => end("lostpointercapture", (ev.buttons & 1) === 1);
    const blur = () => end("blur");
    const hidden = () => {
      if (document.visibilityState === "hidden") end("hidden");
    };
    const stop = () => {
      el.removeEventListener("pointermove", move);
      el.removeEventListener("pointerup", up);
      el.removeEventListener("pointercancel", cancel);
      el.removeEventListener("lostpointercapture", lost);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", cancel);
      window.removeEventListener("blur", blur);
      document.removeEventListener("visibilitychange", hidden);
      stopTracking.current = null;
    };
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", up);
    el.addEventListener("pointercancel", cancel);
    el.addEventListener("lostpointercapture", lost);
    if (!captured) {
      window.addEventListener("pointerup", up);
      window.addEventListener("pointercancel", cancel);
    }
    window.addEventListener("blur", blur);
    document.addEventListener("visibilitychange", hidden);
    stopTracking.current = stop;
  };

  /**
   * One step from a `-` / `+` click, taken from the pending value (else the stored one). A pointer click (`detail > 0`)
   * only sets the pending value and waits for more clicks; Enter or Space (`detail` 0) applies it at once.
   */
  const stepClick = (e: ReactMouseEvent<HTMLButtonElement>, dir: 1 | -1) => {
    const from = pendingRef.current ?? latest.current.uiScale;
    const next = stepUiScale(from, dir);
    if (next === from) return; // at a limit
    if (e.detail === 0) {
      change(next, null, null);
      return;
    }
    pendingRef.current = next;
    held.current = { anchor: e.currentTarget, at: { x: e.clientX, y: e.clientY } };
    setPending(next);
    wait();
  };

  // At a limit the buttons are `aria-disabled`, not `disabled`: a disabled button that has the focus loses it to the body.
  const atMin = base <= UI_SCALE_MIN;
  const atMax = base >= UI_SCALE_MAX;
  const atDefault = base === UI_SCALE_DEFAULT;

  const valueText = t("scale.value", { n: shown });
  return (
    <div
      className="scale-ctl"
      // Only a mouse leaves for good: touch and pen fire a leave after every tap, and the timer applies the value then.
      onPointerLeave={(e) => {
        if (e.pointerType === "mouse") flush();
      }}
    >
      <IconButton icon="minus" size="sm" label={t("scale.dec")} aria-disabled={atMin || undefined} onClick={(e) => stepClick(e, -1)} />
      <output className="scale-value" aria-live="polite">
        {valueText}
      </output>
      <IconButton icon="plus" size="sm" label={t("scale.inc")} aria-disabled={atMax || undefined} onClick={(e) => stepClick(e, 1)} />
      <input
        ref={slider}
        className="scale-range"
        type="range"
        min={UI_SCALE_MIN}
        max={UI_SCALE_MAX}
        step={UI_SCALE_STEP}
        value={shown}
        aria-label={t("scale.label")}
        aria-valuetext={valueText}
        style={{ "--fill": `${((shown - UI_SCALE_MIN) / (UI_SCALE_MAX - UI_SCALE_MIN)) * 100}%` } as CSSProperties}
        onPointerDown={begin}
        onKeyDown={(e) => {
          if (e.repeat && STEP_KEYS.has(e.key)) e.preventDefault();
        }}
        onChange={(e) => dispatch({ type: "input", value: Number(e.currentTarget.value) })}
      />
      <Button size="sm" aria-disabled={atDefault || undefined} onClick={() => !atDefault && change(UI_SCALE_DEFAULT, null, null)}>
        {t("scale.reset")}
      </Button>
    </div>
  );
}
