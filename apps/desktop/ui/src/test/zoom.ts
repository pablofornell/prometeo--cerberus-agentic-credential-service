import { vi } from "vitest";

/**
 * jsdom's CSS parser does not know the `zoom` property and drops it, so `root.style.zoom` always reads empty. This
 * records what the app sets on `<html>` instead. Call `stop()` when done (`afterEach`).
 */
export function watchZoom(): { readonly value: string; stop: () => void } {
  const style = document.documentElement.style;
  const set = style.setProperty.bind(style);
  const remove = style.removeProperty.bind(style);
  let value = "";
  const setSpy = vi.spyOn(style, "setProperty").mockImplementation((name, v, priority) => {
    if (name === "zoom") value = v ?? "";
    else set(name, v, priority ?? "");
  });
  const removeSpy = vi.spyOn(style, "removeProperty").mockImplementation((name) => {
    if (name === "zoom") {
      value = "";
      return "";
    }
    return remove(name);
  });
  return {
    get value() {
      return value;
    },
    stop: () => {
      setSpy.mockRestore();
      removeSpy.mockRestore();
    },
  };
}
