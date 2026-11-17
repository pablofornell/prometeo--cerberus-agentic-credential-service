// Key files for the SSH panel. A path or the file text goes to `ssh_key_import` only. It is never logged,
// shown in a toast or kept in state: the backend reads the file, and only the draft ID comes back.
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { useEffect, useRef } from "react";

/** The backend refuses key files larger than this (MAX_KEY_FILE_BYTES). Checking here saves a round trip. */
export const MAX_KEY_FILE_BYTES = 64 * 1024;

export const inDesktopShell = (): boolean => isTauri();

interface DropHandlers {
  onOver: (over: boolean) => void;
  onPath: (path: string) => void;
}

/**
 * Files dropped on the desktop window arrive as paths from the shell (the webview does not get the file).
 * In a plain browser the HTML drop handler of the drop zone reads the file instead.
 */
export function useNativeFileDrop(handlers: DropHandlers, active: boolean): void {
  const latest = useRef(handlers);
  useEffect(() => {
    latest.current = handlers;
  });
  useEffect(() => {
    if (!active || !isTauri()) return;
    let live = true;
    let stop: (() => void) | undefined;
    getCurrentWebview()
      .onDragDropEvent((event) => {
        const payload = event.payload;
        if (payload.type === "enter" || payload.type === "over") latest.current.onOver(true);
        else if (payload.type === "leave") latest.current.onOver(false);
        else {
          latest.current.onOver(false);
          const first = payload.paths[0];
          if (first) latest.current.onPath(first);
        }
      })
      .then((fn) => {
        if (live) stop = fn;
        else fn();
      })
      .catch(() => undefined);
    return () => {
      live = false;
      stop?.();
    };
  }, [active]);
}
