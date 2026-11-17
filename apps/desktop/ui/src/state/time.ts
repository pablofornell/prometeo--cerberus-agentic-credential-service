import { useCallback, useSyncExternalStore } from "react";

/** `4:10` under one hour, `4 h 16 m` above. */
export function formatLeft(totalSeconds: number): string {
  const sec = Math.max(0, Math.round(totalSeconds));
  if (sec >= 3600) {
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    return `${h} h ${String(m).padStart(2, "0")} m`;
  }
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

/**
 * A length of time in words, for a time span that is not counting down: `15 minutes`, `1 hour`, `2 h 30 min`,
 * `45 seconds`. A countdown uses `formatLeft` instead.
 */
export function formatDuration(totalSeconds: number): string {
  const sec = Math.max(0, Math.round(totalSeconds));
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
  if (sec < 60) return plural(sec, "second");
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (h === 0) return plural(m, "minute");
  if (m === 0) return plural(h, "hour");
  return `${h} h ${m} min`;
}

/** Current time in ms, rounded down to `everyMs`. Re-renders at each step while `active`. */
export function useNow(everyMs = 1000, active = true): number {
  const subscribe = useCallback(
    (listener: () => void) => {
      if (!active) return () => undefined;
      const id = setInterval(listener, everyMs);
      return () => clearInterval(id);
    },
    [everyMs, active],
  );
  return useSyncExternalStore(subscribe, () => Math.floor(Date.now() / everyMs) * everyMs);
}

/** Whole seconds until `endsAt` (ms since epoch). `null` in, `null` out. Ticks each second. */
export function useCountdown(endsAt: number | null): number | null {
  const now = useNow(1000, endsAt !== null);
  return endsAt === null ? null : Math.max(0, Math.floor((endsAt - now) / 1000));
}
