// Hash routing: `index.html#/vault`. Tauri serves one file, so there is no server fallback to configure.
// The backend opens the approval window at `index.html#approval` (no slash), so the path is normalised.
import { useMemo, useSyncExternalStore } from "react";
import { useSearch, type BaseLocationHook } from "wouter";

export const normalizeHash = (hash: string): string => {
  const raw = hash.replace(/^#/, "");
  if (raw === "") return "/";
  return raw.startsWith("/") ? raw : `/${raw}`;
};

/** Splits `/agents?new=1` into the path and the query text (without the `?`). */
export const splitQuery = (location: string): { path: string; query: string } => {
  const at = location.indexOf("?");
  return at < 0 ? { path: location, query: "" } : { path: location.slice(0, at), query: location.slice(at + 1) };
};

const subscribe = (listener: () => void) => {
  window.addEventListener("hashchange", listener);
  return () => window.removeEventListener("hashchange", listener);
};

const useHashPath = () => useSyncExternalStore(subscribe, () => splitQuery(normalizeHash(window.location.hash)).path, () => "/");
const useHashSearch = () => useSyncExternalStore(subscribe, () => splitQuery(normalizeHash(window.location.hash)).query, () => "");

/** The location is the path only. The query stays in the hash and comes from `useHashQuery()` (wouter `useSearch`). */
export const useHashLocation: BaseLocationHook & { searchHook: () => string } = Object.assign(
  () => {
    const path = useHashPath();
    const navigate = (to: string | URL, options?: { replace?: boolean }) => {
      const target = `#${typeof to === "string" ? to : to.pathname + to.search}`;
      if (options?.replace) window.location.replace(target);
      else window.location.hash = target;
    };
    return [path, navigate] as [string, typeof navigate];
  },
  { searchHook: useHashSearch },
);

/** The query of the current location (`#/agents?new=1` gives `new=1`). Updates when the hash changes. */
export function useHashQuery(): URLSearchParams {
  const search = useSearch();
  return useMemo(() => new URLSearchParams(search), [search]);
}
