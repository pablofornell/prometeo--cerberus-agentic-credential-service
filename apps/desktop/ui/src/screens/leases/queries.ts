import { ipc } from "../../ipc/client";
import { qk } from "../../ipc/keys";
import { useIpcQuery } from "../../ipc/queries";

/** Under the `leases` prefix, so a `lease-changed` event refreshes them all. */
export const useLeases = () => useIpcQuery([...qk.leases.all(), "list"], () => ipc.leaseList());
export const SESSIONS_KEY = [...qk.leases.all(), "sessions"] as const;
export const ITEMS_KEY = [...qk.leases.all(), "items"] as const;

/** Items that hold a session: session tokens and browser sessions. Two calls, one list. */
export const useSessionItems = () =>
  useIpcQuery(SESSIONS_KEY, async () => {
    const [tokens, browsers] = await Promise.all([ipc.itemList({ kind: "session_token" }), ipc.itemList({ kind: "browser_session" })]);
    return [...tokens, ...browsers].sort((a, b) => (a.expires_at ?? "9").localeCompare(b.expires_at ?? "9"));
  });

/** Titles and environments for the lease rows. A failure only drops the title. */
export const useItemTitles = () => useIpcQuery(ITEMS_KEY, () => ipc.itemList({}), { retry: false });
