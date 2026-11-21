// RustDesk items (DEC-RD-1): the ID, the servers and the key are item metadata (`custom`), so the share card and the
// Connect button need no reveal. Only the password is a secret; it never goes into a link or the shared text.
import { ipc } from "../../ipc/client";
import { useIpcQuery } from "../../ipc/queries";

export interface RustdeskConnection {
  id: string;
  idServer: string | null;
  relayServer: string | null;
  serverKey: string | null;
}

/** The `custom` keys of a RustDesk item. The backend uses the same names. */
export const RUSTDESK_KEYS = { id: "rustdesk_id", idServer: "id_server", relayServer: "relay_server", serverKey: "server_key" } as const;

/** A RustDesk ID as the backend accepts it: 9 to 20 digits. */
export const isRustdeskId = (text: string): boolean => /^\d{9,20}$/.test(text);

/** RustDesk shows IDs in groups (`123 456 789`). The stored form has no spaces. */
export const cleanRustdeskId = (text: string): string => text.replace(/\s+/g, "");

export function rustdeskConnection(custom: Record<string, string>): RustdeskConnection {
  const opt = (key: string) => {
    const value = custom[key]?.trim() ?? "";
    return value === "" ? null : value;
  };
  return { id: custom[RUSTDESK_KEYS.id] ?? "", idServer: opt(RUSTDESK_KEYS.idServer), relayServer: opt(RUSTDESK_KEYS.relayServer), serverKey: opt(RUSTDESK_KEYS.serverKey) };
}

/** `rustdesk://<id>`, with `?key=<key>` when the server has one. Never the password. */
export function rustdeskLink(c: RustdeskConnection): string {
  return `rustdesk://${c.id}${c.serverKey ? `?key=${encodeURIComponent(c.serverKey)}` : ""}`;
}

/** Labels of the shared text, from the screen messages. */
export interface ShareLabels {
  id: string;
  idServer: string;
  relayServer: string;
  serverKey: string;
  link: string;
}

/** Everything another person needs to add the connection to their RustDesk client, one fact a line. No password. */
export function rustdeskShareText(c: RustdeskConnection, labels: ShareLabels): string {
  const lines: [string, string | null][] = [
    [labels.id, c.id],
    [labels.idServer, c.idServer],
    [labels.relayServer, c.relayServer],
    [labels.serverKey, c.serverKey],
    [labels.link, rustdeskLink(c)],
  ];
  return lines
    .filter((line): line is [string, string] => line[1] !== null)
    .map(([label, value]) => `${label}: ${value}`)
    .join("\n");
}

export const rustdeskKeys = { status: () => ["settings", "rustdesk"] as const };

/** Which RustDesk client the Connect button would start, or none. Nothing is started by this query. */
export const useRustdeskStatus = (enabled = true) => useIpcQuery(rustdeskKeys.status(), () => ipc.rustdeskStatus(), { enabled });
