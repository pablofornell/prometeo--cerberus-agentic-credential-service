import type { AccessRequestView_Serialize, Permission } from "../../bindings";
import type { IconName } from "../../ui/Icon";

export const clockTime = (iso: string): string => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "--:--:--" : d.toLocaleTimeString([], { hour12: false });
};

export const hourMinute = (iso: string): string => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "--:--" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
};

export const PERMISSION_TEXT: Record<Permission, string> = {
  find: "find",
  read: "read",
  create_session: "create a session",
  write: "write",
  use_ssh: "use SSH",
};

/** The request view has no item kind, so the queue row shows what the agent wants to do. */
export const PERMISSION_ICON: Record<Permission, IconName> = {
  find: "search",
  read: "eye",
  create_session: "ticket",
  write: "edit",
  use_ssh: "terminal",
};

/** Seconds from `now` to an ISO time. Can be negative. */
export const secondsUntil = (iso: string, now: number): number => Math.round((Date.parse(iso) - now) / 1000);

export const requestTotalSeconds = (r: AccessRequestView_Serialize): number =>
  Math.max(1, Math.round((Date.parse(r.expires_at) - Date.parse(r.created_at)) / 1000));

export type FeedTone = "ok" | "wait" | "bad" | "info";

/** How the feed colours an event. The word beside it carries the meaning too. */
export function feedTone(eventType: string): FeedTone {
  if (eventType === "request.create") return "wait";
  if (/^(request\.(deny|expire)|auth\.|api\.locked_call|lease\.revoke)/.test(eventType)) return "bad";
  if (/^(item\.(reveal|totp|create|update)|api\.resolve|request\.approve|lease\.(create|use)|ssh\.sign)/.test(eventType)) return "ok";
  return "info";
}
