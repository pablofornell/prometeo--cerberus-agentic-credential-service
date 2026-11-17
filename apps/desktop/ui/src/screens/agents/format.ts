import { format, useScreenT } from "../../i18n";
import { messages } from "./messages";

const MIN = 60;
const HOUR = 3600;
const DAY = 86_400;

/** "1 min ago", "3 h ago", "12 days ago". `null` gives `fallback`. */
export function ago(iso: string | null | undefined, now: number, fallback: string): string {
  if (!iso) return fallback;
  const sec = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (sec < MIN) return messages["time.now"];
  if (sec < HOUR) return format(messages["time.min"], { n: Math.floor(sec / MIN) });
  if (sec < DAY) return format(messages["time.hour"], { n: Math.floor(sec / HOUR) });
  const days = Math.floor(sec / DAY);
  return days === 1 ? messages["time.day.one"] : format(messages["time.day"], { n: days });
}

/** "in 9 h", "in 71 days". A past time gives "Expired". `null` gives `fallback`. */
export function inFuture(iso: string | null | undefined, now: number, fallback: string): string {
  if (!iso) return fallback;
  const sec = Math.round((Date.parse(iso) - now) / 1000);
  if (sec <= 0) return messages["time.expired"];
  if (sec < HOUR) return format(messages["time.in.min"], { n: Math.max(1, Math.floor(sec / MIN)) });
  if (sec < DAY) return format(messages["time.in.hour"], { n: Math.floor(sec / HOUR) });
  const days = Math.floor(sec / DAY);
  return days === 1 ? messages["time.in.day.one"] : format(messages["time.in.day"], { n: days });
}

/** Text hook for this folder. */
export const useAgentsT = () => useScreenT(messages);
