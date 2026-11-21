import { useScreenT } from "../i18n";
import { useNow } from "../state/time";
import { cx } from "../ui";
import { messages } from "./messages";
import "./remote.css";

const DAY_MS = 86_400_000;
/** A certificate this close to its end gets a warning: enrolment again takes a terminal on the server. */
const SOON_DAYS = 14;

interface ProfileFactsProps {
  label: string;
  url: string;
  operator: string;
  notAfter: string;
  /** The pin and hash to compare with `cerberusd status`. Shown at import and in Settings. */
  caPin?: string;
  caSha256?: string;
  serverVersion?: string | null;
}

const formatDate = (iso: string): string => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

/** What the person checks of a remote profile. The labels are the ones `cerberusd status` prints (`CA pin`, `CA SHA-256`). */
export function ProfileFacts({ label, url, operator, notAfter, caPin, caSha256, serverVersion }: ProfileFactsProps) {
  const t = useScreenT(messages);
  const now = useNow(60_000);
  const days = Math.floor((new Date(notAfter).getTime() - now) / DAY_MS);
  const date = formatDate(notAfter);
  const expiry = days < 0 ? t("fact.expires.past", { date }) : days < SOON_DAYS ? t("fact.expires.soon", { date, n: days }) : t("fact.expires.days", { date, n: days });
  return (
    <dl className="remote-facts">
      <dt>{t("fact.server")}</dt>
      <dd>{label}</dd>
      <dt>{t("fact.url")}</dt>
      <dd className="mono">{url}</dd>
      {caPin && (
        <>
          <dt>{t("fact.pin")}</dt>
          <dd className="mono" data-testid="remote-pin">{caPin}</dd>
        </>
      )}
      {caSha256 && (
        <>
          <dt>{t("fact.sha")}</dt>
          <dd className="mono" data-testid="remote-sha">{caSha256}</dd>
        </>
      )}
      <dt>{t("fact.operator")}</dt>
      <dd>{operator}</dd>
      <dt>{t("fact.expires")}</dt>
      <dd className={cx(days < 0 ? "bad" : days < SOON_DAYS && "warn")}>{expiry}</dd>
      {serverVersion && (
        <>
          <dt>{t("fact.version")}</dt>
          <dd className="mono">{serverVersion}</dd>
        </>
      )}
    </dl>
  );
}
