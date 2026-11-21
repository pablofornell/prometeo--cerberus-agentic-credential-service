import { t } from "../i18n";
import { Icon } from "../ui";
import "./remote.css";

/** "Not available for a remote server" in place of controls that work on the local vault only (DEC-RM-11). */
export function LocalOnlyNotice({ body }: { body?: string }) {
  return (
    <p className="local-only" data-testid="local-only">
      <Icon name="serverOff" />
      <span>
        <b>{t("remote.unsupported")}.</b> {body ?? t("remote.unsupported.body")}
      </span>
    </p>
  );
}
