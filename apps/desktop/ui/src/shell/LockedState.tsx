import { useLocation } from "wouter";
import { t } from "../i18n";
import { useRemote } from "../state/backendMode";
import { Button, GateMark } from "../ui";

/**
 * Shared locked state: closed gate, the reason, what agents see, and one Unlock button. In remote mode it is the
 * server: the session ended, and the server vault and its agents are not affected by that (DEC-RM-8).
 */
export function LockedState({ reason = t("locked.reason.locking") }: { reason?: string }) {
  const [, navigate] = useLocation();
  const remote = useRemote();
  return (
    <div className="state-block" role="status">
      <GateMark size={72} mode="locked" />
      <h2>{remote ? t("remote.locked.title", { label: remote.label }) : t("locked.title")}</h2>
      <p>{reason}</p>
      <p>{remote ? t("remote.locked.body") : t("locked.body")}</p>
      <div className="actions">
        <Button variant="primary" icon={remote ? "plug" : "unlock"} onClick={() => navigate("/unlock")}>
          {remote ? t("remote.locked.unlock") : t("locked.unlock")}
        </Button>
      </div>
    </div>
  );
}
