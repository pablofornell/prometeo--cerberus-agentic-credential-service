import { useLocation } from "wouter";
import { t } from "../i18n";
import { Button, GateMark } from "../ui";

/** Shared locked state: closed gate, the reason, what agents see, and one Unlock button. */
export function LockedState({ reason = t("locked.reason.locking") }: { reason?: string }) {
  const [, navigate] = useLocation();
  return (
    <div className="state-block" role="status">
      <GateMark size={72} mode="locked" />
      <h2>{t("locked.title")}</h2>
      <p>{reason}</p>
      <p>{t("locked.body")}</p>
      <div className="actions">
        <Button variant="primary" icon="unlock" onClick={() => navigate("/unlock")}>
          {t("locked.unlock")}
        </Button>
      </div>
    </div>
  );
}
