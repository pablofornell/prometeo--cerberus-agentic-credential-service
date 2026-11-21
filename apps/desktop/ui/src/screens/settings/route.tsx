import { useEffect, useMemo, useRef, useState } from "react";
import { t as shellT, useScreenT } from "../../i18n";
import { isIpcFailure, type UiError } from "../../ipc/client";
import { useSettings, useVaultStatus } from "../../ipc/queries";
import { useCan, useRole } from "../../state/session";
import { EmptyState, ErrorState, errorText, Notice, Skeleton } from "../../ui";
import { AboutSection } from "./AboutSection";
import { AppearanceSection } from "./AppearanceSection";
import { BackupSection } from "./BackupSection";
import { NetworkSection } from "./NetworkSection";
import { RemoteSection } from "./RemoteSection";
import { SecuritySection } from "./SecuritySection";
import { useSetSetting } from "./queries";
import { messages } from "./messages";
import "./settings.css";

const SECTIONS = ["security", "network", "remote", "appearance", "backup", "about"] as const;
type SectionId = (typeof SECTIONS)[number];

/** Screen 11: settings. Opens only with the vault open (route guard); the backend checks every role again. */
export default function SettingsScreen() {
  const t = useScreenT(messages);
  const status = useVaultStatus();
  const settings = useSettings();
  const role = useRole();
  const canOperator = useCan("operator");
  const canOwner = useCan("owner");
  const [saveError, setSaveError] = useState<UiError | null>(null);
  const [current, setCurrent] = useState<SectionId>("security");
  const root = useRef<HTMLDivElement>(null);

  const mutation = useSetSetting((failure) => setSaveError(isIpcFailure(failure) ? failure.error : null));
  const pending = mutation.isPending ? (mutation.variables?.key ?? null) : null;
  const can = useMemo(() => ({ operator: canOperator, owner: canOwner }), [canOperator, canOwner]);

  // The nav marks the section in view. jsdom and old webviews have no IntersectionObserver: the nav then stays on the last click.
  useEffect(() => {
    const el = root.current;
    if (!el || typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          const id = (entry.target as HTMLElement).dataset.section as SectionId | undefined;
          if (entry.isIntersecting && id) setCurrent(id);
        }
      },
      { rootMargin: "-120px 0px -60% 0px" },
    );
    el.querySelectorAll("[data-section]").forEach((s) => io.observe(s));
    return () => io.disconnect();
  }, [settings.isSuccess, status.isSuccess]);

  const go = (id: SectionId) => {
    setCurrent(id);
    const target = root.current?.querySelector<HTMLElement>(`[data-section="${id}"]`);
    if (!target) return;
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
    target.scrollIntoView?.({ behavior: reduce ? "auto" : "smooth", block: "start" });
    target.querySelector<HTMLElement>("h2")?.focus({ preventScroll: true });
  };

  let body;
  if (settings.isPending || status.isPending) {
    body = (
      <div className="sections">
        <Skeleton label={t("loading")} rows={6} />
      </div>
    );
  } else if (settings.isError || status.isError || !status.data) {
    const failed = settings.error ?? status.error;
    body = (
      <ErrorState
        action={t("load.action")}
        error={failed}
        onRetry={() => {
          void settings.refetch();
          void status.refetch();
        }}
        retrying={settings.isFetching}
      />
    );
  } else {
    const values = settings.data.values;
    body = (
      <div className="sections">
        {Object.keys(values).length === 0 && <EmptyState gate title={shellT("empty.settings.title")} body={t("defaults.body")} />}
        {role === "operator" && <Notice tone="info" title={t("role.operator.note")} />}
        {role === "viewer" && <Notice tone="info" title={t("role.viewer.note")} />}
        {saveError && (
          <div role="alert" className="save-error">
            <Notice tone="bad" title={t("save.error.title")} onDismiss={() => setSaveError(null)} dismissLabel={t("save.dismiss")}>
              {errorText(saveError)} {t("save.error.body")} <span className="code block">{t("save.error.line", { command: saveError.command, code: saveError.code })}</span>
            </Notice>
          </div>
        )}
        <SecuritySection
          values={values}
          status={status.data}
          can={can}
          pending={pending}
          onSet={(key, value) => {
            setSaveError(null);
            mutation.mutate({ key, value });
          }}
        />
        <NetworkSection can={can} />
        <RemoteSection
          values={values}
          can={can}
          pending={pending}
          onSet={(key, value) => {
            setSaveError(null);
            mutation.mutate({ key, value });
          }}
        />
        <AppearanceSection />
        <BackupSection can={can} />
        <AboutSection status={status.data} />
      </div>
    );
  }

  return (
    <div className="settings" data-screen="settings" ref={root}>
      <nav className="subnav" aria-label={t("nav.label")}>
        {SECTIONS.map((id) => (
          <button key={id} type="button" aria-current={current === id ? "true" : undefined} onClick={() => go(id)}>
            {t(`nav.${id}`)}
          </button>
        ))}
      </nav>
      {body}
    </div>
  );
}
