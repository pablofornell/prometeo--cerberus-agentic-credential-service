import { useCallback, useMemo, useRef, useState } from "react";
import { t as shellT, useScreenT } from "../../i18n";
import type { Value } from "../../bindings";
import { isIpcFailure, type UiError } from "../../ipc/client";
import { useSettings, useVaultStatus } from "../../ipc/queries";
import { LocalOnlyNotice } from "../../remote/LocalOnly";
import { useCan, useRole } from "../../state/session";
import { EmptyState, ErrorState, errorText, Notice, Skeleton, type IconName } from "../../ui";
import { AboutSection } from "./AboutSection";
import { AppearanceSection } from "./AppearanceSection";
import { BackupSection } from "./BackupSection";
import { NetworkSection } from "./NetworkSection";
import { RemoteSection } from "./RemoteSection";
import { SecuritySection } from "./SecuritySection";
import { ServerSection } from "./ServerSection";
import { useSetSetting } from "./queries";
import { messages } from "./messages";
import { SECTION_ICONS, SettingsNav, type SectionId } from "./SettingsNav";
import { SectionHead } from "./Setting";
import "./settings.css";

const SECTIONS: readonly SectionId[] = ["security", "network", "server", "remote", "appearance", "backup", "about"];
/** In remote mode the server comes first: the sections of a local vault only say they do not apply. */
const REMOTE_SECTIONS: readonly SectionId[] = ["server", "appearance", "security", "network", "remote", "backup", "about"];

/** The heading of a section in remote mode that belongs to a vault on this device (DEC-RM-11). */
function LocalOnlySection({ id, title, icon }: { id: SectionId; title: string; icon: IconName }) {
  const t = useScreenT(messages);
  return (
    <section id={id} aria-labelledby={`${id}-local-h`} className="settings-section" data-section={id}>
      <SectionHead id={`${id}-local-h`} icon={icon} title={title} />
      <div className="setting">
        <LocalOnlyNotice body={t("local.section")} />
      </div>
    </section>
  );
}

/** Screen 11: settings. Opens only with the vault open (route guard); the backend checks every role again. */
export default function SettingsScreen() {
  const t = useScreenT(messages);
  const status = useVaultStatus();
  const remote = status.data?.remote ?? null;
  // A remote server has no desktop settings to read (settings_get is local only).
  const settings = useSettings(remote === null);
  const role = useRole();
  const canOperator = useCan("operator");
  const canOwner = useCan("owner");
  const [saveError, setSaveError] = useState<UiError | null>(null);
  const sections = remote ? REMOTE_SECTIONS : SECTIONS;
  const root = useRef<HTMLDivElement>(null);

  const mutation = useSetSetting((failure) => setSaveError(isIpcFailure(failure) ? failure.error : null));
  const { mutate } = mutation;
  const pending = mutation.isPending ? (mutation.variables?.key ?? null) : null;
  const can = useMemo(() => ({ operator: canOperator, owner: canOwner }), [canOperator, canOwner]);
  const onSet = useCallback(
    (key: string, value: Value) => {
      setSaveError(null);
      mutate({ key, value });
    },
    [mutate],
  );

  let body;
  let bodyKind: "sections" | "loading" | "error" = "sections";
  if (remote && status.data) {
    body = (
      <div className="sections">
        <ServerSection status={status.data} />
        <AppearanceSection />
        <LocalOnlySection id="security" title={t("nav.security")} icon={SECTION_ICONS.security} />
        <LocalOnlySection id="network" title={t("nav.network")} icon={SECTION_ICONS.network} />
        <LocalOnlySection id="remote" title={t("nav.remote")} icon={SECTION_ICONS.remote} />
        <LocalOnlySection id="backup" title={t("nav.backup")} icon={SECTION_ICONS.backup} />
        <AboutSection status={status.data} />
        {saveError && (
          <div role="alert" className="save-error">
            <Notice tone="bad" title={t("save.error.title")} onDismiss={() => setSaveError(null)} dismissLabel={t("save.dismiss")}>
              {errorText(saveError)} {t("save.error.body")} <span className="code block">{t("save.error.line", { command: saveError.command, code: saveError.code })}</span>
            </Notice>
          </div>
        )}
      </div>
    );
  } else if (settings.isPending || status.isPending) {
    bodyKind = "loading";
    body = (
      <div className="sections" aria-busy="true">
        <div className="sr-only">
          <Skeleton label={t("loading")} variant="line" />
        </div>
        {[3, 4, 2].map((rows, i) => (
          <div className="settings-section placeholder" aria-hidden="true" key={i}>
            <div className="section-head">
              <span className="skel section-ico" />
              <div className="section-title">
                <span className="skel line w-30" />
                <span className="skel line w-60" />
              </div>
            </div>
            {Array.from({ length: rows }, (_, r) => (
              <div className="setting" key={r}>
                <div className="lbl">
                  <span className="skel line w-40" />
                  <span className="skel line w-70" />
                </div>
                <span className="skel ctl-box" />
              </div>
            ))}
          </div>
        ))}
      </div>
    );
  } else if (settings.isError || status.isError || !status.data) {
    bodyKind = "error";
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
        <SecuritySection
          values={values}
          status={status.data}
          can={can}
          pending={pending}
          onSet={onSet}
        />
        <NetworkSection can={can} />
        <ServerSection status={status.data} />
        <RemoteSection
          values={values}
          can={can}
          pending={pending}
          onSet={onSet}
        />
        <AppearanceSection />
        <BackupSection can={can} />
        <AboutSection status={status.data} />
        {saveError && (
          <div role="alert" className="save-error">
            <Notice tone="bad" title={t("save.error.title")} onDismiss={() => setSaveError(null)} dismissLabel={t("save.dismiss")}>
              {errorText(saveError)} {t("save.error.body")} <span className="code block">{t("save.error.line", { command: saveError.command, code: saveError.code })}</span>
            </Notice>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="settings" data-screen="settings" ref={root}>
      <SettingsNav key={remote ? "remote" : "local"} sections={sections} root={root} body={bodyKind} link={remote ? (remote.reachable ? "ok" : "bad") : null} />
      {body}
    </div>
  );
}
