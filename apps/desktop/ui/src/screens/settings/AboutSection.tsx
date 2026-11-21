import { getVersion } from "@tauri-apps/api/app";
import { useEffect, useState } from "react";
import type { VaultStatusView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { Button, Dialog, StatusDot } from "../../ui";
import { SectionHead, Setting } from "./Setting";
import { messages } from "./messages";

export function AboutSection({ status }: { status: VaultStatusView }) {
  const t = useScreenT(messages);
  const [version, setVersion] = useState<string | null>(null);
  const [licenses, setLicenses] = useState(false);
  useEffect(() => {
    let live = true;
    getVersion()
      .then((v) => live && setVersion(v))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);
  return (
    <section id="about" aria-labelledby="ab-h" className="settings-section" data-section="about">
      <SectionHead id="ab-h" icon="info" title={t("about.title")} description={t("section.about.desc")} />
      <Setting label={version ? `${t("about.name")} ${version}` : t("about.name")} description={t("about.desc")}>
        <StatusDot tone={status.memlock_ok ? "ok" : "warn"}>{status.memlock_ok ? t("about.memlock.on") : t("about.memlock.off")}</StatusDot>
        <StatusDot tone={status.header_ok ? "ok" : "bad"}>{status.header_ok ? t("about.header.ok") : t("about.header.bad")}</StatusDot>
      </Setting>
      <Setting label={t("lic.label")} description={t("lic.desc")}>
        <Button size="sm" variant="ghost" onClick={() => setLicenses(true)}>
          {t("lic.show")}
        </Button>
      </Setting>
      <Dialog
        open={licenses}
        onOpenChange={setLicenses}
        title={t("lic.title")}
        footer={<Button variant="primary" onClick={() => setLicenses(false)}>{t("close")}</Button>}
      >
        <div className="stack">
          <p>{t("lic.body")}</p>
          <ul className="plain-list">
            <li>{t("lic.sans")}</li>
            <li>{t("lic.mono")}</li>
          </ul>
          <p className="small muted">{t("lic.deps")}</p>
        </div>
      </Dialog>
    </section>
  );
}
