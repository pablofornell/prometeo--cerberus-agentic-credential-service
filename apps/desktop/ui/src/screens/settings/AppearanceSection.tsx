import { useScreenT } from "../../i18n";
import { SegmentedControl } from "../../ui";
import { usePrefs } from "../../state/prefs";
import { modLabel } from "../../state/uiScale";
import { Setting } from "./Setting";
import { UiScaleControl } from "./UiScaleControl";
import { messages } from "./messages";

/** Theme, density, UI scale and language are per person on this device (usePrefs). They are not vault settings. */
export function AppearanceSection() {
  const t = useScreenT(messages);
  const prefs = usePrefs();
  return (
    <section id="appearance" aria-labelledby="ap-h" className="settings-section" data-section="appearance">
      <h2 id="ap-h" tabIndex={-1}>
        {t("app.title")}
      </h2>
      <Setting label={t("theme.label")} description={t("theme.desc")}>
        <SegmentedControl
          label={t("theme.label")}
          value={prefs.theme}
          onChange={prefs.setTheme}
          options={[
            { value: "system", label: t("theme.system") },
            { value: "dark", label: t("theme.dark") },
            { value: "light", label: t("theme.light") },
          ]}
        />
      </Setting>
      <Setting label={t("density.label")} description={t("density.desc")}>
        <SegmentedControl
          label={t("density.label")}
          value={prefs.density}
          onChange={prefs.setDensity}
          options={[
            { value: "comfortable", label: t("density.comfortable") },
            { value: "compact", label: t("density.compact") },
          ]}
        />
      </Setting>
      <Setting wide label={t("scale.label")} description={t("scale.desc", { mod: modLabel() })}>
        <UiScaleControl />
      </Setting>
      <Setting label={t("lang.label")} description={t("lang.desc")}>
        <SegmentedControl label={t("lang.label")} value={prefs.language} onChange={prefs.setLanguage} options={[{ value: "en", label: t("lang.en") }]} />
      </Setting>
    </section>
  );
}
