import { useId, type ReactNode } from "react";
import { useScreenT } from "../../i18n";
import { Icon, type IconName } from "../../ui";
import { messages } from "./messages";

interface SectionHeadProps {
  /** The id of the `h2`: the section is named by it (`aria-labelledby`). */
  id: string;
  icon: IconName;
  title: string;
  description?: ReactNode;
  /** A status chip or a button at the trailing edge. */
  aside?: ReactNode;
}

/** The head of a section: an icon tile, the title, one line of what the section is for. The `h2` holds only the title. */
export function SectionHead({ id, icon, title, description, aside }: SectionHeadProps) {
  return (
    <header className="section-head">
      <span className="section-ico" aria-hidden="true">
        <Icon name={icon} size={18} />
      </span>
      <div className="section-title">
        <h2 id={id} tabIndex={-1}>
          {title}
        </h2>
        {description && <p>{description}</p>}
      </div>
      {aside && <div className="section-aside">{aside}</div>}
    </header>
  );
}

interface SettingGroupProps {
  label: string;
  /** Destructive actions: a red outline around the rows. */
  danger?: boolean;
  children: ReactNode;
}

/** A band with a small title over a run of rows. A danger group is a bordered block of its own. */
export function SettingGroup({ label, danger, children }: SettingGroupProps) {
  const id = useId();
  return (
    <div role="group" aria-labelledby={id} className={danger ? "setting-group danger" : "setting-group"}>
      <h3 id={id} className="group-label">
        {danger && <Icon name="alert" size={14} />}
        {label}
      </h3>
      {children}
    </div>
  );
}

interface SettingProps {
  label: string;
  description?: ReactNode;
  /** Shown beside a control the role cannot use. */
  ownerOnly?: boolean;
  operatorOnly?: boolean;
  /** Full width body under the label (lists). */
  wide?: boolean;
  children?: ReactNode;
}

/** One row: what it is on the left, the control on the right. */
export function Setting({ label, description, ownerOnly, operatorOnly, wide, children }: SettingProps) {
  const t = useScreenT(messages);
  return (
    <div className={wide ? "setting wide" : "setting"}>
      <div className="lbl">
        <b>{label}</b>
        {description && <span>{description}</span>}
      </div>
      <div className="ctl">
        {(ownerOnly || operatorOnly) && (
          <span className="owner-only">
            <Icon name="lock" size={13} />
            {ownerOnly ? t("ownerOnly") : t("operatorOnly")}
          </span>
        )}
        {!wide && children}
      </div>
      {wide && <div className="body">{children}</div>}
    </div>
  );
}

export interface Option {
  value: string;
  label: string;
}

/** `5 minutes`, `1 hour`, `12 hours`. */
export function useDuration() {
  const t = useScreenT(messages);
  return (seconds: number | null): string => {
    if (seconds === null) return t("off");
    if (seconds < 60) return t("unit.s", { n: seconds });
    if (seconds < 3600) {
      const m = Math.round(seconds / 60);
      return m === 1 ? t("unit.min1") : t("unit.min", { n: m });
    }
    const h = Math.round((seconds / 3600) * 10) / 10;
    return h === 1 ? t("unit.h1") : t("unit.h", { n: h });
  };
}

/** The preset list, plus the current value when it is not one of them (so the select never lies). */
export function withCurrent(presets: readonly (number | null)[], current: number | null, label: (v: number | null) => string): Option[] {
  const values = presets.includes(current) ? [...presets] : [...presets, current].sort((a, b) => (a === null ? 1 : b === null ? -1 : a - b));
  return values.map((v) => ({ value: v === null ? "off" : String(v), label: label(v) }));
}

export const parseChoice = (value: string): number | null => (value === "off" ? null : Number(value));
