import type { ReactNode } from "react";
import { useScreenT } from "../../i18n";
import { Icon } from "../../ui";
import { messages } from "./messages";

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
