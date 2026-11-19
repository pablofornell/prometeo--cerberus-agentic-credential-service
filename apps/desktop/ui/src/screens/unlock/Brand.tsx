import type { ReactNode, Ref } from "react";
import { GateMark, type GateMode } from "../../ui";

interface BrandProps {
  mode?: GateMode;
  title: string;
  /** Makes the heading focusable from code (tabIndex -1). */
  headingRef?: Ref<HTMLHeadingElement>;
  /** The line under the title. */
  children?: ReactNode;
}

/** The head of every unlock card, stacked and centered: the mark on top (60 px, sized in unlock.css), the title, then one line of context. */
export function Brand({ mode, title, headingRef, children }: BrandProps) {
  return (
    <header className="unlock-brand">
      <GateMark size={60} {...(mode ? { mode } : {})} />
      <div className="brand-text">
        <h1 {...(headingRef ? { tabIndex: -1, ref: headingRef } : {})}>{title}</h1>
        {children}
      </div>
    </header>
  );
}
