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

/** The head of every unlock card: the mark at 40 px next to the title and one line of context (the Hermes login head). */
export function Brand({ mode, title, headingRef, children }: BrandProps) {
  return (
    <header className="unlock-brand">
      <GateMark size={40} {...(mode ? { mode } : {})} />
      <div className="brand-text">
        <h1 {...(headingRef ? { tabIndex: -1, ref: headingRef } : {})}>{title}</h1>
        {children}
      </div>
    </header>
  );
}
