import { useId, useRef, type ReactNode } from "react";

export interface TabDef<Id extends string> {
  id: Id;
  label: string;
  panel: ReactNode;
}

interface TabsProps<Id extends string> {
  label: string;
  tabs: readonly TabDef<Id>[];
  value: Id;
  onChange: (id: Id) => void;
}

/** Tabs with roving focus: Left and Right move and select, Home and End jump. */
export function Tabs<Id extends string>({ label, tabs, value, onChange }: TabsProps<Id>) {
  const base = useId();
  const list = useRef<HTMLDivElement>(null);
  const index = Math.max(0, tabs.findIndex((tab) => tab.id === value));
  const go = (next: number) => {
    const tab = tabs[(next + tabs.length) % tabs.length];
    if (!tab) return;
    onChange(tab.id);
    queueMicrotask(() => list.current?.querySelector<HTMLElement>(`[data-tab="${tab.id}"]`)?.focus());
  };
  return (
    <div className="tabs">
      <div
        className="tablist"
        role="tablist"
        aria-label={label}
        ref={list}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") go(index + 1);
          else if (e.key === "ArrowLeft") go(index - 1);
          else if (e.key === "Home") go(0);
          else if (e.key === "End") go(tabs.length - 1);
          else return;
          e.preventDefault();
        }}
      >
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            id={`${base}-tab-${tab.id}`}
            data-tab={tab.id}
            aria-selected={tab.id === value}
            aria-controls={`${base}-panel-${tab.id}`}
            tabIndex={tab.id === value ? 0 : -1}
            onClick={() => onChange(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {tabs.map((tab) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={`${base}-panel-${tab.id}`}
          aria-labelledby={`${base}-tab-${tab.id}`}
          hidden={tab.id !== value}
        >
          {tab.id === value && tab.panel}
        </div>
      ))}
    </div>
  );
}
