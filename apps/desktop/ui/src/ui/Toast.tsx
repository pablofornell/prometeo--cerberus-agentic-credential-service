import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { t } from "../i18n";
import { cx } from "./cx";
import { Icon, type IconName } from "./Icon";
import { TtlRing } from "./TtlRing";

export type ToastTone = "success" | "info" | "error";

export interface ToastInput {
  tone?: ToastTone;
  /** Never put a secret here. Name an item only after a person action in the main window (I-19). */
  title: string;
  detail?: string;
  /** Show a TTL ring for this many seconds (the clipboard clear). The toast stays that long, 8 s at most. */
  ringSeconds?: number;
}

interface ToastItem extends ToastInput {
  id: number;
  endsAt: number;
}

interface ToastApi {
  push: (toast: ToastInput) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

const ICON: Record<ToastTone, IconName> = { success: "checkCircle", info: "info", error: "alert" };
const DEFAULT_MS = 5000;
const MAX_MS = 8000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);
  const push = useCallback((toast: ToastInput) => {
    const ms = toast.ringSeconds ? Math.min(toast.ringSeconds * 1000, MAX_MS) : DEFAULT_MS;
    const id = nextId.current++;
    setItems((prev) => [...prev, { ...toast, id, endsAt: Date.now() + (toast.ringSeconds ?? ms / 1000) * 1000 }]);
    setTimeout(() => setItems((prev) => prev.filter((i) => i.id !== id)), ms);
  }, []);
  const api = useMemo(() => ({ push }), [push]);
  return (
    <ToastContext value={api}>
      {children}
      <div className="toasts" role="region" aria-label={t("toast.region")}>
        {items.map((item) => (
          <Toast key={item.id} item={item} onDismiss={() => setItems((prev) => prev.filter((i) => i.id !== item.id))} />
        ))}
      </div>
    </ToastContext>
  );
}

function Toast({ item, onDismiss }: { item: ToastItem; onDismiss: () => void }) {
  const tone = item.tone ?? "success";
  return (
    <div className={cx("toast", tone)} role={tone === "error" ? "alert" : "status"}>
      <Icon name={ICON[tone]} />
      <div className="grow">
        <div>{item.title}</div>
        {item.detail && <div className="small muted">{item.detail}</div>}
      </div>
      {item.ringSeconds && <TtlRing total={item.ringSeconds} endsAt={item.endsAt} size={22} />}
      <button type="button" className="btn sm ghost icon-only" aria-label={t("toast.dismiss")} onClick={onDismiss}>
        <Icon name="x" />
      </button>
    </div>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast needs a ToastProvider");
  return ctx;
}
