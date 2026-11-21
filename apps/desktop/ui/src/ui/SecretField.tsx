import { useCallback, useEffect, useRef, useState } from "react";
import { isIpcFailure } from "../ipc/client";
import { t } from "../i18n";
import { vaultStateStore } from "../state/live";
import { HoldButton, IconButton } from "./Button";
import { errorText } from "./States";
import { Icon } from "./Icon";
import { useToast } from "./Toast";
import { TtlRing } from "./TtlRing";
import { cx } from "./cx";

/** Security limits (PLAN 4.7, tokens.json `behavior`). The backend clears the clipboard itself after 30 s. */
export const SECRET_AUTO_HIDE_MS = 15_000;
export const CLIPBOARD_CLEAR_SECONDS = 30;
export const REVEAL_HOLD_MS = 500;

interface SecretFieldProps {
  /** Names the secret: "Password". Used in button names, never the value. */
  label: string;
  /** Fetches the value (`item_reveal`). It runs once for each reveal. */
  onReveal: () => Promise<string>;
  /** Copies with the IPC clipboard command (`clipboard_copy_secret` or `clipboard_copy_once`). Omit for no copy button. */
  onCopy?: () => Promise<unknown>;
  /** The viewer role cannot see values. */
  denied?: boolean;
  autoHideMs?: number;
  revealHoldMs?: number;
}

const MASK = "●".repeat(12);

/**
 * Runs one clipboard copy of a secret (`clipboard_copy_secret` or `clipboard_copy_once`) with the toast for its result.
 * The copy button of a `SecretField` and the context menus share it, so the text and the 30 s note are the same.
 */
export function useSecretCopy(): (copy: () => Promise<unknown>) => Promise<void> {
  const toast = useToast();
  return useCallback(
    async (copy) => {
      try {
        await copy();
        toast.push({ tone: "success", title: t("secret.copied"), ringSeconds: CLIPBOARD_CLEAR_SECONDS });
      } catch (error) {
        toast.push({
          tone: "error",
          title: t("secret.copyFailed"),
          detail: isIpcFailure(error) ? errorText(error.error) : undefined,
        });
      }
    },
    [toast],
  );
}

/**
 * A masked secret. Mono face, hold the eye for 0.5 s to reveal, hides after 15 s, copy clears the clipboard
 * after 30 s. The value lives only in this component's state. It is dropped on hide, unmount and lock
 * (ADR-0010). It never goes into `title`, `aria-label` or logs.
 */
export function SecretField({ label, onReveal, onCopy, denied = false, autoHideMs = SECRET_AUTO_HIDE_MS, revealHoldMs = REVEAL_HOLD_MS }: SecretFieldProps) {
  const toast = useToast();
  const [value, setValue] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [endsAt, setEndsAt] = useState(0);
  const request = useRef(0);

  const hide = useCallback(() => {
    request.current += 1;
    setValue(null);
    setLoading(false);
  }, []);

  // Drop the value when the vault is no longer open.
  useEffect(
    () =>
      vaultStateStore.subscribe(() => {
        const state = vaultStateStore.get();
        if (state !== "unlocked" && state !== "unknown") hide();
      }),
    [hide],
  );

  // Hide after the time limit. The cleanup also runs on unmount.
  useEffect(() => {
    if (value === null) return;
    const id = setTimeout(hide, autoHideMs);
    return () => clearTimeout(id);
  }, [value, autoHideMs, hide]);

  const reveal = useCallback(async () => {
    const mine = ++request.current;
    setLoading(true);
    try {
      const next = await onReveal();
      if (mine !== request.current) return;
      setEndsAt(Date.now() + autoHideMs);
      setValue(next);
    } catch (error) {
      if (mine !== request.current) return;
      toast.push({
        tone: "error",
        title: t("secret.revealFailed"),
        detail: isIpcFailure(error) ? errorText(error.error) : undefined,
      });
    } finally {
      if (mine === request.current) setLoading(false);
    }
  }, [onReveal, autoHideMs, toast]);

  const copyWithToast = useSecretCopy();
  const copy = useCallback(async () => {
    if (onCopy) await copyWithToast(onCopy);
  }, [onCopy, copyWithToast]);

  if (denied) {
    return (
      <div className="secret denied">
        <Icon name="eyeOff" />
        <span className="value">{t("secret.denied")}</span>
      </div>
    );
  }

  const revealed = value !== null;
  return (
    <div className={cx("secret", revealed && "revealed")} aria-busy={loading || undefined}>
      <output className="value" aria-live="polite">
        {revealed ? (
          value
        ) : (
          <>
            <span className="mask" aria-hidden="true">
              {MASK}
            </span>
            <span className="sr-only">{loading ? t("secret.loading") : t("secret.hidden")}</span>
          </>
        )}
      </output>
      {revealed && (
        <span className="hide-in">
          <TtlRing total={autoHideMs / 1000} endsAt={endsAt} size={20} />
        </span>
      )}
      {revealed ? (
        <IconButton icon="eyeOff" size="sm" label={t("secret.hide", { label })} onClick={hide} />
      ) : (
        <HoldButton
          holdMs={revealHoldMs}
          icon="eye"
          size="sm"
          variant="ghost"
          disabled={loading}
          aria-label={t("secret.reveal", { label })}
          title={t("secret.holdHint")}
          onHold={() => void reveal()}
        />
      )}
      {onCopy && <IconButton icon="copy" size="sm" label={t("secret.copy", { label })} onClick={() => void copy()} />}
    </div>
  );
}
