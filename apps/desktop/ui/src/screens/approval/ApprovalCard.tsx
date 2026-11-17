import { useEffect, useRef } from "react";
import type { AccessRequestView_Serialize, ApprovalOption } from "../../bindings";
import { useScreenT } from "../../i18n";
import { formatDuration, formatLeft, useCountdown } from "../../state/time";
import { Button, EnvBadge, HoldButton, Icon, InlineUntrusted, Kbd, Notice, TtlRing, UntrustedText, showInvisible } from "../../ui";
import { kindLabel } from "../vault/kinds";
import { messages } from "./messages";

export type Choice = ApprovalOption | "deny";

export const HOLD_MS = 600;
const OPTIONS: readonly { choice: ApprovalOption; key: string; className?: string }[] = [
  { choice: "once", key: "A" },
  { choice: "minutes_15", key: "F" },
  { choice: "session", key: "S", className: "session" },
];

interface CardProps {
  request: AccessRequestView_Serialize;
  canDecide: boolean;
  busy: boolean;
  /** The key being held (A, F or S), for the fill. */
  held: ApprovalOption | null;
  onDecide: (choice: Choice) => void;
  /** The window is a whole page of its own: the card is the h1. */
  heading: "h1" | "h2";
  /** Deny takes focus on open: the safe side is the default. */
  focusDeny: boolean;
}

/**
 * One request. The agent name comes from its token. The reason is untrusted text and is only ever React text.
 * Enter on a focused approve button starts a 0.6 s hold, so a tap of Enter never approves. Deny is a plain button.
 */
export function ApprovalCard({ request, canDecide, busy, held, onDecide, heading: Heading, focusDeny }: CardProps) {
  const s = useScreenT(messages);
  const deny = useRef<HTMLButtonElement>(null);
  const endsAt = Date.parse(request.expires_at);
  const total = Math.max(1, Math.round((endsAt - Date.parse(request.created_at)) / 1000));
  const left = useCountdown(endsAt) ?? 0;
  const prod = request.environment === "prod";

  useEffect(() => {
    if (focusDeny && canDecide) deny.current?.focus();
  }, [focusDeny, canDecide, request.id]);

  const asks = request.requested_ttl_seconds
    ? s("item.asksFor", { permission: s(`perm.${request.permission}`), time: formatDuration(request.requested_ttl_seconds) })
    : s("item.asks", { permission: s(`perm.${request.permission}`) });

  return (
    <article className="ap-card" aria-labelledby={`ap-${request.id}`}>
      <div className="trace" role="list" aria-label={s("trace.label")}>
        <span className="step pass" role="listitem"><span className="dot" />{s("trace.token")}</span>
        <span className="step pass" role="listitem"><span className="dot" />{s("trace.grant")}</span>
        <span className="step wait" role="listitem"><span className="dot" />{s("trace.you")}</span>
      </div>
      <Heading id={`ap-${request.id}`} className="ap-title">
        {s("title", { agent: showInvisible(request.agent_name), verb: s(`verb.${request.permission}`), what: s(prod ? "what.prod" : "what.item") })}
      </Heading>
      <div className="ap-ident">
        <Icon name="check" />
        <span>{s("ident", { agent: showInvisible(request.agent_name), id: request.agent_id })}</span>
      </div>
      {request.burst_warning && <Notice tone="warn" title={s("burst.single", { agent: showInvisible(request.agent_name) })} />}
      <div className={prod ? "ap-item prod" : "ap-item"}>
        <div className="between">
          <span className="t"><InlineUntrusted text={request.item_title} /></span>
          <EnvBadge env={request.environment} />
        </div>
        <span className="small secondary">{s("item.in", { workspace: showInvisible(request.workspace_name) })}</span>
        <span className="small secondary" data-testid="ap-kind">
          {request.role_label ? s("item.kindRole", { kind: kindLabel(request.item_kind), role: showInvisible(request.role_label) }) : kindLabel(request.item_kind)}
        </span>
        <span className="small secondary">{asks}</span>
        {prod && (
          <span className="ap-risk">
            <Icon name="shieldAlert" />
            {s("risk.prod")}
          </span>
        )}
      </div>
      {request.reason.trim() === "" ? <p className="small muted">{s("reason.none")}</p> : <UntrustedText text={request.reason} />}
      <div className="ap-expiry">
        <TtlRing total={total} endsAt={endsAt} size={22} />
        <span>{s("expiry", { time: formatLeft(left) })}</span>
      </div>
      {canDecide ? (
        <>
          <div className="ap-choices" role="group" aria-label={s("choices.label")}>
            {OPTIONS.map(({ choice, key, className }) => (
              <HoldButton
                key={choice}
                holdMs={HOLD_MS}
                allowClick
                disabled={busy}
                className={[className, held === choice ? "held" : ""].filter(Boolean).join(" ")}
                onHold={() => onDecide(choice)}
              >
                <span>{s(`choice.${choice}`)}</span>
                <Kbd>{key}</Kbd>
              </HoldButton>
            ))}
            <Button ref={deny} variant="danger-ghost" className="deny" icon="x" disabled={busy} onClick={() => onDecide("deny")}>
              <span>{s("choice.deny")}</span>
              <Kbd>D</Kbd>
            </Button>
          </div>
          <p className="ap-key">{s("keynote")}</p>
        </>
      ) : (
        <Notice tone="info" title={s("viewer")} />
      )}
    </article>
  );
}
