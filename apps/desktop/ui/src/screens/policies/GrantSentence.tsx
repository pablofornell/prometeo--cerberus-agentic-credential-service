import type { ReactNode } from "react";
import type { ConditionsView_Serialize, GrantView_Serialize, WorkspaceView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { messages } from "./messages";
import "./policies.css";

const BADGE_CLASS = { auto: "m-auto", ask_once: "m-once", ask_always: "m-always", deny: "m-deny" } as const;

/** The mode of a grant as a small badge. A word always goes with the colour. */
export function ModeBadge({ mode }: { mode: GrantView_Serialize["mode"] }) {
  const s = useScreenT(messages);
  return <span className={`mode ${BADGE_CLASS[mode]}`}>{s(`badge.${mode}`)}</span>;
}

const B = ({ children }: { children: ReactNode }) => <b>{children}</b>;

function join(values: readonly string[], or: string): string {
  if (values.length <= 1) return values.join("");
  return `${values.slice(0, -1).join(", ")} ${or} ${values[values.length - 1] ?? ""}`;
}

type S = ReturnType<typeof useScreenT<typeof messages>>;

function conditionText(c: ConditionsView_Serialize, s: S): string[] {
  const out: string[] = [];
  if (c.time_window) {
    const days = c.time_window.days.map((d) => s(`day.${d}`)).join(", ");
    out.push(s("sentence.window", { days, start: c.time_window.start.slice(0, 5), end: c.time_window.end.slice(0, 5), tz: c.time_window.tz }));
  }
  if (c.max_reads_per_hour !== null) out.push(s("sentence.reads", { n: c.max_reads_per_hour }));
  if (c.expires_at) out.push(s("sentence.ends", { date: c.expires_at.slice(0, 10) }));
  if (c.reason_required) out.push(s("sentence.reason"));
  return out;
}

/** One grant in plain words: "Can read items in workspace shop-frontend, env staging, any category." */
export function GrantSentence({ grant, workspaces, id }: { grant: GrantView_Serialize; workspaces: readonly WorkspaceView[]; id?: string }) {
  const s = useScreenT(messages);
  const sel = grant.selector;
  const names = sel.workspace_ids.map((id) => workspaces.find((w) => w.id === id)?.slug ?? id);
  const or = s("sentence.or");
  const perms = grant.permissions.map((p) => s(`perm.${p}`));
  const extras: ReactNode[] = [];
  if (sel.tags.length) extras.push(<span key="tags">{s("sentence.tags")} <B>{join(sel.tags.map((x) => `#${x}`), or)}</B></span>);
  if (sel.kinds.length) extras.push(<span key="kinds">{s("sentence.kinds")} <B>{join(sel.kinds.map((k) => s(`kind.${k}`)), or)}</B></span>);
  if (sel.role_labels.length) extras.push(<span key="roles">{s("sentence.roles")} <B>{join(sel.role_labels, or)}</B></span>);
  if (sel.item_ids.length) extras.push(<span key="ids"><B>{s("sentence.items", { count: sel.item_ids.length })}</B></span>);
  const tail = conditionText(grant.conditions, s);
  if (grant.allow_prod_auto) tail.push(s("sentence.prodAuto"));
  const blocked = grant.mode === "deny";
  return (
    <p id={id}>
      {blocked ? (
        <>
          {s("sentence.blocked")} <B>{s("sentence.blockedWord")}</B>{" "}
          {names.length ? (
            <>
              {s("sentence.from")} {s("sentence.workspaceWord")} <B>{join(names, or)}</B>
            </>
          ) : (
            s("sentence.fromAny")
          )}
        </>
      ) : (
        <>
          {s("sentence.can")} <B>{join(perms, or)}</B>{" "}
          {names.length ? (
            <>
              {s("sentence.itemsIn")} <B>{join(names, or)}</B>
            </>
          ) : (
            s("sentence.inAny")
          )}
        </>
      )}
      ,{" "}
      {sel.environments.length ? (
        <>
          {s("sentence.env")} <B>{join(sel.environments, or)}</B>
        </>
      ) : (
        s("sentence.any.env")
      )}
      ,{" "}
      {sel.categories.length ? (
        <>
          {s("sentence.category")} <B>{join(sel.categories, or)}</B>
        </>
      ) : (
        s("sentence.any.category")
      )}
      {extras.map((node, i) => (
        <span key={i}>, {node}</span>
      ))}
      . {tail.join(" ")}
    </p>
  );
}
