import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useLocation } from "wouter";
import type { ItemSummaryView_Serialize as Item } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { useRemoteUnsupported } from "../../state/backendMode";
import { AgentMadeBadge, Button, ConfirmDialog, EmptyState, EnvBadge, errorText, ErrorState, IconButton, KindIcon, RoleChip, SecretField, Skeleton, TtlRing, useToast } from "../../ui";
import { ttlSpan } from "./filters";
import { formatDateTime, isSessionKind, kindLabel } from "./kinds";
import { HistoryDialog } from "./HistoryDialog";
import { messages } from "./messages";
import { invalidateItems, useItemDetail } from "./queries";
import { RustdeskCard } from "./RustdeskCard";
import { pickSecret, SECRET_FIELDS } from "./secrets";

interface Props {
  item: Item | null;
  /** Operators and owners edit and delete. Viewers see no action. */
  canEdit: boolean;
  /** Viewers cannot reveal values. */
  canReveal: boolean;
  agentNames: ReadonlyMap<string, string>;
  operatorNames: ReadonlyMap<string, string>;
  onClose: () => void;
}

/** The details of the selected item, next to the list. Secret values live only in `SecretField` state. */
export function ItemDrawer({ item, canEdit, canReveal, agentNames, operatorNames, onClose }: Props) {
  const tr = useScreenT(messages);
  if (!item) {
    return (
      <aside className="drawer vb-drawer is-empty" aria-label={tr("drawer.none.title")}>
        <EmptyState icon="eye" title={tr("drawer.none.title")} body={tr("drawer.none.body")} />
      </aside>
    );
  }
  return <DrawerBody key={item.id} item={item} canEdit={canEdit} canReveal={canReveal} agentNames={agentNames} operatorNames={operatorNames} onClose={onClose} />;
}

function creatorLabel(createdBy: string, agents: ReadonlyMap<string, string>, operators: ReadonlyMap<string, string>, fallback: string) {
  if (createdBy.startsWith("agent:")) {
    const id = createdBy.slice("agent:".length);
    return <AgentMadeBadge agent={agents.get(id) ?? id} />;
  }
  return <>{operators.get(createdBy.replace(/^operator:/, "")) ?? fallback}</>;
}

function DrawerBody({ item, canEdit, canReveal, agentNames, operatorNames, onClose }: Props & { item: Item }) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const [, navigate] = useLocation();
  const detail = useItemDetail(item.id);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  // Remote mode: copy needs the clipboard timer of this device and the history is not on the remote allowlist
  // (DEC-RM-14). The value can still be revealed.
  const noCopy = useRemoteUnsupported("clipboard_copy_secret");
  const noHistory = useRemoteUnsupported("item_versions");
  const fields = SECRET_FIELDS[item.kind];
  const span = isSessionKind(item.kind) ? ttlSpan(item) : null;

  /** One `item_reveal` per reveal. The backend audits it. The value goes straight to the field and nowhere else. */
  const reveal = async (key: string): Promise<string> => {
    const result = await ipc.itemReveal(item.id);
    if (result.exhausted) {
      toast.push({ tone: "info", title: tr("drawer.exhausted") });
      invalidateItems(queryClient);
    }
    return pickSecret(result.payload, key);
  };

  const remove = async () => {
    setDeleting(true);
    try {
      await ipc.itemDelete(item.id);
      toast.push({ tone: "success", title: tr("delete.done", { title: item.title }) });
      setConfirmDelete(false);
      invalidateItems(queryClient);
      onClose();
    } catch (error) {
      toast.push({ tone: "error", title: tr("delete.fail"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
    } finally {
      setDeleting(false);
    }
  };

  const info = detail.data;
  const exposed = info?.exposed_to ?? [];

  return (
    <aside className="drawer vb-drawer" aria-labelledby="vb-d-title">
      <header>
        <div className="between">
          <span className="row-inline">
            <KindIcon kind={item.kind} prod={item.environment === "prod"} />
            <span className="small muted">{tr("drawer.kindIn", { kind: kindLabel(item.kind), workspace: item.workspace })}</span>
          </span>
          <IconButton icon="x" size="sm" label={tr("drawer.close")} onClick={onClose} />
        </div>
        <h2 id="vb-d-title" tabIndex={-1}>
          {item.title}
        </h2>
        <div className="row-inline">
          <EnvBadge env={item.environment} />
          {item.role_label && <RoleChip role={item.role_label} />}
          {item.tags.map((tag) => (
            <span key={tag} className="tag">
              #{tag}
            </span>
          ))}
        </div>
        {item.description && <p className="secondary small">{item.description}</p>}
      </header>

      {item.kind === "rustdesk" && <RustdeskCard item={item} canReveal={canReveal} />}

      <section className="sec" aria-labelledby="vb-d-secret">
        <h3 id="vb-d-secret">{tr("drawer.secret")}</h3>
        {!canReveal && <p className="small muted">{tr("drawer.viewerNote")}</p>}
        {fields.length === 0 && canReveal && <p className="small muted">{tr("drawer.noSecret")}</p>}
        {fields.map((def) => {
          const label = tr(def.label);
          return (
            <div className="vb-secret-row" key={def.key}>
              <span className="field-k" id={`vb-k-${def.key}`}>
                {label}
              </span>
              <SecretField
                label={label}
                denied={!canReveal}
                onReveal={() => reveal(def.key)}
                onCopy={def.field && !noCopy ? () => ipc.clipboardCopySecret(item.id, def.field ?? "") : undefined}
              />
            </div>
          );
        })}
        {item.target && (
          <div className="vb-secret-row">
            <span className="field-k">{tr("drawer.target")}</span>
            <span className="mono small">{item.target}</span>
          </div>
        )}
        {fields.length > 0 && canReveal && <p className="small muted">{noCopy ? tr("drawer.holdHint.remote") : tr("drawer.holdHint")}</p>}
      </section>

      {item.has_totp && (
        <section className="sec" aria-labelledby="vb-d-otp">
          <h3 id="vb-d-otp">{tr("drawer.otp")}</h3>
          <SecretField
            label={tr("drawer.otp")}
            denied={!canReveal}
            onReveal={async () => {
              const view = await ipc.itemTotpPreview(item.id);
              return `${view.code.slice(0, Math.ceil(view.code.length / 2))} ${view.code.slice(Math.ceil(view.code.length / 2))}`;
            }}
            onCopy={noCopy ? undefined : () => ipc.clipboardCopySecret(item.id, "totp")}
          />
        </section>
      )}

      <section className="sec" aria-labelledby="vb-d-use">
        <h3 id="vb-d-use">{tr("drawer.use")}</h3>
        {detail.isPending && <Skeleton label={tr("drawer.loading")} variant="block" />}
        {detail.isError && <ErrorState action={tr("drawer.detailError")} error={detail.error} onRetry={() => void detail.refetch()} retrying={detail.isFetching} />}
        {info && (
          <dl className="kv small">
            <dt>{tr("drawer.exposed")}</dt>
            <dd>
              {exposed.length === 0
                ? tr("drawer.exposedNone")
                : exposed.slice(0, 3).map((e) => (
                    <div key={`${e.agent_id}-${e.at}`}>{tr("drawer.exposedLine", { agent: agentNames.get(e.agent_id) ?? e.agent_id, time: formatDateTime(e.at) })}</div>
                  ))}
            </dd>
            <dt>{tr("drawer.uses")}</dt>
            <dd>{info.max_uses === null ? tr("drawer.usesLine", { count: info.use_count }) : tr("drawer.usesLimit", { count: info.use_count, max: info.max_uses })}</dd>
            <dt>{tr("drawer.expires")}</dt>
            <dd className="row-inline">
              {span && <TtlRing total={span.total} endsAt={span.endsAt} size={20} />}
              {item.expires_at ? formatDateTime(item.expires_at) : tr("drawer.never")}
            </dd>
            <dt>{tr("drawer.version")}</dt>
            <dd className="row-inline">
              {tr("drawer.versionLine", { version: info.version })}
              {!noHistory && (
                <Button size="sm" variant="ghost" onClick={() => setHistoryOpen(true)}>
                  {tr("drawer.history")}
                </Button>
              )}
            </dd>
            <dt>{tr("drawer.createdBy")}</dt>
            <dd>{creatorLabel(item.created_by, agentNames, operatorNames, tr("drawer.unknownOperator"))}</dd>
            <dt>{tr("drawer.updated")}</dt>
            <dd>{formatDateTime(item.updated_at)}</dd>
          </dl>
        )}
      </section>

      {canEdit && (
        <div className="acts">
          <Button icon="edit" onClick={() => navigate(`~/editor/${encodeURIComponent(item.id)}`)}>
            {tr("drawer.edit")}
          </Button>
          <Button variant="danger-ghost" icon="trash" onClick={() => setConfirmDelete(true)}>
            {tr("drawer.delete")}
          </Button>
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        tone="danger"
        title={tr("delete.title", { title: item.title })}
        description={tr("delete.body", { versions: info?.version ?? 1, workspace: item.workspace, env: item.environment })}
        confirmLabel={tr("delete.confirm")}
        onConfirm={() => void remove()}
        loading={deleting}
      />
      <HistoryDialog open={historyOpen && !noHistory} onOpenChange={setHistoryOpen} item={item} canRestore={canEdit} />
    </aside>
  );
}

