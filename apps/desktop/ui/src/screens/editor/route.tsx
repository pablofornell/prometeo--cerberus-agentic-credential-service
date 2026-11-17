import { useMemo, useState } from "react";
import { Route, Switch, useLocation } from "wouter";
import { useScreenT } from "../../i18n";
import { isLockError, type IpcFailure } from "../../ipc/client";
import { LockedState } from "../../shell/LockedState";
import { useCan } from "../../state/session";
import { Button, EmptyState, ErrorState, Skeleton } from "../../ui";
import { useItemDetail, useWorkspaces } from "../vault/queries";
import { WorkspaceDialog } from "../vault/WorkspaceDialog";
import "./editor.css";
import { ItemForm } from "./ItemForm";
import { messages } from "./messages";
import { fromItem, initialState } from "./model";

/** Screen 5: `/editor/new` makes an item, `/editor/<id>` edits one. */
export default function EditorScreen() {
  const tr = useScreenT(messages);
  const canWrite = useCan("operator");
  const [, navigate] = useLocation();

  if (!canWrite) {
    return (
      <EmptyState
        as="h2"
        icon="eyeOff"
        title={tr("viewer.title")}
        body={tr("viewer.body")}
        action={
          <Button variant="primary" onClick={() => navigate("~/vault")}>
            {tr("viewer.back")}
          </Button>
        }
      />
    );
  }
  return (
    <Switch>
      <Route path="/new">
        <NewItem />
      </Route>
      <Route path="/:id">{(params) => <EditItem id={decodeURIComponent(params.id)} />}</Route>
      <Route>
        <NoItemOpen />
      </Route>
    </Switch>
  );
}

function NoItemOpen() {
  const tr = useScreenT(messages);
  const [, navigate] = useLocation();
  return (
    <EmptyState
      as="h2"
      icon="edit"
      title={tr("none.title")}
      body={tr("none.body")}
      action={
        <>
          <Button onClick={() => navigate("~/vault")}>{tr("none.vault")}</Button>
          <Button variant="primary" icon="plus" onClick={() => navigate("/new")}>
            {tr("none.new")}
          </Button>
        </>
      }
    />
  );
}

function FormSkeleton({ label }: { label: string }) {
  return (
    <div className="ed-layout" aria-busy="true">
      <p role="status" aria-label={label} className="sr-only">
        {label}
      </p>
      <div className="ed-formcol" aria-hidden="true">
        <div className="panel">
          <div className="body stack">
            <Skeleton label={label} variant="line" />
            <Skeleton label={label} variant="block" />
          </div>
        </div>
        <div className="panel">
          <div className="body stack">
            <Skeleton label={label} rows={3} />
          </div>
        </div>
      </div>
      <div className="panel" aria-hidden="true">
        <div className="body stack">
          <Skeleton label={label} variant="block" />
        </div>
      </div>
    </div>
  );
}

function failed(error: IpcFailure | null, action: string, retry: () => void, retrying: boolean, locked: string) {
  if (error && isLockError(error)) return <LockedState reason={locked} />;
  return <ErrorState as="h2" action={action} error={error} onRetry={retry} retrying={retrying} />;
}

function NewItem() {
  const tr = useScreenT(messages);
  const workspaces = useWorkspaces();
  const [wsOpen, setWsOpen] = useState(false);
  const [, navigate] = useLocation();
  const list = workspaces.data;
  const initial = useMemo(() => initialState("web_login", list?.length === 1 ? (list[0]?.id ?? "") : ""), [list]);

  if (workspaces.isPending) return <FormSkeleton label={tr("load.loading")} />;
  if (workspaces.isError) return failed(workspaces.error, tr("load.action"), () => void workspaces.refetch(), workspaces.isFetching, tr("locked"));
  if (!list || list.length === 0) {
    return (
      <>
        <EmptyState
          as="h2"
          gate
          title={tr("noWorkspace.title")}
          body={tr("noWorkspace.body")}
          action={
            <>
              <Button onClick={() => navigate("~/vault")}>{tr("viewer.back")}</Button>
              <Button variant="primary" icon="plus" onClick={() => setWsOpen(true)}>
                {tr("noWorkspace.action")}
              </Button>
            </>
          }
        />
        <WorkspaceDialog open={wsOpen} onOpenChange={setWsOpen} />
      </>
    );
  }
  return <ItemForm initial={initial} itemId={null} workspaces={list} />;
}

function EditItem({ id }: { id: string }) {
  const tr = useScreenT(messages);
  const workspaces = useWorkspaces();
  const detail = useItemDetail(id);

  // Editing does not read the secret: the form sends `{ kind: "keep" }` unless the person replaces it.
  const initial = useMemo(() => (detail.data ? fromItem(detail.data) : null), [detail.data]);

  if (detail.isError) return failed(detail.error, tr("load.action"), () => void detail.refetch(), detail.isFetching, tr("locked"));
  if (!initial || workspaces.isPending) return <FormSkeleton label={tr("load.loading")} />;
  if (workspaces.isError) return failed(workspaces.error, tr("load.action"), () => void workspaces.refetch(), workspaces.isFetching, tr("locked"));

  const ws = workspaces.data.find((w) => w.slug === detail.data?.summary.workspace);
  return (
    <>
      <p className="secondary ed-editing">{tr("title.edit", { title: detail.data?.summary.title ?? "" })}</p>
      <ItemForm key={id} initial={{ ...initial, workspaceId: ws?.id ?? "" }} itemId={id} workspaces={workspaces.data} />
    </>
  );
}
