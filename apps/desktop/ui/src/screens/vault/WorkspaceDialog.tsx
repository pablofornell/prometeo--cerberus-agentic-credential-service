import { useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import type { WorkspaceView } from "../../bindings";
import { t, useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { Button, Dialog, errorText, Field, Input, useToast } from "../../ui";
import { messages } from "./messages";
import { invalidateItems } from "./queries";

const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

const slugOf = (name: string): string =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called with the new workspace after `workspace_put` worked. */
  onCreated?: (workspace: WorkspaceView) => void;
}

/** Creates a workspace (`workspace_put` with no ID). Used by the vault sidebar and by the item editor. */
export function WorkspaceDialog({ open, onOpenChange, onCreated }: Props) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [description, setDescription] = useState("");
  const [problems, setProblems] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setName("");
    setSlug("");
    setSlugTouched(false);
    setDescription("");
    setProblems({});
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const next: Record<string, string> = {};
    if (name.trim() === "") next.name = tr("ws.nameProblem");
    if (!SLUG.test(slug)) next.slug = tr("ws.slugProblem");
    setProblems(next);
    if (Object.keys(next).length > 0) return;
    setBusy(true);
    try {
      const created = await ipc.workspacePut(null, { slug, name: name.trim(), description: description.trim(), aliases: [] });
      invalidateItems(queryClient);
      toast.push({ tone: "success", title: tr("ws.done", { name: created.name }) });
      reset();
      onOpenChange(false);
      onCreated?.(created);
    } catch (error) {
      if (isIpcFailure(error) && error.error.fields.length > 0) {
        setProblems(Object.fromEntries(error.error.fields.map((f) => [f.field, f.problem])));
      } else {
        toast.push({ tone: "error", title: tr("ws.fail"), detail: isIpcFailure(error) ? errorText(error.error) : undefined });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset();
        onOpenChange(next);
      }}
      title={tr("ws.title")}
      description={tr("ws.body")}
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>{t("dialog.cancel")}</Button>
          <Button variant="primary" type="submit" form="vb-ws-form" loading={busy}>
            {tr("ws.save")}
          </Button>
        </>
      }
    >
      <form id="vb-ws-form" className="stack" noValidate onSubmit={(e) => void submit(e)}>
        <Field label={tr("ws.name")} problem={problems.name}>
          {(p) => (
            <Input
              {...p}
              value={name}
              autoComplete="off"
              onChange={(e) => {
                setName(e.target.value);
                if (!slugTouched) setSlug(slugOf(e.target.value));
              }}
            />
          )}
        </Field>
        <Field label={tr("ws.slug")} hint={tr("ws.slugHint")} problem={problems.slug}>
          {(p) => (
            <Input
              {...p}
              mono
              value={slug}
              autoComplete="off"
              onChange={(e) => {
                setSlugTouched(true);
                setSlug(e.target.value);
              }}
            />
          )}
        </Field>
        <Field label={tr("ws.description")}>{(p) => <Input {...p} value={description} onChange={(e) => setDescription(e.target.value)} />}</Field>
      </form>
    </Dialog>
  );
}
