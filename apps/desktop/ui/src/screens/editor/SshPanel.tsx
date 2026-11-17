import { useCallback, useRef, useState, type DragEvent } from "react";
import { useScreenT } from "../../i18n";
import { ipc, isIpcFailure } from "../../ipc/client";
import { openFile } from "../../ipc/dialogs";
import type { SshKeySource } from "../../bindings";
import { Button, cx, errorText, Field, Icon, IconButton, Input, useToast } from "../../ui";
import { inDesktopShell, MAX_KEY_FILE_BYTES, useNativeFileDrop } from "./keyfiles";
import { messages } from "./messages";
import { SecretInput } from "./fields";
import type { FormState } from "./model";

/** `Blob.text()` with a `FileReader` path, so it also works in older webviews and in tests. */
const readText = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });

interface Props {
  state: FormState;
  patch: (patch: Partial<FormState>) => void;
  problems: Record<string, string>;
}

/** SSH key kind: import by drop or file dialog, or generate ed25519. The private key stays in the backend draft. */
export function SshPanel({ state, patch, problems }: Props) {
  const tr = useScreenT(messages);
  const toast = useToast();
  const [over, setOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [importProblem, setImportProblem] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const run = useCallback(
    async (make: () => ReturnType<typeof ipc.sshKeyImport>, done: string) => {
      setBusy(true);
      setImportProblem(null);
      try {
        const draft = await make();
        patch({ sshDraft: draft });
        setPassphrase("");
        toast.push({ tone: "success", title: done });
      } catch (error) {
        const ui = isIpcFailure(error) ? error.error : null;
        setImportProblem(ui?.fields[0]?.problem ?? (ui ? errorText(ui) : tr("ssh.fail")));
      } finally {
        setBusy(false);
      }
    },
    [patch, toast, tr],
  );

  const importSource = useCallback(
    (source: SshKeySource) => run(() => ipc.sshKeyImport(source, passphrase === "" ? null : passphrase), tr("ssh.imported")),
    [run, passphrase, tr],
  );

  const importPath = useCallback((path: string) => void importSource({ kind: "path", path }), [importSource]);

  /** A browser file: read its text, send it once, drop it. Used when there is no desktop shell. */
  const importFile = async (file: File) => {
    if (file.size > MAX_KEY_FILE_BYTES) {
      setImportProblem(tr("ssh.tooBig"));
      return;
    }
    await importSource({ kind: "pem", pem: await readText(file) });
  };

  useNativeFileDrop({ onOver: setOver, onPath: importPath }, state.kind === "ssh_key");

  const choose = async () => {
    if (!inDesktopShell()) {
      fileInput.current?.click();
      return;
    }
    try {
      const path = await openFile({ title: tr("ssh.choose") });
      if (path) importPath(path);
    } catch {
      setImportProblem(tr("ssh.fail"));
    }
  };

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setOver(false);
    const file = event.dataTransfer.files[0];
    if (file) void importFile(file);
  };

  const draft = state.sshDraft;
  const keyProblem = problems["payload.private_key"] ?? problems["payload.public_key"] ?? problems["payload.fingerprint"] ?? importProblem ?? undefined;
  const copyPublic = async () => {
    if (!draft) return;
    try {
      await navigator.clipboard.writeText(draft.public_key);
      toast.push({ tone: "success", title: tr("ssh.copiedPublic") });
    } catch {
      toast.push({ tone: "error", title: tr("ssh.fail") });
    }
  };

  return (
    <fieldset className="ed-group">
      <legend>{tr("ssh.legend")}</legend>
      <Field label={tr("ssh.passphrase")}>
        {(p) => <SecretInput label={tr("ssh.passphrase")} control={p} value={passphrase} onChange={setPassphrase} />}
      </Field>
      <div
        className={cx("ed-drop", over && "over")}
        role="group"
        aria-label={tr("ssh.dropLabel")}
        onDragEnter={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={onDrop}
      >
        <Icon name="upload" size={24} />
        <span>{tr("ssh.drop")}</span>
        <span className="small muted">{tr("ssh.or")}</span>
        <div className="row-inline">
          <Button size="sm" onClick={() => void choose()} disabled={busy}>
            {tr("ssh.choose")}
          </Button>
          <Button size="sm" variant="primary" loading={busy} onClick={() => void run(() => ipc.sshKeyGenerate(state.title.trim() || tr("ssh.comment")), tr("ssh.generated"))}>
            {tr("ssh.generate")}
          </Button>
        </div>
        <input
          ref={fileInput}
          type="file"
          className="sr-only"
          tabIndex={-1}
          aria-hidden="true"
          data-testid="ssh-file-input"
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (file) void importFile(file);
          }}
        />
      </div>
      <div aria-live="polite">
        {keyProblem && (
          <p className="problem" id="ed-ssh-problem">
            <Icon name="alert" />
            {keyProblem}
          </p>
        )}
      </div>
      {draft && (
        <div className="stack">
          <div className="field">
            <span className="label">{tr("ssh.public")}</span>
            <span className="ed-pubkey">
              {draft.public_key}
              <IconButton icon="copy" size="sm" label={tr("ssh.copyPublic")} onClick={() => void copyPublic()} />
            </span>
          </div>
          <div className="field">
            <span className="label">{tr("ssh.fingerprint")}</span>
            <span className="ed-pubkey">{draft.fingerprint}</span>
          </div>
          <p className="small muted">{tr("ssh.privateStays")}</p>
        </div>
      )}
      {!draft && state.keepSecret && <p className="small muted">{tr("ssh.kept")}</p>}
      <div className="form-grid">
        <Field label={tr("ssh.machine")} problem={problems["custom.machine"]}>
          {(p) => <Input {...p} mono value={state.sshMachine} onChange={(e) => patch({ sshMachine: e.target.value })} />}
        </Field>
        <Field label={tr("ssh.host")} problem={problems["custom.host"]}>
          {(p) => <Input {...p} mono value={state.sshHost} onChange={(e) => patch({ sshHost: e.target.value })} />}
        </Field>
        <Field label={tr("ssh.port")} problem={problems["custom.port"]}>
          {(p) => <Input {...p} mono inputMode="numeric" value={state.sshPort} onChange={(e) => patch({ sshPort: e.target.value })} />}
        </Field>
        <Field label={tr("ssh.user")} problem={problems["custom.user"]}>
          {(p) => <Input {...p} mono value={state.sshUser} onChange={(e) => patch({ sshUser: e.target.value })} />}
        </Field>
      </div>
    </fieldset>
  );
}
