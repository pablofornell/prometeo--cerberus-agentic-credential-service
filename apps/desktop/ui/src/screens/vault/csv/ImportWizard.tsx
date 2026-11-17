import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { CsvImportRequest_Deserialize, CsvSource, DuplicatePolicy, Environment, ImportPreviewView_Serialize, ImportReport } from "../../../bindings";
import { useScreenT } from "../../../i18n";
import { ipc, isIpcFailure, type UiError } from "../../../ipc/client";
import { openFile } from "../../../ipc/dialogs";
import { Button, Dialog, errorText, Field, Input, Notice, SegmentedControl, Select } from "../../../ui";
import { ENVIRONMENTS } from "../kinds";
import { invalidateItems, useWorkspaces } from "../queries";
import { guessMapping } from "./fields";
import { MappingTable } from "./MappingTable";
import { messages } from "./messages";
import { PreviewSummary } from "./PreviewSummary";
import "./csv.css";

type Step = "file" | "format" | "target" | "preview" | "result";
const STEPS: readonly Step[] = ["file", "format", "target", "preview", "result"];

const SOURCES: readonly Exclude<CsvSource, "auto">[] = ["bitwarden", "onepassword", "keepassxc", "chrome", "firefox", "generic"];

/** Shows the reason of a failed call: the text for its code and every field problem the backend named. */
function FailureNotice({ title, error, onDismiss, dismissLabel, extra }: { title: string; error: UiError; onDismiss: () => void; dismissLabel: string; extra?: string }) {
  return (
    <Notice tone="bad" title={title} onDismiss={onDismiss} dismissLabel={dismissLabel}>
      {errorText(error)}
      {error.fields.map((f) => (
        <span key={f.field + f.problem} className="csv-problem-line">
          {f.field} {f.problem}
        </span>
      ))}
      {extra && <span className="csv-problem-line">{extra}</span>}
    </Notice>
  );
}

/**
 * The CSV import wizard: file, format and mapping, target, preview, result. The file is read by the backend
 * (the path is sent, the content is not). The preview is a dry run that holds no secret value; the import is
 * one transaction, so a failure adds nothing.
 */
export function ImportWizard({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const tr = useScreenT(messages);
  const queryClient = useQueryClient();
  const workspaces = useWorkspaces();
  const wsList = workspaces.data ?? [];

  const [step, setStep] = useState<Step>("file");
  const [path, setPath] = useState("");
  const [source, setSource] = useState<CsvSource>("auto");
  const [mapping, setMapping] = useState<Record<string, string>>({});
  const [workspaceId, setWorkspaceId] = useState("");
  const [environment, setEnvironment] = useState<Environment>("dev");
  const [role, setRole] = useState("");
  const [duplicates, setDuplicates] = useState<DuplicatePolicy>("skip");
  const [inspect, setInspect] = useState<ImportPreviewView_Serialize | null>(null);
  const [preview, setPreview] = useState<ImportPreviewView_Serialize | null>(null);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<UiError | null>(null);
  const [touched, setTouched] = useState(false);

  const chosenWorkspace = workspaceId || wsList[0]?.id || "";
  const unknownHeader = inspect !== null && inspect.source === null;
  const needsMapping = source === "generic" || (source === "auto" && unknownHeader);
  const titleMissing = needsMapping && !mapping["title"] && !inspect?.detected;

  const reset = () => {
    setStep("file");
    setPath("");
    setSource("auto");
    setMapping({});
    setWorkspaceId("");
    setEnvironment("dev");
    setRole("");
    setDuplicates("skip");
    setInspect(null);
    setPreview(null);
    setReport(null);
    setBusy(false);
    setError(null);
    setTouched(false);
  };
  const close = (next: boolean) => {
    if (busy) return;
    if (!next) reset();
    onOpenChange(next);
  };

  const request = (): CsvImportRequest_Deserialize => ({
    path: path.trim(),
    workspace_id: chosenWorkspace,
    source,
    environment,
    role_label: role.trim() || null,
    // Mapping applies to the generic format; other formats have a preset.
    mapping: { columns: source === "generic" || (source === "auto" && unknownHeader) ? { ...mapping } : {} },
    duplicates,
  });

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (failure) {
      setError(isIpcFailure(failure) ? failure.error : null);
    } finally {
      setBusy(false);
    }
  };

  const choose = async () => {
    try {
      const picked = await openFile({ title: tr("imp.title"), filters: [{ name: tr("imp.file.filter"), extensions: ["csv", "txt"] }] });
      if (picked) setPath(picked);
    } catch {
      // The dialog is not available (a plain browser). The person can type the path.
    }
  };

  const readFile = () => {
    setTouched(true);
    if (path.trim() === "") return;
    void run(async () => {
      // A dry run only to read the header and the row count.
      const first = await ipc.csvPreview({ ...request(), source: "auto", mapping: { columns: {} } });
      setInspect(first);
      setSource(first.source === null ? "generic" : "auto");
      setMapping(first.source === null ? guessMapping(first.columns) : {});
      setStep("format");
    });
  };

  const showPreview = () =>
    void run(async () => {
      setPreview(await ipc.csvPreview(request()));
      setStep("preview");
    });

  const importNow = () =>
    void run(async () => {
      const done = await ipc.csvImport(request());
      setReport(done);
      invalidateItems(queryClient);
      setStep("result");
    });

  const index = STEPS.indexOf(step);
  const stepName = tr(`imp.s.${step}`);
  const back = (to: Step) => (
    <Button variant="ghost" onClick={() => { setError(null); setStep(to); }} disabled={busy}>
      {tr("imp.back")}
    </Button>
  );

  let body: React.ReactNode = null;
  let footer: React.ReactNode = null;

  if (step === "file") {
    const problem = touched && path.trim() === "" ? tr("imp.file.empty") : undefined;
    body = (
      <Field label={tr("imp.file.label")} hint={tr("imp.file.hint")} problem={problem}>
        {(p) => (
          <div className="csv-row">
            <Input {...p} mono value={path} onChange={(e) => setPath(e.target.value)} autoComplete="off" spellCheck={false} />
            <Button icon="upload" onClick={() => void choose()}>
              {tr("imp.file.choose")}
            </Button>
          </div>
        )}
      </Field>
    );
    footer = (
      <>
        <Button variant="ghost" onClick={() => close(false)}>
          {tr("imp.cancel")}
        </Button>
        <Button variant="primary" loading={busy} onClick={readFile}>
          {tr("imp.file.read")}
        </Button>
      </>
    );
  } else if (step === "format" && inspect) {
    body = (
      <>
        <p className="secondary">
          {inspect.detected ? tr("imp.format.detected", { source: tr(`imp.src.${inspect.detected}`) }) : tr("imp.format.unknown")} {tr("imp.format.rows", { count: inspect.total_rows })}
        </p>
        <Field label={tr("imp.format.label")}>
          {(p) => (
            <Select
              {...p}
              value={source}
              onChange={(e) => setSource(e.target.value as CsvSource)}
              options={[
                ...(inspect.detected ? [{ value: "auto", label: tr("imp.format.auto") }] : []),
                ...SOURCES.map((s) => ({ value: s, label: tr(`imp.src.${s}`) })),
              ]}
            />
          )}
        </Field>
        {needsMapping && <MappingTable columns={inspect.columns} mapping={mapping} onChange={setMapping} showRequired={touched && titleMissing} />}
      </>
    );
    footer = (
      <>
        {back("file")}
        <Button
          variant="primary"
          onClick={() => {
            setTouched(true);
            if (!titleMissing) setStep("target");
          }}
        >
          {tr("imp.next")}
        </Button>
      </>
    );
  } else if (step === "target") {
    body = (
      <>
        <Field label={tr("imp.target.workspace")}>
          {(p) => <Select {...p} value={chosenWorkspace} onChange={(e) => setWorkspaceId(e.target.value)} options={wsList.map((w) => ({ value: w.id, label: w.name }))} />}
        </Field>
        <Field label={tr("imp.target.env")}>
          {(p) => <Select {...p} value={environment} onChange={(e) => setEnvironment(e.target.value as Environment)} options={ENVIRONMENTS.map((e) => ({ value: e, label: e }))} />}
        </Field>
        <Field label={tr("imp.target.role")} hint={tr("imp.target.role.hint")}>
          {(p) => <Input {...p} value={role} maxLength={64} onChange={(e) => setRole(e.target.value)} />}
        </Field>
        <div className="field">
          <SegmentedControl
            label={tr("imp.target.dup")}
            value={duplicates}
            onChange={setDuplicates}
            options={[
              { value: "skip", label: tr("imp.dup.skip") },
              { value: "rename", label: tr("imp.dup.rename") },
            ]}
          />
          <span className="hint">{tr("imp.target.dup.hint")}</span>
        </div>
      </>
    );
    footer = (
      <>
        {back("format")}
        <Button variant="primary" loading={busy} disabled={chosenWorkspace === ""} onClick={showPreview}>
          {tr("imp.next")}
        </Button>
      </>
    );
  } else if (step === "preview" && preview) {
    body = <PreviewSummary preview={preview} />;
    footer = (
      <>
        {back("target")}
        <Button variant="primary" icon="upload" loading={busy} disabled={preview.importable === 0} onClick={importNow}>
          {tr("imp.run", { count: preview.importable })}
        </Button>
      </>
    );
  } else if (step === "result" && report) {
    body = (
      <>
        <Notice tone="ok" title={tr("imp.done.title")}>
          {tr("imp.done.body", { imported: report.imported, problems: report.skipped_problems, dups: report.skipped_duplicates, renamed: report.renamed })}
        </Notice>
        {report.notes_dropped > 0 && <Notice tone="info" title={tr("imp.done.notes", { count: report.notes_dropped })} />}
      </>
    );
    footer = (
      <Button variant="primary" onClick={() => close(false)}>
        {tr("imp.close")}
      </Button>
    );
  }

  return (
    <Dialog open={open} onOpenChange={close} wide title={tr("imp.title")} description={tr("imp.privacy")} footer={footer}>
      <p className="csv-step" aria-live="polite">
        {tr("imp.step", { n: index + 1, total: STEPS.length, name: stepName })}
      </p>
      {error && (
        <FailureNotice
          title={step === "file" ? tr("imp.file.fail") : tr("imp.fail")}
          error={error}
          onDismiss={() => setError(null)}
          dismissLabel={tr("imp.close")}
          extra={step === "preview" ? tr("imp.fail.none") : undefined}
        />
      )}
      {body}
    </Dialog>
  );
}
