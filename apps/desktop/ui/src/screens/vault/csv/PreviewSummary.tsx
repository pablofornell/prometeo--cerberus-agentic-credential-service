import type { ImportPreviewView_Serialize } from "../../../bindings";
import { useScreenT } from "../../../i18n";
import { Chip, Notice } from "../../../ui";
import { kindLabel } from "../kinds";
import { messages } from "./messages";

/** The dry run: counts, the rows left out and the titles in use. It holds no secret value. */
export function PreviewSummary({ preview }: { preview: ImportPreviewView_Serialize }) {
  const tr = useScreenT(messages);
  const problemText = (code: string, field: string | null | undefined): string => {
    const key = `imp.p.${code}` as keyof typeof messages;
    return tr(key in messages ? key : "imp.p.invalid_value", { field: field ?? "" });
  };
  return (
    <div className="csv-preview">
      <p>{tr("imp.prev.counts", { total: preview.total_rows, ok: preview.importable, problems: preview.problem_count, dups: preview.duplicate_count })}</p>
      <ul className="csv-stats" aria-label={tr("imp.title")}>
        <li>
          <b>{preview.importable}</b> {tr("imp.prev.ok")}
        </li>
        <li>
          <b>{preview.problem_count}</b> {tr("imp.prev.problems")}
        </li>
        <li>
          <b>{preview.duplicate_count}</b> {tr("imp.prev.dups")}
        </li>
      </ul>
      {preview.by_kind.length > 0 && (
        <div className="csv-kinds" role="group" aria-label={tr("imp.prev.kinds")}>
          {preview.by_kind.map((k) => (
            <Chip key={k.kind}>
              {kindLabel(k.kind)} {k.count}
            </Chip>
          ))}
        </div>
      )}
      {preview.importable === 0 && <Notice tone="warn" title={tr("imp.prev.none")} />}
      {preview.renamed > 0 && <Notice tone="info" title={tr("imp.prev.renamed", { count: preview.renamed })} />}
      {preview.notes_dropped > 0 && <Notice tone="info" title={tr("imp.prev.notes", { count: preview.notes_dropped })} />}
      {preview.problems.length > 0 && (
        <section aria-labelledby="csv-prob-h">
          <h3 id="csv-prob-h">{tr("imp.prev.problemsList")}</h3>
          <ul className="csv-list">
            {preview.problems.map((p) => (
              <li key={p.row}>
                <span className="mono">{tr("imp.prev.row", { row: p.row })}</span> {problemText(p.code, p.field)}
              </li>
            ))}
          </ul>
          {preview.problem_count > preview.problems.length && <p className="hint">{tr("imp.prev.more", { shown: preview.problems.length, count: preview.problem_count })}</p>}
        </section>
      )}
      {preview.duplicates.length > 0 && (
        <section aria-labelledby="csv-dup-h">
          <h3 id="csv-dup-h">{tr("imp.prev.dupsList")}</h3>
          <ul className="csv-list">
            {preview.duplicates.map((d) => (
              <li key={d.row}>
                <span className="mono">{tr("imp.prev.row", { row: d.row })}</span> <span className="csv-title">{d.title}</span>{" "}
                {d.in_file ? tr("imp.prev.dup.file") : tr("imp.prev.dup.vault")} {d.renamed ? tr("imp.prev.dup.renamed") : tr("imp.prev.dup.skipped")}
              </li>
            ))}
          </ul>
          {preview.duplicate_count > preview.duplicates.length && <p className="hint">{tr("imp.prev.more", { shown: preview.duplicates.length, count: preview.duplicate_count })}</p>}
        </section>
      )}
      <p className="hint">{tr("imp.prev.allOrNothing")}</p>
    </div>
  );
}
