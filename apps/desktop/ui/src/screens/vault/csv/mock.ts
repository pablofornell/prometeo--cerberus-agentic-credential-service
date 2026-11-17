// Dev mock of the CSV commands. The file name picks the answer, so the states are easy to reach in a browser:
// a path with "unknown" has a header that no format matches, "bad" makes the preview show problems,
// "empty" has nothing to import, "fail" makes the import fail. Fake values only.
import type { ImportPreviewView_Serialize } from "../../../bindings";
import { mockError, type MockHandlers } from "../../../ipc/mock/core";

const COLUMNS = ["folder", "type", "name", "notes", "login_uri", "login_username", "login_password", "login_totp"];

function preview(path: string): ImportPreviewView_Serialize {
  const unknown = path.includes("unknown");
  const bad = path.includes("bad");
  const empty = path.includes("empty");
  return {
    source: unknown ? null : "bitwarden",
    detected: unknown ? null : "bitwarden",
    columns: unknown ? ["Label", "User name", "Pass", "Type"] : COLUMNS,
    total_rows: empty ? 2 : 14,
    importable: empty ? 0 : bad ? 10 : 12,
    by_kind: empty ? [] : [
      { kind: "web_login", count: bad ? 8 : 10 },
      { kind: "note", count: 2 },
    ],
    problems: bad || empty ? [
      { row: 3, code: "unsupported_kind", field: null },
      { row: 9, code: "invalid_value", field: "payload.username" },
    ] : [],
    problem_count: bad || empty ? 2 : 0,
    duplicates: bad ? [{ row: 5, title: "Staging admin", in_file: false, renamed: false }] : [],
    duplicate_count: bad ? 1 : 0,
    renamed: 0,
    notes_dropped: bad ? 3 : 0,
  };
}

const pathOf = (args: Record<string, unknown> | undefined): string => String((args?.request as { path?: string } | undefined)?.path ?? "");

export const handlers: MockHandlers = {
  csv_preview: (args) => {
    const path = pathOf(args);
    if (path.includes("utf8")) throw mockError("validation_failed", "validation failed", { fields: [{ field: "file", problem: "the file is not UTF-8 text; save it as CSV UTF-8 and try again" }] });
    return preview(path);
  },
  csv_import: (args) => {
    const path = pathOf(args);
    if (path.includes("fail")) throw mockError("internal", "internal error");
    const p = preview(path);
    return { imported: p.importable, skipped_problems: p.problem_count, skipped_duplicates: p.duplicate_count, renamed: p.renamed, notes_dropped: p.notes_dropped };
  },
  csv_export: () => 14,
};
