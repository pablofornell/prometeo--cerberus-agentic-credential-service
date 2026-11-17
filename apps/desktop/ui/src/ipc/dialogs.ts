import { open, save } from "@tauri-apps/plugin-dialog";
import { ipc } from "./client";

/** One file type filter of an open dialog, for example `{ name: "Backup", extensions: ["cerb"] }`. */
export interface OpenFilter {
  name: string;
  extensions: string[];
}

/** Options of the open dialog. */
export interface OpenOptions {
  title?: string;
  filters?: OpenFilter[];
}

/** Opens the native save dialog. Returns the chosen path, or `null` when the person cancels. */
export async function pickSavePath(defaultPath: string): Promise<string | null> {
  return save({ defaultPath });
}

/**
 * Opens the native dialog for one file to read (the folder dialog below is only for writing). The dialog runs in the backend, which remembers the answer:
 * only a path that comes from here can be read by the import, restore and certificate commands (AUD-11).
 * Returns the chosen path, or `null` when the person cancels.
 */
export async function openFile({ title, filters }: OpenOptions = {}): Promise<string | null> {
  return ipc.filePickOpen(title ?? null, (filters ?? []).flatMap((filter) => filter.extensions));
}

/** Opens the native dialog for one folder to write into. Returns the chosen path, or `null` when the person cancels. */
export async function pickDirectory({ title }: Pick<OpenOptions, "title"> = {}): Promise<string | null> {
  const picked = await open({ multiple: false, directory: true, title });
  return typeof picked === "string" ? picked : null;
}
