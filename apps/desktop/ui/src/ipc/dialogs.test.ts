import { beforeEach, describe, expect, it, vi } from "vitest";

const plugin = vi.hoisted(() => ({ open: vi.fn(), save: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => plugin);
const backend = vi.hoisted(() => ({ filePickOpen: vi.fn() }));
vi.mock("./client", () => ({ ipc: backend }));

import { openFile, pickDirectory, pickSavePath } from "./dialogs";

beforeEach(() => {
  plugin.open.mockReset();
  plugin.save.mockReset();
  backend.filePickOpen.mockReset();
});

describe("save dialog", () => {
  it("passes the default path and returns the choice", async () => {
    plugin.save.mockResolvedValue("/tmp/a.jsonl");
    expect(await pickSavePath("a.jsonl")).toBe("/tmp/a.jsonl");
    expect(plugin.save).toHaveBeenCalledWith({ defaultPath: "a.jsonl" });
  });
});

describe("open dialog (AUD-11)", () => {
  it("is opened by the backend, so the backend knows the path the person chose", async () => {
    backend.filePickOpen.mockResolvedValue("/tmp/a.cerb");
    const filters = [{ name: "Backup", extensions: ["cerb"] }];
    expect(await openFile({ title: "Pick a backup", filters })).toBe("/tmp/a.cerb");
    expect(backend.filePickOpen).toHaveBeenCalledWith("Pick a backup", ["cerb"]);
  });

  it("works with no options and gives null on cancel", async () => {
    backend.filePickOpen.mockResolvedValue(null);
    expect(await openFile()).toBeNull();
    expect(backend.filePickOpen).toHaveBeenCalledWith(null, []);
  });
});

describe("folder dialog (for writing only)", () => {
  it("asks for a folder and gives null on cancel", async () => {
    plugin.open.mockResolvedValue("/tmp/out");
    expect(await pickDirectory({ title: "Pick a folder" })).toBe("/tmp/out");
    expect(plugin.open).toHaveBeenCalledWith({ multiple: false, directory: true, title: "Pick a folder" });
    plugin.open.mockResolvedValue(null);
    expect(await pickDirectory()).toBeNull();
  });

  it("the file dialog never goes through the plugin", async () => {
    backend.filePickOpen.mockResolvedValue("/tmp/a");
    await openFile();
    expect(plugin.open).not.toHaveBeenCalled();
  });
});
