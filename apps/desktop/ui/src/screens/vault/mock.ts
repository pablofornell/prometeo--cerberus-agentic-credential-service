// Dev mock of the vault commands. Loaded by `ipc/mock/dev.ts`. `?items=empty|error|slow` picks a state for screenshots.
import type { MockHandlers } from "../../ipc/mock/core";
import { scenario } from "../../ipc/mock/fixtures";
import { handlers as csvHandlers } from "./csv/mock";
import { createVaultMock, type VaultMockOptions } from "./mockData";

const MODES: readonly NonNullable<VaultMockOptions["mode"]>[] = ["normal", "empty", "error", "slow"];
const param = new URLSearchParams(window.location.search).get("items") ?? scenario();

export const handlers: MockHandlers = { ...createVaultMock({ mode: MODES.find((m) => m === param) ?? "normal" }).handlers, ...csvHandlers };
