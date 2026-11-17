import { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { memoryLocation } from "wouter/memory-location";
import { App } from "../App";
import type { LockReasonView, OperatorRole, VaultState } from "../bindings";
import { installMock, type MockController, type MockHandlers } from "../ipc/mock/core";

interface Options {
  state?: VaultState;
  role?: OperatorRole;
  lockReason?: LockReasonView;
  stranded?: string[];
  path?: string;
  handlers?: MockHandlers;
}

/** Renders the whole app on the mock backend with a memory location. */
export function renderApp({ state = "unlocked", role = "owner", lockReason, stranded, path = "/", handlers }: Options = {}) {
  const mock: MockController = installMock({ state, role, lockReason, stranded, handlers });
  const location = memoryLocation({ path, record: true });
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  const view = render(<App queryClient={queryClient} hook={location.hook} />);
  return { ...view, mock, location, queryClient };
}
