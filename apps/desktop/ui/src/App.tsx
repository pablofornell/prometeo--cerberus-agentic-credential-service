import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { useMemo } from "react";
import { Router, type BaseLocationHook } from "wouter";
import { EventBridge } from "./ipc/events";
import { createQueryClient } from "./ipc/queryClient";
import { SetupServerDialog } from "./remote/SetupServerDialog";
import { Routes } from "./shell/Routes";
import { useHashLocation } from "./shell/location";
import { PrefsProvider } from "./state/prefs";
import { ContextMenuProvider, ToastProvider } from "./ui";

interface AppProps {
  /** Tests pass their own client and location hook. */
  queryClient?: QueryClient;
  hook?: BaseLocationHook;
}

/** Providers, event bridge and the guarded routes. One per window. */
export function App({ queryClient, hook = useHashLocation }: AppProps) {
  const client = useMemo(() => queryClient ?? createQueryClient(), [queryClient]);
  return (
    <PrefsProvider>
      <QueryClientProvider client={client}>
        <ToastProvider>
          <ContextMenuProvider>
            <Router hook={hook}>
              <EventBridge />
              <Routes />
              <SetupServerDialog />
            </Router>
          </ContextMenuProvider>
        </ToastProvider>
      </QueryClientProvider>
    </PrefsProvider>
  );
}
