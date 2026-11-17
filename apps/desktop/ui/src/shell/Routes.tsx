import { useQueryClient } from "@tanstack/react-query";
import { useEffect, type ReactNode } from "react";
import { Redirect, Router, useLocation } from "wouter";
import { t } from "../i18n";
import { dropVaultData } from "../ipc/events";
import { useVaultStatus } from "../ipc/queries";
import { vaultStateStore } from "../state/live";
import { ErrorState, LoadingState } from "../ui";
import { createFlowStore } from "./createFlow";
import { resolveRoute } from "./guard";
import { LockedState } from "./LockedState";
import { ScreenView } from "./registry";
import { screenById, screenForPath } from "./screens";
import { Shell } from "./Shell";
import { windowLabel } from "./windowLabel";

/** Sets the browser tab and window title to the screen name. Never a secret (I-19). */
function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} - ${t("app.name")}`;
  }, [title]);
}

function Solo({ title, children }: { title: string; children: ReactNode }) {
  useDocumentTitle(title);
  return (
    <main className="solo">
      <div className="solo-wrap">{children}</div>
    </main>
  );
}

/** The approval window: the approval screen alone, no rail (IA section 1). It handles its own states. */
function ApprovalWindow() {
  useDocumentTitle(t("screen.approval"));
  return (
    <main className="solo approval-window">
      <div className="solo-wrap">
        <ScreenView id="approval" />
      </div>
    </main>
  );
}

/**
 * Reads `vault_status` first, then applies the guard (IA section 1):
 * no vault gives create, sealed gives unlock, locking gives the locked state, unlocked gives the app.
 */
export function Routes() {
  const [location] = useLocation();
  const status = useVaultStatus();
  const queryClient = useQueryClient();
  const state = status.data?.state;
  const label = windowLabel();
  const creating = createFlowStore.use();

  useEffect(() => {
    if (!state) return;
    vaultStateStore.set(state);
    if (state !== "unlocked") dropVaultData(queryClient);
  }, [state, queryClient]);

  if (label === "approval") return <ApprovalWindow />;

  if (status.isPending) return <LoadingState label={t("app.boot")} />;
  if (status.isError || !state) {
    return (
      <Solo title={t("app.name")}>
        <ErrorState as="h1" action={t("error.status.action")} error={status.error} onRetry={() => void status.refetch()} retrying={status.isFetching} />
      </Solo>
    );
  }

  const screen = screenForPath(location);
  const redirect = resolveRoute(state, screen, creating, (status.data?.stranded_restore.length ?? 0) > 0);
  if (redirect) return <Redirect to={redirect} replace />;

  if (state === "locking") {
    return (
      <Shell screen={screenById("dashboard")}>
        <LockedState />
      </Shell>
    );
  }
  if (!screen) return <Redirect to="/" replace />;

  if (screen.layout === "solo") {
    return (
      <Solo title={t(`screen.${screen.id}`)}>
        <Router base={screen.path}>
          <ScreenView id={screen.id} />
        </Router>
      </Solo>
    );
  }
  return (
    <ScreenTitle id={screen.id}>
      <Shell screen={screen}>
        <ScreenView id={screen.id} />
      </Shell>
    </ScreenTitle>
  );
}

function ScreenTitle({ id, children }: { id: Parameters<typeof screenById>[0]; children: ReactNode }) {
  useDocumentTitle(t(`screen.${id}`));
  return children;
}
