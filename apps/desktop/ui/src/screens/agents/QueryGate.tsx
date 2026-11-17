import type { UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { t } from "../../i18n";
import { isLockError } from "../../ipc/client";
import { LockedState } from "../../shell/LockedState";
import { ErrorState, Skeleton } from "../../ui";

interface QueryGateProps<T> {
  query: UseQueryResult<T>;
  /** What failed, as a verb phrase: "load leases". */
  action: string;
  loadingLabel: string;
  rows?: number;
  /** Shown instead of the default error state, for example to add a panic button (leases). */
  errorExtra?: ReactNode;
  children: (data: T) => ReactNode;
}

/** The three states every screen shares: loading, locked (the vault closed under us) and error. */
export function QueryGate<T>({ query, action, loadingLabel, rows = 4, errorExtra, children }: QueryGateProps<T>) {
  if (query.isPending) return <Skeleton label={loadingLabel} rows={rows} />;
  if (query.isError) {
    if (isLockError(query.error)) return <LockedState reason={t("error.code.vault_locked")} />;
    return (
      <>
        <ErrorState action={action} error={query.error} onRetry={() => void query.refetch()} retrying={query.isFetching} />
        {errorExtra}
      </>
    );
  }
  return <>{children(query.data)}</>;
}
