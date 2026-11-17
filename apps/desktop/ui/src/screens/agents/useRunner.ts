import { useQueryClient, type QueryKey } from "@tanstack/react-query";
import { useCallback } from "react";
import { isIpcFailure } from "../../ipc/client";
import { errorText, useToast } from "../../ui";

interface RunOptions {
  /** Toast text after success. */
  done?: string;
  /** Toast title after failure. */
  failed: string;
  /** Query key prefixes to refresh after success. */
  refresh: readonly QueryKey[];
}

/**
 * Runs one IPC action with a toast for the result. It returns `true` on success.
 * It does not keep the result: token replies must never sit in the query cache.
 */
export function useRunner() {
  const toast = useToast();
  const queryClient = useQueryClient();
  return useCallback(
    async (task: () => Promise<unknown>, { done, failed, refresh }: RunOptions): Promise<boolean> => {
      try {
        await task();
      } catch (error) {
        toast.push({ tone: "error", title: failed, detail: isIpcFailure(error) ? errorText(error.error) : undefined });
        return false;
      }
      await Promise.all(refresh.map((queryKey) => queryClient.invalidateQueries({ queryKey })));
      if (done) toast.push({ tone: "success", title: done });
      return true;
    },
    [queryClient, toast],
  );
}
