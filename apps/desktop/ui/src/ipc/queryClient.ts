import { MutationCache, QueryCache, QueryClient } from "@tanstack/react-query";
import { isFinalError, isLockError } from "./client";
import { qk } from "./keys";

/**
 * One query client per window. When any call says the vault is locked, the vault status is read again so
 * the route guard moves to the unlock screen. Failed calls to the same command are not repeated if the
 * error is final (a second try would give the same answer).
 */
export function createQueryClient(): QueryClient {
  const onLockError = (error: unknown) => {
    if (isLockError(error)) {
      void client.invalidateQueries({ queryKey: qk.vault.status() });
    }
  };
  const client: QueryClient = new QueryClient({
    queryCache: new QueryCache({ onError: onLockError }),
    mutationCache: new MutationCache({ onError: onLockError }),
    defaultOptions: {
      queries: {
        staleTime: 5_000,
        retry: (count, error) => !isFinalError(error) && count < 2,
        refetchOnWindowFocus: true,
      },
    },
  });
  return client;
}
