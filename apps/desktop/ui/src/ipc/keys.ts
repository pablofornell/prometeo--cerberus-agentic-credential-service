// Query keys. A screen adds its own keys under its own prefix, for example ["vault", "items", filter].
// Events invalidate by these prefixes (see `events.tsx`).
export const qk = {
  vault: {
    status: () => ["vault", "status"] as const,
    operators: () => ["vault", "operators"] as const,
    /** `remote_status`: the backend mode and the stored remote profiles. Kept at a lock (no vault data). */
    remote: () => ["vault", "remote"] as const,
  },
  requests: {
    all: () => ["requests"] as const,
    pending: () => ["requests", "pending"] as const,
  },
  leases: {
    all: () => ["leases"] as const,
  },
  settings: () => ["settings"] as const,
  agents: () => ["agents"] as const,
  items: {
    all: () => ["items"] as const,
    search: (q: string) => ["items", "search", q] as const,
  },
};
