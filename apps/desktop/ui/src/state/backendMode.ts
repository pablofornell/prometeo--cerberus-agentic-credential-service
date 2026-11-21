// Remote mode (ADR-0034): the desktop is a client of one cerberusd. `vault_status.remote` says so (null in local mode),
// and `remote_status` lists the commands the server answers. Every other command answers `remote_unsupported`, so the UI
// greys or hides it with "Not available for a remote server" (DEC-RM-11).
import type { RemoteStatusView } from "../bindings";
import { useRemoteOverview, useVaultStatus } from "../ipc/queries";

/** The remote server of this run, or `null` in local mode. */
export function useRemote(): RemoteStatusView | null {
  return useVaultStatus().data?.remote ?? null;
}

/** `"remote"` while the desktop runs against a server, else `"local"` (also before the first status). */
export function useBackendMode(): "local" | "remote" {
  return useRemote() ? "remote" : "local";
}

/**
 * True in remote mode when `command` (snake case) is not on the remote allowlist. Until the list is read it is true
 * for every command, so a local-only action never flashes on. Always false in local mode.
 */
export function useRemoteUnsupported(command: string): boolean {
  const remote = useRemote();
  const overview = useRemoteOverview(remote !== null);
  if (!remote) return false;
  return !(overview.data?.remote_commands.includes(command) ?? false);
}
