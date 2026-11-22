import type { RemoteProfileView } from "../bindings";
import type { UiError } from "../ipc/client";
import { createStore } from "../state/store";

/** What the server gave back after it made the vault. The recovery key is shown once; the profile may not be stored yet. */
export interface SetupMade {
  key: string;
  /** The stored profile of the new server, or `null` while this computer could not keep it. */
  profile: RemoteProfileView | null;
  /** Why the profile is not stored. */
  storeError: UiError | null;
}

export interface SetupFlow {
  /** The dialog is open. */
  open: boolean;
  /** The local vault is unlocked where the flow started (Settings): the switch locks it first. */
  lockFirst: boolean;
  /** The long call to the server runs. */
  creating: boolean;
  /** The server made the vault: the recovery step shows until the person is done with it. */
  made: SetupMade | null;
}

export const SETUP_FLOW_IDLE: SetupFlow = { open: false, lockFirst: false, creating: false, made: null };

/**
 * State of "Set up a new server" that must outlive the screen that started it. The call to the server takes up to two
 * minutes, and the key it answers is shown once, so neither can depend on a screen that may close in between (an idle
 * lock sends the person to the unlock screen). One dialog, mounted by `App`, reads this store.
 */
export const setupFlowStore = createStore<SetupFlow>(SETUP_FLOW_IDLE);

/** Opens the dialog. `lockFirst` is true where the local vault is unlocked (Settings). */
export const openSetupDialog = (lockFirst: boolean): void => setupFlowStore.set((flow) => ({ ...flow, open: true, lockFirst }));
