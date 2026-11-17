import { createStore } from "../state/store";

/**
 * True while the create wizard runs, from `vault_create` until "Open the vault".
 * `vault_create` leaves the vault unlocked, but the recovery key is not saved yet, so the guard keeps the `create` screen.
 */
export const createFlowStore = createStore<boolean>(false);
