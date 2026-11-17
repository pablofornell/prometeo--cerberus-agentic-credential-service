// Hands the ID of the item the editor just saved to the vault screen, so the details open on it.
// A query string cannot carry it: the hash router reads `/vault?item=x` as a path.
let pending: string | null = null;

export function handoffSelection(id: string): void {
  pending = id;
}

/** The handed-over ID. Read it in a state initializer, then call `clearSelection` in an effect (strict mode runs initializers twice). */
export const peekSelection = (): string | null => pending;

export function clearSelection(): void {
  pending = null;
}
