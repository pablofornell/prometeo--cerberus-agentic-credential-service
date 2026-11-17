// Helpers for the tests of the four T19 screens: fresh fake backend state and a record of the calls made.
// The vault mock is part of it, because leases, grants and approvals read items and workspaces.
import type { MockHandlers } from "../../ipc/mock/core";
import { approvalHandlers } from "../approval/mock";
import { leaseHandlers } from "../leases/mock";
import { policyHandlers } from "../policies/mock";
import { createVaultMock } from "../vault/mockData";
import { agentHandlers } from "./mock";

export interface Recorded {
  handlers: MockHandlers;
  /** Arguments of every call, by command name. */
  calls: Record<string, unknown[]>;
}

/** All handlers of the four screens and of the vault, each with fresh state, and a log of the calls. */
export function recordedHandlers(overrides: MockHandlers = {}, role: () => string = () => "owner"): Recorded {
  const merged: MockHandlers = { ...createVaultMock().handlers, ...agentHandlers(), ...policyHandlers(role), ...approvalHandlers(), ...leaseHandlers(), ...overrides };
  const calls: Record<string, unknown[]> = {};
  const handlers: MockHandlers = {};
  for (const [name, handler] of Object.entries(merged)) {
    handlers[name] = (args, ctl) => {
      (calls[name] ??= []).push(args);
      return handler(args, ctl);
    };
  }
  return { handlers, calls };
}
