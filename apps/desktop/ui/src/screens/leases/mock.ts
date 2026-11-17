// Dev mock of the lease commands.
// Switches: `?mock_leases=empty|error|slow`.
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { devFlag, fixtureLeases, sleep } from "../../ipc/mock/fixtures";

/** A fresh set of handlers with its own state. Tests call this for each test. */
export function leaseHandlers(): MockHandlers {
  let leases = fixtureLeases();
  return {
    lease_list: async () => {
      const flag = devFlag("mock_leases");
      if (flag === "slow") await sleep(60_000);
      if (flag === "error") throw mockError("internal", "the lease list did not load");
      return flag === "empty" ? [] : leases;
    },
    lease_revoke: (args) => {
      leases = leases.filter((l) => l.view.id !== (args as { lease: string }).lease);
      return null;
    },
    lease_revoke_all: () => {
      const count = leases.length;
      leases = [];
      return count;
    },
  };
}

export const handlers: MockHandlers = leaseHandlers();
