import type { AccessRequestView_Serialize, ApprovalOption, LeaseView_Serialize } from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { devFlag, fixtureRequest, fixtureRequests, INJECTION_REASON, secondsFromNow, sleep } from "../../ipc/mock/fixtures";

function seed(): AccessRequestView_Serialize[] {
  const flag = devFlag("mock_approval");
  if (flag === "empty") return [];
  if (flag === "burst") {
    return [
      fixtureRequest("req_1", "agent-qa", "it-admin", "read", INJECTION_REASON, 94, true),
      fixtureRequest("req_2", "agent-qa", "it-billing", "read", "Check the invoice export.", 95, true),
      fixtureRequest("req_3", "agent-qa", "it-db", "read", "Count rows.", 96, true),
      fixtureRequest("req_4", "agent-qa", "it-cloud", "read", "List buckets.", 97, true),
    ];
  }
  const requests = fixtureRequests();
  return flag === "noreason" ? requests.map((r) => ({ ...r, reason: "" })) : requests;
}

/** A fresh set of handlers with its own state. Tests call this for each test. */
export function approvalHandlers(initial: AccessRequestView_Serialize[] = seed()): MockHandlers {
  let pending = initial;
  const take = (id: string): AccessRequestView_Serialize => {
    if (devFlag("mock_approval") === "expired") throw mockError("conflict", "the request expired");
    const found = pending.find((r) => r.id === id);
    if (!found) throw mockError("not_found", "no such request");
    pending = pending.filter((r) => r.id !== id);
    return found;
  };
  return {
    request_list_pending: async () => {
      const flag = devFlag("mock_approval");
      if (flag === "slow") await sleep(60_000);
      if (flag === "error") throw mockError("internal", "the request list did not load");
      return pending;
    },
    request_approve: (args) => {
      const a = args as { request: string; option: ApprovalOption };
      const found = take(a.request);
      const lease: LeaseView_Serialize = {
        id: `lse_${found.id}`,
        item_id: found.item_id,
        permission: found.permission,
        expires_at: secondsFromNow(a.option === "once" ? 300 : a.option === "minutes_15" ? 900 : 28_800),
        uses_left: a.option === "once" ? 1 : null,
      };
      return lease;
    },
    request_deny: (args) => {
      take((args as { request: string }).request);
      return null;
    },
  };
}

export const handlers: MockHandlers = approvalHandlers();
