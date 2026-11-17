import type {
  DayOfWeek,
  Environment,
  GrantInputView_Deserialize,
  GrantMode,
  GrantView_Serialize,
  ItemKind,
  Permission,
} from "../../bindings";

/** What the builder holds while a person edits one grant. Plain values only. */
export interface Draft {
  id: string | null;
  permissions: Permission[];
  workspaceIds: string[];
  environments: Environment[];
  categories: string[];
  kinds: ItemKind[];
  roleLabels: string[];
  tags: string;
  itemIds: string[];
  mode: GrantMode;
  windowOn: boolean;
  days: DayOfWeek[];
  start: string;
  end: string;
  tz: string;
  reads: string;
  ends: string;
  reason: boolean;
  prodAuto: boolean;
}

const zone = (): string => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
};

export const emptyDraft = (): Draft => ({
  id: null,
  permissions: ["read"],
  workspaceIds: [],
  environments: [],
  categories: [],
  kinds: [],
  roleLabels: [],
  tags: "",
  itemIds: [],
  mode: "auto",
  windowOn: false,
  days: ["monday", "tuesday", "wednesday", "thursday", "friday"],
  start: "08:00",
  end: "20:00",
  tz: zone(),
  reads: "",
  ends: "",
  reason: false,
  prodAuto: false,
});

export function draftFromGrant(grant: GrantView_Serialize): Draft {
  const base = emptyDraft();
  const c = grant.conditions;
  const sel = grant.selector;
  return {
    ...base,
    id: grant.id,
    permissions: [...grant.permissions],
    workspaceIds: [...sel.workspace_ids],
    environments: [...sel.environments],
    categories: [...sel.categories],
    kinds: [...sel.kinds],
    roleLabels: [...sel.role_labels],
    tags: sel.tags.join(", "),
    itemIds: [...sel.item_ids],
    mode: grant.mode,
    windowOn: c.time_window !== null,
    days: c.time_window ? [...c.time_window.days] : base.days,
    start: c.time_window ? c.time_window.start.slice(0, 5) : base.start,
    end: c.time_window ? c.time_window.end.slice(0, 5) : base.end,
    tz: c.time_window ? c.time_window.tz : base.tz,
    reads: c.max_reads_per_hour === null ? "" : String(c.max_reads_per_hour),
    ends: c.expires_at ? c.expires_at.slice(0, 10) : "",
    reason: c.reason_required,
    prodAuto: grant.allow_prod_auto,
  };
}

export function draftToInput(agentId: string, d: Draft): GrantInputView_Deserialize {
  const reads = Number.parseInt(d.reads, 10);
  return {
    id: d.id,
    agent_id: agentId,
    selector: {
      workspace_ids: d.workspaceIds,
      environments: d.environments,
      categories: d.categories,
      tags: d.tags.split(",").map((x) => x.trim().replace(/^#/, "")).filter(Boolean),
      kinds: d.kinds,
      role_labels: d.roleLabels,
      item_ids: d.itemIds,
    },
    permissions: d.permissions,
    mode: d.mode,
    conditions: {
      time_window: d.windowOn ? { days: d.days, start: `${d.start}:00`, end: `${d.end}:00`, tz: d.tz } : null,
      max_reads_per_hour: Number.isFinite(reads) && reads > 0 ? reads : null,
      expires_at: d.ends ? `${d.ends}T23:59:59Z` : null,
      reason_required: d.reason,
    },
    allow_prod_auto: d.prodAuto && d.mode === "auto",
  };
}
