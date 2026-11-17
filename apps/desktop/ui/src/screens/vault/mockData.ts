// A fake vault for the dev mock and for the tests of screens 4 and 5. Every value is made up.
import type {
  ItemFilterView_Deserialize,
  ItemInputView_Deserialize as ItemInput,
  ItemKind,
  ItemSummaryView_Serialize as Item,
  PayloadView_Serialize as Payload,
  RevealedSecretView_Serialize,
  SshKeyDraft,
  SshMetaView_Serialize,
  WorkspaceView,
} from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { filterItems, fixtureItems, fixtureWorkspaces } from "../../ipc/mock/fixtures";

interface StoredItem {
  summary: Item;
  payload: Payload;
  max_uses: number | null;
  use_count: number;
  version: number;
  ssh: SshMetaView_Serialize | null;
  versions: { version: number; created_at: string; title: string }[];
}

export interface VaultMockOptions {
  /** `empty` has no items and no workspace. `error` fails `item_list`. `slow` never answers `item_list`. */
  mode?: "normal" | "empty" | "error" | "slow";
  /** Seconds a session item has left at the start. */
  now?: () => number;
}

export interface VaultMock {
  handlers: MockHandlers;
  /** What the handlers saw, for the tests. Item IDs and field names only. */
  calls: { revealed: string[]; copied: { item: string; field: string }[]; created: ItemInput[]; updated: { item: string; input: ItemInput }[]; deleted: string[] };
}

const FAKE_PEM_MARK = "FAKE-KEY-FOR-TESTS";

export const FAKE_PEM = `-----BEGIN OPENSSH PRIVATE KEY-----\n${FAKE_PEM_MARK}\n-----END OPENSSH PRIVATE KEY-----\n`;

function payloadFor(kind: ItemKind): Payload {
  switch (kind) {
    case "web_login":
      return { kind, username: "fake-user@example.test", password: "fake-password-0000", url: null, totp: { secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30 } };
    case "api_key":
      return { kind, key: "fake-api-key-0000", key_id: "key-fake-01", header_name: "Authorization", base_url: null };
    case "ssh_key":
      return { kind, private_key: FAKE_PEM, passphrase: null, public_key: "ssh-ed25519 AAAAFAKEFAKEFAKE build-01-deploy", fingerprint: "SHA256:FAKEFAKEFAKEFAKEFAKE" };
    case "session_token":
      return { kind, token: "fake-session-token-0000", token_type: "Bearer", header_name: null };
    case "browser_session":
      return { kind, storage_state: '{"cookies":[],"origins":[]}', origin: "http://localhost:5173" };
    case "database":
      return { kind, url: null, engine: "postgres", host: "db.staging.internal", port: 5432, database: "billing", username: "fake-db-user", password: "fake-db-password", params: {} };
    case "cloud":
      return { kind, provider: "aws", access_key_id: "FAKEACCESSKEY0000", secret_access_key: "fake-secret-0000", session_token: null, region: "eu-west-1", extra: {} };
    case "certificate":
      return { kind, cert_pem: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----", key_pem: null, chain_pem: null };
    case "env_bundle":
      return { kind, vars: { API_URL: "https://api.shop.example", FEATURE_FLAG: "fake-flag" } };
    case "note":
      return { kind, text: "Fake runbook text." };
  }
}

const iso = (ms: number) => new Date(ms).toISOString();

/** Problems like the real validator: path names, plain text, no value. */
function validate(input: ItemInput): { field: string; problem: string }[] {
  const problems: { field: string; problem: string }[] = [];
  if (input.title.trim() === "") problems.push({ field: "title", problem: "must be 1..200 characters" });
  if (input.target && input.target.length > 512) problems.push({ field: "target", problem: "must be 1..512 characters" });
  const p = input.payload;
  if (p.kind === "web_login" && p.url && !/^https?:\/\//.test(p.url)) problems.push({ field: "payload.url", problem: "must be an http or https URL" });
  if (p.kind === "web_login" && (p.password ?? "") === "") problems.push({ field: "payload.password", problem: "must be 1..1024 characters" });
  if (p.kind === "api_key" && (p.key ?? "") === "") problems.push({ field: "payload.key", problem: "must be 1..8192 characters" });
  if (input.custom.port !== undefined && !/^\d+$/.test(input.custom.port)) problems.push({ field: "custom.port", problem: "must be a port number 1..65535" });
  return problems;
}

/** A fresh in-memory vault with the handlers of every command the two screens use. */
export function createVaultMock(options: VaultMockOptions = {}): VaultMock {
  const mode = options.mode ?? "normal";
  const now = options.now ?? (() => Date.now());
  const calls: VaultMock["calls"] = { revealed: [], copied: [], created: [], updated: [], deleted: [] };
  const drafts = new Map<string, SshKeyDraft>();
  let counter = 100;

  const workspaces: Omit<WorkspaceView, "item_count">[] = mode === "empty" ? [] : fixtureWorkspaces().map(({ id, slug, name, description, aliases }) => ({ id, slug, name, description, aliases }));
  const store = new Map<string, StoredItem>();
  if (mode !== "empty") {
    const start = now();
    for (const summary of fixtureItems(start)) {
      const { id, kind, title } = summary;
      store.set(id, {
        summary,
        payload: payloadFor(kind),
        max_uses: null,
        use_count: id === "it-stage" ? 41 : 3,
        version: id === "it-stage" ? 3 : 1,
        ssh: kind === "ssh_key" ? { machine: "build-01", host: "build-01.internal", port: 22, user: "deploy" } : null,
        versions: id === "it-stage" ? [1, 2, 3].map((v) => ({ version: v, created_at: iso(start - (4 - v) * 86_400_000), title })) : [{ version: 1, created_at: iso(start - 86_400_000), title }],
      });
    }
  }

  const need = (id: string): StoredItem => {
    const found = store.get(id);
    if (!found) throw mockError("not_found", "no such item");
    return found;
  };

  const detail = (s: StoredItem) => ({
    summary: s.summary,
    version: s.version,
    use_count: s.use_count,
    max_uses: s.max_uses,
    exposed_to: s.summary.id === "it-stage" ? [{ agent_id: "agent-qa", at: "2026-11-16T14:21:07Z" }] : [],
  });

  const keepOnCreate = () => mockError("validation_failed", "validation failed", { fields: [{ field: "payload", problem: "keep is only for an update" }] });

  const resolvePayload = (input: ItemInput, current?: Payload): Payload => {
    const p = input.payload;
    if (p.kind === "keep") {
      if (current) return current;
      throw keepOnCreate();
    }
    if (p.kind === "ssh_key_draft") {
      const draft = drafts.get(p.draft_id);
      if (!draft) throw mockError("not_found", "no such draft");
      return { kind: "ssh_key", private_key: FAKE_PEM, passphrase: null, public_key: draft.public_key, fingerprint: draft.fingerprint };
    }
    return p as unknown as Payload;
  };

  const kindOf = (payload: ItemInput["payload"]): ItemKind => {
    if (payload.kind === "keep") throw keepOnCreate();
    return payload.kind === "ssh_key_draft" ? "ssh_key" : payload.kind;
  };

  const toSummary = (id: string, input: ItemInput, previous?: Item): Item => {
    const ws = workspaces.find((w) => w.id === input.workspace_id);
    return {
      id,
      kind: previous?.kind ?? kindOf(input.payload),
      title: input.title.trim(),
      description: input.description,
      role_label: input.role_label ?? null,
      category: input.category,
      tags: input.tags,
      environment: input.environment,
      workspace: ws?.slug ?? "unknown",
      target: input.target ?? null,
      created_by: previous?.created_by ?? "operator:op-ana",
      expires_at: input.expires_at ?? null,
      updated_at: iso(now()),
      has_totp: input.payload.kind === "keep" ? (previous?.has_totp ?? false) : input.payload.kind === "web_login" && Boolean(input.payload.totp),
      custom: input.custom,
    };
  };

  const handlers: MockHandlers = {
    workspace_list: () => workspaces.map((w) => ({ ...w, item_count: [...store.values()].filter((s) => s.summary.workspace === w.slug).length })),
    workspace_put: (args) => {
      const input = args?.input as { slug: string; name: string; description: string; aliases: string[] };
      if (workspaces.some((w) => w.slug === input.slug)) throw mockError("conflict", "slug in use", { fields: [{ field: "slug", problem: "is already used" }] });
      const ws = { id: `ws-${input.slug}`, ...input };
      workspaces.push(ws);
      return { ...ws, item_count: 0 };
    },
    item_list: async (args) => {
      if (mode === "error") throw mockError("internal", "the search index did not answer");
      if (mode === "slow") await new Promise<never>(() => undefined);
      return filterItems([...store.values()].map((s) => s.summary), args?.filter as ItemFilterView_Deserialize | undefined);
    },
    item_get: (args) => detail(need(String(args?.item))),
    item_reveal: (args) => {
      const s = need(String(args?.item));
      calls.revealed.push(s.summary.id);
      s.use_count += 1;
      const exhausted = s.max_uses !== null && s.use_count >= s.max_uses;
      const view: RevealedSecretView_Serialize = { summary: s.summary, payload: s.payload, use_count: s.use_count, exhausted, ssh: s.ssh };
      return view;
    },
    item_totp_preview: (args) => {
      need(String(args?.item));
      return { code: "492113", period: 30, expires_in_seconds: 18 };
    },
    clipboard_copy_secret: (args) => {
      calls.copied.push({ item: String(args?.item), field: String(args?.field) });
      return null;
    },
    item_create: (args) => {
      const input = args?.input as ItemInput;
      const problems = validate(input);
      if (problems.length > 0) throw mockError("validation_failed", "validation failed", { fields: problems });
      calls.created.push(input);
      counter += 1;
      const id = `it-${counter}`;
      const payload = resolvePayload(input);
      const stored: StoredItem = {
        summary: toSummary(id, input),
        payload,
        max_uses: input.max_uses ?? null,
        use_count: 0,
        version: 1,
        ssh: null,
        versions: [{ version: 1, created_at: iso(now()), title: input.title }],
      };
      store.set(id, stored);
      return detail(stored);
    },
    item_update: (args) => {
      const id = String(args?.item);
      const input = args?.input as ItemInput;
      const s = need(id);
      const problems = validate(input);
      if (problems.length > 0) throw mockError("validation_failed", "validation failed", { fields: problems });
      calls.updated.push({ item: id, input });
      s.summary = toSummary(id, input, s.summary);
      s.max_uses = input.max_uses ?? null;
      if (input.payload.kind === "keep") {
        // A metadata update changes the current version in place (DEC-INT10-6).
        const current = s.versions.find((v) => v.version === s.version);
        if (current) current.title = input.title;
        return detail(s);
      }
      s.payload = resolvePayload(input, s.payload);
      s.version += 1;
      s.versions.push({ version: s.version, created_at: iso(now()), title: input.title });
      return detail(s);
    },
    item_delete: (args) => {
      const id = String(args?.item);
      need(id);
      calls.deleted.push(id);
      store.delete(id);
      return null;
    },
    item_versions: (args) => need(String(args?.item)).versions,
    item_restore_version: (args) => {
      const s = need(String(args?.item));
      s.version += 1;
      return detail(s);
    },
    password_generate: (args) => {
      const length = Number(args?.length);
      const classes = (args?.classes as string[]) ?? [];
      if (classes.length === 0) throw mockError("validation_failed", "validation failed", { fields: [{ field: "classes", problem: "choose at least one class" }] });
      const pool: Record<string, string> = { lower: "abcdefghijkmnpqrstuvwxyz", upper: "ABCDEFGHJKLMNPQRSTUVWXYZ", digits: "23456789", symbols: "!@#$%^&*-_=+" };
      const chars = classes.map((c) => pool[c] ?? "").join("");
      return Array.from({ length }, (_, i) => chars[(i * 7 + 3) % chars.length]).join("");
    },
    ssh_key_generate: (args) => {
      const draft: SshKeyDraft = {
        draft_id: `draft-${(counter += 1)}`,
        public_key: `ssh-ed25519 AAAAFAKEGENERATED ${String(args?.comment ?? "")}`.trim(),
        fingerprint: "SHA256:FAKEGENERATEDFAKEGENERATED",
      };
      drafts.set(draft.draft_id, draft);
      return draft;
    },
    ssh_key_import: (args) => {
      const source = args?.source as { kind: "path"; path: string } | { kind: "pem"; pem: string };
      if (source.kind === "pem" && !source.pem.includes("PRIVATE KEY")) {
        throw mockError("validation_failed", "validation failed", { fields: [{ field: "private_key", problem: "is not an OpenSSH private key" }] });
      }
      const draft: SshKeyDraft = { draft_id: `draft-${(counter += 1)}`, public_key: "ssh-ed25519 AAAAFAKEIMPORTED imported", fingerprint: "SHA256:FAKEIMPORTEDFAKEIMPORTED" };
      drafts.set(draft.draft_id, draft);
      return draft;
    },
  };
  return { handlers, calls };
}
