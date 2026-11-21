// Form state of the item editor, and the two conversions: item to form (`fromItem`) and form to IPC input (`toInput`).
// Editing never reads the secret (DEC-INT10-6): the form keeps it with `{ kind: "keep" }` until the person replaces it.
// Secret values live in this state only while the form is open. Nothing here logs or stores them.
import type {
  Environment,
  ItemDetailView_Serialize as Detail,
  ItemInputView_Deserialize as ItemInput,
  ItemKind,
  PayloadView_Deserialize as PayloadIn,
  SshKeyDraft,
  TotpAlgorithmView,
} from "../../bindings";
import { DEFAULT_CATEGORY } from "../vault/kinds";
import { cleanRustdeskId, isRustdeskId, RUSTDESK_KEYS } from "../vault/rustdesk";

export interface Pair {
  id: number;
  name: string;
  value: string;
}

export interface FormState {
  kind: ItemKind;
  title: string;
  workspaceId: string;
  category: string;
  /** True once the person picked a category, so a kind change no longer replaces it. */
  categoryTouched: boolean;
  environment: Environment;
  roleLabel: string;
  target: string;
  description: string;
  /** Comma separated. */
  tags: string;
  /** `never`, `keep`, `date`, or a number of seconds from now. */
  expiry: string;
  expiryDate: string;
  /** The expiry an edited item has now. */
  currentExpiry: string | null;
  maxUses: string;
  /** The `custom` values the item has now. They go back on save, apart from the SSH and RustDesk fields below. */
  custom: Record<string, string>;
  /** True while an edited item keeps its secret. Save then sends `{ kind: "keep" }`. */
  keepSecret: boolean;

  webUsername: string;
  webPassword: string;
  webUrl: string;
  totpSecret: string;
  totpAlgorithm: TotpAlgorithmView;
  totpDigits: string;
  totpPeriod: string;

  apiKey: string;
  apiKeyId: string;
  apiHeader: string;
  apiBaseUrl: string;

  sshDraft: SshKeyDraft | null;
  sshMachine: string;
  sshHost: string;
  sshPort: string;
  sshUser: string;

  token: string;
  tokenType: string;
  tokenHeader: string;

  storageState: string;
  origin: string;

  dbMode: "url" | "fields";
  dbUrl: string;
  dbEngine: string;
  dbHost: string;
  dbPort: string;
  dbName: string;
  dbUser: string;
  dbPassword: string;
  dbParams: Pair[];

  cloudProvider: string;
  cloudKeyId: string;
  cloudSecret: string;
  cloudToken: string;
  cloudRegion: string;
  cloudExtra: Pair[];

  certPem: string;
  certKey: string;
  certChain: string;

  envVars: Pair[];

  noteText: string;

  /** RustDesk connection: metadata in `custom`, so it can change while the item keeps its password (DEC-RD-1). */
  rdId: string;
  rdIdServer: string;
  rdRelayServer: string;
  rdKey: string;
  rdPassword: string;
}

let pairId = 0;
export const newPair = (name = "", value = ""): Pair => ({ id: ++pairId, name, value });

export const isSession = (kind: ItemKind): boolean => kind === "session_token" || kind === "browser_session";

export function initialState(kind: ItemKind = "web_login", workspaceId = ""): FormState {
  return {
    kind,
    title: "",
    workspaceId,
    category: DEFAULT_CATEGORY[kind],
    categoryTouched: false,
    environment: "dev",
    roleLabel: "",
    target: "",
    description: "",
    tags: "",
    expiry: isSession(kind) ? "3600" : "never",
    expiryDate: "",
    currentExpiry: null,
    maxUses: "",
    custom: {},
    keepSecret: false,
    webUsername: "",
    webPassword: "",
    webUrl: "",
    totpSecret: "",
    totpAlgorithm: "SHA1",
    totpDigits: "6",
    totpPeriod: "30",
    apiKey: "",
    apiKeyId: "",
    apiHeader: "",
    apiBaseUrl: "",
    sshDraft: null,
    sshMachine: "",
    sshHost: "",
    sshPort: "22",
    sshUser: "",
    token: "",
    tokenType: "",
    tokenHeader: "",
    storageState: "",
    origin: "",
    dbMode: "url",
    dbUrl: "",
    dbEngine: "",
    dbHost: "",
    dbPort: "",
    dbName: "",
    dbUser: "",
    dbPassword: "",
    dbParams: [],
    cloudProvider: "",
    cloudKeyId: "",
    cloudSecret: "",
    cloudToken: "",
    cloudRegion: "",
    cloudExtra: [],
    certPem: "",
    certKey: "",
    certChain: "",
    envVars: [newPair()],
    noteText: "",
    rdId: "",
    rdIdServer: "",
    rdRelayServer: "",
    rdKey: "",
    rdPassword: "",
  };
}

/** Switching kind keeps what was typed for other kinds, and moves the default category and expiry along. */
export function withKind(state: FormState, kind: ItemKind): FormState {
  return {
    ...state,
    kind,
    category: state.categoryTouched ? state.category : DEFAULT_CATEGORY[kind],
    expiry: isSession(kind) !== isSession(state.kind) ? (isSession(kind) ? "3600" : "never") : state.expiry,
  };
}

const text = (value: string | null | undefined): string => value ?? "";

/** Fills the form from `item_get` of an existing item. The secret fields stay empty: the item keeps its secret. */
export function fromItem(detail: Detail): FormState {
  const s = detail.summary;
  return {
    ...initialState(s.kind),
    title: s.title,
    category: s.category,
    categoryTouched: true,
    environment: s.environment,
    roleLabel: text(s.role_label),
    target: text(s.target),
    description: s.description,
    tags: s.tags.join(", "),
    expiry: s.expires_at ? "keep" : "never",
    currentExpiry: s.expires_at,
    maxUses: detail.max_uses === null ? "" : String(detail.max_uses),
    custom: { ...s.custom },
    keepSecret: true,
    sshMachine: text(s.custom.machine),
    sshHost: text(s.custom.host),
    sshPort: s.custom.port ?? "22",
    sshUser: text(s.custom.user),
    rdId: text(s.custom[RUSTDESK_KEYS.id]),
    rdIdServer: text(s.custom[RUSTDESK_KEYS.idServer]),
    rdRelayServer: text(s.custom[RUSTDESK_KEYS.relayServer]),
    rdKey: text(s.custom[RUSTDESK_KEYS.serverKey]),
  };
}

const orNull = (value: string): string | null => {
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
};
const intOrNull = (value: string): number | null => {
  const trimmed = value.trim();
  return trimmed === "" || !/^\d+$/.test(trimmed) ? null : Number(trimmed);
};
const toMap = (pairs: readonly Pair[]): Record<string, string> =>
  Object.fromEntries(pairs.filter((p) => p.name.trim() !== "" || p.value !== "").map((p) => [p.name.trim(), p.value]));

/** Base32 seeds are written in groups and in any case. The backend wants upper case without spaces. */
export const cleanSeed = (value: string): string => value.replace(/[\s-]/g, "").toUpperCase();

export function parseTags(value: string): string[] {
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const raw of value.split(",")) {
    const tag = raw.trim().replace(/^#/, "");
    if (tag !== "" && !seen.has(tag.toLowerCase())) {
      seen.add(tag.toLowerCase());
      tags.push(tag);
    }
  }
  return tags;
}

/** The end time for the chosen expiry, or `null` for no expiry. */
export function expiryOf(state: FormState, nowMs: number): string | null {
  switch (state.expiry) {
    case "never":
      return null;
    case "keep":
      return state.currentExpiry;
    case "date": {
      const at = new Date(state.expiryDate);
      return Number.isNaN(at.getTime()) ? null : at.toISOString();
    }
    default:
      return new Date(nowMs + Number(state.expiry) * 1000).toISOString();
  }
}

export function payloadOf(state: FormState): PayloadIn {
  if (state.keepSecret && !state.sshDraft) return { kind: "keep" };
  switch (state.kind) {
    case "web_login": {
      const seed = cleanSeed(state.totpSecret);
      return {
        kind: "web_login",
        username: state.webUsername,
        password: state.webPassword,
        url: orNull(state.webUrl),
        totp: seed === "" ? null : { secret: seed, algorithm: state.totpAlgorithm, digits: Number(state.totpDigits), period: Number(state.totpPeriod) },
      };
    }
    case "api_key":
      return { kind: "api_key", key: state.apiKey, key_id: orNull(state.apiKeyId), header_name: orNull(state.apiHeader), base_url: orNull(state.apiBaseUrl) };
    case "ssh_key":
      return { kind: "ssh_key_draft", draft_id: state.sshDraft?.draft_id ?? "" };
    case "session_token":
      return { kind: "session_token", token: state.token, token_type: orNull(state.tokenType), header_name: orNull(state.tokenHeader) };
    case "browser_session":
      return { kind: "browser_session", storage_state: state.storageState, origin: state.origin.trim() };
    case "database":
      return state.dbMode === "url"
        ? { kind: "database", url: orNull(state.dbUrl), engine: null, host: null, port: null, database: null, username: null, password: null, params: toMap(state.dbParams) }
        : {
            kind: "database",
            url: null,
            engine: orNull(state.dbEngine),
            host: orNull(state.dbHost),
            port: intOrNull(state.dbPort),
            database: orNull(state.dbName),
            username: orNull(state.dbUser),
            password: state.dbPassword === "" ? null : state.dbPassword,
            params: toMap(state.dbParams),
          };
    case "cloud":
      return {
        kind: "cloud",
        provider: state.cloudProvider.trim(),
        access_key_id: orNull(state.cloudKeyId),
        secret_access_key: state.cloudSecret === "" ? null : state.cloudSecret,
        session_token: state.cloudToken === "" ? null : state.cloudToken,
        region: orNull(state.cloudRegion),
        extra: toMap(state.cloudExtra),
      };
    case "certificate":
      return { kind: "certificate", cert_pem: state.certPem.trim(), key_pem: state.certKey.trim() === "" ? null : state.certKey.trim(), chain_pem: orNull(state.certChain) };
    case "env_bundle":
      return { kind: "env_bundle", vars: toMap(state.envVars) };
    case "note":
      return { kind: "note", text: state.noteText };
    case "rustdesk":
      return { kind: "rustdesk", password: state.rdPassword === "" ? null : state.rdPassword };
  }
}

/** The full `item_create` / `item_update` input. */
export function toInput(state: FormState, nowMs: number): ItemInput {
  const custom: Record<string, string> = { ...state.custom };
  const entries: [string, string][] =
    state.kind === "ssh_key"
      ? [
          ["machine", state.sshMachine.trim()],
          ["host", state.sshHost.trim()],
          ["port", state.sshPort.trim()],
          ["user", state.sshUser.trim()],
        ]
      : state.kind === "rustdesk"
        ? [
            [RUSTDESK_KEYS.id, cleanRustdeskId(state.rdId)],
            [RUSTDESK_KEYS.idServer, state.rdIdServer.trim()],
            [RUSTDESK_KEYS.relayServer, state.rdRelayServer.trim()],
            [RUSTDESK_KEYS.serverKey, state.rdKey.trim()],
          ]
        : [];
  for (const [key, value] of entries) {
    if (value !== "") custom[key] = value;
    else delete custom[key];
  }
  return {
    workspace_id: state.workspaceId,
    title: state.title.trim(),
    description: state.description.trim(),
    role_label: orNull(state.roleLabel),
    category: state.category.trim(),
    tags: parseTags(state.tags),
    environment: state.environment,
    target: orNull(state.target),
    custom,
    expires_at: expiryOf(state, nowMs),
    max_uses: intOrNull(state.maxUses),
    payload: payloadOf(state),
  };
}

/** Checks that need no backend. The backend still validates everything (ADR-0027). */
export function localProblems(state: FormState): Record<string, string> {
  const problems: Record<string, string> = {};
  if (state.title.trim() === "") problems.title = "title";
  if (state.workspaceId === "") problems.workspace = "workspace";
  if (state.kind === "ssh_key" && !state.sshDraft && !state.keepSecret) problems["payload.private_key"] = "key";
  if (state.kind === "rustdesk" && !isRustdeskId(cleanRustdeskId(state.rdId))) problems["custom.rustdesk_id"] = "rustdeskId";
  if (state.expiry === "date" && Number.isNaN(new Date(state.expiryDate).getTime())) problems.expires_at = "date";
  return problems;
}

/** Field paths the form shows next to a control. Other problems go to the banner. */
const INLINE =
  /^(title|description|role_label|category|target|tags(\[\d+\])?|expires_at|max_uses|workspace|custom\.(machine|host|port|user|rustdesk_id|id_server|relay_server|server_key)|payload\.(username|password|url|totp|key|key_id|header_name|base_url|passphrase|private_key|public_key|fingerprint|token|token_type|storage_state|origin|engine|host|port|database|provider|access_key_id|secret_access_key|session_token|region|cert_pem|key_pem|chain_pem|text)|payload\.(vars|params|extra)(\..+)?|vars(\..+)?|params(\..+)?|extra(\..+)?)$/;

export const isInline = (field: string): boolean => INLINE.test(field);

/** `tags[2]` shows under the tags field. Backend field names without `payload.` (older paths) are accepted too. */
export function normalizeField(field: string): string {
  if (/^tags\[\d+\]$/.test(field)) return "tags";
  if (/^(vars|params|extra)(\..+)?$/.test(field)) return `payload.${field}`;
  return field;
}
