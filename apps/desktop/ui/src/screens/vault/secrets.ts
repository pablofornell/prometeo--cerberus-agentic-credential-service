// Which secret fields the details drawer shows for each kind, and how to read one from a revealed payload.
import type { ItemKind, PayloadView_Serialize as Payload } from "../../bindings";
import type { messages } from "./messages";

export interface SecretFieldDef {
  /** The field name `clipboard_copy_secret` takes. `null` has no copy button. */
  field: string | null;
  /** Key of the label in `messages`. */
  label: keyof typeof messages;
  /** Name in the payload, when it differs from `field`. */
  key: string;
}

const f = (key: string, copy = true): SecretFieldDef => ({ field: copy ? key : null, label: `field.${key}` as keyof typeof messages, key });

export const SECRET_FIELDS: Record<ItemKind, readonly SecretFieldDef[]> = {
  web_login: [f("username"), f("password")],
  api_key: [f("key")],
  // The private key never needs to be on screen. The editor shows the public key and the fingerprint.
  ssh_key: [],
  session_token: [f("token")],
  browser_session: [f("storage_state")],
  database: [f("url"), f("username"), f("password")],
  cloud: [f("access_key_id"), f("secret_access_key")],
  certificate: [f("key_pem")],
  env_bundle: [f("vars", false)],
  note: [f("text")],
  rustdesk: [f("password")],
};

/** The text of one field. Env bundles show `NAME=value` pairs. A field that is not set reads as "Not set". */
export function pickSecret(payload: Payload, key: string): string {
  const record = payload as unknown as Record<string, unknown>;
  const value = record[key];
  if (key === "vars" && typeof value === "object" && value !== null) {
    return Object.entries(value as Record<string, string>)
      .map(([name, text]) => `${name}=${text}`)
      .join("; ");
  }
  return typeof value === "string" && value !== "" ? value : "Not set";
}
