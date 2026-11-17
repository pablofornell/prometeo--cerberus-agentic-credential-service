import { en, type MessageKey } from "./en";

export type { MessageKey };
export type Vars = Record<string, string | number>;

/** Fills `{name}` slots. A slot with no value stays as written, so a missing value is easy to see. */
export function format(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) => (name in vars ? String(vars[name]) : whole));
}

/** True when `key` is a shell key. Use it to pick text by a runtime value, such as an error code. */
export function hasMessage(key: string): key is MessageKey {
  return key in en;
}

/** Translate a shell key. */
export function t(key: MessageKey, vars?: Vars): string {
  return format(en[key], vars);
}

/** Hook form of `t`. It gives screens a stable place to switch language later. */
export function useT(): typeof t {
  return t;
}

/** Declare the strings of one screen: `export const messages = defineMessages({ "title": "Vault" })`. */
export function defineMessages<const M extends Record<string, string>>(messages: M): M {
  return messages;
}

/** Typed translate function for one screen catalog. */
export function useScreenT<M extends Record<string, string>>(messages: M) {
  return (key: keyof M & string, vars?: Vars): string => format(messages[key] ?? key, vars);
}
