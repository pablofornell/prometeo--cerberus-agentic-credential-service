import type { UiError } from "../ipc/client";
import { errorText } from "../ui";
import type { messages } from "./messages";

type T = (key: keyof typeof messages & string, vars?: Record<string, string | number>) => string;

/** What a person reads for a failed check of the server of a setup code. Field problems of the code and the address have their own place. */
export function checkProblem(error: UiError, t: T): { title: string; body: string } {
  switch (error.code) {
    case "setup_wrong_server":
      return { title: t("setup.err.wrong.title"), body: t("setup.err.wrong.body") };
    case "remote_unreachable":
      return { title: t("setup.err.unreachable.title"), body: t("setup.err.unreachable.body") };
    case "conflict":
      return { title: t("setup.err.exists.title"), body: t("setup.err.exists.body") };
    case "remote_protocol_mismatch":
      return { title: t("setup.err.protocol.title"), body: t("setup.err.protocol.body") };
    default:
      return { title: t("setup.check.failed"), body: errorText(error) };
  }
}

/** The fields of a `validation_failed` answer that the code or the address form owns. */
export const problemOf = (error: UiError | null, field: string): string | undefined =>
  error?.code === "validation_failed" ? error.fields.find((f) => f.field === field)?.problem : undefined;

export interface CreateProblem {
  title: string;
  body: string;
  /** The code cannot work again: the person needs a new one from the server. A wait (`too_many_failures`) is not that: the code stays valid. */
  newCode: boolean;
}

/** What a person reads for a failed creation of the vault. The vault may exist only after `setup_unconfirmed`. */
export function createProblem(error: UiError, t: T): CreateProblem {
  const title = t("setup.fail.title");
  switch (error.code) {
    case "unauthenticated":
      return { title, body: t("setup.fail.token"), newCode: true };
    case "too_many_failures":
      return { title: t("setup.fail.locked.title"), body: t("setup.fail.locked"), newCode: false };
    case "setup_wrong_server":
      return { title: t("setup.err.wrong.title"), body: t("setup.err.wrong.body"), newCode: true };
    case "conflict":
      return { title, body: t("setup.fail.conflict"), newCode: true };
    case "setup_unconfirmed":
      return { title: t("setup.fail.unconfirmed.title"), body: t("setup.fail.unconfirmed.body"), newCode: false };
    case "remote_unreachable":
      return { title: t("setup.err.unreachable.title"), body: t("setup.err.unreachable.body"), newCode: false };
    default:
      return { title, body: `${errorText(error)} ${t("setup.fail.retry")}`, newCode: false };
  }
}
