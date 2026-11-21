// Dev and test backend for the settings screen. Fake data only: the pins, paths and keys here are not real.
import type { OperatorPublic_Serialize, OperatorRole, Value } from "../../bindings";
import { mockError, type MockHandlers } from "../../ipc/mock/core";
import { fixtureNetwork, fixtureSettings, LOCAL_CA_PIN, MOCK_OPERATORS } from "../../ipc/mock/fixtures";
import { MOCK_RECOVERY_KEY } from "../create/mock";

let settings = fixtureSettings();
let network = fixtureNetwork();
let operators: OperatorPublic_Serialize[] = MOCK_OPERATORS.map((o) => ({ ...o }));

/** Puts the mock data back to its start. Tests call it in `beforeEach`. */
export const resetSettingsMock = () => {
  settings = fixtureSettings();
  network = fixtureNetwork();
  operators = MOCK_OPERATORS.map((o) => ({ ...o }));
};

type Args = Record<string, unknown> | undefined;
const arg = <T>(args: Args, key: string): T => (args as Record<string, T>)[key] as T;

export const handlers: MockHandlers = {
  settings_get: () => ({ values: settings }),
  settings_set: (args) => {
    const key = arg<string>(args, "key");
    if (!(key in settings)) throw mockError("validation_failed", "is not a setting", { fields: [{ field: key, problem: "is not a setting" }] });
    settings = { ...settings, [key]: arg<Value>(args, "value") };
    return { values: settings };
  },
  network_status: () => network,
  network_set_bind: (args) => {
    const addrs = arg<string[]>(args, "addrs");
    const lan = addrs.some((a) => a !== "127.0.0.1" && a !== "::1");
    if (lan) throw mockError("validation_failed", "invalid request", { fields: [{ field: "addrs", problem: "a LAN address needs a client certificate on every active key" }] });
    network = { ...network, bind: addrs, port: arg<number>(args, "port") };
    return network;
  },
  tls_export_ca: () => null,
  tls_load_custom: (args) => {
    if (String(arg<string>(args, "chainPath")).includes("bad")) {
      throw mockError("validation_failed", "invalid request", { fields: [{ field: "certificate", problem: "the certificate has expired" }] });
    }
    network = { ...network, custom_cert: true, pin: "sha256/DEMOCUSTOMDEMOCUSTOMDEMOCUSTOM00000000000=" };
    return network;
  },
  tls_use_local_ca: () => {
    network = { ...network, custom_cert: false, pin: LOCAL_CA_PIN };
    return network;
  },
  backup_create: () => null,
  backup_restore: (args, ctl) => {
    const unlock = arg<{ kind: string; recovery_key?: string }>(args, "unlock");
    if (unlock.kind === "recovery" && !String(unlock.recovery_key).includes("DEMO")) throw mockError("bad_credentials", "that does not open the backup");
    ctl.lockReason = "restore";
    void ctl.setState("sealed");
    return null;
  },
  vault_list_operators: () => operators,
  operator_add: (args) => {
    const op: OperatorPublic_Serialize = { id: `op-${operators.length + 1}`, label: arg<string>(args, "label"), role: arg<OperatorRole>(args, "role"), last_unlock_at: null };
    operators = [...operators, op];
    return op;
  },
  operator_remove: (args) => {
    operators = operators.filter((o) => o.id !== arg<string>(args, "operator"));
    return null;
  },
  operator_set_role: (args) => {
    operators = operators.map((o) => (o.id === arg<string>(args, "operator") ? { ...o, role: arg<OperatorRole>(args, "role") } : o));
    return null;
  },
  phrase_change: (args) => {
    if (arg<string>(args, "currentPhrase") === "wrong current phrase") throw mockError("bad_credentials", "that phrase does not open the vault");
    return null;
  },
  recovery_rotate: () => MOCK_RECOVERY_KEY,
  "plugin:app|version": () => "0.1.0",
  "plugin:dialog|save": () => "/tmp/cerberus-demo.cerb",
  // The open dialog runs in the backend now (AUD-11), so the test answers `file_pick_open`.
  file_pick_open: (args) =>
    ((args as { extensions?: string[] } | undefined)?.extensions ?? []).includes("cerberus-admin") ? "/home/demo/build-server.cerberus-admin" : "/tmp/cerberus-demo.cerb",
};
