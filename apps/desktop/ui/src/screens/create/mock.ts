// Dev and test backend for the create screen. Fake data only: the phrases and the key here are not real.
import { mockError, type MockHandlers } from "../../ipc/mock/core";

export const MOCK_RECOVERY_KEY = "CRK1-DEMO-AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH-JJJJ-KKKK-MMMM-NNNN-PPPP";

const WORDS = ["lantern", "oyster", "gravel", "quiet", "dynamo", "ribbon", "thaw", "meadow", "copper", "falcon", "harbor", "velvet", "anchor", "pepper", "summit"];

export const handlers: MockHandlers = {
  kdf_benchmark: async () => {
    await new Promise((r) => setTimeout(r, 400));
    return { params: { m_cost_kib: 262_144, t_cost: 3, p_cost: 4 }, measured_ms: 706 };
  },
  passphrase_strength: (args) => {
    const phrase = String((args as { phrase?: string } | undefined)?.phrase ?? "");
    const words = phrase.trim().split(/\s+/).filter(Boolean).length;
    const score = words >= 5 ? 4 : phrase.length >= 14 ? 3 : phrase.length >= 8 ? 2 : phrase.length >= 4 ? 1 : 0;
    return {
      score,
      guesses_log10: Math.round(phrase.length * 1.7 * 10) / 10,
      warning: score < 3 ? "This is a common pattern." : null,
      suggestions: score < 3 ? ["Add more words."] : [],
      acceptable: phrase.length >= 12 && score >= 3,
    };
  },
  passphrase_generate: (args) => {
    const n = Number((args as { words?: number } | undefined)?.words ?? 7);
    return Array.from({ length: n }, (_, i) => WORDS[(i * 5 + Math.floor(Math.random() * 3)) % WORDS.length]).join(" ");
  },
  vault_create: async (args, ctl) => {
    const label = String((args as { ownerLabel?: string } | undefined)?.ownerLabel ?? "");
    await new Promise((r) => setTimeout(r, 600));
    if (label.toLowerCase() === "fail") throw mockError("internal", "internal error");
    if (label.toLowerCase() === "invalid") {
      throw mockError("validation_failed", "some fields need a change", { fields: [{ field: "owner_label", problem: "must not hold control characters" }] });
    }
    await ctl.setState("unlocked");
    return { owner_id: "op-ana", recovery_key: MOCK_RECOVERY_KEY, ca_pin: "sha256/DEMOPINDEMOPINDEMOPINDEMOPIN0000000000000=" };
  },
};
