import { useState } from "react";
import type { KdfTuningView, Value, VaultStatusView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { ipc } from "../../ipc/client";
import { Button, Chip, Select, Switch } from "../../ui";
import { CLIPBOARD_CLEAR_SECONDS, SECRET_AUTO_HIDE_MS } from "../../ui";
import { costSummary } from "../create/Steps";
import { OperatorsPanel } from "./OperatorsPanel";
import { PhraseDialog } from "./PhraseDialog";
import { RecoveryRotate } from "./RecoveryRotate";
import { Setting, SettingGroup, SectionHead, parseChoice, useDuration, withCurrent } from "./Setting";
import { flag, num } from "./queries";
import { messages } from "./messages";

const IDLE = [300, 900, 1800, 3600, null] as const;
const HARD = [14_400, 43_200, 86_400, null] as const;
const LEASE = [900, 3600, 28_800] as const;
const APPROVAL = [30, 120, 300, 600] as const;

export interface Can {
  operator: boolean;
  owner: boolean;
}

interface Props {
  values: Record<string, Value>;
  status: VaultStatusView;
  can: Can;
  pending: string | null;
  onSet: (key: string, value: Value) => void;
}

const isLinux = () => typeof navigator !== "undefined" && /linux/i.test(navigator.userAgent) && !/android/i.test(navigator.userAgent);

export function SecuritySection({ values, status, can, pending, onSet }: Props) {
  const t = useScreenT(messages);
  const duration = useDuration();
  const [phraseOpen, setPhraseOpen] = useState(false);
  const [tuning, setTuning] = useState<KdfTuningView | null>(null);
  const [useTuned, setUseTuned] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testFailed, setTestFailed] = useState(false);

  const idle = num(values, "idle_lock_seconds", 1800);
  const hard = num(values, "max_unlocked_seconds", 43_200);
  const lease = num(values, "session_ttl_default_seconds", 3600);
  const leaseMax = num(values, "session_ttl_max_seconds", 86_400);
  const approval = num(values, "approval_timeout_seconds", 120);

  const runTest = async () => {
    setTesting(true);
    setTestFailed(false);
    try {
      setTuning(await ipc.kdfBenchmark());
    } catch {
      setTuning(null);
      setTestFailed(true);
    } finally {
      setTesting(false);
    }
  };

  const select = (key: string, current: number | null, presets: readonly (number | null)[], aria: string, allowed: boolean) => (
    <Select
      aria-label={aria}
      value={current === null ? "off" : String(current)}
      options={withCurrent(presets, current, duration)}
      disabled={!allowed || pending === key}
      onChange={(e) => onSet(key, parseChoice(e.target.value))}
    />
  );

  const cost = tuning ? costSummary(tuning.params) : null;
  const current = status.kdf ? t("kdf.current", costSummary(status.kdf)) : t("kdf.current.none");
  return (
    <section id="security" aria-labelledby="sec-h" className="settings-section" data-section="security">
      <SectionHead id="sec-h" icon="shield" title={t("sec.title")} description={t("section.sec.desc")} />
      <SettingGroup label={t("group.locking")}>
        <Setting label={t("idle.label")} description={t("idle.desc")} operatorOnly={!can.operator}>
          {select("idle_lock_seconds", idle, IDLE, t("idle.aria"), can.operator)}
        </Setting>
        <Setting label={t("hard.label")} description={t("hard.desc")} operatorOnly={!can.operator}>
          {select("max_unlocked_seconds", hard, HARD, t("hard.aria"), can.operator)}
        </Setting>
        <Setting label={t("agent.label")} description={t("agent.desc")} operatorOnly={!can.operator}>
          <Switch
            label={t("agent.label")}
            className="switch-bare"
            checked={flag(values, "agent_activity_keeps_unlocked", true)}
            disabled={!can.operator || pending === "agent_activity_keeps_unlocked"}
            onChange={(e) => onSet("agent_activity_keeps_unlocked", e.target.checked)}
          />
        </Setting>
        <Setting label={t("oslock.label")} description={status.os_hook_ok ? t("oslock.desc") : `${t("oslock.desc")} ${t("oslock.nohook")}`} operatorOnly={!can.operator}>
          <Switch
            label={t("oslock.label")}
            className="switch-bare"
            checked={flag(values, "lock_on_os_lock", true)}
            disabled={!can.operator || pending === "lock_on_os_lock"}
            onChange={(e) => onSet("lock_on_os_lock", e.target.checked)}
          />
        </Setting>
        <Setting label={t("autostart.label")} description={t("autostart.desc")} operatorOnly={!can.operator}>
          <Switch
            label={t("autostart.label")}
            className="switch-bare"
            checked={flag(values, "autostart", false)}
            disabled={!can.operator || pending === "autostart"}
            onChange={(e) => onSet("autostart", e.target.checked)}
          />
        </Setting>
      </SettingGroup>
      <SettingGroup label={t("group.agents")}>
        <Setting label={t("lease.label")} description={t("lease.desc", { max: duration(leaseMax) })} ownerOnly={!can.owner}>
          {select("session_ttl_default_seconds", lease, LEASE, t("lease.aria"), can.owner)}
        </Setting>
        <Setting label={t("approval.label")} description={t("approval.desc")} ownerOnly={!can.owner}>
          {select("approval_timeout_seconds", approval, APPROVAL, t("approval.aria"), can.owner)}
        </Setting>
      </SettingGroup>
      <SettingGroup label={t("group.secrets")}>
        <Setting label={t("shot.label")} description={isLinux() ? `${t("shot.desc")} ${t("shot.linux")}` : t("shot.desc")} operatorOnly={!can.operator}>
          <Switch
            label={t("shot.label")}
            className="switch-bare"
            checked={flag(values, "content_protection", false)}
            disabled={!can.operator || isLinux() || pending === "content_protection"}
            onChange={(e) => onSet("content_protection", e.target.checked)}
          />
        </Setting>
        <Setting label={t("fixed.label")} description={t("fixed.desc")}>
          <Chip>{SECRET_AUTO_HIDE_MS / 1000} s</Chip>
          <Chip>{CLIPBOARD_CLEAR_SECONDS} s</Chip>
        </Setting>
      </SettingGroup>
      <SettingGroup label={t("group.encryption")}>
        <Setting
          label={t("kdf.label")}
          ownerOnly={!can.owner}
          description={
            <>
              {t("kdf.desc")} {current}
              {cost && tuning && (
                <span className="result" role="status">
                  {t("kdf.result", { ...cost, seconds: (tuning.measured_ms / 1000).toFixed(2) })} {t("kdf.note")}
                </span>
              )}
              {testFailed && <span className="result bad" role="alert">{t("kdf.error")}</span>}
            </>
          }
        >
          <Button size="sm" icon="refresh" loading={testing} disabled={!can.owner} onClick={() => void runTest()}>
            {testing ? t("kdf.testing") : t("kdf.test")}
          </Button>
          {tuning && (
            <Button
              size="sm"
              disabled={!can.owner}
              onClick={() => {
                setUseTuned(true);
                setPhraseOpen(true);
              }}
            >
              {t("kdf.apply")}
            </Button>
          )}
        </Setting>
        <Setting label={t("phrase.label")} description={t("phrase.desc")}>
          <Button
            size="sm"
            onClick={() => {
              setUseTuned(false);
              setPhraseOpen(true);
            }}
          >
            {t("phrase.change")}
          </Button>
        </Setting>
      </SettingGroup>
      <SettingGroup label={t("group.operators")}>
        <OperatorsPanel status={status} canOwner={can.owner} />
      </SettingGroup>
      <SettingGroup label={t("group.danger")} danger>
        <Setting label={t("recovery.label")} description={t("recovery.desc")} ownerOnly={!can.owner}>
          <RecoveryRotate disabled={!can.owner} />
        </Setting>
      </SettingGroup>
      <PhraseDialog open={phraseOpen} onOpenChange={setPhraseOpen} tuning={tuning} defaultCost={useTuned} />
    </section>
  );
}
