import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { errorText } from "../../ui";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";
import { useScreenT } from "../../i18n";
import { Button, GateMark, Icon } from "../../ui";
import { createFlowStore } from "../../shell/createFlow";
import { useBenchmark, useStrength } from "./hooks";
import { messages } from "./messages";
import { RecoveryStep } from "./RecoveryStep";
import { CostStep, NameStep, PhraseStep } from "./Steps";

type Step = 1 | 2 | 3 | 4;
type Phase = "form" | "creating" | "failed" | "recovery";

const STEP_KEYS = ["step.name", "step.phrase", "step.cost", "step.recovery"] as const;
const PHRASE_WORDS = 7;

/** The five spectrum colors, as the variables of tokens.css. They appear on one thin stroke only: the ring of the current step. */
const SPECTRUM_VARS = ["--c-spectrum-red", "--c-spectrum-amber", "--c-spectrum-green", "--c-spectrum-blue", "--c-spectrum-violet"] as const;

function Rings({ step }: { step: Step }) {
  const grad = `${useId().replace(/[^a-zA-Z0-9_-]/g, "")}-rings`;
  const cls = (k: number) => (k < step ? "done" : k === step ? "now" : "");
  const props = (k: number) => ({ className: cls(k), ...(k === step ? { style: { stroke: `url(#${grad})` } } : {}) });
  return (
    <svg className="rings" viewBox="0 0 200 200" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={grad} gradientUnits="userSpaceOnUse" x1="8" y1="192" x2="192" y2="8">
          {SPECTRUM_VARS.map((name, i) => (
            <stop key={name} offset={i / (SPECTRUM_VARS.length - 1)} style={{ stopColor: `var(${name})` }} />
          ))}
        </linearGradient>
      </defs>
      <circle {...props(1)} cx="100" cy="100" r="92" />
      <circle {...props(2)} cx="100" cy="100" r="68" />
      <circle {...props(3)} cx="100" cy="100" r="44" />
      <circle className={`core ${cls(4)}`} cx="100" cy="100" r="18" />
    </svg>
  );
}

/** The four steps of vault creation. Secrets (phrase, recovery key) live in this component only and are cleared before it closes. */
export function Wizard() {
  const t = useScreenT(messages);
  const queryClient = useQueryClient();
  const [step, setStep] = useState<Step>(1);
  const [phase, setPhase] = useState<Phase>("form");
  const [name, setName] = useState("");
  const [hosts, setHosts] = useState<string[]>([]);
  const [phrase, setPhrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [generated, setGenerated] = useState<string[] | null>(null);
  const [generating, setGenerating] = useState(false);
  const [generateFailed, setGenerateFailed] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState("");
  const [failure, setFailure] = useState<UiError | null>(null);
  const [opening, setOpening] = useState(false);
  const heading = useRef<HTMLDivElement>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      createFlowStore.set(false);
    };
  }, []);

  const strength = useStrength(step === 2 ? phrase : "", [name]);
  const bench = useBenchmark(step === 3 && phase === "form");

  // Move focus to the new step heading after a step change (not on first paint).
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    heading.current?.querySelector<HTMLElement>("h1")?.focus();
  }, [step, phase]);

  const go = (next: Step) => setStep(next);

  const generate = useCallback(async () => {
    setGenerating(true);
    setGenerateFailed(false);
    try {
      const text = await ipc.passphraseGenerate(PHRASE_WORDS);
      if (!mounted.current) return;
      setPhrase(text);
      setConfirm(text);
      setGenerated(text.split(/\s+/).filter(Boolean));
    } catch {
      if (mounted.current) setGenerateFailed(true);
    } finally {
      if (mounted.current) setGenerating(false);
    }
  }, []);

  const create = async () => {
    if (bench.state.status !== "ready") return;
    setPhase("creating");
    setFailure(null);
    createFlowStore.set(true);
    try {
      const created = await ipc.vaultCreate(name.trim(), phrase, bench.state.tuning.params, hosts);
      if (!mounted.current) return;
      setPhrase("");
      setConfirm("");
      setGenerated(null);
      setRecoveryKey(created.recovery_key);
      setStep(4);
      setPhase("recovery");
    } catch (error) {
      createFlowStore.set(false);
      if (!mounted.current) return;
      setFailure(isIpcFailure(error) ? error.error : null);
      setPhase("failed");
    }
  };

  const open = async () => {
    setOpening(true);
    setRecoveryKey("");
    createFlowStore.set(false);
    await queryClient.invalidateQueries({ queryKey: ["vault"] });
  };

  const locked = phase === "recovery" || phase === "creating";
  let body;
  if (phase === "creating") {
    body = (
      <div className="state-block" role="status" aria-busy="true">
        <GateMark size={48} mode="spin" />
        <h1 id="create-h" tabIndex={-1}>
          {t("creating.title")}
        </h1>
        <ul className="progress-list">
          <li><span className="status warn" />{t("creating.step1")}</li>
          <li><span className="status warn" />{t("creating.step2")}</li>
          <li><span className="status warn" />{t("creating.step3")}</li>
        </ul>
        <p className="small muted">{t("creating.note")}</p>
      </div>
    );
  } else if (phase === "failed") {
    body = (
      <div className="state-block" role="alert">
        <Icon name="shieldAlert" size={32} />
        <h1 id="create-h" tabIndex={-1}>
          {t("fail.title")}
        </h1>
        {failure && <p>{errorText(failure)}</p>}
        <p>{t("fail.body")}</p>
        {failure && failure.fields.length > 0 && (
          <ul className="problem-list" aria-label={t("fail.fields")}>
            {failure.fields.map((f, i) => (
              <li key={i}>
                <code>{f.field}</code> {f.problem}
              </li>
            ))}
          </ul>
        )}
        <div className="actions">
          <Button
            variant="primary"
            icon="refresh"
            onClick={() => {
              setPhase("form");
            }}
          >
            {t("fail.retry")}
          </Button>
        </div>
        {failure && <span className="code">{t("fail.line", { command: failure.command, code: failure.code })}</span>}
      </div>
    );
  } else if (step === 1) {
    body = <NameStep name={name} onName={setName} hosts={hosts} onHosts={setHosts} onNext={() => go(2)} />;
  } else if (step === 2) {
    body = (
      <PhraseStep
        phrase={phrase}
        confirm={confirm}
        onPhrase={(v) => {
          setPhrase(v);
          setGenerated(null);
        }}
        onConfirm={setConfirm}
        strength={strength}
        generated={generated}
        generating={generating}
        generateFailed={generateFailed}
        onGenerate={() => void generate()}
        onBack={() => go(1)}
        onNext={() => go(3)}
      />
    );
  } else if (step === 3) {
    body = <CostStep bench={bench.state} onRun={bench.run} onBack={() => go(2)} onCreate={() => void create()} />;
  } else {
    body = <RecoveryStep recoveryKey={recoveryKey} opening={opening} onOpen={() => void open()} />;
  }

  return (
    <div className="wizard">
      <aside className="rail" aria-label={t("rail.label")}>
        <div className="row-inline">
          <GateMark size={36} />
          <span className="word">Cerberus</span>
        </div>
        <Rings step={step} />
        <ol className="steplist">
          {STEP_KEYS.map((key, i) => {
            const n = (i + 1) as Step;
            const state = n < step ? "done" : n === step ? "now" : "todo";
            const reachable = !locked && n < step;
            return (
              <li key={key}>
                <button
                  type="button"
                  className={state}
                  aria-current={n === step ? "step" : undefined}
                  disabled={!reachable && n !== step}
                  onClick={() => reachable && go(n)}
                >
                  <span className="n" aria-hidden="true">{state === "done" ? <Icon name="check" size={13} /> : n}</span>
                  {t(key)}
                </button>
              </li>
            );
          })}
        </ol>
        <p className="small muted">{t("rail.note")}</p>
      </aside>
      <div ref={heading} className="pane-wrap">
        {body}
      </div>
    </div>
  );
}
