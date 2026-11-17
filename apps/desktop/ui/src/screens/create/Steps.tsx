import { useState, type FormEvent, type ReactNode } from "react";
import type { KdfParamsView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { Button, Checkbox, Chip, Field, Icon, IconButton, Input, Notice } from "../../ui";
import type { BenchState, StrengthState } from "./hooks";
import { messages } from "./messages";

export const DEFAULT_NAMES = ["localhost", "127.0.0.1", "::1"] as const;
const NAME_MAX = 64;
const HOST_PATTERN = /^[A-Za-z0-9:._-]{1,253}$/;

export const MIN_PHRASE_LENGTH = 12;

function Nav({ children }: { children: ReactNode }) {
  return <div className="nav-row">{children}</div>;
}

interface NameStepProps {
  name: string;
  onName: (name: string) => void;
  hosts: string[];
  onHosts: (hosts: string[]) => void;
  onNext: () => void;
}

export function NameStep({ name, onName, hosts, onHosts, onNext }: NameStepProps) {
  const t = useScreenT(messages);
  const [touched, setTouched] = useState(false);
  const [extra, setExtra] = useState("");
  const [extraProblem, setExtraProblem] = useState<string | undefined>();
  const trimmed = name.trim();
  const problem = trimmed === "" ? t("name.problem.empty") : trimmed.length > NAME_MAX ? t("name.problem.long") : undefined;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!problem) onNext();
  };
  const addHost = () => {
    const value = extra.trim();
    if (value === "") return;
    if (!HOST_PATTERN.test(value)) {
      setExtraProblem(t("hosts.add.problem"));
      return;
    }
    if (![...DEFAULT_NAMES, ...hosts].includes(value)) onHosts([...hosts, value]);
    setExtra("");
    setExtraProblem(undefined);
  };

  return (
    <form className="pane" noValidate onSubmit={submit}>
      <h1 id="create-h" tabIndex={-1}>
        {t("name.title")}
      </h1>
      <p className="lede">{t("name.lede")}</p>
      <Field label={t("name.label")} hint={t("name.hint")} {...(touched && problem ? { problem } : {})}>
        {(control) => (
          <Input
            {...control}
            large
            autoFocus
            autoComplete="name"
            value={name}
            maxLength={NAME_MAX + 16}
            onChange={(e) => onName(e.target.value)}
          />
        )}
      </Field>
      <details>
        <summary className="secondary">{t("hosts.summary")}</summary>
        <div className="stack host-box">
          <p className="small muted">{t("hosts.body")}</p>
          <ul className="chip-list">
            {[...DEFAULT_NAMES, ...hosts].map((host) => (
              <li key={host}>
                <Chip className="mono">{host}</Chip>
                {hosts.includes(host) && (
                  <IconButton icon="x" size="sm" label={t("hosts.remove", { name: host })} onClick={() => onHosts(hosts.filter((h) => h !== host))} />
                )}
              </li>
            ))}
          </ul>
          <div className="input-row">
            <Field label={t("hosts.add.label")} className="grow" {...(extraProblem ? { problem: extraProblem } : {})}>
              {(control) => (
                <Input
                  {...control}
                  mono
                  value={extra}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(e) => setExtra(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      addHost();
                    }
                  }}
                />
              )}
            </Field>
            <Button icon="plus" onClick={addHost}>
              {t("hosts.add.button")}
            </Button>
          </div>
        </div>
      </details>
      <Nav>
        <span />
        <Button variant="primary" size="lg" type="submit">
          {t("continue")}
        </Button>
      </Nav>
    </form>
  );
}

interface PhraseStepProps {
  phrase: string;
  confirm: string;
  onPhrase: (value: string) => void;
  onConfirm: (value: string) => void;
  strength: StrengthState;
  generated: string[] | null;
  generating: boolean;
  generateFailed: boolean;
  onGenerate: () => void;
  onBack: () => void;
  onNext: () => void;
}

const WORD_COUNT = 7;

export function PhraseStep(props: PhraseStepProps) {
  const { phrase, confirm, strength, generated } = props;
  const t = useScreenT(messages);
  const [show, setShow] = useState(false);
  const longEnough = phrase.length >= MIN_PHRASE_LENGTH;
  const score = strength.status === "ready" ? strength.view.score : null;
  const strongEnough = strength.status === "ready" && strength.view.acceptable;
  const matches = phrase !== "" && phrase === confirm;
  const ready = longEnough && strongEnough && matches;
  const type = show ? "text" : "password";

  let line: string;
  let lineTone: "muted" | "danger" | "ok" = "muted";
  if (strength.status === "empty") line = t("phrase.strength.empty");
  else if (strength.status === "checking") line = t("phrase.strength.checking");
  else if (strength.status === "error") {
    line = t("phrase.strength.error");
    lineTone = "danger";
  } else {
    const s = strength.view.score;
    line = t(`phrase.strength.${Math.min(4, Math.max(0, s))}` as "phrase.strength.0");
    if (strength.view.guesses_log10 !== null) line += ` ${t("phrase.guesses", { n: Math.floor(strength.view.guesses_log10) })}`;
    lineTone = strength.view.acceptable ? "ok" : "danger";
  }

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (ready) props.onNext();
  };

  return (
    <form className="pane" noValidate onSubmit={submit}>
      <h1 id="create-h" tabIndex={-1}>
        {t("phrase.title")}
      </h1>
      <p className="lede">{t("phrase.lede")}</p>
      <Field label={t("phrase.label")}>
        {(control) => (
          <div className="input-row">
            <Input
              {...control}
              large
              mono
              autoFocus
              type={type}
              autoComplete="new-password"
              spellCheck={false}
              aria-describedby="phrase-strength phrase-reqs"
              value={phrase}
              onChange={(e) => props.onPhrase(e.target.value)}
            />
            <Button size="lg" icon="refresh" loading={props.generating} onClick={props.onGenerate}>
              {t("phrase.generate")}
            </Button>
          </div>
        )}
      </Field>
      <div className="meter" data-score={score ?? ""} aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span />
      </div>
      <div className="between small">
        <span id="phrase-strength" className={`strength ${lineTone}`} role="status">
          {line}
        </span>
        <Checkbox label={t("phrase.show")} checked={show} onChange={(e) => setShow(e.target.checked)} />
      </div>
      <ul className="reqs" id="phrase-reqs">
        <Req ok={longEnough} text={t("phrase.req.length")} />
        <Req ok={strongEnough} text={t("phrase.req.score")} hint={!strongEnough && phrase !== "" && strength.status === "ready" ? t("phrase.req.score.hint") : undefined} />
        <Req ok={matches} text={t("phrase.req.match")} />
      </ul>
      {props.generateFailed && <p className="problem"><Icon name="alert" />{t("phrase.generate.error")}</p>}
      {generated && (
        <div className="field">
          <span className="label">{t("phrase.generated.label", { count: WORD_COUNT })}</span>
          <ul className="words">
            {generated.map((word, i) => (
              <li key={i}>{word}</li>
            ))}
          </ul>
          <span className="hint">{t("phrase.generated.hint")}</span>
        </div>
      )}
      <Field label={t("phrase.again")} {...(confirm !== "" && !matches ? { problem: t("phrase.mismatch") } : {})}>
        {(control) => (
          <Input
            {...control}
            large
            mono
            type={type}
            autoComplete="new-password"
            spellCheck={false}
            value={confirm}
            onChange={(e) => props.onConfirm(e.target.value)}
          />
        )}
      </Field>
      <Nav>
        <Button variant="ghost" size="lg" onClick={props.onBack}>
          {t("back")}
        </Button>
        <Button variant="primary" size="lg" type="submit" disabled={!ready} aria-disabled={!ready}>
          {t("continue")}
        </Button>
      </Nav>
    </form>
  );
}

function Req({ ok, text, hint }: { ok: boolean; text: string; hint?: string | undefined }) {
  return (
    <li className={ok ? "yes" : "no"}>
      <Icon name={ok ? "check" : "x"} />
      <span>
        {text}
        {hint ? `. ${hint}` : ""}
      </span>
    </li>
  );
}

const mib = (kib: number) => Math.round(kib / 1024);

export function costSummary(params: KdfParamsView) {
  return { memory: `${mib(params.m_cost_kib)} MiB`, passes: String(params.t_cost), lanes: String(params.p_cost) };
}

interface CostStepProps {
  bench: BenchState;
  onRun: () => void;
  onBack: () => void;
  onCreate: () => void;
}

export function CostStep({ bench, onRun, onBack, onCreate }: CostStepProps) {
  const t = useScreenT(messages);
  let body: ReactNode;
  if (bench.status === "running") {
    body = (
      <div className="notice info" role="status" aria-busy="true">
        <span className="spinner" aria-hidden="true" />
        <div className="grow">{t("cost.running")}</div>
      </div>
    );
  } else if (bench.status === "error") {
    body = (
      <Notice tone="bad" title={t("cost.error.title")}>
        {t("cost.error.body")}
        {bench.error && <span className="code block">{bench.error.command}: {bench.error.code}</span>}
      </Notice>
    );
  } else {
    const { params, measured_ms } = bench.tuning;
    const c = costSummary(params);
    const seconds = measured_ms / 1000;
    const tone = seconds > 1.2 ? "warn" : "ok";
    body = (
      <>
        <dl className="bench" aria-label={t("cost.group")}>
          <div>
            <dt className="small muted">{t("cost.memory")}</dt>
            <dd>{c.memory}</dd>
          </div>
          <div>
            <dt className="small muted">{t("cost.passes")}</dt>
            <dd>{c.passes}</dd>
          </div>
          <div>
            <dt className="small muted">{t("cost.lanes")}</dt>
            <dd>{c.lanes}</dd>
          </div>
          <div>
            <dt className="small muted">{t("cost.time")}</dt>
            <dd>{`${seconds.toFixed(2)} s`}</dd>
          </div>
        </dl>
        <Notice tone={tone} title={seconds > 1.2 ? t("cost.slow") : seconds < 0.4 ? t("cost.fast") : t("cost.ok")} />
      </>
    );
  }
  return (
    <section className="pane" aria-labelledby="create-h">
      <h1 id="create-h" tabIndex={-1}>
        {t("cost.title")}
      </h1>
      <p className="lede">{t("cost.lede")}</p>
      {body}
      <Button icon="refresh" className="self-start" disabled={bench.status === "running"} onClick={onRun}>
        {t("cost.again")}
      </Button>
      <Notice tone="info" title={t("cost.next")} />
      <Nav>
        <Button variant="ghost" size="lg" onClick={onBack}>
          {t("back")}
        </Button>
        <Button variant="primary" size="lg" icon="shield" disabled={bench.status !== "ready"} onClick={onCreate}>
          {t("cost.create")}
        </Button>
      </Nav>
    </section>
  );
}
