import { useCallback, useEffect, useRef, useState } from "react";
import type { KdfTuningView, StrengthView } from "../../bindings";
import { ipc, isIpcFailure, type UiError } from "../../ipc/client";

export type StrengthState =
  | { status: "empty" }
  | { status: "checking" }
  | { status: "error" }
  | { status: "ready"; view: StrengthView };

const STRENGTH_DEBOUNCE_MS = 150;

interface StrengthAnswer {
  key: string;
  view: StrengthView | null;
}

/**
 * Strength of the phrase, asked from the backend 150 ms after the last key. The phrase goes only to the IPC call.
 * The answer is kept with the question it belongs to, so a late answer never shows for a newer phrase.
 * That key sits in this hook's state, which has the same life as the phrase state of the caller.
 * `userInputs` makes the name a weak guess.
 */
export function useStrength(phrase: string, userInputs: readonly string[]): StrengthState {
  const [answer, setAnswer] = useState<StrengthAnswer | null>(null);
  const inputsKey = userInputs.join("\n");
  const key = `${inputsKey}\u0000${phrase}`;
  useEffect(() => {
    if (phrase === "") return;
    let live = true;
    const timer = setTimeout(() => {
      ipc
        .passphraseStrength(phrase, inputsKey ? inputsKey.split("\n") : [])
        .then((view) => live && setAnswer({ key, view }))
        .catch(() => live && setAnswer({ key, view: null }));
    }, STRENGTH_DEBOUNCE_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [phrase, inputsKey, key]);
  if (phrase === "") return { status: "empty" };
  if (answer?.key !== key) return { status: "checking" };
  return answer.view ? { status: "ready", view: answer.view } : { status: "error" };
}

export type BenchState =
  | { status: "running" }
  | { status: "error"; error: UiError | null }
  | { status: "ready"; tuning: KdfTuningView };

interface BenchAnswer {
  run: number;
  state: BenchState;
}

/** Runs `kdf_benchmark` when `active` turns on (once), and again on `run()`. */
export function useBenchmark(active: boolean): { state: BenchState; run: () => void } {
  const [runs, setRuns] = useState(0);
  const [answer, setAnswer] = useState<BenchAnswer | null>(null);
  useEffect(() => {
    if (!active) return;
    let live = true;
    ipc
      .kdfBenchmark()
      .then((tuning) => live && setAnswer({ run: runs, state: { status: "ready", tuning } }))
      .catch((error: unknown) => live && setAnswer({ run: runs, state: { status: "error", error: isIpcFailure(error) ? error.error : null } }));
    return () => {
      live = false;
    };
  }, [active, runs]);
  const run = useCallback(() => setRuns((n) => n + 1), []);
  return { state: answer?.run === runs ? answer.state : { status: "running" }, run };
}

export interface PhraseGenerator {
  /** The words of the last generated phrase, until `forget`. */
  words: string[] | null;
  generating: boolean;
  failed: boolean;
  generate: () => void;
  /** Drops the words (the person typed over them, or the phrase was used). */
  forget: () => void;
}

/** Asks the backend for a word phrase (`passphrase_generate`) and hands it to `onPhrase`. A late answer after unmount is dropped. */
export function usePhraseGenerator(wordCount: number, onPhrase: (text: string) => void): PhraseGenerator {
  const [words, setWords] = useState<string[] | null>(null);
  const [generating, setGenerating] = useState(false);
  const [failed, setFailed] = useState(false);
  const mounted = useRef(true);
  const sink = useRef(onPhrase);
  useEffect(() => {
    sink.current = onPhrase;
  });
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const generate = useCallback(() => {
    setGenerating(true);
    setFailed(false);
    ipc
      .passphraseGenerate(wordCount)
      .then((text) => {
        if (!mounted.current) return;
        sink.current(text);
        setWords(text.split(/\s+/).filter(Boolean));
      })
      .catch(() => mounted.current && setFailed(true))
      .finally(() => mounted.current && setGenerating(false));
  }, [wordCount]);
  const forget = useCallback(() => setWords(null), []);
  return { words, generating, failed, generate, forget };
}
