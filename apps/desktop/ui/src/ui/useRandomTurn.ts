import { useEffect, useRef, useState } from "react";

interface RandomTurnOptions {
  /** Shortest and longest wait between two turns. */
  minMs?: number;
  maxMs?: number;
  /** How long `turning` stays true: the length of the CSS one-shot (`gate-mark--turn`). */
  turnMs?: number;
  /** Source of randomness in [0, 1); injected by tests. */
  random?: () => number;
}

/**
 * True for `turnMs` at random moments, one every `minMs`..`maxMs`, just for looks (the logo gives a single turn).
 * Timers are cleared on unmount. With `prefers-reduced-motion` the moment passes without turning.
 */
export function useRandomTurn({ minMs = 20_000, maxMs = 60_000, turnMs = 1800, random = Math.random }: RandomTurnOptions = {}): boolean {
  const [turning, setTurning] = useState(false);
  const rand = useRef(random);
  useEffect(() => {
    rand.current = random;
  });
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    const wait = () => {
      timer = setTimeout(() => {
        if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return wait();
        setTurning(true);
        timer = setTimeout(() => {
          setTurning(false);
          wait();
        }, turnMs);
      }, minMs + rand.current() * (maxMs - minMs));
    };
    wait();
    return () => clearTimeout(timer);
  }, [minMs, maxMs, turnMs]);
  return turning;
}
