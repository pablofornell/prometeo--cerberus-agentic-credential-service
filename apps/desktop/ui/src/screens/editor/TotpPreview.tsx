import { useEffect, useState } from "react";
import type { TotpAlgorithmView } from "../../bindings";
import { useScreenT } from "../../i18n";
import { TtlRing } from "../../ui";
import { messages } from "./messages";
import { decodeBase32, groupCode, secondsLeft, totpCode } from "./totp";

interface Props {
  secret: string;
  algorithm: TotpAlgorithmView;
  digits: number;
  period: number;
}

/** The code a seed makes right now, with a ring for the seconds left. It runs only while the seed is valid. */
export function TotpPreview({ secret, algorithm, digits, period }: Props) {
  const tr = useScreenT(messages);
  const [now, setNow] = useState(() => Date.now());
  const [code, setCode] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const valid = decodeBase32(secret) !== null && period >= 15 && period <= 120;

  useEffect(() => {
    if (!valid) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [valid]);

  const step = Math.floor(now / 1000 / period);
  useEffect(() => {
    if (!valid) return;
    let live = true;
    totpCode({ secret, algorithm, digits, period }, Date.now())
      .then((next) => {
        if (!live) return;
        setCode(next);
        setFailed(next === null);
      })
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
  }, [valid, secret, algorithm, digits, period, step]);

  if (secret.trim() === "") return null;
  if (!valid) {
    return (
      <p className="problem" role="status">
        {tr("web.totp.invalid")}
      </p>
    );
  }
  if (failed) return <p className="small muted">{tr("web.totp.unavailable")}</p>;
  return (
    <div className="row-inline">
      <TtlRing total={period} left={secondsLeft(period, now)} size={28} />
      <output className="ed-preview-code" aria-label={tr("web.totp.preview")} aria-live="off">
        {code ? groupCode(code) : "…"}
      </output>
      <span className="small muted">{tr("web.totp.help")}</span>
    </div>
  );
}
