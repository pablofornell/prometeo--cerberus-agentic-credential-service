// TOTP code (RFC 6238) for the live preview in the form. The seed is already in the form, so the preview
// makes it no more exposed. It is computed here because the preview IPC command works on a saved item.
import type { TotpAlgorithmView } from "../../bindings";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Bytes of a Base32 text, or `null` when a character is not Base32. Spaces, dashes and `=` are ignored. */
export function decodeBase32(input: string): Uint8Array<ArrayBuffer> | null {
  const clean = input.replace(/[\s=-]/g, "").toUpperCase();
  if (clean === "") return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export interface TotpParams {
  secret: string;
  algorithm: TotpAlgorithmView;
  digits: number;
  period: number;
}

const HASH: Record<TotpAlgorithmView, string> = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

/** The code at `nowMs`, or `null` when the seed is not valid Base32 or the browser has no Web Crypto. */
export async function totpCode(params: TotpParams, nowMs: number): Promise<string | null> {
  const key = decodeBase32(params.secret);
  const subtle = globalThis.crypto?.subtle;
  if (!key || !subtle || params.period < 1) return null;
  const counter = Math.floor(nowMs / 1000 / params.period);
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  const cryptoKey = await subtle.importKey("raw", key, { name: "HMAC", hash: HASH[params.algorithm] }, false, ["sign"]);
  const mac = new Uint8Array(await subtle.sign("HMAC", cryptoKey, message));
  const last = mac[mac.length - 1] ?? 0;
  const offset = last & 0x0f;
  const binary =
    (((mac[offset] ?? 0) & 0x7f) << 24) | ((mac[offset + 1] ?? 0) << 16) | ((mac[offset + 2] ?? 0) << 8) | (mac[offset + 3] ?? 0);
  return String(binary % 10 ** params.digits).padStart(params.digits, "0");
}

/** Seconds until the code changes. */
export const secondsLeft = (period: number, nowMs: number): number => period - (Math.floor(nowMs / 1000) % period);

/** `492 113`: the code in two halves, easier to compare with an authenticator. */
export function groupCode(code: string): string {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}
