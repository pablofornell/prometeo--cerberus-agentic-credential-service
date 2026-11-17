/** A backup file name with today's date: `cerberus-2026-11-17.cerb`. */
export function backupName(now = new Date()): string {
  return `cerberus-${now.toISOString().slice(0, 10)}.cerb`;
}
