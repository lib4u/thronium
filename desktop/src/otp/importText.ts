import { limits } from '../shared/api/generated/limits.ts';
const maxBytes = limits.maxOtpTextBytes;
const lines = (text: string) =>
  text
    .split(/[\r\n]+/)
    .map((line) => line.trim())
    .filter(Boolean);
const migrationOnly = (values: string[]) =>
  values.length > 0 && values.every((line) => /^otpauth-migration:\/\//i.test(line));

// Successive QR scans form one reviewable import. The native parser checks batch
// identities and completeness; only an exact rescan is discarded here.
export function stageImportText(previous: string, incoming: string): string {
  if (new TextEncoder().encode(incoming).length > maxBytes) throw 'otp_text_too_large';
  const before = lines(previous),
    next = lines(incoming);
  const result =
    migrationOnly(next) && (!before.length || migrationOnly(before))
      ? [...new Set([...before, ...next])].join('\n')
      : incoming;
  if (new TextEncoder().encode(result).length > maxBytes) throw 'otp_text_too_large';
  return result;
}
