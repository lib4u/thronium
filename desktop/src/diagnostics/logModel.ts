import type { LogEntry } from '../shared/api/generated/commands';
import { isMessageKey, translate } from '../shared/i18n/index.ts';
import { catalogError } from '../shared/i18n/message.ts';

/**
 * The window text of one entry. Application events are shown in the user's
 * language; core output and unknown codes keep the logged line.
 */
export function logText(entry: LogEntry, language: string): string {
  if (!entry.code) return entry.text;
  const key = `diagnostics.log_${entry.code}`;
  if (isMessageKey(key)) {
    const detail = entry.detail ?? '';
    return translate(language, key, { detail: catalogError(language, detail) ?? detail });
  }
  return catalogError(language, entry.code) ?? entry.text;
}

/** Export exactly the visible entries, including the identity of concurrent tests. */
export function formatLogEntries(entries: readonly LogEntry[]): string {
  return entries
    .map((entry) => {
      const probe = entry.probe;
      const context = probe ? ` [test ${probe.runId} ${probe.kind} ${probe.profileName}]` : '';
      return `${new Date(entry.at).toISOString()} [${entry.level.toUpperCase()}] [${entry.source}]${context} ${entry.text}${entry.truncated ? ' [truncated]' : ''}`;
    })
    .join('\n');
}
