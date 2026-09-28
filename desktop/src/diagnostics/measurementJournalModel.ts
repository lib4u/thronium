// Row text for the measurement journal; the engine records codes, the view only labels them.
import type * as Wire from '../shared/api/generated/commands';
import { formatDateTime, formatMilliseconds, formatSpeedPair } from '../shared/i18n/format.ts';
import { plural, translate, type Language } from '../shared/i18n/index.ts';
import { kindName, memberOrigin, message as probeMessage } from '../probes/messages.ts';
import { transportLabel } from '../settings/testActionsModel.ts';

export type JournalEntry = Wire.MeasurementJournalEntry;
export type Journal = Wire.MeasurementJournal;

export const journalWords = {
  title: 'diagnostics.measurement_journal',
  hint: 'diagnostics.measurement_journal_hint',
  empty: 'diagnostics.measurement_journal_empty',
  loading: 'diagnostics.loading_journal',
  clear: 'diagnostics.clear_journal',
  confirm: 'diagnostics.clear_journal_confirm',
  single: 'diagnostics.journal_source_single',
  batch: 'diagnostics.journal_source_batch',
  autoSelect: 'diagnostics.journal_source_auto_select',
  periodic: 'diagnostics.journal_source_periodic',
  internet: 'diagnostics.journal_kind_internet',
  direct: 'settings.transport_direct',
  retention: 'diagnostics.journal_retention',
} as const;

/** Header cells in table order: when, what, on which server, how it ended, the value, who asked. */
export const journalColumns = [
  'diagnostics.journal_column_time',
  'diagnostics.journal_column_check',
  'settings.server_772c781',
  'common.status',
  'diagnostics.journal_column_result',
  'diagnostics.source_64835b1',
] as const;

const statuses = {
  ok: 'diagnostics.reachable_4209c06',
  error: 'diagnostics.failed_462dea0',
  cancelled: 'diagnostics.cancelled_2f9561b',
  stale: 'diagnostics.profile_changed_5cab20c',
  unsupported: 'diagnostics.not_supported_yet_fa3c72b',
  'connected-only': 'diagnostics.vpn_connected_no_http_response_eac115f',
  'auth-required': 'diagnostics.vpn_sign_in_required_3600a5c',
} as const;

export function kindLabel(entry: JournalEntry, language: Language) {
  return entry.kind === 'internet'
    ? translate(language, journalWords.internet)
    : kindName(entry.kind, language);
}

export function statusLabel(entry: JournalEntry, language: Language) {
  const key = statuses[entry.status as keyof typeof statuses];
  return key ? translate(language, key) : entry.status;
}

/** The measured value in one short cell: exit, speed, latency or nothing. */
export function valueText(entry: JournalEntry, language: Language) {
  if (entry.status !== 'ok') return entry.error ? probeMessage(entry.error, language) : '—';
  if (entry.kind === 'ip') return `${entry.countryCode || '?'} · ${entry.ip || '—'}`;
  if (entry.kind === 'speed') return formatSpeedPair(entry.download, entry.upload, language);
  return typeof entry.latencyMs === 'number'
    ? formatMilliseconds(entry.latencyMs, language)
    : translate(language, statuses.ok);
}

/** Profile, member and path in one cell; the direct internet check names only its path. */
export function subjectText(entry: JournalEntry, language: Language) {
  const parts = [
    entry.profileName,
    entry.memberName ? `${entry.memberName}${memberOrigin(entry.memberOrigin, language)}` : '',
  ].filter(Boolean);
  if (entry.transport) parts.push(transportLabel(entry.transport, language));
  return parts.join(' · ') || translate(language, journalWords.direct);
}

export function timeText(entry: JournalEntry, language: Language) {
  return formatDateTime(new Date(entry.at * 1000), language);
}

export function sourceLabel(entry: JournalEntry, language: Language) {
  const key =
    entry.source === 'batch'
      ? journalWords.batch
      : entry.source === 'periodic'
        ? journalWords.periodic
        : entry.source === 'auto-select'
          ? journalWords.autoSelect
          : journalWords.single;
  return translate(language, key);
}

/** "Kept for N days, up to M entries." with both counts in their plural forms. */
export function retention(language: string, days: number, limit: number): string {
  return translate(language, 'diagnostics.journal_retention', {
    days: plural(language, 'diagnostics.kept_days', days),
    entries: plural(language, 'diagnostics.up_to_entries', limit),
  });
}
