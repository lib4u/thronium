// Row text for the auto-selector switch history; the engine stores names, the view only formats them.
import type * as Wire from '../shared/api/generated/commands';
import { formatDateTime } from '../shared/i18n/format.ts';
import { translate, type Language } from '../shared/i18n/index.ts';
import { AUTO_SELECT_ID, autoSelectWords } from '../selectors/autoSelectModel.ts';

export type SwitchEntry = Wire.SwitchHistoryEntry;
export type SwitchHistory = Wire.SwitchHistory;

export const switchWords = {
  title: 'diagnostics.switch_history',
  hint: 'diagnostics.switch_history_hint',
  empty: 'diagnostics.switch_history_empty',
  loading: 'diagnostics.loading_switch_history',
  clear: 'diagnostics.clear_switch_history',
  confirm: 'diagnostics.clear_switch_history_confirm',
  retention: 'diagnostics.journal_retention',
  columnTime: 'diagnostics.journal_column_time',
  columnPool: 'settings.server_772c781',
  columnChange: 'diagnostics.switch_column_change',
  first: 'diagnostics.switch_first_selection',
} as const;

export const switchColumns = [
  switchWords.columnTime,
  switchWords.columnPool,
  switchWords.columnChange,
] as const;

/** The pool column; the built-in auto-select pool is named in the interface language. */
export function poolText(entry: SwitchEntry, language: Language) {
  return entry.poolId === AUTO_SELECT_ID ? translate(language, autoSelectWords.title) : entry.poolName;
}

export function timeText(entry: SwitchEntry, language: Language) {
  return formatDateTime(new Date(entry.at * 1000), language);
}

/** The move in one cell: the pool's first selection has no origin. */
export function changeText(entry: SwitchEntry, language: Language) {
  if (!entry.fromName) return translate(language, switchWords.first, { name: entry.toName });
  return `${entry.fromName} → ${entry.toName}`;
}
