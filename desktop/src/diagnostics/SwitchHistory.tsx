import type { Language } from '../shared/i18n/index.ts';
import { command } from '../api';
import { changeText, poolText, switchColumns, switchWords, timeText } from './switchHistoryModel.ts';
import DiagnosticLogPanel from './DiagnosticLogPanel';

const read = () => command('getSwitchHistory');
const erase = () => command('clearSwitchHistory');

export default function SwitchHistory({
  language,
  revision = 0,
  translateError,
}: {
  language: Language;
  revision?: number;
  translateError(e: unknown): string;
}) {
  return (
    <DiagnosticLogPanel
      id="switch-history"
      read={read}
      erase={erase}
      revision={revision}
      words={switchWords}
      columns={switchColumns}
      language={language}
      translateError={translateError}
      row={(entry) => ({
        attributes: { 'data-switch-entry': String(entry.id) },
        cells: [timeText(entry, language), poolText(entry, language), changeText(entry, language)],
      })}
    />
  );
}
