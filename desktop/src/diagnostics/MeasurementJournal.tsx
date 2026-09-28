import type { Language } from '../shared/i18n/index.ts';
import { command } from '../api';
import {
  journalColumns,
  journalWords,
  kindLabel,
  sourceLabel,
  statusLabel,
  subjectText,
  timeText,
  valueText,
} from './measurementJournalModel.ts';
import DiagnosticLogPanel from './DiagnosticLogPanel';
import './MeasurementJournal.css';

const read = () => command('getMeasurementJournal');
const erase = () => command('clearMeasurementJournal');

export default function MeasurementJournal({
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
      id="measurement-journal"
      read={read}
      erase={erase}
      revision={revision}
      words={journalWords}
      columns={journalColumns}
      language={language}
      translateError={translateError}
      row={(entry) => ({
        attributes: { 'data-journal-entry': String(entry.id), 'data-journal-status': entry.status },
        cells: [
          timeText(entry, language),
          kindLabel(entry, language),
          subjectText(entry, language),
          statusLabel(entry, language),
          valueText(entry, language),
          sourceLabel(entry, language),
        ],
      })}
    />
  );
}
