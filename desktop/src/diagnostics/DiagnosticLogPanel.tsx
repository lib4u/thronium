import type { ReactNode } from 'react';
import { Button, InlineError } from '../shared/ui/controls';
import { translate, type Language, type MessageKey } from '../shared/i18n/index.ts';
import { retention } from './measurementJournalModel.ts';
import { useDiagnosticLog } from './useDiagnosticLog.ts';

type Log<E> = { entries: E[]; retentionDays: number; limit: number };
export type LogWords = Readonly<
  Record<'title' | 'hint' | 'empty' | 'loading' | 'clear' | 'confirm', MessageKey>
>;

/**
 * A bounded log the backend keeps: polled entries in a table, the retention
 * policy and a clear action that asks once more. Element ids start with `id`.
 */
export default function DiagnosticLogPanel<E extends { id: string | number }>({
  id,
  read,
  erase,
  revision,
  words,
  columns,
  row,
  language,
  translateError,
}: {
  id: string;
  read(): Promise<Log<E>>;
  erase(): Promise<unknown>;
  revision: number;
  words: LogWords;
  columns: readonly MessageKey[];
  row(entry: E): { attributes?: Record<string, string>; cells: ReactNode[] };
  language: Language;
  translateError(e: unknown): string;
}) {
  const t = (key: keyof LogWords) => translate(language, words[key]);
  const { data, loading, busy, error, confirm, clear, cancelClear } = useDiagnosticLog(read, erase, revision);
  const entries = data?.entries ?? [];
  return (
    <section className={`feature-panel desktop-section ${id}`} id={id}>
      <div className="feature-panel-head">
        <div>
          <h2>{t('title')}</h2>
          <p className="field-hint">
            {t('hint')}
            {data ? ` ${retention(language, data.retentionDays, data.limit)}` : ''}
          </p>
        </div>
      </div>
      {error && (
        <InlineError role="alert" className="desktop-inline-error" id={`${id}-error`}>
          {translateError(error)}
        </InlineError>
      )}
      {loading && !data && (
        <p className="field-hint" id={`${id}-loading`} role="status">
          {t('loading')}
        </p>
      )}
      {data && entries.length === 0 && (
        <p className="field-hint" id={`${id}-empty`}>
          {t('empty')}
        </p>
      )}
      {entries.length > 0 && (
        <>
          <div className={`feature-table-wrap desktop-section ${id}-entries`}>
            <table className="feature-table" id={`${id}-table`}>
              <thead>
                <tr>
                  {columns.map((column) => (
                    <th key={column}>{translate(language, column)}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => {
                  const { attributes, cells } = row(entry);
                  return (
                    <tr key={entry.id} {...attributes}>
                      {cells.map((cell, index) => (
                        <td key={index}>{cell}</td>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className={`feature-toolbar ${id}-actions`}>
            <Button
              type="button"
              id={`${id}-clear`}
              className={confirm ? 'button danger' : 'button secondary'}
              disabled={busy}
              onClick={() => void clear()}
            >
              {confirm ? t('confirm') : t('clear')}
            </Button>
            {confirm && (
              <Button type="button" id={`${id}-keep`} className="button secondary" onClick={cancelClear}>
                {translate(language, 'diagnostics.close_c9a286c')}
              </Button>
            )}
          </div>
        </>
      )}
    </section>
  );
}
