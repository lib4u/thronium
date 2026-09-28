import './LogsPanel.css';
import { InlineError, Field } from '../shared/ui/controls';
import { Input, Select, Button, Checkbox } from '../shared/ui/controls';
import { formatTime } from '../shared/i18n/format.ts';
import { translate, type Language } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useRef, useState } from 'react';
import { command } from '../api';
import { label, type Label } from '../profiles/schema';
import { formatLogEntries, logText } from './logModel';
import { limits } from '../shared/api/generated/limits.ts';

const messageKeys = {
  title: 'diagnostics.core_log_a3be850',
  hint: 'diagnostics.messages_from_this_application_session_including_4e08528',
  search: 'diagnostics.search_log_371c965',
  severity: 'diagnostics.level_9c55705',
  source: 'diagnostics.source_64835b1',
  scope: 'diagnostics.log_scope',
  session: 'diagnostics.log_session',
  tests: 'diagnostics.log_tests',
  all: 'diagnostics.all_c9a970f',
  info: 'diagnostics.information_3b56127',
  warn: 'diagnostics.warnings_d4bf021',
  error: 'diagnostics.errors_9546b09',
  debug: 'diagnostics.debug_f44d59a',
  trace: 'diagnostics.trace_e33de04',
  app: 'diagnostics.application_c79eec6',
  stdout: 'diagnostics.core_stdout_3de7d58',
  stderr: 'diagnostics.core_stderr_d23bcd5',
  pause: 'diagnostics.pause_updates_e7a6848',
  resume: 'diagnostics.resume_updates_53eab40',
  follow: 'diagnostics.scroll_to_new_messages_f0c97d7',
  clear: 'diagnostics.clear_d9605aa',
  copy: 'diagnostics.copy_visible_20ad4de',
  save: 'diagnostics.save_visible_f0eb906',
  empty: 'diagnostics.no_log_messages_yet_they_appear_when_the_core_st_dec2212',
  noMatches: 'diagnostics.no_messages_match_these_filters_a820466',
  truncated: 'diagnostics.long_message_truncated_7ff1db7',
  memory: 'diagnostics.visible_logs_hint',
  copied: 'diagnostics.visible_messages_copied_050c010',
  saved: 'diagnostics.log_file_saved_a269dad',
} satisfies Record<string, Label>;
type View = Wire.LogView;
export default function LogsPanel({
  language,
  translateError,
}: {
  language: Language;
  translateError(e: unknown): string;
}) {
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const [view, setView] = useState<View>({ entries: [], total: 0, matching: 0, dropped: 0, revision: 0 });
  const [search, setSearch] = useState('');
  const [level, setLevel] = useState('all');
  const [source, setSource] = useState('all');
  const [scope, setScope] = useState('all');
  const [paused, setPaused] = useState(false);
  const [follow, setFollow] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [readError, setReadError] = useState('');
  const area = useRef<HTMLUListElement>(null);
  const wasPaused = useRef(false);
  useEffect(() => {
    let stopped = false;
    void command('settings')
      .then((s) => {
        if (!stopped) setFollow(s.logging?.log_auto_scroll !== false);
      })
      .catch(() => {});
    return () => {
      stopped = true;
    };
  }, []);
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    let revision = -1;
    const poll = async () => {
      try {
        const next = await command('getLogs', { search, level, source, scope });
        if (!stopped) {
          if (revision !== next.revision) {
            revision = next.revision;
            setView(next);
          }
          setReadError('');
        }
      } catch (e) {
        if (!stopped) setReadError(errorCode(e));
      }
      if (!stopped && !paused) timer = setTimeout(poll, 1000);
    };
    // Pausing keeps the entries on screen; filters changed while paused still apply.
    const justPaused = paused && !wasPaused.current;
    wasPaused.current = paused;
    if (!justPaused) timer = setTimeout(() => void poll(), 100);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [search, level, source, scope, paused, refresh]);
  useEffect(() => {
    if (follow && area.current) area.current.scrollTop = area.current.scrollHeight;
  }, [view, follow]);
  const text = () => formatLogEntries(view.entries);
  async function run(task: () => Promise<void>) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await task();
    } catch (e) {
      setError(errorCode(e));
    } finally {
      setBusy(false);
    }
  }
  const clear = () =>
    run(async () => {
      await command('clearLogs');
      setRefresh((n) => n + 1);
    });
  /** Hands the shown messages to the clipboard or a file the user picks. */
  const deliver = (name: 'writeClipboard' | 'exportLogs') =>
    run(async () => setNotice((await command(name, { text: text() })).status));
  return (
    <section className="feature-panel desktop-section core-log-panel" id="core-logs">
      <div className="feature-panel-head">
        <div>
          <h2>{t('title')}</h2>
          <p className="field-hint">{t('hint')}</p>
        </div>
      </div>
      <div className="core-log-filters">
        <Field className="feature-field" label={t('search')}>
          <Input
            id="log-search"
            className="text-input"
            type="search"
            maxLength={limits.maxLogSearchBytes}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </Field>
        <Field className="feature-field" label={t('severity')}>
          <Select
            id="log-level"
            className="text-input"
            value={level}
            onChange={(e) => setLevel(e.target.value)}
          >
            {(['all', 'error', 'warn', 'info', 'debug', 'trace'] as const).map((key) => (
              <option key={key} value={key}>
                {t(key)}
              </option>
            ))}
          </Select>
        </Field>
        <Field className="feature-field" label={t('source')}>
          <Select
            id="log-source"
            className="text-input"
            value={source}
            onChange={(e) => setSource(e.target.value)}
          >
            {(['all', 'app', 'stdout', 'stderr'] as const).map((key) => (
              <option key={key} value={key}>
                {t(key)}
              </option>
            ))}
          </Select>
        </Field>
        <Field className="feature-field" label={t('scope')}>
          <Select id="log-scope" value={scope} onChange={(e) => setScope(e.target.value)}>
            {(['all', 'session', 'tests'] as const).map((key) => (
              <option key={key} value={key}>
                {t(key)}
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <div className="core-log-actions">
        <Button
          id="log-pause"
          className="text-button"
          aria-pressed={paused}
          onClick={() => setPaused(!paused)}
        >
          {t(paused ? 'resume' : 'pause')}
        </Button>
        <label className="import-toggle">
          <Checkbox
            id="log-follow"
            type="checkbox"
            checked={follow}
            onChange={(e) => setFollow(e.target.checked)}
          />
          {t('follow')}
        </label>
        <Button id="log-clear" className="text-button" disabled={busy} onClick={() => void clear()}>
          {t('clear')}
        </Button>
        <Button
          id="log-copy"
          className="text-button"
          disabled={busy || !view.entries.length}
          onClick={() => void deliver('writeClipboard')}
        >
          {t('copy')}
        </Button>
        <Button
          id="log-save"
          className="text-button"
          disabled={busy || !view.entries.length}
          onClick={() => void deliver('exportLogs')}
        >
          {t('save')}
        </Button>
      </div>
      {(error || readError) && (
        <InlineError className="desktop-inline-error" role="alert">
          {translateError(error || readError)}
        </InlineError>
      )}
      {(notice === 'copied' || notice === 'saved') && (
        <p className="import-valid" id="log-notice" role="status">
          {t(notice)}
        </p>
      )}
      <p className="field-hint" id="log-count">
        {translate(language, view.dropped > 0 ? 'diagnostics.log_count_discarded' : 'diagnostics.log_count', {
          shown: view.entries.length,
          total: view.matching,
          discarded: view.dropped,
        })}
      </p>
      <ul className="core-log-entries mono" ref={area} aria-label={t('title')}>
        {view.entries.map((e) => (
          <li key={e.id} data-log-id={e.id} data-log-level={e.level} data-log-code={e.code}>
            <span className="core-log-meta">
              <time dateTime={new Date(e.at).toISOString()}>{formatTime(new Date(e.at), language)}</time>
              <b>{e.level.toUpperCase()}</b>
              <span>{e.source}</span>
              {e.probe && (
                <span className="core-log-probe" title={e.probe.runId}>
                  {t('tests')} · {e.probe.profileName} · {e.probe.kind.toUpperCase()} ·{' '}
                  {e.probe.runId.slice(0, 8)}
                </span>
              )}
            </span>
            <span className="core-log-text">
              {logText(e, language)}
              {e.truncated && <em> [{t('truncated')}]</em>}
            </span>
          </li>
        ))}
      </ul>
      {!view.entries.length && <p className="resource-empty">{t(view.total ? 'noMatches' : 'empty')}</p>}
      <p className="field-hint">{t('memory')}</p>
    </section>
  );
}
