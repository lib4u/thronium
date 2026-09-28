import { Button } from '../shared/ui/controls';
import type { ProbeBatch } from '../api';
import { active, tr, methodName, kindName, type Language } from './messages';

export default function PingStatus({
  batch,
  language,
  busy,
  cancel,
  clear,
  settings,
}: {
  batch: ProbeBatch | null;
  language: Language;
  busy: boolean;
  cancel(): void;
  clear(): void;
  settings(): void;
}) {
  if (!batch) return null;
  const t = (key: Parameters<typeof tr>[0]) => tr(key, language);
  const entries = batch.entries;
  const pending = entries.filter((e) => active(e.status)).length;
  const failed = entries.filter((e) => e.status === 'error').length;
  const connected = entries.filter((e) => e.status === 'connected-only').length;
  const auth = entries.filter((e) => e.status === 'auth-required').length;
  const cancelled = entries.filter((e) => e.status === 'cancelled').length;
  const unsupported = entries.filter((e) => e.status === 'unsupported').length;
  return (
    <div id="ping-status" className="library-ping-status" data-ping-batch={batch.id}>
      <div className="library-ping-summary">
        <span role="status">
          {t(pending ? 'running' : 'finished')} · {batch.source === 'periodic' ? `${t('periodic')} · ` : ''}
          {batch.kind === 'latency'
            ? methodName(batch.method, language)
            : kindName(batch.kind, language)} · {entries.length - pending}/{entries.length}
          {failed > 0 && ` · ${t('failedCount')}: ${failed}`}
          {connected > 0 && ` · ${t('connectedCount')}: ${connected}`}
          {auth > 0 && ` · ${t('authCount')}: ${auth}`}
          {cancelled > 0 && ` · ${t('cancelled')}: ${cancelled}`}
          {unsupported > 0 && ` · ${t('unsupported')}: ${unsupported}`}
        </span>
        <div className="library-ping-actions">
          {pending ? (
            <Button id="probe-cancel" className="text-button" disabled={busy} onClick={cancel}>
              {t('cancel')}
            </Button>
          ) : (
            <Button id="probe-clear" className="text-button" disabled={busy} onClick={clear}>
              {t('clear')}
            </Button>
          )}
          <Button id="ping-open-settings" className="text-button" onClick={settings}>
            {t('openSettings')}
          </Button>
        </div>
      </div>
      {pending > 0 && (
        <progress
          className="probe-progress"
          value={entries.length - pending}
          max={entries.length}
          aria-label={t('completed')}
        />
      )}
    </div>
  );
}
