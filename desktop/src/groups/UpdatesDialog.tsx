import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { useState } from 'react';
import { command, type Snapshot } from '../api';
import { Modal } from '../ui';
import { tr, message, jobText } from './messages';
import { jobActive, jobHasCounts, jobNeedsAttention } from './jobStatus';
export default function UpdatesDialog({
  snapshot,
  close,
  changed,
  review,
  translateError,
}: {
  snapshot: Snapshot;
  close(): void;
  changed(): Promise<void>;
  review(id: string): void;
  translateError(e: unknown): string;
}) {
  const language = snapshot.preferences.language;
  const t = (key: Parameters<typeof tr>[0]) => tr(key, language);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useMessageState(language, (value) => message(value, language, translateError));
  const jobs = snapshot.subscriptionJobs;
  const active = jobs.filter((j) => jobActive(j.status)).length;
  async function run(
    name: 'startSubscriptionUpdates' | 'cancelSubscriptionUpdates' | 'clearSubscriptionJobs',
  ) {
    setBusy(true);
    setError('');
    try {
      await command(name);
      await changed();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      className="desktop-import-modal subscription-updates-modal"
      title={t('updates')}
      description={t('queueHint')}
      close={close}
      closeLabel={t('close')}
      footer={
        <>
          <Button className="text-button" onClick={close}>
            {t('close')}
          </Button>
          {active > 0 ? (
            <Button
              id="subscription-cancel-jobs"
              className="button secondary"
              disabled={busy}
              onClick={() => void run('cancelSubscriptionUpdates')}
            >
              {t('cancelQueue')}
            </Button>
          ) : (
            <Button
              id="subscription-update-all"
              className="button primary"
              disabled={busy || !snapshot.groups.some((g) => g.subscribed)}
              onClick={() => void run('startSubscriptionUpdates')}
            >
              {t('updateAll')}
            </Button>
          )}
        </>
      }
    >
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
      <div className="import-summary">
        <span role="status">
          {t('pending')}: {active} · {t('finished')}: {jobs.length - active}
        </span>
        {jobs.some((j) => !jobActive(j.status)) && (
          <Button
            id="subscription-clear-jobs"
            className="text-button"
            disabled={busy}
            onClick={() => void run('clearSubscriptionJobs')}
          >
            {t('clearHistory')}
          </Button>
        )}
      </div>
      {!jobs.length && <p className="resource-empty">{t('emptyQueue')}</p>}
      <div className="subscription-job-list">
        {jobs.map((job) => (
          <article
            key={job.id}
            className="subscription-job"
            data-subscription-job={job.id}
            data-job-group={job.groupId}
            data-job-status={job.status}
          >
            <div className="subscription-job-head">
              <strong>{job.groupName}</strong>
              <span>{jobText(job, language)}</span>
            </div>
            <small>{t(job.scheduled ? 'scheduled' : 'manualUpdate')}</small>
            {/* One pass over all servers: its length is unknown, so the bar is indeterminate. */}
            {(job.status === 'geodata' || job.status === 'checking') && (
              <progress aria-label={t(job.status)} />
            )}
            {job.status === 'checking' && <p className="field-hint">{t('checkingHint')}</p>}
            {jobHasCounts(job.status) && (
              <p className="field-hint" data-job-counts={job.id}>
                {(['added', 'updated', 'removed', 'kept'] as const)
                  .map((key) => `${t(key)}: ${job.counts[key]}`)
                  .concat(
                    (['skipped', 'warned'] as const)
                      .filter((key) => job.counts[key] > 0)
                      .map((key) => `${t(key)}: ${job.counts[key]}`),
                  )
                  .join(' · ')}
              </p>
            )}
            {job.error && (
              <p className="desktop-inline-error" role={job.status === 'error' ? 'alert' : undefined}>
                {message(job.error, language, translateError)}
              </p>
            )}
            {job.counts.kept > 0 && <p className="field-hint">{t('protectedEntries')}</p>}
            {jobNeedsAttention(job.status) &&
              snapshot.groups.some((g) => g.id === job.groupId && g.subscribed) && (
                <Button
                  className="text-button"
                  data-job-review={job.groupId}
                  onClick={() => review(job.groupId)}
                >
                  {t('reviewUpdate')}
                </Button>
              )}
          </article>
        ))}
      </div>
    </Modal>
  );
}
