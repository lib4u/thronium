import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { formatBytes, formatDateTime, formatDate } from '../shared/i18n/format.ts';
import { translate, type Language } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useState } from 'react';
import { command } from '../api';
import { ConfirmDialog } from '../ui';
type Entry = Wire.TrafficHistoryEntry;
export default function ExtraActions({
  section,
  language,
  translateError,
}: {
  section: string;
  language: Language;
  translateError(e: unknown): string;
}) {
  const [busy, setBusy] = useState(false),
    [error, setError] = useMessageState(language, translateError),
    [history, setHistory] = useState<Entry[]>(),
    [confirm, setConfirm] = useState(false),
    [release, setRelease] = useState<{
      version: string;
      publishedAt: string;
      url: string;
      prerelease: boolean;
    }>();
  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  const totals = history?.reduce(
    (a, e) => ({ upload: a.upload + e.upload, download: a.download + e.download }),
    { upload: 0, download: 0 },
  );
  const bytes = (n: number) => formatBytes(n, language);
  return (
    <div className="settings-extra-actions">
      {section === 'logging' && (
        <>
          <Button
            className="button secondary"
            disabled={busy}
            onClick={() => void run(async () => setHistory(await command('trafficHistory')))}
          >
            {translate(language, 'settings.view_traffic_history_e760fdd')}
          </Button>
          {history && (
            <>
              <p>
                {translate(language, 'settings.uploaded_59736e4')}: {bytes(totals!.upload)} ·{' '}
                {translate(language, 'settings.downloaded_7c1d546')}: {bytes(totals!.download)}
              </p>
              <div className="settings-history">
                <table>
                  <thead>
                    <tr>
                      <th>{translate(language, 'settings.hour_2032a17')}</th>
                      <th>{translate(language, 'settings.process_817a3ed')}</th>
                      <th>↑</th>
                      <th>↓</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history
                      .slice(-100)
                      .reverse()
                      .map((e, i) => (
                        <tr key={i}>
                          <td>{formatDateTime(new Date(e.hour * 1000), language)}</td>
                          <td>{e.process || '—'}</td>
                          <td>{bytes(e.upload)}</td>
                          <td>{bytes(e.download)}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
              <Button className="text-button" disabled={busy} onClick={() => setConfirm(true)}>
                {translate(language, 'settings.clear_traffic_history_ba22156')}
              </Button>
            </>
          )}
          {confirm && (
            <ConfirmDialog
              title={translate(language, 'settings.clear_traffic_history_483af2b')}
              cancelLabel={translate(language, 'settings.cancel_bf4c449')}
              confirmLabel={translate(language, 'settings.clear_d9605aa')}
              cancel={() => setConfirm(false)}
              busy={busy}
              confirm={() =>
                void run(async () => {
                  await command('clearTrafficHistory');
                  setHistory([]);
                  setConfirm(false);
                })
              }
            />
          )}
        </>
      )}
      {section === 'system' && (
        <>
          <Button
            className="button secondary"
            disabled={busy}
            onClick={() => void run(async () => setRelease(await command('checkUpstreamRelease')))}
          >
            {translate(language, 'settings.check_throne_releases_ff9e028')}
          </Button>
          <p className="field-hint">
            {translate(language, 'settings.checks_the_upstream_project_thronium_and_its_cor_6d510ce')}
          </p>
          {release && (
            <p>
              {release.version} {release.prerelease ? `· ${translate(language, 'settings.prerelease')}` : ''}{' '}
              · {formatDate(new Date(release.publishedAt), language)}{' '}
              <Button
                className="text-button"
                onClick={() =>
                  void run(async () => {
                    await command('writeClipboard', { text: release.url });
                  })
                }
              >
                {translate(language, 'settings.copy_release_link_c04eaa4')}
              </Button>
            </p>
          )}
        </>
      )}
      {error && (
        <InlineError role="alert" className="desktop-inline-error">
          {error}
        </InlineError>
      )}
    </div>
  );
}
