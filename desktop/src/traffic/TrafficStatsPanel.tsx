import { useEffect, useState } from 'react';
import { Button, Select } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import { formatBytes } from '../shared/i18n/format.ts';
import { command } from '../api';
import type * as Wire from '../shared/api/generated/commands';
import { applicationLabel, bars, periodKeys, periods, profileLabel, type Period } from './statsModel';

type Tab = 'profiles' | 'applications';

/** Qt's traffic statistics dialog: a period, its chart and two breakdowns. */
export default function TrafficStatsPanel({ language }: { language: Language }) {
  const [period, setPeriod] = useState<Period>(1);
  const [tab, setTab] = useState<Tab>('profiles');
  const [stats, setStats] = useState<Wire.TrafficStats>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const t = (key: string, params?: Record<string, number | string>) =>
    translate(language, key as Parameters<typeof translate>[1], params);

  async function load(days: Period) {
    setBusy(true);
    setError('');
    try {
      setStats(
        await command('trafficStats', {
          days,
          // The buckets are drawn on the viewer's own calendar, as in Qt.
          utcOffsetMinutes: -new Date().getTimezoneOffset(),
        }),
      );
    } catch (e) {
      setError(String(e && typeof e === 'object' && 'code' in e ? e.code : e));
    } finally {
      setBusy(false);
    }
  }
  // The period is the only thing that re-reads; a redraw of the same period is
  // the explicit Refresh.
  useEffect(() => {
    void load(period);
  }, [period]);

  const bytes = (value: number) => formatBytes(value, language, 'short');
  // Qt charts and totals follow the open tab, because a copy imported from it
  // counted servers and applications in tables of their own.
  const shown = stats && (tab === 'profiles' ? stats.profiles : stats.applications);
  const columns = bars(shown ? shown.series : [], stats?.bucketSeconds ?? 3600, language);
  const empty = shown && !shown.upload && !shown.download;
  return (
    <section className="feature-panel desktop-section" data-traffic-stats>
      <div className="feature-panel-head">
        <h2>{t('common.trafficStats')}</h2>
        <div className="traffic-stats-controls">
          <Select
            aria-label={t('common.trafficPeriod')}
            id="traffic-period"
            value={String(period)}
            disabled={busy}
            onChange={(e) => setPeriod(Number(e.target.value) as Period)}
          >
            {periods.map((days) => (
              <option key={days} value={String(days)}>
                {t(periodKeys[days])}
              </option>
            ))}
          </Select>
          <Button
            className="button secondary"
            id="traffic-refresh"
            disabled={busy}
            onClick={() => void load(period)}
          >
            {t('common.trafficRefresh')}
          </Button>
        </div>
      </div>
      {error && <p role="alert">{t(`errors.${error}`)}</p>}
      {stats && (
        <>
          <p data-traffic-totals>
            {t('common.download')}: {bytes(shown!.download)} · {t('common.upload')}: {bytes(shown!.upload)} ·{' '}
            {t('common.trafficTotal')}: {bytes(shown!.download + shown!.upload)}
          </p>
          {empty ? (
            <p data-traffic-empty>{t('common.trafficEmpty')}</p>
          ) : (
            <>
              <div className="traffic-chart" data-traffic-chart>
                {columns.map((bar) => (
                  <div
                    className="traffic-chart-column"
                    key={bar.bucket}
                    data-traffic-bucket={bar.bucket}
                    title={`${bar.label} · ${bytes(bar.download)} / ${bytes(bar.upload)}`}
                  >
                    <div className="traffic-chart-stack">
                      <div className="traffic-chart-down" style={{ height: `${bar.downloadShare * 100}%` }} />
                      <div className="traffic-chart-up" style={{ height: `${bar.uploadShare * 100}%` }} />
                    </div>
                    <span className="traffic-chart-label">{bar.labelled ? bar.label : ''}</span>
                  </div>
                ))}
              </div>
              <div className="import-tabs" role="tablist">
                {(['profiles', 'applications'] as Tab[]).map((id) => (
                  <Button
                    className={`text-button ${tab === id ? 'active' : ''}`}
                    key={id}
                    role="tab"
                    data-traffic-tab={id}
                    aria-selected={tab === id}
                    onClick={() => setTab(id)}
                  >
                    {t(id === 'profiles' ? 'common.trafficByProfile' : 'common.trafficByApplication')}
                  </Button>
                ))}
              </div>
              <div className="feature-table-wrap desktop-section">
                <table className="feature-table" data-traffic-table={tab}>
                  <thead>
                    <tr>
                      <th>{t(tab === 'profiles' ? 'common.name' : 'common.application')}</th>
                      {tab === 'profiles' && <th>{t('common.group')}</th>}
                      <th>{t('common.download')}</th>
                      <th>{t('common.upload')}</th>
                      <th>{t('common.trafficTotal')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tab === 'profiles'
                      ? stats.profiles.rows.map((row, index) => (
                          <tr key={row.other ? 'other' : row.id || index} data-traffic-row>
                            <td>{profileLabel(row, t)}</td>
                            <td>{row.group || '—'}</td>
                            <td className="mono">{bytes(row.download)}</td>
                            <td className="mono">{bytes(row.upload)}</td>
                            <td className="mono">{bytes(row.download + row.upload)}</td>
                          </tr>
                        ))
                      : stats.applications.rows.map((row, index) => (
                          <tr key={row.other ? 'other' : row.process || index} data-traffic-row>
                            <td>{applicationLabel(row, t)}</td>
                            <td className="mono">{bytes(row.download)}</td>
                            <td className="mono">{bytes(row.upload)}</td>
                            <td className="mono">{bytes(row.download + row.upload)}</td>
                          </tr>
                        ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </section>
  );
}
