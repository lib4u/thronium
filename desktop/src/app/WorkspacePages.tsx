import { Button, SearchField } from '../shared/ui/controls';
import { formatBytes, formatSpeed } from '../shared/i18n/format.ts';
import { command } from '../api';
import SettingsPage from '../settings/Page';
import DashboardCard from '../dashboard/Card';
import { Icon } from '../ui';
import SelectorPanel from '../selectors/Panel';
import RoutingPage from '../routing/Page';
import LogsPanel from '../diagnostics/LogsPanel';
import MeasurementJournal from '../diagnostics/MeasurementJournal';
import SwitchHistory from '../diagnostics/SwitchHistory';
import ResourcesPanel from '../diagnostics/ResourcesPanel';
import TrafficStatsPanel from '../traffic/TrafficStatsPanel';
import type { useAppController } from '../useAppController';
import { SessionClock } from '../connection/SessionClock';
export default function WorkspacePages({ controller }: { controller: ReturnType<typeof useAppController> }) {
  const {
    busy,
    perform,
    refresh,
    setModal,
    state,
    t,
    translateError,
    activity: { connectionQuery, setConnectionQuery },
    connection: { connectionStatus, current },
    profiles: { edit, openNew },
    navigation: { page, routingImport, routingImportOpened, settingsNavigated, openSettings, settingsFocus },
  } = controller;

  return (
    <main>
      {page === 'routing' ? (
        <RoutingPage
          snapshot={state}
          refresh={refresh}
          translateError={translateError}
          requestedImport={routingImport}
          importOpened={() => routingImportOpened()}
        />
      ) : page === 'settings' ? (
        <SettingsPage
          snapshot={state}
          changed={refresh}
          translateError={translateError}
          requested={settingsFocus?.section}
          focus={settingsFocus?.input}
          navigated={() => settingsNavigated()}
        />
      ) : (
        <>
          <div className="page-heading">
            <div>
              <h1>{t(page)}</h1>
            </div>
          </div>
          {page === 'activity' ? (
            <>
              <ResourcesPanel language={state.preferences.language} />
              <section className="feature-panel desktop-section">
                <div className="feature-panel-head">
                  <h2>{t('session')}</h2>
                  <span className="status-tag" data-activity-connection-state={state.phase}>
                    {connectionStatus}
                  </span>
                </div>
                <dl className="desktop-details">
                  <dt>{t('name')}</dt>
                  <dd>{current?.name || '—'}</dd>
                  <dt>{t('localProxy')}</dt>
                  <dd>{state.localProxy || '—'}</dd>
                  <dt>{t('session')}</dt>
                  <dd>
                    <SessionClock since={state.since} />
                  </dd>
                  <dt>{t('download')}</dt>
                  <dd>
                    {state.trafficAvailable
                      ? formatBytes(state.trafficDown, state.preferences.language, 'short')
                      : '—'}
                  </dd>
                  <dt>{t('upload')}</dt>
                  <dd>
                    {state.trafficAvailable
                      ? formatBytes(state.trafficUp, state.preferences.language, 'short')
                      : '—'}
                  </dd>
                </dl>
              </section>
              <section className="feature-panel desktop-section">
                <div className="feature-panel-head">
                  <h2>
                    {t('connections')} · {state.connections.length}
                  </h2>
                </div>
                <SearchField
                  placeholder={t('connectionSearch')}
                  aria-label={t('connectionSearch')}
                  value={connectionQuery}
                  onChange={(e) => setConnectionQuery(e.target.value)}
                />
                <div className="feature-table-wrap desktop-section">
                  <table className="feature-table">
                    <thead>
                      <tr>
                        <th>{t('source')}</th>
                        <th>{t('application')}</th>
                        <th>{t('destination')}</th>
                        <th>{t('protocol')}</th>
                        <th>{t('trafficRoute')}</th>
                        <th>↓ / ↑</th>
                        <th>{t('speed')}</th>
                        <th>
                          <span className="sr-only">{t('closeConnection')}</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {state.connections
                        .filter((c) =>
                          `${c.process} ${c.domain} ${c.destination} ${c.protocol} ${c.outbound}`
                            .toLowerCase()
                            .includes(connectionQuery.toLowerCase()),
                        )
                        .map((c) => (
                          <tr key={c.id}>
                            <td title={c.source}>{c.source || '—'}</td>
                            <td>{c.process || '—'}</td>
                            <td title={c.destination}>{c.domain || c.destination}</td>
                            <td>{[c.network, c.protocol].filter(Boolean).join(' · ')}</td>
                            <td>{c.chain.length ? c.chain.join(' → ') : c.outbound}</td>
                            <td className="mono">
                              {formatBytes(c.download, state.preferences.language, 'short')} /{' '}
                              {formatBytes(c.upload, state.preferences.language, 'short')}
                            </td>
                            <td className="mono" data-connection-speed={c.id}>
                              {formatSpeed(c.downloadSpeed, state.preferences.language)} /{' '}
                              {formatSpeed(c.uploadSpeed, state.preferences.language)}
                            </td>
                            <td>
                              <Button
                                className="icon-button"
                                data-close-connection={c.id}
                                aria-label={t('closeConnection')}
                                disabled={busy}
                                onClick={() =>
                                  void perform(() => command('closeConnections', { ids: [c.id] }))
                                }
                              >
                                <Icon name="x" />
                              </Button>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
                {!state.connections.length && (
                  <p className="field-hint">
                    {t(
                      state.phase === 'connected' && !state.trafficAvailable ? 'noTracker' : 'noConnections',
                    )}
                  </p>
                )}
              </section>
              <TrafficStatsPanel language={state.preferences.language} />
              <SelectorPanel
                language={state.preferences.language}
                running={state.running}
                revision={state.libraryRevision}
                translateError={translateError}
              />
              <MeasurementJournal
                language={state.preferences.language}
                revision={state.libraryRevision}
                translateError={translateError}
              />
              <SwitchHistory
                language={state.preferences.language}
                revision={state.libraryRevision}
                translateError={translateError}
              />
              <LogsPanel language={state.preferences.language} translateError={translateError} />
            </>
          ) : page === 'tools' ? (
            <div className="tools-grid">
              <DashboardCard
                language={state.preferences.language}
                revision={state.libraryRevision}
                running={state.running}
                settings={() => openSettings('core')}
                translateError={translateError}
              />
              <article className="tool-card">
                <Icon name="plus" />
                <h2>{t('addConfiguration')}</h2>
                <p>{t('addConfigurationHint')}</p>
                <Button className="button secondary" onClick={openNew}>
                  <Icon name="plus" />
                  {t('add')}
                </Button>
              </article>
              <article className="tool-card">
                <Icon name="folder" />
                <h2>{t('groups')}</h2>
                <Button className="button secondary" onClick={() => setModal({ type: 'groups' })}>
                  {t('groups')}
                </Button>
              </article>
            </div>
          ) : (
            <section className="feature-panel">
              <p className="field-hint">{t('unavailable')}</p>
              {current && (
                <Button className="button secondary" onClick={() => void edit(current)}>
                  {t('profileConfig')}
                </Button>
              )}
            </section>
          )}
        </>
      )}
    </main>
  );
}
