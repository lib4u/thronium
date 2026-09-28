import { messageRef } from '../shared/i18n/message';
import { useMessageState } from '../shared/i18n/react';
import { FormActions, InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { formatDate } from '../shared/i18n/format.ts';
import { translate, type Language } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useRef, useState } from 'react';
import { command } from '../api';
import { Icon } from '../ui';

type Status = Wire.DashboardStatus;

export default function DashboardCard({
  language,
  revision,
  running,
  settings,
  translateError,
}: {
  language: Language;
  revision: number | undefined;
  running: string | null;
  settings(): void;
  translateError(e: unknown): string;
}) {
  const [status, setStatus] = useState<Status>(),
    [busy, setBusy] = useState(false),
    [opening, setOpening] = useState(false),
    [cancelling, setCancelling] = useState(false),
    [error, setError] = useMessageState(language, translateError),
    [notice, setNotice] = useMessageState(language, () => '');
  const owner = useRef<string | undefined>(undefined),
    mounted = useRef(true),
    refreshId = useRef(0);
  async function refresh() {
    const id = ++refreshId.current;
    const next = await command('dashboardStatus');
    if (mounted.current && id === refreshId.current) setStatus(next);
  }
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      const requestId = owner.current;
      owner.current = undefined;
      if (requestId) void command('cancelDashboardInstallation', { requestId }).catch(() => {});
    };
  }, []);
  useEffect(() => {
    void refresh().catch((e) => {
      if (mounted.current) setError(e);
    });
  }, [revision, running]);
  async function install() {
    if (owner.current) return;
    const requestId = crypto.randomUUID();
    owner.current = requestId;
    setBusy(true);
    setCancelling(false);
    setError('');
    setNotice('');
    try {
      await command('installDashboard', { requestId });
      if (owner.current === requestId) {
        await refresh();
        if (owner.current === requestId)
          setNotice(messageRef('common.dashboard_installed_the_current_connection_is_un_77a79d4'));
      }
    } catch (e) {
      if (owner.current === requestId) {
        const key = errorCode(e);
        if (key !== 'dashboard_cancelled') setError(e);
        else setNotice(messageRef('common.installation_cancelled_2394203'));
        await refresh().catch(() => {});
      }
    } finally {
      if (owner.current === requestId) {
        owner.current = undefined;
        setBusy(false);
        setCancelling(false);
      }
    }
  }
  async function cancel() {
    const requestId = owner.current;
    if (!requestId) return;
    setCancelling(true);
    try {
      await command('cancelDashboardInstallation', { requestId });
    } catch (e) {
      if (mounted.current) {
        setError(e);
        setCancelling(false);
      }
    }
  }
  async function open() {
    setOpening(true);
    setError('');
    try {
      await command('openDashboard');
    } catch (e) {
      if (mounted.current) setError(e);
    } finally {
      if (mounted.current) setOpening(false);
    }
  }
  return (
    <article className="tool-card" id="dashboard-card">
      <Icon name="activity" />
      <h2>{translate(language, 'common.web_dashboard_022efff')}</h2>
      <p>{translate(language, 'common.open_the_sing_box_dashboard_in_your_browser_to_i_08dc730')}</p>
      <p id="dashboard-installed">
        {status?.installed
          ? translate(language, 'common.installed_on', {
              date: formatDate(new Date(status.installed.installedAt * 1000), language),
            })
          : translate(language, 'common.not_installed_e926e92')}
      </p>
      {status?.reason && <p id="dashboard-reason">{translateError(status.reason)}</p>}
      <FormActions className="feature-toolbar">
        <Button
          type="button"
          className="button secondary"
          id="dashboard-open"
          disabled={!status?.canOpen || opening}
          onClick={() => void open()}
        >
          {translate(language, 'common.open_in_browser_458cf40')}
        </Button>
        <Button
          type="button"
          className="button secondary"
          id="dashboard-install"
          disabled={busy || !status?.canInstall}
          onClick={() => void install()}
        >
          {busy
            ? translate(language, 'common.installing_977805b')
            : status?.installed
              ? translate(language, 'common.update_9c5847c')
              : translate(language, 'common.install_d0fb898')}
        </Button>
        {busy && (
          <Button
            type="button"
            className="text-button"
            id="dashboard-cancel"
            disabled={cancelling}
            onClick={() => void cancel()}
          >
            {cancelling
              ? translate(language, 'common.cancelling_4bcce1c')
              : translate(language, 'common.cancel_bf4c449')}
          </Button>
        )}
      </FormActions>
      <Button type="button" className="text-button" id="dashboard-settings" onClick={settings}>
        {translate(language, 'common.api_settings_94640b9')}
      </Button>
      <p>{translate(language, 'common.downloads_the_official_sing_box_dashboard_throug_fc69049')}</p>
      {notice && (
        <p role="status" id="dashboard-notice">
          {notice}
        </p>
      )}
      {error && (
        <InlineError role="alert" className="desktop-inline-error" id="dashboard-error">
          {error}
        </InlineError>
      )}
    </article>
  );
}
