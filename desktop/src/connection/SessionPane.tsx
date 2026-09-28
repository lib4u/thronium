import { Button, IconButton } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type { Profile, Snapshot } from '../api';
import type { Key } from '../i18n';
import { Icon } from '../ui';
import { profileName } from '../library/profileName';
import { latencyParts, tooltip } from '../probes/messages';
import { vpnText } from './vpnMessages';
import './SessionPane.css';
import { AutoSelectConnectionStatus } from '../selectors/AutoSelectConnectionStatus';
import type { AutoSelectStatus } from '../selectors/autoSelectStatus';
import { protocolLabel } from '../library/rowData';
import { groupName } from '../groups/groupModel';
import { isDefaultRoutingProfile } from '../routing/model';
import { SessionClock } from './SessionClock';
import type { Quantity } from '../shared/i18n/format.ts';

type Props = {
  snapshot: Snapshot;
  profile?: Profile;
  autoSelect?: AutoSelectStatus;
  busy: boolean;
  status: string;
  since: number | null;
  transition: boolean;
  downloaded: Quantity;
  uploaded: Quantity;
  t(key: Key): string;
  edit(profile: Profile): void;
  connect(): void;
  routing(): void;
  settings(): void;
  diagnostics(): void;
  profileDiagnostics(profile: Profile): void;
  copy(text: string): void;
};

function amount({ value, unit }: Quantity) {
  return (
    <>
      {value}
      {unit && <small>{unit}</small>}
    </>
  );
}

export default function SessionPane({
  snapshot: s,
  profile,
  busy,
  status,
  since,
  transition,
  downloaded,
  uploaded,
  t,
  edit,
  connect,
  routing,
  settings,
  diagnostics,
  profileDiagnostics,
  copy,
  autoSelect,
}: Props) {
  const name = profileName(profile?.name || t('chooseProfile'));
  const group = s.groups.find((g) => g.id === profile?.groupId);
  const groupLabel = group ? groupName(group, s.preferences.language) : undefined;
  const { quantity: delay, method } = latencyParts(profile?.measurement, s.preferences.language);
  const routeName = s.routing.profileOwned
    ? t('profileConfig')
    : s.routing.providerOwned
      ? translate(s.preferences.language, 'connection.subscription_4ae2629')
      : isDefaultRoutingProfile(s.routing)
        ? t('routing')
        : s.routing.name;
  const routeHop =
    s.routing.mode === 'direct' && !s.routing.profileOwned && !s.routing.providerOwned
      ? translate(s.preferences.language, 'connection.direct_cc7ab89')
      : 'VPN';
  const mode =
    s.preferences.connectionMode === 'tun'
      ? 'TUN'
      : t(s.preferences.connectionMode === 'system-proxy' ? 'systemProxy' : 'localOnly');
  return (
    <>
      <div className="pane-heading session-heading">
        <h1>{t('connection')}</h1>
        <Button className="session-diagnostics" onClick={diagnostics}>
          {t('activity')}
          <Icon name="arrow-up-right" />
        </Button>
      </div>
      <article className="session-card" data-session-profile={profile?.id}>
        <div className="session-card-top">
          <span className="live-indicator">
            <span className="status-dot" />
            <span className="session-overline" role="status">
              {status}
            </span>
          </span>
          <span className="session-timer" title={t('session')}>
            <Icon name="clock" />
            <span>
              <SessionClock since={since} />
            </span>
          </span>
        </div>
        <div className="session-server">
          <span className={`session-server-icon${name.emoji ? ' has-emoji' : ''}`} aria-hidden="true">
            {name.emoji || <Icon name="server" />}
          </span>
          <div className="session-server-info">
            <h2 className="destination-city" title={profile?.name}>
              {name.text || name.emoji}
            </h2>
            <div className="destination-country">
              <span>{profile ? groupLabel : t('savedProfiles')}</span>
              <span className="destination-divider" />
              <span>
                {profile ? protocolLabel(profile.protocol, s.preferences.language) : '—'}
                {profile?.security ? ` · ${profile.security}` : ''}
              </span>
            </div>
            <AutoSelectConnectionStatus status={autoSelect} language={s.preferences.language} />
          </div>
          <div className="session-server-actions">
            <IconButton
              id="session-profile-diagnostics"
              className="icon-button session-server-details"
              icon="activity"
              label={translate(s.preferences.language, 'common.ip_country_and_speed_6c5c817')}
              aria-haspopup="dialog"
              disabled={busy || !profile}
              onClick={() => profile && profileDiagnostics(profile)}
            />
            <IconButton
              id="session-edit-profile"
              className="icon-button session-server-details"
              icon="sliders"
              label={t('editProfile')}
              disabled={busy || !profile}
              onClick={() => profile && edit(profile)}
            />
          </div>
        </div>
        <div className="connection-path" aria-label={t('trafficRoute')}>
          <div className="path-stop">
            <Icon name="laptop" />
            <small>{translate(s.preferences.language, 'connection.device_57687d1')}</small>
          </div>
          <span className="path-line">
            <Icon name="arrow-right" />
          </span>
          <div className="path-stop exit-stop">
            <Icon name={routeHop === 'VPN' ? 'shield-check' : 'globe'} />
            <small>{routeHop}</small>
          </div>
          <span className="path-line">
            <Icon name="arrow-right" />
          </span>
          <div className="path-stop">
            <Icon name="globe" />
            <small>{t('internet')}</small>
          </div>
        </div>
        <div className="session-metrics">
          <div title={tooltip(profile?.measurement, s.preferences.language)}>
            <span>
              <Icon name="activity" />
              {t('latency')}
            </span>
            <strong>{amount(delay)}</strong>
            {method && <small className="session-ping-method">{method}</small>}
          </div>
          <div>
            <span>
              <Icon name="arrow-down" />
              {t('download')}
            </span>
            <strong>{amount(downloaded)}</strong>
          </div>
          <div>
            <span>
              <Icon name="arrow-up" />
              {t('upload')}
            </span>
            <strong>{amount(uploaded)}</strong>
          </div>
        </div>
        <Button
          className="power-button session-connect"
          disabled={busy || (!s.running && (!profile || !s.coreAvailable))}
          aria-pressed={!!s.running}
          onClick={connect}
        >
          <Icon name="power" />
          <span>{transition ? status : t(s.running ? 'disconnect' : 'connect')}</span>
        </Button>
        <p className="session-description">
          {s.phase === 'auth-pending' || s.phase === 'connecting'
            ? vpnText('waiting', s.preferences.language)
            : s.phase === 'error'
              ? vpnText('failed', s.preferences.language)
              : s.phase === 'unknown'
                ? vpnText('vpn_status_unavailable', s.preferences.language)
                : t(
                    s.phase === 'reconnecting'
                      ? 'core_reconnecting'
                      : s.running
                        ? s.preferences.connectionMode === 'tun'
                          ? 'tunDescription'
                          : s.systemProxy.active
                            ? 'systemProxyDescription'
                            : 'description'
                        : 'idleDescription',
                  )}
        </p>
      </article>
      <section className="connection-options" aria-label={t('parameters')}>
        <div className="connection-option">
          <span className="option-icon">
            <Icon name="route" />
          </span>
          <div className="option-text">
            <strong>{t('routing')}</strong>
          </div>
          <Button className="network-mode" title={routeName} onClick={routing}>
            <span>{routeName}</span>
            <Icon name="chevron-down" />
          </Button>
        </div>
        <div className="connection-option">
          <span className="option-icon">
            <Icon name="laptop" />
          </span>
          <div className="option-text">
            <strong>{t('mode')}</strong>
          </div>
          <Button className="network-mode" title={mode} onClick={settings}>
            <span>{mode}</span>
            <Icon name="chevron-down" />
          </Button>
        </div>
        <div className="session-address">
          <span>{t('address')}</span>
          <div>
            <span className="mono" title={profile?.address}>
              {profile?.address || '—'}
            </span>
            <Button
              className="inline-icon"
              disabled={!profile?.address}
              title={translate(s.preferences.language, 'connection.copy_server_address_446c415')}
              aria-label={translate(s.preferences.language, 'connection.copy_server_address_446c415')}
              onClick={() => profile?.address && copy(profile.address)}
            >
              <Icon name="copy" />
            </Button>
          </div>
        </div>
        <div className="session-address session-proxy">
          <span>{t('localProxy')}</span>
          <div>
            <span className="mono">{s.localProxy || '—'}</span>
            <Button
              className="inline-icon"
              disabled={!s.localProxy}
              title={translate(s.preferences.language, 'connection.copy_local_proxy_address_337b3ce')}
              aria-label={translate(s.preferences.language, 'connection.copy_local_proxy_address_337b3ce')}
              onClick={() => s.localProxy && copy(s.localProxy)}
            >
              <Icon name="copy" />
            </Button>
          </div>
        </div>
      </section>
      <div className="session-footer">
        <span>
          <Icon name="shield-check" />
          {t('localData')}
        </span>
      </div>
    </>
  );
}
