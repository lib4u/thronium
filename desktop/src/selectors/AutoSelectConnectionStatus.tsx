import { Icon } from '../shared/ui/Icon';
import { translate, type Language } from '../shared/i18n/index.ts';
import { profileName } from '../library/profileName';
import type { Profile } from '../api';
import type { AutoSelectStatus } from './autoSelectStatus.ts';

function Host({ profile, label }: { profile: Profile; label: string }) {
  return (
    <div className="session-auto-host" title={profile.address || profile.name}>
      <Icon name="corner-down-right" />
      <span className="session-auto-host-label">{label}</span>
      <strong>{profileName(profile.name).text || profile.name}</strong>
      {profile.address && <span className="session-auto-host-addr">{profile.address}</span>}
    </div>
  );
}

export function AutoSelectConnectionStatus({
  status,
  language,
}: {
  status?: AutoSelectStatus;
  language: Language;
}) {
  if (!status) return null;
  const split = status.udp && status.udp.id !== status.tcp?.id;
  return (
    <>
      {status.tcp && (
        <Host
          profile={status.tcp}
          label={split || status.balance ? 'TCP' : translate(language, 'connection.auto_select_current_host')}
        />
      )}
      {split && status.udp && <Host profile={status.udp} label="UDP" />}
      {status.balance && (
        <small className="session-auto-note">{translate(language, 'connection.auto_select_balancing')}</small>
      )}
      {status.needsReconnect && (
        <small className="session-auto-note" id="auto-select-reconnect-notice" role="status">
          {translate(language, 'library.auto_select_apply_on_reconnect')}
        </small>
      )}
    </>
  );
}
