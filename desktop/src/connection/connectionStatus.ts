import { translate } from '../shared/i18n/index.ts';
import { AUTO_SELECT_ID, autoSelectWords } from '../selectors/autoSelectModel.ts';
import type { Snapshot } from '../api';
import type { Translate } from '../AppModel';
import { vpnText } from './vpnMessages';

export type Transition = 'connecting' | 'disconnecting' | null;

/** The one label for the connection state, shown on the session card and the activity page. */
export function connectionStatus(state: Snapshot, transition: Transition, t: Translate): string {
  const language = state.preferences.language;
  const preparation = state.connectionPreparation;
  if (preparation)
    return translate(
      language,
      preparation.profileId !== AUTO_SELECT_ID
        ? 'common.checking_servers_db1f430'
        : preparation.reusing
          ? 'connection.auto_select_rechecking'
          : autoSelectWords.searching,
    );
  if (transition) return t(transition);
  switch (state.phase) {
    case 'connected':
      return t('connected');
    case 'reconnecting':
      return t('reconnecting');
    // Only the primary VPN endpoint reports these phases.
    case 'auth-pending':
      return vpnText('pending', language);
    case 'connecting':
      return vpnText('connecting', language);
    case 'error':
      return vpnText('error', language);
    case 'unknown':
      return vpnText('unknown', language);
    default:
      return t('disconnected');
  }
}
