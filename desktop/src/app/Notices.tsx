import { Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { vpnText } from '../connection/vpnMessages';
import { AUTO_SELECT_ID } from '../selectors/autoSelectModel.ts';
import { Icon } from '../ui';
import type { AppController } from '../useAppController';

/** Window-wide notices above the page: errors and states that need an action. */
export default function Notices({ controller }: { controller: AppController }) {
  const {
    busy,
    error,
    modal,
    setError,
    state,
    t,
    translateError,
    connection: {
      cancelPreparation,
      connectAction,
      openVpn,
      pendingVpn,
      restoreSystemProxy,
      transition,
      vpn,
    },
  } = controller;
  return (
    <>
      {(error || state.error) && (
        <div className="desktop-error" role="alert">
          <Icon name="info" />
          <span>{translateError(error || state.error)}</span>
          <Button className="icon-button" onClick={() => setError('')} aria-label={t('close')}>
            <Icon name="x" />
          </Button>
        </div>
      )}
      {state.systemProxy.error && (
        <div id="system-proxy-notice" className="desktop-error" role="alert">
          <Icon name="info" />
          <span>{translateError(state.systemProxy.error)}</span>
          <Button
            id="system-proxy-restore"
            className="text-button"
            disabled={busy}
            onClick={() => void restoreSystemProxy()}
          >
            {t('systemProxyRestore')}
          </Button>
        </div>
      )}
      {pendingVpn && vpn.sessionId && (
        <div id="vpn-auth-notice" className="desktop-error vpn-auth-notice" role="status">
          <Icon name="info" />
          <span>{vpnText('notice', state.preferences.language)}</span>
          <Button
            id="vpn-auth-open"
            className="text-button"
            disabled={busy || !!modal}
            onClick={() =>
              openVpn({
                sessionId: vpn.sessionId!,
                endpointTag: pendingVpn.tag,
                challengeId: pendingVpn.challengeId!,
              })
            }
          >
            {vpnText('open', state.preferences.language)}
          </Button>
        </div>
      )}
      {state.connectionPreparation && (
        <div className="desktop-error connection-preparation" role="status" id="connection-preparation">
          <span>
            {state.connectionPreparation.profileId === AUTO_SELECT_ID
              ? translate(
                  state.preferences.language,
                  state.connectionPreparation.reusing
                    ? 'library.auto_select_reusing_progress'
                    : 'library.auto_select_checking_progress',
                  { done: state.connectionPreparation.done, total: state.connectionPreparation.total },
                )
              : translate(state.preferences.language, 'common.connection_preparation_progress', {
                  name: state.connectionPreparation.name,
                  done: state.connectionPreparation.done,
                  total: state.connectionPreparation.total,
                  fresh: state.connectionPreparation.fresh,
                })}
          </span>
          <Button
            type="button"
            className="text-button"
            id="cancel-connection-preparation"
            onClick={() => cancelPreparation(state.connectionPreparation!.id)}
          >
            {translate(state.preferences.language, 'common.cancel_checks_2a9154d')}
          </Button>
        </div>
      )}
      {state.selectorSubscriptionUpdate && !state.connectionPreparation && (
        <div className="desktop-error" role="status" id="selector-subscription-pending">
          <span>
            {translate(
              state.preferences.language,
              'common.subscription_changes_have_not_reached_the_connec_5b5f30a',
            )}
            : {state.selectorSubscriptionUpdate.pools.map((p) => p.name).join(', ')}.{' '}
            {translate(state.preferences.language, 'common.previous_servers_remain_in_use_c394830')}
          </span>
          <Button
            type="button"
            className="text-button"
            id="apply-selector-subscription"
            disabled={busy || !!transition}
            onClick={() => void connectAction('connect', state.selectorSubscriptionUpdate!.profileId)}
          >
            {translate(state.preferences.language, 'common.reconnect_now_28d1fad')}
          </Button>
        </div>
      )}
    </>
  );
}
