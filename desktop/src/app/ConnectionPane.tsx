import { byteQuantity } from '../shared/i18n/format.ts';
import { translate } from '../shared/i18n/index.ts';
import { errorCode } from '../shared/api/errors.ts';
import { command } from '../api';
import SessionPane from '../connection/SessionPane';
import VpnPanel from '../connection/VpnPanel';
import SelectorPanel from '../selectors/Panel';
import type { useAppController } from '../useAppController';
export default function ConnectionPane({ controller }: { controller: ReturnType<typeof useAppController> }) {
  const {
    busy,
    modal,
    setError,
    setModal,
    setToast,
    state,
    t,
    translateError,
    connection: {
      autoSelectStatus,
      connectAction,
      current,
      openVpn,
      openVpnCredentials,
      status,
      transition,
      vpn,
    },
    profiles: { edit },
    navigation: { openSettings, setPage },
  } = controller;

  return (
    <section className="session-pane" aria-label={t('yourConnection')}>
      <SessionPane
        snapshot={state}
        profile={current}
        autoSelect={autoSelectStatus}
        busy={busy || !!state.connectionPreparation}
        status={status}
        since={state.since}
        transition={!!transition || !!state.connectionPreparation}
        downloaded={
          state.trafficAvailable
            ? byteQuantity(state.trafficDown, state.preferences.language, 'short')
            : { value: '—' }
        }
        uploaded={
          state.trafficAvailable
            ? byteQuantity(state.trafficUp, state.preferences.language, 'short')
            : { value: '—' }
        }
        t={t}
        edit={(p) => void edit(p)}
        connect={() => void connectAction(state.running ? 'disconnect' : 'connect', current?.id)}
        routing={() => setPage('routing')}
        settings={() => openSettings('inbound')}
        diagnostics={() => setPage('activity')}
        profileDiagnostics={(profile) => setModal({ type: 'diagnostics', profileId: profile.id })}
        copy={(text) =>
          void command('writeClipboard', { text })
            .then(() => setToast(translate(state.preferences.language, 'common.address_copied_700b704')))
            .catch((e) => setError(errorCode(e)))
        }
      />
      {current?.kind === 'auto-selector' && (
        <SelectorPanel
          compact
          language={state.preferences.language}
          running={state.running}
          translateError={translateError}
        />
      )}
      <VpnPanel
        status={vpn}
        profile={current}
        language={state.preferences.language}
        busy={busy || !!modal}
        open={openVpn}
        openCredentials={openVpnCredentials}
      />
    </section>
  );
}
