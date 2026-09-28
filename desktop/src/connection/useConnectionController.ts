import { useEffect, useRef, useState, type Dispatch, type SetStateAction } from 'react';
import { command, empty, type Snapshot, type VpnChallengeRequest } from '../api';
import type { CredentialRequest } from './vpnCredentials';
import type { ModalState, Translate } from '../AppModel';
import { connectionStatus, type Transition } from './connectionStatus';
export function useConnectionController({
  state,
  modal,
  setModal,
  perform,
  t,
}: {
  state: Snapshot;
  modal: ModalState;
  setModal: Dispatch<SetStateAction<ModalState>>;
  perform(action: () => Promise<unknown>, done?: () => void): Promise<void>;
  t: Translate;
}) {
  const action = useRef(false);
  const [transition, setTransition] = useState<Transition>(null);
  const vpn = state.vpn || empty.vpn;
  const status = connectionStatus(state, transition, t);
  const pendingVpn = vpn.endpoints.find((endpoint) => endpoint.challengeId);
  function openVpnCredentials(request: CredentialRequest) {
    if (modal || document.querySelector('dialog[open]')) return;
    setModal({ type: 'vpn-credentials', request });
  }
  function openVpn(request: VpnChallengeRequest) {
    if (modal || document.querySelector('dialog[open]')) return;
    setModal({ type: 'vpn-auth', request });
  }
  useEffect(() => {
    if (modal?.type !== 'vpn-auth') return;
    const endpoint =
      vpn.sessionId === modal.request.sessionId
        ? vpn.endpoints.find((e) => e.tag === modal.request.endpointTag)
        : undefined;
    if (!endpoint?.challengeId) {
      setModal(null);
      return;
    }
    if (endpoint.challengeId !== modal.request.challengeId) {
      setModal({ type: 'vpn-auth', request: { ...modal.request, challengeId: endpoint.challengeId } });
    }
  }, [vpn, modal]);
  async function connectAction(name: 'connect' | 'disconnect', id?: string) {
    if (action.current) return;
    action.current = true;
    setTransition(name === 'connect' ? 'connecting' : 'disconnecting');
    try {
      await perform(async () => {
        if (name === 'disconnect') await command('disconnect');
        else {
          if (!id) throw new Error('profile_not_found');
          await command('connect', { id });
        }
      });
    } finally {
      action.current = false;
      setTransition(null);
    }
  }
  return {
    vpn,
    connectionStatus: status,
    pendingVpn,
    openVpnCredentials,
    openVpn,
    connectAction,
    transition,
  };
}
