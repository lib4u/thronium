import { AUTO_SELECT_ID, autoSelectSummary } from './selectors/autoSelectModel.ts';
import { useAutoSelectStatus } from './selectors/useAutoSelectStatus.ts';
import { useSnapshot } from './app/useSnapshot';
import { useConnectionController } from './connection/useConnectionController';
import { useLibraryActions } from './library/useLibraryActions';
import { nextLanguage } from './shared/i18n/index.ts';
import { errorCode } from './shared/api/errors.ts';
import { catalogError } from './shared/i18n/message.ts';
import { useEffect, useRef, useState } from 'react';
import { command, type Preferences } from './api';
import { text, hasKey } from './i18n';
import { isVpnOtpError, vpnOtpError } from './connection/vpnOtpMessages';
import { type MenuEdge } from './DropdownMenu';
import { batchText } from './profiles/BatchDialog';
import { orderText } from './library/profileOrder';
import { message as probeMessage, isProbeError } from './probes/messages';
import useSubscriptionWorker from './groups/useSubscriptionWorker';
import { ModalState, MenuState, Translate } from './AppModel';
import { useNavigation } from './app/useNavigation';
import { useLibraryView } from './app/useLibraryView';
import { useProbeActions } from './app/useProbeActions';
import { useNativeRequests } from './app/useNativeRequests';
import { useDocumentState, useToast } from './app/useDocumentState';
import { useUpdateNotice } from './app/useUpdateNotice';
export type { SettingsFocus } from './app/useNavigation';

/**
 * The application window: the snapshot, one action at a time with its error,
 * dialogs and menus, and the controllers of each area grouped by purpose.
 */
export function useAppController() {
  const [error, setError] = useState('');
  const { state, refresh } = useSnapshot(setError, (code) =>
    setError((shown) => (shown === code ? '' : shown)),
  );
  useSubscriptionWorker();
  useDocumentState(state);
  const language = state.preferences.language;
  const [toast, setToast] = useToast();
  const [modal, setModal] = useState<ModalState>(null);
  const [busy, setBusy] = useState(false);
  const actionInFlight = useRef(false);
  async function perform(action: () => Promise<unknown>, done?: () => void) {
    if (actionInFlight.current) return;
    actionInFlight.current = true;
    setBusy(true);
    setError('');
    try {
      await action();
      await refresh();
      done?.();
    } catch (e) {
      setError(errorCode(e));
      await refresh().catch(() => {});
    } finally {
      actionInFlight.current = false;
      setBusy(false);
    }
  }
  const t: Translate = (key) => text(language, key);
  function translateError(e: unknown) {
    const key = errorCode(e);
    if (key === 'invalid_profile_order') return orderText(key, language);
    if (isProbeError(key)) return probeMessage(key, language);
    if (isVpnOtpError(key)) return vpnOtpError(key, language);
    // Every registered code with a catalog text is shown, not only the codes
    // listed in the legacy key map.
    return hasKey(key) ? t(key) : (catalogError(language, key) ?? t('operation_failed'));
  }
  const navigation = useNavigation(language, setToast);
  const { page } = navigation;
  const library = useLibraryView({ state, busy, interactive: !modal && page === 'connection', perform });
  const probes = useProbeActions(state, refresh, setError);
  const [menu, setMenu] = useState<MenuState>(null);
  const menuGroup = menu?.type === 'group' ? state.groups.find((g) => g.id === menu.id) : undefined;
  const menuProfile = menu?.type === 'profile' ? state.profiles.find((p) => p.id === menu.id) : undefined;
  // An open menu belongs to the connection page and its row: it closes when a
  // dialog, an action, another page or a drag takes over, or the row is gone.
  useEffect(() => {
    if (
      menu &&
      (modal ||
        busy ||
        page !== 'connection' ||
        library.profileDrag.source ||
        (!menuGroup && !menuProfile) ||
        !menu.anchor.isConnected)
    )
      setMenu(null);
  }, [modal, busy, page, menu, menuGroup, menuProfile, library.profileDrag.source]);
  useNativeRequests({
    modal,
    setModal,
    navigation,
    closeMenu: () => setMenu(null),
    setError,
    notify: setToast,
  });
  useUpdateNotice(state, page, modal, setModal);
  const connection = useConnectionController({ state, modal, setModal, perform, t });
  const { configure, edit, clone } = useLibraryActions({ perform, setModal, language });
  const [connectionQuery, setConnectionQuery] = useState('');
  const activeId = state.running || state.selected;
  const current =
    state.profiles.find((p) => p.id === activeId) ??
    (activeId === AUTO_SELECT_ID && (state.running === AUTO_SELECT_ID || state.autoSelectAvailable)
      ? autoSelectSummary(language)
      : undefined);
  const autoSelectStatus = useAutoSelectStatus(state);
  return {
    state,
    refresh,
    t,
    translateError,
    error,
    setError,
    toast,
    setToast,
    busy,
    perform,
    modal,
    setModal,
    subscriptionGroup:
      modal?.type === 'subscription' ? state.groups.find((g) => g.id === modal.groupId) : undefined,
    navigation,
    library,
    probes,
    connection: {
      ...connection,
      status: connection.connectionStatus,
      current,
      autoSelectStatus,
      restoreSystemProxy: () => perform(() => command('restoreSystemProxy')),
      cancelPreparation(id: string) {
        void command('cancelConnectionPreparation', { id }).catch((e) => setError(errorCode(e)));
      },
    },
    activity: { connectionQuery, setConnectionQuery },
    menus: {
      menu,
      setMenu,
      menuGroup,
      menuProfile,
      openMenu(type: 'profile' | 'group', id: string, anchor: HTMLButtonElement, edge?: MenuEdge) {
        setMenu((old) => (old?.anchor === anchor && !edge ? null : { type, id, anchor, edge }));
      },
    },
    profiles: {
      edit,
      clone,
      configure,
      batchText: (key: Parameters<typeof batchText>[0]) => batchText(key, language),
      openNew: () =>
        setModal({ type: 'add', initialGroup: library.group !== 'all' ? library.group : undefined }),
      savePreferences: (preferences: Preferences) => perform(() => command('preferences', preferences)),
      toggleAppearance: (key: 'theme' | 'language') =>
        perform(async () => {
          const { appearance } = await command('settings');
          // The quick switch flips what is shown, also when that follows the system.
          const shown = document.documentElement.dataset.theme;
          const value =
            key === 'theme'
              ? shown === 'dark'
                ? 'light'
                : 'dark'
              : nextLanguage(String(appearance.language));
          await command('saveSettings', {
            section: 'appearance',
            previous: appearance,
            values: { ...appearance, [key]: value },
          });
        }),
    },
  };
}
export type AppController = ReturnType<typeof useAppController>;
