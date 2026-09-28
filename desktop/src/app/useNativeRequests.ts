import { listen } from '@tauri-apps/api/event';
import { useEffect, useRef, type Dispatch, type SetStateAction } from 'react';
import { command } from '../api';
import type { ModalState } from '../AppModel';
import { errorCode } from '../shared/api/errors.ts';
import { translate } from '../shared/i18n/index.ts';
import { profileCatalogs } from '../routing/catalog';
import { navigationLocked, type Navigation } from './useNavigation';

/**
 * Requests from outside the window content: tray and hotkey navigation, links
 * received by the system, and the window's keyboard shortcuts. Native events
 * are subscribed once and read the current dialog and page through refs, so no
 * event is lost while listeners would be replaced.
 */
export function useNativeRequests({
  modal,
  setModal,
  navigation,
  closeMenu,
  setError,
  notify,
}: {
  modal: ModalState;
  setModal: Dispatch<SetStateAction<ModalState>>;
  navigation: Navigation;
  closeMenu(): void;
  setError(code: string): void;
  notify(text: string): void;
}) {
  const modalRef = useRef(modal);
  modalRef.current = modal;
  const dialogOpen = () => !!modalRef.current || !!document.querySelector('dialog[open]');
  const handlers = useRef({ navigation, closeMenu });
  handlers.current = { navigation, closeMenu };
  // A link or files from the system wait in the backend while a dialog is open
  // and are taken when they arrive or the dialog closes. Route links open the
  // routing profile loader, everything else the import dialog, as Qt's
  // deep link handler does.
  const takeSettingsLink = () => {
    if (dialogOpen()) return;
    void command('takeSettingsLink').then(
      (request) => {
        if (!request || dialogOpen()) return;
        if (request.kind === 'link') {
          if (!/^throne:\/\/(?:route|remoteroute)\//i.test(request.text))
            setModal({ type: 'add', initialText: request.text });
          else {
            // Unsaved settings keep the window on their page, which says why.
            handlers.current.closeMenu();
            handlers.current.navigation.openRoutingImport({ text: request.text });
          }
          return;
        }
        setModal({ type: 'add', initialDocuments: request.documents, initialProblems: request.problems });
      },
      (e: unknown) => setError(errorCode(e)),
    );
  };
  const takeLink = useRef(takeSettingsLink);
  takeLink.current = takeSettingsLink;
  useEffect(() => {
    if (!modal) takeLink.current();
  }, [modal]);
  useEffect(() => {
    let disposed = false;
    const cleanups: (() => void)[] = [];
    const subscribe = (off: Promise<() => void>) =>
      void off.then((stop) => (disposed ? stop() : cleanups.push(stop)));
    subscribe(
      listen<string>('settings-navigation', ({ payload }) => {
        if (dialogOpen()) return;
        const { navigation } = handlers.current;
        if (payload === 'hotkey_route') navigation.setPage('routing');
        else if (payload === 'hotkey_group') setModal({ type: 'groups' });
        // Qt's system proxy menu; the window owns the same three modes.
        else navigation.openSettings('inbound');
      }),
    );
    subscribe(
      listen('otp-quick-open', () => {
        if (!dialogOpen()) setModal({ type: 'otp-quick' });
      }),
    );
    subscribe(
      listen<string>('routing-import-open', ({ payload }) => {
        if (dialogOpen()) return;
        const country = profileCatalogs.find((c) => c.id === payload);
        if (!country) return;
        if (navigationLocked()) {
          notify(
            translate(
              document.documentElement.lang,
              'common.save_or_reset_your_settings_changes_before_openi_6794522',
            ),
          );
          return;
        }
        handlers.current.closeMenu();
        handlers.current.navigation.openRoutingImport({ country: country.id });
      }),
    );
    subscribe(listen('settings-link-ready', () => takeLink.current()));
    return () => {
      disposed = true;
      cleanups.forEach((stop) => stop());
    };
  }, []);
  useEffect(() => {
    const keydown = (e: KeyboardEvent) => {
      if (
        modal ||
        document.querySelector('[role=menu]') ||
        document.querySelector('dialog[open]') ||
        /INPUT|TEXTAREA|SELECT/.test((e.target as HTMLElement).tagName)
      )
        return;
      if (e.key === '/') {
        e.preventDefault();
        document.getElementById('client-search')?.focus();
      }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'n') {
        e.preventDefault();
        setModal({ type: 'add' });
      }
    };
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [modal]);
}
