import { useRef, useState } from 'react';
import { translate } from '../shared/i18n/index.ts';
import type { PageId } from '../AppModel';
import type { RoutingImportRequest } from '../routing/catalog';

// Settings navigation requested by another page: a section, optionally the
// id of the control to expand and focus there.
export type SettingsFocus = { section: string; input?: string };
export const navigationLocked = () => !!document.querySelector('[data-navigation-locked="true"]');

/** The shown workspace page and requests to open a place on another page. */
export function useNavigation(language: string, notify: (text: string) => void) {
  const [page, showPage] = useState<PageId>('connection');
  const pageRef = useRef(page);
  pageRef.current = page;
  const [settingsFocus, setSettingsFocus] = useState<SettingsFocus>();
  const [routingImport, setRoutingImport] = useState<RoutingImportRequest>();
  /**
   * Leaving a page unmounts it, so a page with unsaved changes keeps the user
   * and says why; navigation, hotkeys and tray requests all pass through here.
   */
  const setPage = (next: PageId) => {
    if (next !== pageRef.current && navigationLocked()) {
      notify(translate(language, 'common.navigation_locked'));
      return false;
    }
    showPage(next);
    return true;
  };
  return {
    page,
    setPage,
    /** Opens Settings on a section, optionally focusing one of its inputs. */
    openSettings(section: string, input?: string) {
      if (setPage('settings')) setSettingsFocus({ section, input });
    },
    settingsFocus,
    settingsNavigated: () => setSettingsFocus(undefined),
    /** Opens the routing profile loader on a country catalog or a received link. */
    openRoutingImport(request: RoutingImportRequest) {
      if (setPage('routing')) setRoutingImport(request);
    },
    routingImport,
    routingImportOpened: () => setRoutingImport(undefined),
  };
}
export type Navigation = ReturnType<typeof useNavigation>;
