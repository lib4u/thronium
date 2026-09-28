import { useEffect, useState } from 'react';
import type { Snapshot } from '../api';
import { BASE_FONT_SIZE } from '../settings/SettingsCatalog';

/** Language, theme, interface scale and connection state reflected on the document. */
export function useDocumentState(state: Snapshot) {
  useEffect(() => {
    const a = state.appearance || {},
      root = document.documentElement;
    root.dataset.compact = String(a.compact === true);
    root.dataset.reduceMotion = String(a.reduce_motion === true);
    (document.body.style as CSSStyleDeclaration & { zoom: string }).zoom = String(
      Number(a.font_size || BASE_FONT_SIZE) / BASE_FONT_SIZE,
    );
    document.body.style.fontFamily = typeof a.font === 'string' && a.font.trim() ? a.font : '';
  }, [JSON.stringify(state.appearance)]);
  const theme = useResolvedTheme(state.preferences.theme);
  useEffect(() => {
    document.documentElement.lang = state.preferences.language;
    document.documentElement.dataset.theme = theme;
  }, [state.preferences.language, theme]);
  useEffect(() => {
    document.body.className = `client-page ${state.phase === 'connected' ? '' : 'disconnected'} ${state.phase === 'reconnecting' ? 'reconnecting' : ''}`;
  }, [state.phase]);
}

/** A short message that disappears by itself. */
export function useToast() {
  const [toast, setToast] = useState('');
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(''), 2800);
    return () => clearTimeout(timer);
  }, [toast]);
  return [toast, setToast] as const;
}

/** The theme actually shown: "system" follows the operating system's light or
 * dark mode and changes with it. */
export function useResolvedTheme(choice: string): 'light' | 'dark' {
  const query = '(prefers-color-scheme: dark)';
  const [systemDark, setSystemDark] = useState(() => window.matchMedia?.(query).matches ?? false);
  useEffect(() => {
    const media = window.matchMedia?.(query);
    if (!media) return;
    const changed = () => setSystemDark(media.matches);
    media.addEventListener('change', changed);
    return () => media.removeEventListener('change', changed);
  }, []);
  if (choice === 'system') return systemDark ? 'dark' : 'light';
  return choice === 'dark' ? 'dark' : 'light';
}
