import { Button } from './shared/ui/controls';
import { useEffect, useMemo, useRef, useState } from 'react';
import { command } from './api';
import { platform } from './shared/platform.ts';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { isTauri } from '@tauri-apps/api/core';
import type { Key } from './i18n';
import './WindowChrome.css';

const edges: Parameters<ReturnType<typeof getCurrentWindow>['startResizeDragging']>[0][] = [
  'North',
  'South',
  'East',
  'West',
  'NorthEast',
  'NorthWest',
  'SouthEast',
  'SouthWest',
];

// A frameless window on Windows gets its snap layouts and system menu back
// from the host (window_chrome.rs); other systems have neither.
const windows = platform === 'windows';
const SNAP_HOVER_MS = 600;

export default function WindowChrome({ t, failed }: { t(key: Key): string; failed(): void }) {
  const native = useMemo(() => (isTauri() ? getCurrentWindow() : null), []);
  const [maximized, setMaximized] = useState(false);
  const snap = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => {
    if (!native || !windows) return;
    const menu = (event: KeyboardEvent) => {
      if (event.altKey && event.code === 'Space' && !event.ctrlKey && !event.shiftKey) {
        event.preventDefault();
        void command('windowSystemMenu', {}).catch(() => {});
      }
    };
    window.addEventListener('keydown', menu);
    return () => {
      window.removeEventListener('keydown', menu);
      clearTimeout(snap.current);
    };
  }, [native]);
  useEffect(() => {
    if (!native) return;
    let active = true;
    const update = async () => {
      try {
        const value = await native.isMaximized();
        if (active) setMaximized(value);
      } catch {
        /* Window may already be closing. */
      }
    };
    const listener = native.onResized(() => void update());
    void update();
    return () => {
      active = false;
      void listener.then((unlisten) => unlisten()).catch(() => {});
    };
  }, [native]);
  if (!native) return null;
  const run = (action: Promise<unknown>) => {
    void action.catch(failed);
  };
  return (
    <>
      <div className="window-controls" data-tauri-drag-region="false">
        <Button
          type="button"
          className="window-button"
          data-window-action="minimize"
          aria-label={t('windowMinimize')}
          title={t('windowMinimize')}
          onClick={() => run(native.minimize())}
        >
          <svg viewBox="0 0 16 16" aria-hidden="true">
            <path d="M3 8h10" />
          </svg>
        </Button>
        <Button
          type="button"
          className="window-button"
          data-window-action="maximize"
          aria-label={t(maximized ? 'windowRestore' : 'windowMaximize')}
          title={t(maximized ? 'windowRestore' : 'windowMaximize')}
          onPointerEnter={() => {
            if (!windows) return;
            clearTimeout(snap.current);
            snap.current = setTimeout(
              () => void command('windowSnapLayouts', {}).catch(() => {}),
              SNAP_HOVER_MS,
            );
          }}
          onPointerLeave={() => clearTimeout(snap.current)}
          onClick={() => {
            clearTimeout(snap.current);
            run(native.toggleMaximize());
          }}
        >
          <svg viewBox="0 0 16 16" aria-hidden="true">
            {maximized ? <path d="M5 5V3h8v8h-2M3 5h8v8H3z" /> : <path d="M3 3h10v10H3z" />}
          </svg>
        </Button>
        <Button
          type="button"
          className="window-button window-close"
          data-window-action="close"
          aria-label={t('close')}
          title={t('close')}
          onClick={() => run(native.close())}
        >
          <svg viewBox="0 0 16 16" aria-hidden="true">
            <path d="m4 4 8 8m0-8-8 8" />
          </svg>
        </Button>
      </div>
      {!maximized && (
        <div className="window-resize-handles" aria-hidden="true" data-tauri-drag-region="false">
          {edges.map((edge) => (
            <div
              key={edge}
              className={`window-resize window-resize-${edge}`}
              onMouseDown={(event) => {
                if (event.button === 0) {
                  event.preventDefault();
                  run(native.startResizeDragging(edge));
                }
              }}
            />
          ))}
        </div>
      )}
    </>
  );
}
