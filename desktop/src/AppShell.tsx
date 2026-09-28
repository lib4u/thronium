import DialogHost from './app/DialogHost';
import WorkspacePages from './app/WorkspacePages';
import LibraryPane from './app/LibraryPane';
import ConnectionPane from './app/ConnectionPane';
import Notices from './app/Notices';
import { Button } from './shared/ui/controls';
import { translate } from './shared/i18n/index.ts';
import { LocaleProvider } from './shared/i18n/react';
import { pages } from './AppModel';
import mark from './assets/mark.svg';
import WindowChrome from './WindowChrome';
import { Icon } from './ui';
import type { useAppController } from './useAppController';
import { useResolvedTheme } from './app/useDocumentState';
export default function AppShell({ controller }: { controller: ReturnType<typeof useAppController> }) {
  const {
    busy,
    setError,
    state,
    t,
    navigation: { page, setPage },
    profiles: { toggleAppearance },
  } = controller;
  const theme = useResolvedTheme(state.preferences.theme);
  return (
    <LocaleProvider language={state.preferences.language}>
      <div className="app-shell">
        <div className="workspace">
          <header className="topbar" data-tauri-drag-region="deep">
            <a
              className="client-wordmark"
              href="#"
              onClick={(e) => {
                e.preventDefault();
                setPage('connection');
              }}
            >
              <img src={mark} alt="" />
              <span>
                thronium<span className="wordmark-period">.</span>
              </span>
            </a>
            <nav className="primary-nav" aria-label={t('connection')}>
              {pages.map(({ id, label, icon }) => (
                <Button
                  className={`nav-link ${page === id ? 'active' : ''}`}
                  key={id}
                  onClick={() => setPage(id)}
                  aria-current={page === id ? 'page' : undefined}
                >
                  <Icon name={icon} />
                  <span>{translate(state.preferences.language, label)}</span>
                </Button>
              ))}
            </nav>
            <div className="topbar-actions">
              <Button
                className="icon-button"
                aria-label={t('theme')}
                title={t('theme')}
                disabled={busy}
                onClick={() => void toggleAppearance('theme')}
              >
                <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
              </Button>
              <Button
                className="desktop-language"
                aria-label={t('language')}
                disabled={busy}
                onClick={() => void toggleAppearance('language')}
              >
                {state.preferences.language.toUpperCase()}
              </Button>
            </div>
            <WindowChrome t={t} failed={() => setError('window_action_failed')} />
          </header>
          <Notices controller={controller} />
          {page === 'connection' ? (
            <main className="client-workspace compact-session">
              <ConnectionPane controller={controller} />
              <LibraryPane controller={controller} />
            </main>
          ) : (
            <WorkspacePages controller={controller} />
          )}
        </div>
      </div>

      <DialogHost controller={controller} />
    </LocaleProvider>
  );
}
