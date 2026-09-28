import { Section, Select } from '../shared/ui/controls';
import { InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { formatDateTime } from '../shared/i18n/format.ts';
import { errorCode } from '../shared/api/errors.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useState } from 'react';
import { command } from '../api';
import { label, type Label } from '../profiles/schema';
import './History.css';
import type { Language } from '../shared/i18n/index.ts';
import { Pager } from '../shared/ui/Pager';

const messageKeys = {
  title: 'library.pool_startup_history_b44114a',
  hint: 'library.counts_each_time_a_server_was_included_in_a_succ_94f2e11',
  empty: 'library.no_saved_pool_startups_yet_5c09354',
  loading: 'library.loading_history_5be39e8',
  pool: 'library.pool_a15ca1f',
  last: 'library.last_startup_2fb52ef',
  members: 'library.last_startup_membership_283582d',
  builds: 'library.starts_in_the_pool_4499467',
  first: 'library.first_included_472e393',
  recent: 'library.last_included_f31ec96',
  removed: 'library.profile_deleted_4a8ac63',
  clear: 'library.clear_this_pool_s_history_30fc71e',
  confirm: 'library.delete_saved_startup_history_for_this_pool_7be5303',
  erase: 'library.delete_history_382bc58',
  cancel: 'library.cancel_bf4c449',
} satisfies Record<string, Label>;
type Pool = Wire.SelectorHistoryPool;
const PAGE_SIZE = 50;
export default function SelectorHistory({
  language,
  revision = 0,
  translateError,
}: {
  language: Language;
  revision?: number;
  translateError(e: unknown): string;
}) {
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const [open, setOpen] = useState(false),
    [pools, setPools] = useState<Pool[]>([]),
    [selected, setSelected] = useState('');
  const [reload, setReload] = useState(0),
    [loading, setLoading] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    // The page and a pending clear belong to the pool they were chosen for.
    [pageOf, setPageOf] = useState({ pool: '', page: 0, confirm: '' });
  useEffect(() => {
    if (!open) return;
    let alive = true;
    setLoading(true);
    void command('getSelectorHistory')
      .then((result) => {
        if (alive) {
          setPools(result);
          setSelected((id) => (result.some((p) => p.profileId === id) ? id : result[0]?.profileId || ''));
          setError('');
        }
      })
      .catch((e) => {
        if (alive) setError(errorCode(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [open, revision, reload]);
  const page = pageOf.pool === selected ? pageOf.page : 0,
    confirm = pageOf.pool === selected ? pageOf.confirm : '';
  const setPage = (next: number) => setPageOf({ pool: selected, page: next, confirm });
  const setConfirm = (next: string) => setPageOf({ pool: selected, page, confirm: next });
  const pool = pools.find((p) => p.profileId === selected);
  const pages = Math.max(1, Math.ceil((pool?.entries.length || 0) / PAGE_SIZE)),
    currentPage = Math.min(page, pages - 1);
  const date = (at: number) => formatDateTime(new Date(at * 1000), language);
  async function clear() {
    if (!pool || confirm !== pool.profileId) return;
    setBusy(true);
    setError('');
    try {
      await command('clearSelectorHistory', { id: pool.profileId });
      setConfirm('');
      setReload((v) => v + 1);
    } catch (e) {
      setError(errorCode(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Section
      title={<>{t('title')}</>}
      className="selector-history"
      id="selector-history"
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      <p className="field-hint">{t('hint')}</p>
      {error && (
        <InlineError role="alert" className="desktop-inline-error" id="selector-history-error">
          {translateError(error)}
        </InlineError>
      )}
      {loading && (
        <p id="selector-history-loading" role="status">
          {t('loading')}
        </p>
      )}
      {!loading && !pool && <p id="selector-history-empty">{t('empty')}</p>}
      {pool && (
        <div data-selector-history-pool={pool.profileId}>
          <label htmlFor="selector-history-pool">
            {t('pool')}
            <Select
              className=""
              id="selector-history-pool"
              value={selected}
              disabled={busy}
              onChange={(e) => setSelected(e.target.value)}
            >
              {pools.map((p) => (
                <option key={p.profileId} value={p.profileId}>
                  {p.name}
                </option>
              ))}
            </Select>
          </label>
          <p>
            {t('last')}:{' '}
            <time dateTime={new Date(pool.lastBuiltAt * 1000).toISOString()}>{date(pool.lastBuiltAt)}</time>
          </p>
          <Section
            title={
              <>
                {t('members')}: {pool.lastBuilt.length}
              </>
            }
            className="selector-history-built"
          >
            <ol>
              {pool.lastBuilt.map((id) => {
                const entry = pool.entries.find((e) => e.profileId === id);
                return (
                  <li key={id} data-selector-history-built={id}>
                    {entry?.name || id}
                    {entry?.missing ? ` · ${t('removed')}` : ''}
                  </li>
                );
              })}
            </ol>
          </Section>
          <div className="selector-history-entries">
            {pool.entries.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE).map((entry) => (
              <article key={entry.profileId} data-selector-history-member={entry.profileId}>
                <strong>{entry.name}</strong>
                {entry.missing && <small>{t('removed')}</small>}
                <p>
                  {t('builds')}: <span data-selector-history-builds={entry.profileId}>{entry.builds}</span>
                </p>
                <small>
                  {t('first')}: {date(entry.firstUsed)}
                  <br />
                  {t('recent')}: {date(entry.lastUsed)}
                </small>
              </article>
            ))}
          </div>
          {pages > 1 && (
            <Pager
              className="selector-history-actions"
              label={t('title')}
              page={currentPage}
              pages={pages}
              language={language}
              onChange={setPage}
            />
          )}
          {confirm === pool.profileId ? (
            <div className="selector-history-confirm" role="group">
              <p>{t('confirm')}</p>
              <div className="selector-history-actions">
                <Button
                  className="button secondary"
                  id="selector-history-cancel"
                  disabled={busy}
                  onClick={() => setConfirm('')}
                >
                  {t('cancel')}
                </Button>
                <Button
                  className="button danger"
                  id="selector-history-erase"
                  disabled={busy}
                  onClick={() => void clear()}
                >
                  {t('erase')}
                </Button>
              </div>
            </div>
          ) : (
            <Button
              className="text-button"
              id="selector-history-clear"
              disabled={busy}
              onClick={() => setConfirm(pool.profileId)}
            >
              {t('clear')}
            </Button>
          )}
        </div>
      )}
    </Section>
  );
}
