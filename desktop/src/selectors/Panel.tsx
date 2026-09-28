import { InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import { formatTime } from '../shared/i18n/format.ts';
import { errorCode } from '../shared/api/errors.ts';
import type * as Wire from '../shared/api/generated/commands';
import { useEffect, useState } from 'react';
import { command } from '../api';
import SelectorHistory from './History';
import MemberTable from './MemberTable';
import { refreshAutoSelectors, useAutoSelectorPools } from './autoSelectorPools.ts';
import { AUTO_SELECT_ID } from './autoSelectModel.ts';
import { label, type Label } from '../profiles/schema';
const messageKeys = {
  title: 'library.automatic_server_selection_4e1b800',
  empty: 'library.no_automatic_pool_is_running_8165184',
  selected: 'library.selected_0ac20d1',
  healthy: 'library.available_5a0f9c6',
  ready: 'library.ready_31b12ff',
  starting: 'library.starting_aa02b5b',
  probing: 'library.checking_bf4c568',
  suspended: 'library.local_network_unavailable_checks_paused_1143ab1',
  recheck: 'library.recheck_pool_f86ee26',
  auto: 'library.release_pin_d5c2f2c',
  pin: 'library.pin_for_this_session_e897fb3',
  pinned: 'library.pinned_179addd',
  ok: 'library.available_4ab0b47',
  degraded: 'library.degraded_1835ad5',
  untested: 'library.not_measured_58fb018',
  dead: 'library.unavailable_bb54d7f',
  cooldown: 'library.retry_later_266f54b',
  unknown: 'library.unknown_12049ad',
  balance: 'library.balancing_8140850',
  rotate: 'library.by_interval_564b177',
  connection: 'library.by_connection_3b511af',
  hint: 'library.pinning_here_lasts_until_disconnect_set_a_prefer_608bc58',
} satisfies Record<string, Label>;
type Pool = Wire.SelectorPool;
export default function SelectorPanel({
  language,
  running,
  translateError,
  revision,
  compact = false,
}: {
  language: Language;
  running: string | null;
  revision?: number;
  translateError(e: unknown): string;
  compact?: boolean;
}) {
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  // The core's own reasons, translated; an unknown one is simply not shown.
  const switchReason = (reason: string) => {
    const key = {
      initial: 'library.pool_switch_initial',
      pinned: 'library.pool_switch_pinned',
      balance: 'library.pool_switch_balance',
      best: 'library.pool_switch_best',
      failover: 'library.pool_switch_failover',
      'fallback-unqualified': 'library.pool_switch_fallback_unqualified',
      'fallback-cooldown': 'library.pool_switch_fallback_cooldown',
    }[reason];
    return key ? ` · ${translate(language, key as Parameters<typeof translate>[1])}` : '';
  };
  // Pools of another connection are not shown; an action's refresh keeps the
  // shown pools until the new reply, so the panel does not flash empty.
  const read = useAutoSelectorPools(running);
  const pools: Pool[] = read?.pools ?? [];
  const readError = read?.error === undefined ? '' : errorCode(read.error);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => setError(''), [running]);
  async function act(tag: string, action: string, member = '') {
    setBusy(true);
    setError('');
    try {
      await command('autoSelectorAction', { tag, action, member });
      refreshAutoSelectors();
    } catch (e) {
      setError(errorCode(e));
    } finally {
      setBusy(false);
    }
  }
  function state(value: string) {
    return t(
      Object.prototype.hasOwnProperty.call(messageKeys, value)
        ? (value as keyof typeof messageKeys)
        : 'unknown',
    );
  }
  if (compact && !pools.length && !readError) return null;
  return (
    <section className={`feature-panel desktop-section selector-panel ${compact ? 'selector-compact' : ''}`}>
      <div className="feature-panel-head">
        <h2>{t('title')}</h2>
      </div>
      {(error || readError) && (
        <InlineError className="desktop-inline-error" role="alert">
          {translateError(error || readError)}
        </InlineError>
      )}
      {!pools.length && <p>{t('empty')}</p>}
      {pools.map((pool) => (
        <div className="selector-status" key={pool.tag} data-selector-status={pool.tag}>
          <h3>
            {pool.profileId === AUTO_SELECT_ID ? translate(language, 'library.auto_select_title') : pool.name}
          </h3>
          <p>
            {pool.suspended ? t('suspended') : state(pool.phase)} · {t('healthy')}: {pool.membersAlive} /{' '}
            {pool.membersTotal}
          </p>
          <p>
            <strong>{t('selected')}: </strong>
            <span data-selector-selected={pool.tag}>
              {pool.members.find((m) => m.tag === pool.selected)?.name || '—'}
            </span>
          </p>
          {pool.selectedUdp !== pool.selected && (
            <p>UDP: {pool.members.find((m) => m.tag === pool.selectedUdp)?.name || '—'}</p>
          )}
          {pool.balance && (
            <p>
              {t('balance')}: {state(pool.balanceMode)}
            </p>
          )}
          <p data-selector-rounds={pool.tag}>
            {translate(language, 'library.pool_rounds', { rounds: pool.roundsCompleted })}
            {pool.probesInFlight > 0
              ? ` · ${translate(language, 'library.pool_probes_in_flight', { count: pool.probesInFlight })}`
              : ''}
            {pool.membersCooldown > 0
              ? ` · ${translate(language, 'library.pool_cooldown', { count: pool.membersCooldown })}`
              : ''}
            {pool.nextRoundMs > 0
              ? ` · ${translate(language, 'library.pool_next_round', { time: formatTime(pool.nextRoundMs, language) })}`
              : ''}
          </p>
          {pool.lastSwitchMs > 0 && (
            <p data-selector-switch={pool.tag}>
              {translate(language, 'library.pool_last_switch', {
                time: formatTime(pool.lastSwitchMs, language),
              })}
              {switchReason(pool.lastSwitchReason)}
            </p>
          )}
          {pool.rebuild && (
            <p data-selector-rebuild={pool.tag}>
              {translate(language, 'library.rebuild_after_failure_b3c0241')}: {pool.rebuild.attempts} /{' '}
              {pool.rebuild.limit}
              {pool.rebuild.paused ? translate(language, 'library.paused_reconnect_manually_f2967d9') : ''}
            </p>
          )}
          {pool.subscriptionUpdate?.pending && (
            <p data-selector-subscription={pool.tag}>
              {translate(language, 'library.subscription_update_awaiting_checks_af991d3')}:{' '}
              {pool.subscriptionUpdate.attempts} / {pool.subscriptionUpdate.limit}
              {pool.subscriptionUpdate.paused
                ? translate(language, 'library.paused_reconnect_manually_f2967d9')
                : ''}
            </p>
          )}
          <div className="selector-pool-actions">
            <Button
              className="button secondary"
              data-selector-recheck={pool.tag}
              disabled={busy}
              onClick={() => void act(pool.tag, 'recheck')}
            >
              {t('recheck')}
            </Button>
            <Button
              className="text-button"
              data-selector-auto={pool.tag}
              disabled={busy || !pool.pinned}
              onClick={() => void act(pool.tag, 'select')}
            >
              {t('auto')}
            </Button>
          </div>
          {!compact && (
            <>
              <p className="field-hint">{t('hint')}</p>
              <MemberTable
                pool={pool}
                language={language}
                busy={busy}
                stateText={state}
                translateError={translateError}
                pin={(member) => void act(pool.tag, 'select', member.tag)}
              />
            </>
          )}
        </div>
      ))}
      {!compact && (
        <SelectorHistory language={language} revision={revision} translateError={translateError} />
      )}
    </section>
  );
}
