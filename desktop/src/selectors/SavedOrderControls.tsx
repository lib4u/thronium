import { InlineError, Field } from '../shared/ui/controls';
import { Checkbox, Button } from '../shared/ui/controls';
import { formatDateTime } from '../shared/i18n/format.ts';
import { translate } from '../shared/i18n/index.ts';
import type { Config } from '../profiles/schema';
import type { useDynamicSelector } from './useDynamicSelector';

/** Saved HTTP order of a dynamic pool: measuring before connecting, rebuilding and ranking. */
export default function SavedOrderControls({
  controller,
}: {
  controller: ReturnType<typeof useDynamicSelector>;
}) {
  const {
    cancelMeasurement,
    change,
    config,
    current,
    disabled,
    language,
    measure,
    measurementState,
    rank,
    rankingState,
    setSource,
    source,
    translateError,
  } = controller;
  return (
    <>
      <Field
        className="feature-field span-all"
        label={translate(language, 'library.measure_and_update_order_before_connecting_2573ae3')}
      >
        <Checkbox
          type="checkbox"
          id="selector-connect-measurements"
          disabled={disabled}
          checked={source.measure_before_connect === true}
          onChange={(e) => {
            const next: Config = { ...source, measure_before_connect: e.target.checked };
            if (!e.target.checked) {
              delete next.rebuild_on_exhaustion;
              delete next.rebuild_on_subscription;
            }
            change({ ...config, member_source: next });
          }}
        />
      </Field>
      {source.measure_before_connect === true && (
        <>
          <Field
            className="feature-field span-all"
            label={translate(language, 'library.apply_subscription_replacements_automatically_8eee56b')}
          >
            <Checkbox
              type="checkbox"
              id="selector-rebuild-subscription"
              disabled={disabled}
              checked={source.rebuild_on_subscription === true}
              aria-describedby="selector-subscription-hint"
              onChange={(e) => setSource('rebuild_on_subscription', e.target.checked)}
            />
          </Field>
          <p className="field-hint span-all" id="selector-subscription-hint">
            {translate(language, 'library.keeps_the_current_connection_while_checking_repl_2f4fb9d')}
          </p>
        </>
      )}
      {source.measure_before_connect === true && (
        <Field
          className="feature-field span-all"
          label={translate(language, 'library.rebuild_when_every_running_server_fails_491e66b')}
        >
          <Checkbox
            type="checkbox"
            id="selector-rebuild-exhausted"
            disabled={disabled}
            checked={source.rebuild_on_exhaustion === true}
            aria-describedby="selector-rebuild-hint"
            onChange={(e) => setSource('rebuild_on_exhaustion', e.target.checked)}
          />
        </Field>
      )}
      {source.measure_before_connect === true && (
        <p className="field-hint" id="selector-rebuild-hint">
          {translate(language, 'library.pool_recheck_hint')}
        </p>
      )}

      <p className="field-hint">
        {translate(language, 'library.when_enabled_connection_waits_for_missing_http_c_c92c808')}
      </p>
      <p className="field-hint" id="selector-saved-order-hint">
        {translate(language, 'library.keep_eligible_servers_in_the_saved_order_append__6fa371d')}
      </p>
      <div className="selector-pool-actions">
        <Button
          type="button"
          id="selector-measure-order"
          className="text-button"
          disabled={disabled || !current?.result || rankingState?.busy || measurementState?.busy}
          onClick={() => void measure()}
        >
          {translate(language, 'library.measure_missing_checks_and_update_order_e975e85')}
        </Button>
        {measurementState?.busy && (
          <Button
            type="button"
            id="selector-cancel-measurements"
            className="text-button"
            onClick={() => cancelMeasurement(true)}
          >
            {translate(language, 'library.cancel_checks_2a9154d')}
          </Button>
        )}
      </div>
      <p className="field-hint">
        {translate(language, 'library.checks_all_matching_servers_before_both_pool_lim_329f463')}
      </p>
      {measurementState?.busy && (
        <p className="field-hint" id="selector-measure-progress" role="status">
          {measurementState.progress
            ? translate(language, 'library.selector_measure_progress', {
                phase:
                  measurementState.progress.phase === 'ranking'
                    ? translate(language, 'library.updating_order_9dd68dd')
                    : translate(language, 'library.http_checks_7bc8de1'),
                done: measurementState.progress.done,
                total: measurementState.progress.total,
                fresh: measurementState.progress.fresh,
              })
            : translate(language, 'library.preparing_checks_717cd92')}
        </p>
      )}
      {measurementState?.error && (
        <InlineError role="alert" id="selector-measure-error" className="desktop-inline-error">
          {translateError(measurementState.error)}
        </InlineError>
      )}
      <div className="selector-pool-actions">
        <Button
          type="button"
          id="selector-rank-order"
          className="text-button"
          disabled={disabled || !current?.result || rankingState?.busy || measurementState?.busy}
          onClick={() => void rank()}
        >
          {rankingState?.busy
            ? translate(language, 'library.updating_order_9dd68dd')
            : translate(language, 'library.update_order_from_http_checks_8f5ae72')}
        </Button>
        <Button
          type="button"
          id="selector-clear-order"
          className="text-button"
          disabled={disabled || measurementState?.busy || source.saved_ranking === undefined}
          onClick={() => {
            const next = { ...source };
            delete next.saved_ranking;
            change({ ...config, member_source: next });
          }}
        >
          {translate(language, 'library.clear_saved_order_f5ca2e7')}
        </Button>
      </div>
      {rankingState?.error && (
        <InlineError role="alert" id="selector-rank-order-error" className="desktop-inline-error">
          {translateError(rankingState.error)}
        </InlineError>
      )}
      {current?.result && (
        <p className="field-hint" id="selector-saved-order-count">
          {current.result.savedRankedAt == null
            ? translate(language, 'library.no_saved_order_yet_ba1a083')
            : translate(language, 'library.selector_saved_order', {
                date: formatDateTime(new Date(current.result.savedRankedAt * 1000), language),
                count: current.result.savedRankingCount ?? 0,
              })}{' '}
          {translate(language, 'library.selector_order_pool', {
            kept: current.result.savedOrderKept ?? 0,
            fresh: current.result.newCandidatesCount ?? 0,
          })}
        </p>
      )}
    </>
  );
}
