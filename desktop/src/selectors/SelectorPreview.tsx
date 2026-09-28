import SelectorCandidates from './SelectorCandidates';
import { InlineError } from '../shared/ui/controls';
import { Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type { useDynamicSelector } from './useDynamicSelector';
import { limits } from '../shared/api/generated/limits.ts';

/** Preview of the members a dynamic pool resolves now, with limits, rankings and candidates. */
export default function SelectorPreview({
  controller,
}: {
  controller: ReturnType<typeof useDynamicSelector>;
}) {
  const { current, disabled, language, setReload, source, translateError } = controller;
  return (
    <>
      <div className="selector-pool-actions">
        <span id="selector-preview-count">
          {translate(
            language,
            source.build_limit !== undefined
              ? 'library.selector_startup_count'
              : 'library.selector_matching_count',
            { count: current?.result ? `${current.result.total} / ${limits.maxPoolMembers}` : '—' },
          )}
        </span>
        <Button
          type="button"
          id="selector-refresh-preview"
          className="text-button"
          disabled={disabled || !current}
          onClick={() => setReload((v) => v + 1)}
        >
          {translate(language, 'library.refresh_preview_e8dc3d6')}
        </Button>
      </div>
      {current?.result?.matchingBeforePoolCap !== undefined && (
        <p className="field-hint" id="selector-pool-cap-count">
          {translate(language, 'library.selector_pool_cap_count', {
            eligible: current.result.matchingBeforePoolCap,
            kept: current.result.candidatePoolSize ?? 0,
            omitted: current.result.omittedByPoolCap ?? 0,
          })}
        </p>
      )}
      {current?.result?.matchingBeforeLimit !== undefined && (
        <p className="field-hint" id="selector-limit-count">
          {translate(
            language,
            source.pool_cap !== undefined
              ? 'library.selector_pool_limit_count'
              : 'library.selector_limit_count',
            { eligible: current.result.matchingBeforeLimit, omitted: current.result.omittedByLimit ?? 0 },
          )}
        </p>
      )}
      {!current && (
        <p role="status" id="selector-preview-loading">
          {translate(language, 'library.updating_the_list_05d5686')}
        </p>
      )}
      {current?.error && (
        <InlineError role="alert" id="selector-preview-error" className="desktop-inline-error">
          {translateError(current.error)}
        </InlineError>
      )}
      {current?.result?.total === 0 && (
        <p id="selector-preview-empty" className="field-hint">
          {translate(language, 'library.no_matching_servers_yet_you_can_save_this_pool_c_cd9cdc5')}
        </p>
      )}
      {!!current?.result?.unknownCountryCount && (
        <p id="selector-preview-unknown" className="field-hint">
          {translate(language, 'library.selector_unknown_country_count', {
            count: current.result.unknownCountryCount,
          })}
        </p>
      )}
      {current?.result?.rankedByHttp !== undefined && (
        <p className="field-hint" id="selector-ranking-summary">
          {translate(language, 'library.selector_ranking_summary', {
            ranked: current.result.rankedByHttp,
            unknown: current.result.unknownHttpCount ?? 0,
          })}
        </p>
      )}
      {current?.result?.warmCandidatesCount !== undefined && (
        <p className="field-hint" id="selector-warm-count">
          {translate(language, 'library.selector_warm_count', { count: current.result.warmCandidatesCount })}
        </p>
      )}
      {!!current?.result?.keptUnavailable && (
        <p className="field-hint" id="selector-ranking-fallback">
          {translate(language, 'library.selector_kept_unavailable', {
            count: current.result.keptUnavailable,
          })}
        </p>
      )}
      {!!current?.result?.total && <SelectorCandidates controller={controller} />}
    </>
  );
}
