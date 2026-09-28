import { Field } from '../shared/ui/controls';
import { Select, Input, Checkbox, NumberField } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { groupName } from '../groups/groupModel';
import type { Config } from '../profiles/schema';
import type { useDynamicSelector } from './useDynamicSelector';
import { limits } from '../shared/api/generated/limits.ts';
import { defaults } from '../shared/api/generated/defaults.ts';
import SavedOrderControls from './SavedOrderControls';
import SelectorPreview from './SelectorPreview';
export default function DynamicSelectorView({
  controller,
}: {
  controller: ReturnType<typeof useDynamicSelector>;
}) {
  const { change, config, disabled, groups, language, setSource, source, usesHttp } = controller;
  return (
    <>
      <p className="field-hint">
        {translate(language, 'library.the_pool_uses_ordinary_sing_box_xray_profiles_fr_5fffb45')}
      </p>
      <div className="feature-fields">
        <Field className="feature-field span-all" label={translate(language, 'library.source_group_a2869db')}>
          <Select
            id="selector-source-group"
            className="text-input"
            value={String(source.group_id || '')}
            disabled={disabled}
            onChange={(e) => setSource('group_id', e.target.value)}
          >
            {!groups.some((g) => g.id === source.group_id) && (
              <option value={String(source.group_id || '')}>
                {translate(language, 'library.select_a_group_42ab56e')}
              </option>
            )}
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {groupName(g, language)}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          className="feature-field"
          label={translate(language, 'library.include_names_regular_expression_bba34cb')}
        >
          <Input
            id="selector-name-regex"
            className="text-input"
            spellCheck={false}
            disabled={disabled}
            value={String(source.name_regex || '')}
            onChange={(e) => setSource('name_regex', e.target.value)}
            placeholder={translate(language, 'library.empty_all_names_aed429a')}
          />
        </Field>
        <Field
          className="feature-field"
          label={translate(language, 'library.exclude_names_regular_expression_4207e28')}
        >
          <Input
            id="selector-exclude-regex"
            className="text-input"
            spellCheck={false}
            disabled={disabled}
            value={String(source.exclude_regex || '')}
            onChange={(e) => setSource('exclude_regex', e.target.value)}
            placeholder={translate(language, 'library.empty_no_exclusions_9aa5554')}
          />
        </Field>
        <Field
          className="feature-field span-all"
          label={translate(language, 'library.measured_exit_countries_73c68a6')}
        >
          <Input
            id="selector-country-filter"
            className="text-input"
            spellCheck={false}
            disabled={disabled}
            value={String(source.country_filter || '')}
            onChange={(e) => setSource('country_filter', e.target.value)}
            placeholder="DE,NL"
            aria-describedby="selector-country-hint"
          />
        </Field>
      </div>
      <p className="field-hint" id="selector-country-hint">
        {translate(language, 'library.comma_separated_country_codes_empty_all_countrie_cfa3e5a')}
      </p>
      <p className="field-hint">
        {translate(language, 'library.name_filter_examples_germany_netherlands_or_fast_789ec7e')}
      </p>
      <div className="feature-fields">
        <Field
          className="feature-field span-all"
          label={translate(language, 'library.initial_member_order_4a9a729')}
        >
          <Select
            id="selector-member-order"
            className="text-input"
            disabled={disabled}
            value={String(source.order ?? 'library')}
            onChange={(e) => {
              const next: Config = { ...source, order: e.target.value };
              if (e.target.value !== 'saved-http-latency') {
                delete next.measure_before_connect;
                delete next.rebuild_on_exhaustion;
                delete next.rebuild_on_subscription;
              }
              change({ ...config, member_source: next });
            }}
          >
            <option value="library">{translate(language, 'library.library_order_bb590b2')}</option>
            <option value="http-latency">{translate(language, 'library.fresh_http_latency_00b8b88')}</option>
            <option value="saved-http-latency">
              {translate(language, 'library.saved_http_order_6684fa5')}
            </option>
          </Select>
        </Field>
        <Field
          className="feature-field span-all"
          label={translate(language, 'library.exclude_recent_http_failures_d9a5f46')}
        >
          <Checkbox
            type="checkbox"
            id="selector-exclude-unavailable"
            disabled={disabled}
            checked={source.exclude_unavailable === true}
            onChange={(e) => setSource('exclude_unavailable', e.target.checked)}
          />
        </Field>
        <Field
          className="feature-field span-all"
          label={translate(language, 'library.save_core_health_measurements_8fb87ea')}
        >
          <Checkbox
            type="checkbox"
            id="selector-persist-health"
            disabled={disabled}
            checked={source.persist_health === true}
            aria-describedby="selector-health-hint"
            onChange={(e) => setSource('persist_health', e.target.checked)}
          />
        </Field>
        <Field
          className="feature-field span-all"
          label={translate(language, 'library.use_saved_measurements_at_startup_b057a96')}
        >
          <Checkbox
            type="checkbox"
            id="selector-warm-start"
            disabled={disabled}
            checked={source.warm_start === true}
            aria-describedby="selector-warm-hint"
            onChange={(e) => setSource('warm_start', e.target.checked)}
          />
        </Field>
        <Field
          className="feature-field span-all"
          label={translate(language, 'library.limit_servers_at_startup_2a5efbd')}
        >
          <Checkbox
            type="checkbox"
            id="selector-limit-enabled"
            disabled={disabled}
            checked={source.build_limit !== undefined}
            aria-describedby="selector-limit-hint"
            onChange={(e) => {
              const next = { ...source };
              if (e.target.checked) next.build_limit = defaults.dynamicPool.buildLimit;
              else {
                delete next.build_limit;
                delete next.pool_cap;
              }
              change({ ...config, member_source: next });
            }}
          />
        </Field>
        {source.build_limit !== undefined && (
          <Field
            className="feature-field span-all"
            label={translate(language, 'library.maximum_servers_at_startup_6304828')}
          >
            <NumberField
              type="number"
              id="selector-build-limit"
              className="text-input"
              min="1"
              max={limits.maxPoolMembers}
              step="1"
              required
              disabled={disabled}
              value={source.build_limit === null ? '' : String(source.build_limit)}
              onChange={(e) =>
                setSource('build_limit', e.target.value === '' ? null : Number(e.target.value))
              }
            />
          </Field>
        )}
        {source.build_limit !== undefined && (
          <Field
            className="feature-field span-all"
            label={translate(language, 'library.limit_candidate_pool_size_06db9e1')}
          >
            <Checkbox
              type="checkbox"
              id="selector-pool-cap-enabled"
              disabled={disabled}
              checked={source.pool_cap !== undefined}
              aria-describedby="selector-pool-cap-hint"
              onChange={(e) => {
                const next = { ...source };
                if (e.target.checked) next.pool_cap = defaults.dynamicPool.poolCap;
                else delete next.pool_cap;
                change({ ...config, member_source: next });
              }}
            />
          </Field>
        )}
        {source.build_limit !== undefined && source.pool_cap !== undefined && (
          <Field
            className="feature-field span-all"
            label={translate(language, 'library.maximum_candidate_pool_size_2614287')}
          >
            <NumberField
              type="number"
              id="selector-pool-cap"
              className="text-input"
              min="1"
              max={limits.maxPoolCandidates}
              step="1"
              required
              disabled={disabled}
              value={source.pool_cap === null ? '' : String(source.pool_cap)}
              onChange={(e) => setSource('pool_cap', e.target.value === '' ? null : Number(e.target.value))}
            />
          </Field>
        )}
        {usesHttp && (
          <Field
            className="feature-field span-all"
            label={translate(language, 'library.measurement_lifetime_minutes_fa38711')}
          >
            <NumberField
              type="number"
              id="selector-result-validity"
              className="text-input"
              min="0"
              max={limits.maxResultValidityMinutes}
              step="1"
              required
              disabled={disabled}
              value={
                source.result_validity_mins === undefined
                  ? 60
                  : source.result_validity_mins === null
                    ? ''
                    : String(source.result_validity_mins)
              }
              onChange={(e) =>
                setSource('result_validity_mins', e.target.value === '' ? null : Number(e.target.value))
              }
            />
          </Field>
        )}
      </div>
      {source.order === 'saved-http-latency' && <SavedOrderControls controller={controller} />}
      {source.persist_health === true && (
        <p className="field-hint" id="selector-health-hint">
          {translate(language, 'library.saves_the_average_delay_of_new_core_http_checks__9405396')}
        </p>
      )}
      {source.build_limit !== undefined && (
        <p className="field-hint" id="selector-limit-hint">
          {translate(language, 'library.build_limit_hint')}
        </p>
      )}
      {source.pool_cap !== undefined && (
        <p className="field-hint" id="selector-pool-cap-hint">
          {translate(language, 'library.after_filters_and_ordering_keep_up_to_this_many__b6c83c7')}
        </p>
      )}
      {source.warm_start === true && (
        <p className="field-hint" id="selector-warm-hint">
          {translate(language, 'library.core_starts_with_saved_http_measurements_their_a_249a659')}
        </p>
      )}
      {usesHttp && (
        <p className="field-hint" id="selector-ranking-hint">
          {translate(language, 'library.uses_completed_http_checks_of_this_pool_s_health_6919999')}
        </p>
      )}
      <SelectorPreview controller={controller} />
    </>
  );
}
