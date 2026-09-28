import { Section, Field } from '../shared/ui/controls';
import { Input, Button } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import type { SubscriptionNameRules } from '../api';
import { limits } from '../shared/api/generated/limits.ts';
const empty: SubscriptionNameRules = { include: '', exclude: '', rename: [] };
export default function NameRules({
  value = empty,
  language,
  changed,
}: {
  value?: Partial<SubscriptionNameRules>;
  language: Language;
  changed(value: SubscriptionNameRules): void;
}) {
  function rule(index: number, field: 'pattern' | 'replacement', value: string) {
    changed({
      ...current,
      rename: current.rename.map((r, i) => (i === index ? { ...r, [field]: value } : r)),
    });
  }
  const current: SubscriptionNameRules = {
    include: value?.include ?? '',
    exclude: value?.exclude ?? '',
    rename: value?.rename ?? [],
  };
  return (
    <Section
      title={<>{translate(language, 'subscriptions.filter_and_rename_servers_24393df')}</>}
      className="route-advanced"
      id="group-name-rules"
    >
      <p className="field-hint">
        {translate(language, 'subscriptions.applied_to_provider_names_on_the_next_update_bef_96341ef')}
      </p>
      <Field
        className="feature-field"
        label={translate(language, 'subscriptions.include_names_matching_regex_fe4cde1')}
      >
        <Input
          id="group-name-include"
          className="text-input mono"
          maxLength={limits.maxPatternBytes}
          spellCheck={false}
          value={current.include}
          onChange={(e) => changed({ ...current, include: e.target.value })}
        />
      </Field>
      <Field
        className="feature-field"
        label={translate(language, 'subscriptions.exclude_names_matching_regex_2552d94')}
      >
        <Input
          id="group-name-exclude"
          className="text-input mono"
          maxLength={limits.maxPatternBytes}
          spellCheck={false}
          value={current.exclude}
          onChange={(e) => changed({ ...current, exclude: e.target.value })}
        />
      </Field>
      <p className="field-hint">
        {translate(language, 'subscriptions.case_sensitive_by_default_use_i_to_ignore_case_r_0ec1ff7')}
      </p>
      {current.rename.map((r, i) => (
        <div className="editor-card" key={i} data-name-rule={i}>
          <Field
            className="feature-field"
            label={
              <>
                {translate(language, 'subscriptions.find_regex_823a249')} {i + 1}
              </>
            }
          >
            <Input
              data-name-pattern={i}
              className="text-input mono"
              maxLength={limits.maxPatternBytes}
              required
              spellCheck={false}
              value={r.pattern}
              onChange={(e) => rule(i, 'pattern', e.target.value)}
            />
          </Field>
          <Field className="feature-field" label={translate(language, 'subscriptions.replace_with_bfaeba3')}>
            <Input
              data-name-replacement={i}
              className="text-input"
              maxLength={limits.maxNameBytes}
              value={r.replacement}
              onChange={(e) => rule(i, 'replacement', e.target.value)}
            />
          </Field>
          <Button
            type="button"
            className="text-button"
            data-name-remove={i}
            onClick={() => changed({ ...current, rename: current.rename.filter((_, n) => n !== i) })}
          >
            {translate(language, 'subscriptions.remove_step_0cef0c1')}
          </Button>
        </div>
      ))}
      <Button
        type="button"
        id="group-name-add"
        className="text-button"
        disabled={current.rename.length >= limits.maxRenameRules}
        onClick={() => changed({ ...current, rename: [...current.rename, { pattern: '', replacement: '' }] })}
      >
        {translate(language, 'subscriptions.add_rename_step_d91e423')}
      </Button>
    </Section>
  );
}
