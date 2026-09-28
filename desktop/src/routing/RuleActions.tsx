import RuleField from './RuleField';
import { Section, Field } from '../shared/ui/controls';
import { Select } from '../shared/ui/controls';
import { label } from '../profiles/schema';
import { actions, defaultTarget, type MatchField } from './model';
import { Targets } from './RuleEditorModel';
import type { useRuleEditor } from './useRuleEditor';
export default function RuleActions({ controller }: { controller: ReturnType<typeof useRuleEditor> }) {
  const {
    tr,
    action,
    busy,
    changeAction,
    language,
    profiles,
    config,
    setConfig,
    setDirty,
    common,
    additional,
    errors,
  } = controller;
  function input(field: MatchField, condition = false) {
    return <RuleField field={field} condition={condition} controller={controller} />;
  }
  function actionInput(field: MatchField) {
    return (
      <label className={field.kind === 'bool' ? 'feature-check' : 'feature-field'} key={field.key}>
        {field.kind === 'bool' ? (
          <>
            {input(field)}
            <span>{label(field.label, language)}</span>
          </>
        ) : (
          <>
            <span>{label(field.label, language)}</span>
            {input(field)}
          </>
        )}
        {errors[field.key] && <small className="desktop-inline-error">{tr('badValue')}</small>}
      </label>
    );
  }
  return (
    <section className="rule-section">
      <h3>{tr('trafficAction')}</h3>
      <div className="rule-action-grid">
        <Field className="feature-field" label={tr('action')}>
          <Select
            id="rule-action"
            className="text-input"
            value={action}
            disabled={busy}
            onChange={(e) => changeAction(e.target.value)}
          >
            {!actions.some((a) => a.id === action) && <option value={action}>{action}</option>}
            {actions.map((a) => (
              <option key={a.id} value={a.id}>
                {label(a.label, language)}
              </option>
            ))}
          </Select>
        </Field>
        {(action === 'route' || action === 'bypass') && (
          <Field className="feature-field" label={tr('ruleOutbound')}>
            <Targets
              profiles={profiles}
              value={String(config.outbound || (action === 'bypass' ? '' : defaultTarget))}
              system={action === 'bypass'}
              tr={tr}
              disabled={busy}
              changed={(value) => {
                setConfig((old) => ({ ...old, outbound: value }));
                setDirty(true);
              }}
            />
          </Field>
        )}
        {common.map(actionInput)}
      </div>
      {(config.outbound === 'warp' || config.outbound === 'warp-bypass') && (
        <p className="rule-hint">{tr('warpHint')}</p>
      )}
      {action === 'bypass' && <p className="rule-hint">{tr('bypassHint')}</p>}
      {additional.length > 0 && (
        <Section title={<>{tr('moreOptions')}</>} className="route-advanced">
          <div className="rule-action-grid">{additional.map(actionInput)}</div>
        </Section>
      )}
    </section>
  );
}
