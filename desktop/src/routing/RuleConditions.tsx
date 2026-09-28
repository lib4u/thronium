import RuleField from './RuleField';
import { JsonEditor } from '../shared/ui/controls';
import { Select, Checkbox, Button } from '../shared/ui/controls';
import LogicalConditions from './LogicalConditions';
import { Icon } from '../ui';
import { label, type Config } from '../profiles/schema';
import { matches, type MatchField } from './model';
import type { useRuleEditor } from './useRuleEditor';
export default function RuleConditions({ controller }: { controller: ReturnType<typeof useRuleEditor> }) {
  const {
    tab,
    tr,
    busy,
    switchTab,
    raw,
    config,
    language,
    setNestedInvalid,
    setNestedUnfinished,
    fields,
    errors,
    groupConditions,
    addCondition,
    changeInvert,
    changeLogical,
    changeRaw,
    removeCondition,
    replaceCondition,
  } = controller;
  function input(field: MatchField, condition = false) {
    return <RuleField field={field} condition={condition} controller={controller} />;
  }
  return (
    <section className="rule-section">
      <div className="rule-section-head">
        <h3>{tab === 'json' ? 'JSON' : tr('conditions')}</h3>
        <Button
          type="button"
          className="text-button"
          data-rule-tab={tab === 'json' ? 'fields' : 'json'}
          disabled={busy}
          onClick={() => switchTab(tab === 'json' ? 'fields' : 'json')}
        >
          {tab === 'json' ? tr('builder') : 'JSON'}
        </Button>
      </div>
      {tab === 'json' ? (
        <JsonEditor
          id="rule-json"
          aria-label="JSON"
          className="text-input mono"
          disabled={busy}
          value={raw}
          spellCheck={false}
          onChange={(e) => changeRaw(e.target.value)}
        />
      ) : (
        <>
          {config.type === 'logical' ? (
            <LogicalConditions
              value={config}
              language={language}
              disabled={busy}
              invalidChanged={setNestedInvalid}
              unfinishedChanged={setNestedUnfinished}
              change={(value) => changeLogical(value as Config)}
            />
          ) : (
            <>
              {!fields.length && <p className="rule-hint">{tr('any')}</p>}
              <div className="route-condition-list">
                {fields.map((key, i) => {
                  const field = matches.find((f) => f.key === key)!;
                  return (
                    <div className="route-condition" key={key}>
                      <Select
                        className="text-input"
                        data-route-condition={i}
                        aria-label={`${tr('field')} ${i + 1}`}
                        value={key}
                        disabled={busy}
                        onChange={(e) => replaceCondition(key, e.target.value)}
                      >
                        {matches
                          .filter((f) => f.key === key || !fields.includes(f.key))
                          .map((f) => (
                            <option key={f.key} value={f.key}>
                              {label(f.label, language)}
                            </option>
                          ))}
                      </Select>
                      <div>
                        {input(field, true)}
                        {errors[key] && <small className="desktop-inline-error">{tr('badValue')}</small>}
                      </div>
                      <Button
                        type="button"
                        className="icon-button"
                        disabled={busy}
                        aria-label={tr('remove')}
                        data-remove-condition={i}
                        onClick={() => removeCondition(key)}
                      >
                        <Icon name="x" />
                      </Button>
                    </div>
                  );
                })}
              </div>
              <Button
                type="button"
                className="text-button"
                id="rule-add-condition"
                disabled={fields.length === matches.length || busy}
                onClick={addCondition}
              >
                <Icon name="plus" />
                {tr('addCondition')}
              </Button>
              <Button
                type="button"
                className="text-button"
                id="rule-group-conditions"
                disabled={busy}
                onClick={groupConditions}
              >
                {tr('groupConditions')}
              </Button>
            </>
          )}
          <label className="feature-check">
            <Checkbox
              id="rule-invert"
              type="checkbox"
              disabled={busy}
              checked={config.invert === true}
              onChange={(e) => changeInvert(e.target.checked)}
            />
            <span>{tr('invert')}</span>
          </label>
        </>
      )}
    </section>
  );
}
