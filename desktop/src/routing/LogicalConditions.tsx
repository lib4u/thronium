import { useMessageState } from '../shared/i18n/react';
import { InlineError } from '../shared/ui/controls';
import { Select, Button, Checkbox } from '../shared/ui/controls';
import { errorCode } from '../shared/api/errors.ts';
import { useEffect, useRef, useState } from 'react';
import { Icon } from '../ui';
import { label, type Config, type Label } from '../profiles/schema';
import { matches, type MatchField } from './model';
import { headlessFields } from './headlessFields';
import { commaValues } from './ruleInput';
import {
  actionOnlyKeys,
  addField,
  addGroup,
  addLeaf,
  createTree,
  createRuleSetTree,
  editField,
  fieldText,
  moveNode,
  reconcileRoot,
  reconcileRuleSet,
  removeField,
  replaceField,
  removeNode,
  serializeTree,
  unwrapNode,
  updateNode,
  validateDraft,
  wrapNode,
  type ConditionNode,
  type ConditionTree,
} from './conditionTree';
import './LogicalConditions.css';
import type { Language } from '../shared/i18n/index.ts';
import ValueInput from './ValueInput';

const messageKeys = {
  set: 'routing.rules_29241d7',
  setHint: 'routing.the_set_matches_when_any_rule_matches_combine_co_d7c686a',
  emptySet: 'routing.add_at_least_one_condition_to_this_rule_set_22258b5',
  group: 'routing.group_aaf618a',
  leaf: 'routing.conditions_16b104c',
  all: 'routing.all_groups_must_match_and_4c3573c',
  any: 'routing.any_group_may_match_or_587a2b3',
  addLeaf: 'routing.add_conditions_0684886',
  addGroup: 'routing.add_group_7889764',
  addField: 'routing.add_condition_889cb05',
  field: 'routing.condition_type_dbb9cfc',
  value: 'routing.value_a08fa53',
  invert: 'routing.invert_this_match_27b4ea0',
  up: 'routing.move_up_441b312',
  down: 'routing.move_down_d672813',
  remove: 'routing.delete_55f670b',
  wrap: 'routing.put_in_a_group_01da3fb',
  unwrap: 'routing.remove_the_group_wrapper_a3c5b68',
  empty: 'routing.add_a_condition_to_this_group_9035ce2',
  invalid: 'routing.check_this_value_046ee79',
  comma: 'routing.comma_separated_values_b9e824d',
  lines: 'routing.one_value_per_line_5405bd3',
  hint: 'routing.each_group_combines_complete_conditions_the_traf_f3ada7a',
  extra: 'routing.additional_parameters_are_preserved_and_can_be_e_ef98e1b',
  raw: 'routing.this_part_of_the_rule_can_be_edited_in_the_json__4fe18ad',
  limit: 'routing.builder_limit',
  conflict: 'routing.finish_or_remove_the_incomplete_conditions_befor_b3efe38',
  unsupported: 'routing.this_structure_cannot_be_changed_without_losing__dbe1209',
} satisfies Record<string, Label>;

export default function LogicalConditions({
  value,
  language,
  disabled,
  change,
  invalidChanged,
  unfinishedChanged,
  schema = 'route',
}: {
  value: unknown;
  schema?: 'route' | 'headless';
  language: Language;
  disabled: boolean;
  change(value: unknown): void;
  invalidChanged(value: boolean): void;
  unfinishedChanged(value: boolean): void;
}) {
  const [tree, setTree] = useState<ConditionTree>(() =>
    schema === 'headless' ? createRuleSetTree(value) : createTree(value),
  );
  const fields = schema === 'headless' ? headlessFields : matches;
  const reconcile = (tree: ConditionTree, value: unknown) =>
    schema === 'headless' ? reconcileRuleSet(tree, value) : reconcileRoot(tree, value as Config);
  const [error, setError] = useMessageState(language, (value) => explain(value));
  const current = useRef(tree),
    incoming = useRef(value),
    emitted = useRef<unknown>(Symbol());
  incoming.current = value;
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  function explain(e: unknown) {
    const code = errorCode(e);
    return t(
      code === 'condition_tree_limit'
        ? 'limit'
        : code === 'condition_tree_draft_conflict'
          ? 'conflict'
          : 'unsupported',
    );
  }
  useEffect(() => {
    if (value === emitted.current) return;
    try {
      const next = reconcile(current.current, value);
      current.current = next;
      setTree(next);
      setError('');
    } catch (e) {
      setError(e);
    }
  }, [value]);
  // Raw/over-limit imports remain accessible in JSON. Only unfinished form
  // input blocks switching tabs, because it is not represented in config yet.
  const unfinished = (tree: ConditionTree) =>
    validateDraft(tree).some((issue) => issue.code === 'invalid_condition' && issue.key !== undefined);
  useEffect(() => {
    invalidChanged(validateDraft(tree).length > 0);
    unfinishedChanged(unfinished(tree));
  }, [tree, invalidChanged, unfinishedChanged]);

  function alter(operation: (tree: ConditionTree) => ConditionTree) {
    if (disabled) return;
    try {
      const next = operation(reconcile(current.current, incoming.current));
      const config = serializeTree(next);
      current.current = next;
      emitted.current = config;
      setTree(next);
      setError('');
      invalidChanged(validateDraft(next).length > 0);
      unfinishedChanged(unfinished(next));
      change(config);
    } catch (e) {
      setError(e);
    }
  }
  function input(node: ConditionNode, field: MatchField) {
    const text = fieldText(node, field.key, schema);
    return (
      <ValueInput
        kind={field.kind}
        text={text}
        language={language}
        rows={field.kind === 'json' ? 3 : Math.min(4, text.split('\n').length)}
        placeholder={
          ['list', 'numbers'].includes(field.kind)
            ? t(commaValues(field) || field.key === 'query_type' ? 'comma' : 'lines')
            : undefined
        }
        control={{
          disabled,
          'data-condition-value': field.key,
          'aria-label': label(field.label, language),
          'aria-invalid': node.errors[field.key] || undefined,
          onChange: (e) => alter((tree) => editField(tree, node.id, field.key, e.target.value)),
        }}
      />
    );
  }
  function render(node: ConditionNode, path: number[], siblings = 1) {
    const root = path.length === 0;
    const index = path[path.length - 1] || 0;
    const extra = Object.keys(node.config).some(
      (key) =>
        ![
          'type',
          'mode',
          'rules',
          'invert',
          ...fields.map((f) => f.key),
          ...(root && schema === 'route' ? actionOnlyKeys : []),
        ].includes(key),
    );
    return (
      <fieldset
        className={`condition-node condition-node-${node.kind}`}
        key={node.id}
        data-condition-node={node.id}
        data-condition-kind={node.kind}
      >
        <legend>
          {t(node.kind === 'set' ? 'set' : node.kind === 'group' ? 'group' : 'leaf')}
          {root ? '' : ` ${path.map((i) => i + 1).join('.')}`}
        </legend>
        {node.kind === 'raw' ? (
          <p className="rule-hint">{t('raw')}</p>
        ) : (
          <>
            {node.kind === 'group' || node.kind === 'set' ? (
              <>
                {node.kind === 'group' && (
                  <Select
                    className="text-input condition-mode"
                    aria-label={t('group')}
                    data-condition-mode={node.id}
                    value={String(node.config.mode)}
                    disabled={disabled}
                    onChange={(e) =>
                      alter((tree) =>
                        updateNode(tree, node.id, (old) => ({
                          ...old,
                          config: { ...old.config, mode: e.target.value },
                        })),
                      )
                    }
                  >
                    <option value="and">{t('all')}</option>
                    <option value="or">{t('any')}</option>
                  </Select>
                )}
                <div className="condition-children">
                  {node.children.map((child, i) => render(child, [...path, i], node.children.length))}
                </div>
                {!node.children.length && (
                  <p className="desktop-inline-error">{t(node.kind === 'set' ? 'emptySet' : 'empty')}</p>
                )}
                <div className="condition-add-actions">
                  <Button
                    className="text-button"
                    type="button"
                    data-condition-add-leaf={node.id}
                    disabled={disabled}
                    onClick={() => alter((tree) => addLeaf(tree, node.id))}
                  >
                    <Icon name="plus" />
                    {t('addLeaf')}
                  </Button>
                  <Button
                    className="text-button"
                    type="button"
                    data-condition-add-group={node.id}
                    disabled={disabled}
                    onClick={() => alter((tree) => addGroup(tree, node.id))}
                  >
                    {t('addGroup')}
                  </Button>
                </div>
              </>
            ) : (
              <>
                <div className="condition-fields">
                  {node.fields.map((key) => {
                    const field = fields.find((f) => f.key === key);
                    if (!field) return null;
                    return (
                      <div className="condition-field-row" data-condition-row={key} key={key}>
                        <Select
                          className="text-input"
                          data-condition-field={key}
                          aria-label={t('field')}
                          value={key}
                          disabled={disabled}
                          onChange={(e) => alter((tree) => replaceField(tree, node.id, key, e.target.value))}
                        >
                          {fields
                            .filter((f) => f.key === key || !node.fields.includes(f.key))
                            .map((f) => (
                              <option key={f.key} value={f.key}>
                                {label(f.label, language)}
                              </option>
                            ))}
                        </Select>
                        <div>
                          {input(node, field)}
                          {node.errors[key] && <small className="desktop-inline-error">{t('invalid')}</small>}
                        </div>
                        <Button
                          className="icon-button"
                          type="button"
                          disabled={disabled}
                          aria-label={t('remove')}
                          data-condition-remove-field={key}
                          onClick={() => alter((tree) => removeField(tree, node.id, key))}
                        >
                          <Icon name="x" />
                        </Button>
                      </div>
                    );
                  })}
                </div>
                {!node.fields.length && !extra && <p className="desktop-inline-error">{t('empty')}</p>}
                <Button
                  className="text-button"
                  type="button"
                  data-condition-add-field={node.id}
                  disabled={disabled || node.fields.length === fields.length}
                  onClick={() =>
                    alter((tree) =>
                      addField(
                        tree,
                        node.id,
                        !node.fields.includes('process_name')
                          ? 'process_name'
                          : fields.find((f) => !node.fields.includes(f.key))!.key,
                      ),
                    )
                  }
                >
                  {t('addField')}
                </Button>
              </>
            )}
            {extra && <p className="rule-hint">{t('extra')}</p>}
            {!root && (
              <label className="feature-check">
                <Checkbox
                  type="checkbox"
                  disabled={disabled}
                  data-condition-invert={node.id}
                  checked={node.config.invert === true}
                  onChange={(e) =>
                    alter((tree) =>
                      updateNode(tree, node.id, (old) => ({
                        ...old,
                        config: { ...old.config, invert: e.target.checked },
                      })),
                    )
                  }
                />
                <span>{t('invert')}</span>
              </label>
            )}
          </>
        )}
        {!root && (
          <div className="condition-node-actions">
            <Button
              type="button"
              className="icon-button"
              disabled={disabled || index === 0}
              aria-label={t('up')}
              data-condition-up={node.id}
              onClick={() => alter((tree) => moveNode(tree, node.id, -1))}
            >
              <Icon name="arrow-up" />
            </Button>
            <Button
              type="button"
              className="icon-button"
              disabled={disabled || index === siblings - 1}
              aria-label={t('down')}
              data-condition-down={node.id}
              onClick={() => alter((tree) => moveNode(tree, node.id, 1))}
            >
              <Icon name="arrow-down" />
            </Button>
            {node.kind !== 'raw' && (
              <Button
                type="button"
                className="text-button"
                disabled={disabled}
                data-condition-wrap={node.id}
                onClick={() => alter((tree) => wrapNode(tree, node.id))}
              >
                {t('wrap')}
              </Button>
            )}
            {node.kind === 'group' && node.children.length === 1 && (
              <Button
                type="button"
                className="text-button"
                disabled={disabled}
                data-condition-unwrap={node.id}
                onClick={() => alter((tree) => unwrapNode(tree, node.id))}
              >
                {t('unwrap')}
              </Button>
            )}
            <Button
              type="button"
              className="icon-button"
              disabled={disabled}
              aria-label={t('remove')}
              data-condition-delete={node.id}
              onClick={() => alter((tree) => removeNode(tree, node.id))}
            >
              <Icon name="trash" />
            </Button>
          </div>
        )}
      </fieldset>
    );
  }
  return (
    <div id="logical-conditions">
      <p className="rule-hint">{t(schema === 'headless' ? 'setHint' : 'hint')}</p>
      {render(tree.root, [])}
      {error && (
        <InlineError className="desktop-inline-error" role="alert">
          {error}
        </InlineError>
      )}
    </div>
  );
}
