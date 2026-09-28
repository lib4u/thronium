import { errorCode } from '../shared/api/errors.ts';
import { useRef, useState } from 'react';
import { parseRuleValue, formatRuleValue, primaryActionKeys } from './ruleInput';
import { actionOnlyKeys, createTree, serializeTree, wrapNode } from './conditionTree';
import { type Profile } from '../api';
import { type Config } from '../profiles/schema';
import {
  matches,
  actionFields,
  defaultCondition,
  defaultTarget,
  presentConditions,
  targetAction,
  type MatchField,
  type RouteRule,
} from './model';
import { messageKeys as words, Tr } from './RuleEditorModel';
import { useMessageState } from '../shared/i18n/react';
import { messageRef } from '../shared/i18n/message';
import type { Language } from '../shared/i18n/index.ts';
import { useDiscardGuard } from './useDiscardGuard';
export function useRuleEditor({
  rule,
  creating = !rule,
  profiles,
  tr,
  language,
  close,
  save,
  translateError,
}: {
  rule?: RouteRule;
  /** A preset opens with a prepared rule that is not saved yet. */
  creating?: boolean;
  profiles: Profile[];
  tr: Tr;
  language: Language;
  close(): void;
  save(r: RouteRule): Promise<void>;
  translateError(e: unknown): string;
}) {
  const [name, setName] = useState(rule?.name || '');
  const [config, setConfig] = useState<Config>(rule?.config || targetAction(defaultTarget));
  const [fields, setFields] = useState<string[]>(rule ? presentConditions(rule.config) : [defaultCondition]);
  const [buffers, setBuffers] = useState<Record<string, string>>({});
  const [errors, setErrors] = useState<Record<string, boolean>>({});
  const [tab, setTab] = useState('fields');
  const [raw, setRaw] = useState('');
  const jsonBase = useRef<string>(undefined);
  const [nestedInvalid, setNestedInvalid] = useState(false);
  const [nestedUnfinished, setNestedUnfinished] = useState(false);
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);
  const [error, setError] = useMessageState(language, translateError);
  const [dirty, setDirty] = useState(false);
  const [variants, setVariants] = useState<
    Record<string, { config: Config; buffers: Record<string, string>; errors: Record<string, boolean> }>
  >({});
  const action = String(config.action || 'route');
  const guard = useDiscardGuard({ busy, dirty, close });
  const { requestClose } = guard;
  const discard = guard.asking;
  function update(field: MatchField, value: string) {
    setDirty(true);
    setError('');
    setBuffers((old) => ({ ...old, [field.key]: value }));
    try {
      const parsed = parseRuleValue(field, value);
      setConfig((old) => {
        const next = { ...old };
        if (parsed === undefined) delete next[field.key];
        else next[field.key] = parsed;
        return next;
      });
      setErrors((old) => ({ ...old, [field.key]: false }));
    } catch {
      setErrors((old) => ({ ...old, [field.key]: true }));
    }
  }
  function changeAction(next: string) {
    const keys = new Set(actionOnlyKeys);
    setVariants((old) => ({
      ...old,
      [action]: {
        config: Object.fromEntries(Object.entries(config).filter(([k]) => keys.has(k))),
        buffers: Object.fromEntries(Object.entries(buffers).filter(([k]) => keys.has(k))),
        errors: Object.fromEntries(Object.entries(errors).filter(([k]) => keys.has(k))),
      },
    }));
    setConfig((old) => ({
      ...Object.fromEntries(Object.entries(old).filter(([k]) => !keys.has(k))),
      ...(variants[next]?.config || {}),
      action: next,
      ...(next === 'route' ? { outbound: variants[next]?.config.outbound || defaultTarget } : {}),
    }));
    setBuffers((old) => ({
      ...Object.fromEntries(Object.entries(old).filter(([k]) => !keys.has(k))),
      ...(variants[next]?.buffers || {}),
    }));
    setErrors((old) => ({
      ...Object.fromEntries(Object.entries(old).filter(([k]) => !keys.has(k))),
      ...(variants[next]?.errors || {}),
    }));
    setDirty(true);
  }
  function groupConditions() {
    setError('');
    try {
      if (Object.values(errors).some(Boolean)) throw Error('invalid_condition');
      for (const key of fields) {
        const field = matches.find((f) => f.key === key)!;
        if (parseRuleValue(field, buffers[key] ?? formatRuleValue(field, config[key])) === undefined)
          throw Error('invalid_condition');
      }
      const tree = createTree(config);
      setConfig(serializeTree(wrapNode(tree, tree.root.id)) as Config);
      setFields([]);
      const conditionKeys = new Set(matches.map((f) => f.key));
      setBuffers((old) => Object.fromEntries(Object.entries(old).filter(([key]) => !conditionKeys.has(key))));
      setErrors((old) => Object.fromEntries(Object.entries(old).filter(([key]) => !conditionKeys.has(key))));
      setDirty(true);
    } catch (e) {
      setError(
        messageRef(errorCode(e).startsWith('condition_tree_') ? words.groupUnsupported : words.badValue),
      );
    }
  }
  async function submit() {
    if (submitting.current) return;
    setError('');
    if (!name.trim()) {
      setError(messageRef(words.badName));
      return;
    }
    let result = config;
    try {
      if (tab === 'json') {
        result = JSON.parse(raw);
        if (!result || typeof result !== 'object' || Array.isArray(result)) throw Error('invalid_routing');
      } else {
        if (Object.values(errors).some(Boolean) || (config.type === 'logical' && nestedInvalid))
          throw Error('invalid_condition');
        if (config.type !== 'logical')
          for (const key of fields) {
            const field = matches.find((f) => f.key === key)!;
            if (parseRuleValue(field, buffers[key] ?? formatRuleValue(field, config[key])) === undefined)
              throw Error('invalid_condition');
          }
      }
      submitting.current = true;
      setBusy(true);
      await save({
        id: rule?.id || crypto.randomUUID(),
        name: name.trim(),
        enabled: rule?.enabled ?? true,
        config: result,
      });
      close();
    } catch (e) {
      setError(e);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  function switchTab(next: string) {
    setError('');
    if (next === 'json') {
      if (Object.values(errors).some(Boolean) || (config.type === 'logical' && nestedUnfinished)) {
        setError(messageRef(words.badValue));
        return;
      }
      try {
        const text = JSON.stringify(config, null, 2);
        setRaw(text);
        jsonBase.current = text;
      } catch {
        setError(messageRef(words.groupUnsupported));
        return;
      }
    } else if (raw === jsonBase.current) {
      // Unchanged JSON returns to the form as it was, including conditions
      // that were added but not filled in yet.
    } else {
      try {
        const value = JSON.parse(raw);
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error();
        // Keep the original text accessible when the WebView serializer cannot
        // represent its depth on a later return from the builder.
        try {
          JSON.stringify(value, null, 2);
        } catch {
          setError(messageRef(words.groupUnsupported));
          return;
        }
        setConfig(value);
        setFields(presentConditions(value));
        setBuffers({});
        setErrors({});
      } catch {
        setError(messageRef(words.badValue));
        return;
      }
    }
    setTab(next);
  }
  const options = actionFields(action);
  const routeOptions = ['route', 'route-options', 'bypass'].includes(action);
  const common = routeOptions ? options.filter((f) => primaryActionKeys.has(f.key)) : options;
  const additional = routeOptions ? options.filter((f) => !primaryActionKeys.has(f.key)) : [];
  /** Replaces the match field `key` of the rule with `next`, dropping its value. */
  function replaceCondition(key: string, next: string) {
    setFields((old) => old.map((k) => (k === key ? next : k)));
    setBuffers((old) => {
      const b = { ...old };
      delete b[key];
      delete b[next];
      return b;
    });
    setConfig((old) => {
      const c = { ...old };
      delete c[key];
      return c;
    });
    setErrors((old) => ({ ...old, [key]: false, [next]: false }));
    setDirty(true);
  }
  function removeCondition(key: string) {
    setFields((old) => old.filter((k) => k !== key));
    setBuffers((old) => {
      const b = { ...old };
      delete b[key];
      return b;
    });
    setConfig((old) => {
      const c = { ...old };
      delete c[key];
      return c;
    });
    setErrors((old) => ({ ...old, [key]: false }));
    setDirty(true);
  }
  /** Adds the next unused match field, process name first. */
  function addCondition() {
    setFields((old) => [
      ...old,
      !old.includes('process_name') ? 'process_name' : matches.find((f) => !old.includes(f.key))!.key,
    ]);
    setDirty(true);
  }
  function changeRaw(text: string) {
    setRaw(text);
    setDirty(true);
  }
  /** The logical condition tree changed as a whole. */
  function changeLogical(value: Config) {
    setConfig(value);
    setDirty(true);
    setError('');
  }
  function changeInvert(invert: boolean) {
    setConfig((old) => ({ ...old, invert }));
    setDirty(true);
  }
  return {
    action,
    addCondition,
    changeInvert,
    changeLogical,
    changeRaw,
    additional,
    buffers,
    busy,
    changeAction,
    close,
    common,
    config,
    discard,
    error,
    guard,
    errors,
    fields,
    groupConditions,
    language,
    name,
    profiles,
    raw,
    removeCondition,
    replaceCondition,
    requestClose,
    rule,
    creating,
    setBuffers,
    setConfig,
    setDirty,
    setError,
    setErrors,
    setFields,
    setName,
    setNestedInvalid,
    setNestedUnfinished,
    setRaw,
    submit,
    switchTab,
    tab,
    tr,
    update,
  };
}
