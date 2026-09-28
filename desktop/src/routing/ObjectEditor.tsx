import { messageRef } from '../shared/i18n/message';
import { useMessageState } from '../shared/i18n/react';
import { Button, Field, InlineError, JsonEditor, TabList } from '../shared/ui/controls';
import ValueInput from './ValueInput';
import { useEffect, useState } from 'react';
import { Modal, Icon } from '../ui';
import { get, set, label, type Config, type Label } from '../profiles/schema';
import { parseResource, formatResource, type ResourceField, type ResourceSection } from './resources';
import type { Language } from '../shared/i18n/index.ts';
import { secretPath } from '../shared/secretFields.ts';
import DiscardDialog from './DiscardDialog';
import { useDiscardGuard } from './useDiscardGuard';
const messageKeys = {
  save: 'routing.save_9cd85bd',
  check: 'routing.validate_e2a8979',
  cancel: 'routing.cancel_bf4c449',
  close: 'routing.close_c9a286c',
  busy: 'routing.validating_4629974',
  invalid: 'routing.correct_the_highlighted_fields_5a97997',
  invalidJSON: 'routing.enter_a_json_object_a3c6a2a',
  fields: 'routing.parameters_8f0e762',
  raw: 'routing.additional_parameters_are_preserved_json_contain_6f9aefa',
  checked: 'routing.the_core_accepted_this_configuration_dde5666',
} satisfies Record<string, Label>;
type Working = { config: Config; buffers: Record<string, string>; invalid: Record<string, boolean> };
export type ObjectEditorProps = {
  initialField?: string;
  title: string;
  initial: Config;
  language: Language;
  sections(c: Config): ResourceSection[];
  close(): void;
  save(c: Config): Promise<void>;
  check(c: Config): Promise<void>;
  translateError(e: unknown): string;
  hint?: string;
  optionLabels?: Record<string, string>;
  variant?: { path: string; seed(type: string): Config; shared(c: Config): Config };
};
export default function ObjectEditor(props: ObjectEditorProps) {
  const tr = (key: keyof typeof messageKeys) => label(messageKeys[key], props.language);
  const [work, setWork] = useState<Working>({
    config: structuredClone(props.initial),
    buffers: {},
    invalid: {},
  });
  const [variants, setVariants] = useState<Record<string, Working>>({});
  const [tab, setTab] = useState(
    props.initialField
      ? props.sections(props.initial).find((s) => s.fields.some((f) => f.path === props.initialField))?.id ||
          'main'
      : 'main',
  );
  const [raw, setRaw] = useState('');
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useMessageState(props.language, props.translateError);
  const [notice, setNotice] = useMessageState(props.language, () => '');
  const [busy, setBusy] = useState(false);
  const tabs = props.sections(work.config);
  const active = tabs.find((s) => s.id === tab) || tabs[0];
  const guard = useDiscardGuard({ busy, dirty, close: props.close });
  const { requestClose } = guard;
  const discard = guard.asking;
  function change(field: ResourceField, text: string) {
    setDirty(true);
    setError('');
    setNotice('');
    if (props.variant?.path === field.path) {
      const variant = props.variant;
      const old = String(get(work.config, field.path) || '');
      setVariants((prev) => ({ ...prev, [old]: work }));
      const next = variants[text] || { config: variant.seed(text), buffers: {}, invalid: {} };
      const shared = variant.shared(work.config);
      const sharedKeys = new Set([...Object.keys(shared), ...Object.keys(variant.shared(next.config))]);
      const specific = (entries: Record<string, unknown>) =>
        Object.fromEntries(Object.entries(entries).filter(([key]) => !sharedKeys.has(key.split('.')[0])));
      setWork({
        config: { ...specific(next.config), ...shared, [field.path]: text },
        buffers: specific(next.buffers) as Record<string, string>,
        invalid: specific(next.invalid) as Record<string, boolean>,
      });
      return;
    }
    const buffers = { ...work.buffers, [field.path]: text },
      invalid = { ...work.invalid };
    try {
      let value = parseResource(field, text);
      // A resolver can be either a tag or an object with extra options.
      const existing = get(work.config, field.path);
      if (field.path === 'domain_resolver' && existing && typeof existing === 'object' && value)
        value = { ...existing, server: value };
      const config = set(work.config, field.path, value);
      delete invalid[field.path];
      setWork({ config, buffers, invalid });
    } catch {
      invalid[field.path] = true;
      setWork({ ...work, buffers, invalid });
    }
  }
  function value(): Config {
    if (tab === 'json') {
      const c = JSON.parse(raw);
      if (!c || typeof c !== 'object' || Array.isArray(c)) throw Error('invalid_routing');
      return c;
    }
    if (Object.values(work.invalid).some(Boolean)) throw Error('invalid_condition');
    return work.config;
  }
  function chooseTab(next: string) {
    if (next === tab) return;
    setError('');
    try {
      if (next === 'json') {
        setRaw(JSON.stringify(value(), null, 2));
      } else if (tab === 'json') setWork({ config: value(), buffers: {}, invalid: {} });
      setTab(next);
    } catch (e) {
      setError(e);
    }
  }
  async function submit(save: boolean) {
    setError('');
    setNotice('');
    setBusy(true);
    try {
      const config = value();
      await (save ? props.save(config) : props.check(config));
      if (save) props.close();
      else setNotice(messageRef(messageKeys.checked));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  const optionNames = {
    h3: 'routing.http_3_daf3ad8',
    local: 'routing.local_cc44a62',
    remote: 'routing.remote_url_43b5796',
    inline: 'routing.inline_b1f9ba2',
    binary: 'routing.binary_srs_9f46177',
    source: 'routing.source_json_c991c97',
    proxy: 'routing.selected_server_1797ac9',
    direct: 'routing.direct_cc7ab89',
    route: 'routing.use_server_7499640',
    reject: 'routing.block_59fb954',
    predefined: 'routing.predefined_answer_71aa341',
    'route-options': 'routing.query_options_2ea5f7a',
    evaluate: 'routing.evaluate_response_c459a7b',
    respond: 'routing.return_response_22b8fbc',
  } as Record<string, Label>;
  const optionLabel = (value: string): string => {
    if (props.optionLabels && Object.prototype.hasOwnProperty.call(props.optionLabels, value))
      return props.optionLabels[value];
    return Object.prototype.hasOwnProperty.call(optionNames, value)
      ? label(optionNames[value], props.language)
      : value;
  };
  function render(field: ResourceField) {
    let stored = get(work.config, field.path);
    if (field.path === 'domain_resolver' && stored && typeof stored === 'object')
      stored = (stored as Config).server;
    const text = work.buffers[field.path] ?? formatResource(field, stored);
    const id = 'resource-' + field.path.replace(/\./g, '-');
    const invalid = work.invalid[field.path];
    const multiline = ['json', 'hosts', 'list', 'integers'].includes(field.kind);
    return (
      <Field
        key={field.path}
        id={id}
        label={label(field.label, props.language)}
        hint={field.hint ? label(field.hint, props.language) : undefined}
        error={invalid ? tr('invalid') : undefined}
        className={`feature-field ${field.wide || multiline ? 'span-all' : ''}`}
      >
        {(aria) => (
          <ValueInput
            kind={field.kind}
            text={text}
            language={props.language}
            options={field.kind === 'select' ? (field.options?.map(String) ?? []) : undefined}
            optionLabel={optionLabel}
            multiline={multiline}
            rows={field.kind === 'json' ? 6 : 3}
            mono={multiline}
            // DNS-over-HTTPS headers usually carry the authorization token.
            secret={secretPath.test(field.path) || field.path === 'headers'}
            control={{
              ...aria,
              'data-resource-field': field.path,
              disabled: busy,
              onChange: (e) => change(field, e.target.value),
            }}
          />
        )}
      </Field>
    );
  }
  useEffect(() => {
    if (props.initialField) {
      requestAnimationFrame(() =>
        document.querySelector<HTMLElement>(`[data-resource-field="${props.initialField}"]`)?.focus(),
      );
    }
  }, []);
  return (
    <Modal
      title={props.title}
      description={props.hint}
      className="editor-modal resource-modal"
      close={requestClose}
      closeLabel={tr('close')}
      footer={
        <>
          <Button
            id="resource-check"
            className="button secondary"
            disabled={busy || discard}
            onClick={() => void submit(false)}
          >
            {tr(busy ? 'busy' : 'check')}
          </Button>
          <span className="filter-spacer" />
          <Button className="text-button" disabled={busy} onClick={requestClose}>
            {tr('cancel')}
          </Button>
          <Button
            id="resource-save"
            className="button primary"
            disabled={busy || discard}
            onClick={() => void submit(true)}
          >
            <Icon name="check" />
            {tr('save')}
          </Button>
        </>
      }
    >
      <DiscardDialog guard={guard} language={props.language} confirmId="resource-discard" />
      <div inert={discard || undefined}>
        {error && (
          <InlineError className="desktop-inline-error" role="alert">
            {error}
          </InlineError>
        )}
        {notice && (
          <p className="resource-notice" role="status">
            {notice}
          </p>
        )}
        <div className="editor-layout">
          <TabList
            className="editor-nav"
            aria-label={tr('fields')}
            aria-orientation="vertical"
            value={tab}
            onChange={chooseTab}
            disabled={busy}
            tabs={[...tabs, { id: 'json', label: 'routing.json_96a5a28' as Label, fields: [] }].map((s) => ({
              id: s.id,
              attributes: { 'data-resource-tab': s.id },
              label: (
                <>
                  {label(s.label, props.language)}
                  {s.fields.some((f) => work.invalid[f.path]) && <span className="editor-invalid-dot" />}
                </>
              ),
            }))}
          />
          <div className="editor-content">
            <div className="feature-section">
              <h3>{tab === 'json' ? 'JSON' : label(active.label, props.language)}</h3>
            </div>
            {tab === 'json' ? (
              <JsonEditor
                id="resource-json"
                aria-label="JSON"
                className="text-input desktop-json mono"
                value={raw}
                spellCheck={false}
                autoComplete="off"
                disabled={busy}
                onChange={(e) => {
                  setRaw(e.target.value);
                  setDirty(true);
                  setError('');
                  setNotice('');
                }}
              />
            ) : (
              <div className="feature-fields">{active.fields.map(render)}</div>
            )}
            <p className="field-hint resource-hint">{tr('raw')}</p>
          </div>
        </div>
      </div>
    </Modal>
  );
}
