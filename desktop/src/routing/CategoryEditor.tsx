import { messageRef } from '../shared/i18n/message';
import { useMessageState } from '../shared/i18n/react';
import { InlineError, TabList, Field } from '../shared/ui/controls';
import { Button, Input, Textarea } from '../shared/ui/controls';
import { translate, type Language } from '../shared/i18n/index.ts';
import { useState } from 'react';
import { Modal } from '../ui';
import type { Config } from '../profiles/schema';
import { categoryText, parseCategoryText } from './catalog';
import LogicalConditions from './LogicalConditions';
import { limits } from '../shared/api/generated/limits.ts';
import DiscardDialog from './DiscardDialog';
import { useDiscardGuard } from './useDiscardGuard';

export default function CategoryEditor({
  name,
  rules,
  language,
  close,
  save,
  check,
  copy = true,
  translateError,
}: {
  name: string;
  rules: unknown;
  language: Language;
  close(): void;
  save(name: string, rules: Config[]): Promise<void>;
  check?(name: string, rules: Config[]): Promise<void>;
  copy?: boolean;
  translateError(e: unknown): string;
}) {
  const initial = categoryText(rules);
  const [title, setTitle] = useState(name),
    [tab, setTab] = useState(initial === null ? 'json' : 'list');
  const [value, setValue] = useState(rules),
    [list, setList] = useState(initial || ''),
    [listSource, setListSource] = useState(initial || '');
  const [json, setJson] = useState(() => JSON.stringify(rules, null, 2));
  const [invalid, setInvalid] = useState(false),
    [unfinished, setUnfinished] = useState(false);
  const [busy, setBusy] = useState(false),
    [error, setError] = useMessageState(language, translateError),
    [notice, setNotice] = useMessageState(language, () => '');
  const [dirty, setDirty] = useState(false);
  const guard = useDiscardGuard({ busy, dirty, close });
  const { requestClose } = guard;
  const discard = guard.asking;
  function read(): unknown {
    if (tab === 'fields') {
      if (unfinished) throw Error('invalid_condition');
      return value;
    }
    if (tab === 'json') return JSON.parse(json);
    // Viewing a simple list must preserve scalar/array spelling, duplicates,
    // grouping and explicit defaults until the user actually edits that list.
    return list === listSource ? value : parseCategoryText(list);
  }
  function checkedValue(): Config[] {
    const result = read();
    if (
      (tab === 'fields' && invalid) ||
      !Array.isArray(result) ||
      result.some((r) => !r || typeof r !== 'object' || Array.isArray(r))
    )
      throw Error('invalid_routing');
    if (new TextEncoder().encode(JSON.stringify(result)).length > limits.maxRoutingProfileBytes)
      throw Error('routing_import_too_large');
    return result;
  }
  function switchTab(next: string) {
    if (next === tab) return;
    try {
      const result = read();
      // Check the serializer before leaving the text that can still represent
      // deeply nested input. A failed transition keeps the original draft.
      const encoded = JSON.stringify(result, null, 2);
      if (next === 'list') {
        const text = categoryText(result);
        if (text === null) throw Error('category_json_required');
        setList(text);
        setListSource(text);
      } else if (next === 'json') setJson(encoded);
      setValue(result);
      setTab(next);
      setError('');
      setNotice('');
    } catch (e) {
      setError(
        e instanceof RangeError ? messageRef('routing.edit_this_level_of_nesting_in_json_42c5175') : e,
      );
    }
  }
  function changed() {
    setDirty(true);
    setError('');
    setNotice('');
  }
  async function submit(validateOnly = false) {
    setError('');
    setNotice('');
    try {
      if (!title.trim()) throw Error('resource_tag_required');
      const result = checkedValue();
      setBusy(true);
      const finalTitle = title === name ? name : title.trim();
      if (validateOnly && check) {
        await check(finalTitle, result);
        setNotice(messageRef('routing.the_core_accepted_this_configuration_dde5666'));
      } else {
        await save(finalTitle, result);
        close();
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      className="geo-content-modal"
      title={translate(language, 'routing.content_editor_68811e2')}
      description={
        copy
          ? translate(language, 'routing.this_is_your_own_copy_of_the_category_source_upd_b5b74fa')
          : translate(language, 'routing.conditions_in_this_inline_rule_set_the_traffic_a_4326188')
      }
      close={requestClose}
      footer={
        <>
          <Button className="button secondary" disabled={busy} onClick={requestClose}>
            {translate(language, 'routing.cancel_bf4c449')}
          </Button>
          {check && (
            <Button
              id="geo-content-check"
              className="button secondary"
              disabled={busy || discard}
              onClick={() => void submit(true)}
            >
              {translate(language, 'routing.validate_e2a8979')}
            </Button>
          )}
          <Button
            id="geo-content-save"
            className="button primary"
            disabled={busy || discard}
            onClick={() => void submit()}
          >
            {busy
              ? translate(language, 'routing.validating_4629974')
              : copy
                ? translate(language, 'routing.save_copy_d24fe76')
                : translate(language, 'routing.save_9cd85bd')}
          </Button>
        </>
      }
    >
      <Field className="feature-field" label={translate(language, 'routing.name_5163a2e')}>
        <Input
          id="geo-content-name"
          className="text-input"
          value={title}
          maxLength={limits.maxNameBytes}
          disabled={busy}
          onChange={(e) => {
            setTitle(e.target.value);
            changed();
          }}
        />
      </Field>
      <TabList
        value={tab}
        onChange={switchTab}
        disabled={busy}
        tabs={[
          { id: 'list', label: translate(language, 'routing.entries_a32836e') },
          { id: 'fields', label: translate(language, 'routing.conditions_16b104c') },
          { id: 'json', label: 'JSON' },
        ].map((t) => ({ ...t, attributes: { 'data-geo-content-tab': t.id } }))}
      />
      {tab === 'fields' ? (
        <LogicalConditions
          schema="headless"
          value={value}
          language={language}
          disabled={busy}
          invalidChanged={setInvalid}
          unfinishedChanged={setUnfinished}
          change={(next) => {
            setValue(next);
            changed();
          }}
        />
      ) : (
        <>
          <p className="geo-hint">
            {tab === 'list'
              ? translate(language, 'routing.one_entry_per_line_domain_suffix_keyword_regex_o_65f4a95')
              : translate(language, 'routing.the_complete_conditions_array_including_nested_g_c28769d')}
          </p>
          <Textarea
            id="geo-content-text"
            aria-label={translate(language, 'routing.category_contents_33e6f11')}
            className="text-input mono geo-content-text"
            spellCheck={false}
            value={tab === 'list' ? list : json}
            disabled={busy}
            onChange={(e) => {
              if (tab === 'list') setList(e.target.value);
              else setJson(e.target.value);
              changed();
            }}
          />
        </>
      )}
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
      <DiscardDialog guard={guard} language={language} />
    </Modal>
  );
}
