import { messageRef } from '../shared/i18n/message';
import { useMessageState } from '../shared/i18n/react';
import { translate, type Language } from '../shared/i18n/index.ts';
import { isRequest } from '../shared/api/validation';
import { useEffect, useState } from 'react';
import { command, type Profile } from '../api';
import { label, type Config, type Label } from '../profiles/schema';
import { defaultTarget, outboundProfiles, type RouteProfile } from './model';
import type { ObjectEditorProps } from './ObjectEditor';
import {
  objects,
  tags,
  dnsTags,
  dnsSeed,
  dnsServerSections,
  dnsGeneralSections,
  dnsRuleSections,
  dnsRuleShared,
  ruleSetSeed,
  ruleSetSections,
  strategyOptions,
} from './resources';
import { saveServer, removeServer, saveRuleSet, removeRuleSet } from './resourceReferences';

export const messageKeys = {
  fields: 'routing.parameters_8f0e762',
  json: 'routing.json_96a5a28',
  servers: 'routing.dns_servers_163b6d8',
  rules: 'routing.dns_rules_02300d7',
  sets: 'routing.rule_sets_28d0c07',
  addServer: 'routing.add_server_aa1c302',
  addRule: 'routing.add_dns_rule_230e0d7',
  addSet: 'routing.add_rule_set_e8e8779',
  options: 'routing.resolution_and_cache_27fb3bd',
  newServer: 'routing.new_dns_server_081dad1',
  editServer: 'routing.edit_dns_server_d3f4504',
  newRule: 'routing.new_dns_rule_1a49789',
  editRule: 'routing.edit_dns_rule_811c197',
  newSet: 'routing.new_rule_set_1cbf244',
  editSet: 'routing.edit_rule_set_0a42875',
  serverHint: 'routing.add_hosts_or_fakeip_to_also_create_an_a_aaaa_dns_309ef2d',
  ruleHint: 'routing.rules_run_from_top_to_bottom_empty_conditions_ma_54ae8ab',
  setHint: 'routing.local_files_remote_urls_and_inline_rules_referen_76933eb',
  resolveDomains: 'routing.resolve_connection_domains_3f01a1f',
  resolveHint: 'routing.in_by_rules_mode_add_a_first_routing_rule_that_r_b9d858d',
  defaultServer: 'routing.default_server_c9c82db',
  firstServer: 'routing.first_server_6796864',
  empty: 'routing.no_entries_yet_bf4d3ef',
  all: 'routing.all_queries_37fd521',
  nested: 'routing.nested_conditions_3c70b63',
  edit: 'routing.edit_0fd5c3c',
  remove: 'routing.delete_55f670b',
  up: 'routing.move_up_441b312',
  down: 'routing.move_down_d672813',
  confirm: 'routing.delete_this_entry_c60d66c',
  cancel: 'routing.cancel_bf4c449',
  close: 'routing.close_c9a286c',
  save: 'routing.save_9cd85bd',
  check: 'routing.validate_e2a8979',
  checked: 'routing.the_core_accepted_this_configuration_dde5666',
  saved: 'routing.saved_c2b7708',
  busy: 'routing.validating_4629974',
  unsaved: 'routing.unsaved_changes_f73b98c',
  discard: 'routing.discard_json_changes_b38e017',
  keep: 'routing.keep_editing_7c292c4',
  discardButton: 'routing.discard_6febe61',
  direct: 'routing.direct_cc7ab89',
  proxy: 'routing.selected_server_1797ac9',
  reject: 'routing.block_59fb954',
  predefined: 'routing.predefined_answer_71aa341',
  'route-options': 'routing.query_options_2ea5f7a',
  evaluate: 'routing.evaluate_response_c459a7b',
  respond: 'routing.return_response_22b8fbc',
  local: 'routing.local_cc44a62',
  remote: 'routing.remote_46ab878',
  inline: 'routing.inline_b1f9ba2',
  rawHint: 'routing.the_complete_configuration_for_this_section_addi_6b7635d',
} satisfies Record<string, Label>;
export type Entry = { kind: 'server' | 'rule' | 'set'; index: number };
export type ResourcesPanelProps = {
  requested?: string;
  navigated?(): void;
  kind: 'dns' | 'sets';
  profile: RouteProfile;
  profiles: Profile[];
  language: Language;
  busy: boolean;
  rawDraft?: string;
  setRawDraft(value?: string): void;
  update(profile: RouteProfile): Promise<void>;
  translateError(e: unknown): string;
};

type Candidate = (current: RouteProfile, value: Config) => RouteProfile;

/** DNS and rule set resources of a routing profile: editors, ordering, deletion and the raw JSON view. */
export function useResourcesPanel({
  kind,
  requested,
  navigated,
  profile,
  profiles,
  language,
  busy: parentBusy,
  rawDraft,
  setRawDraft,
  update,
  translateError,
}: ResourcesPanelProps) {
  const tr = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  // A kept JSON draft reopens in JSON, so saving the form cannot drop it.
  const [view, setView] = useState(() => (rawDraft === undefined ? 'fields' : 'json'));
  const raw = rawDraft ?? null;
  const setRaw = (value: string | null) => setRawDraft(value ?? undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useMessageState(language, translateError);
  const [notice, setNotice] = useMessageState(language, () => '');
  const [discard, setDiscard] = useState(false);
  // An open editor keeps how to build its candidate, not a save callback: the
  // candidate is built from the profile saved when Save is pressed, so a
  // change made elsewhere meanwhile is not overwritten or refused as stale.
  const [editor, setEditor] = useState<{
    props: Omit<
      ObjectEditorProps,
      'close' | 'language' | 'translateError' | 'save' | 'check' | 'optionLabels'
    >;
    candidate: Candidate;
  } | null>(null);
  const [deleting, setDeleting] = useState<Entry | null>(null);
  const [content, setContent] = useState<{
    index: number;
    name: string;
    rules: unknown;
    source: Config;
  } | null>(null);
  const disabled = busy || parentBusy;
  const servers = objects(profile.dns.servers),
    rules = objects(profile.dns.rules),
    sets = objects(profile.route.rule_set);
  const resolvers = dnsTags(profile);
  const outbounds = [defaultTarget, 'direct', ...outboundProfiles(profiles).map((p) => 'profile:' + p.id)];
  const optionLabels = Object.fromEntries(profiles.map((p) => ['profile:' + p.id, p.name]));
  const check = (candidate: RouteProfile) => command('checkRouting', candidate);
  const encoded = JSON.stringify(kind === 'dns' ? profile.dns : profile.route.rule_set || [], null, 2);
  const dirty = raw !== null && raw !== encoded;
  async function run(action: () => Promise<void>, message: 'saved' | 'checked' | null = 'saved') {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
      if (message) setNotice(messageRef(messageKeys[message]));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  function open(
    initial: Config,
    title: string,
    sections: ObjectEditorProps['sections'],
    candidate: Candidate,
    extra: Partial<ObjectEditorProps> = {},
  ) {
    setError('');
    setNotice('');
    setEditor({ props: { title, initial, sections, ...extra }, candidate });
  }
  function server(index?: number) {
    open(
      index === undefined ? dnsSeed('udp') : servers[index],
      tr(index === undefined ? 'newServer' : 'editServer'),
      (c) =>
        dnsServerSections(
          c,
          resolvers,
          outbounds,
          profiles
            .filter(
              (p) =>
                p.kind === 'sing-box-outbound' &&
                p.protocol === (c.type === 'openvpn' ? 'openvpn-client' : c.type),
            )
            .map((p) => 'profile:' + p.id),
        ),
      (current, c) => saveServer(current, index, c),
      {
        hint: index === undefined ? tr('serverHint') : undefined,
        variant: { path: 'type', seed: dnsSeed, shared: (c) => ({ tag: c.tag }) },
      },
    );
  }
  function rule(index?: number) {
    const initial =
      index === undefined
        ? { action: 'route', server: resolvers[0] || '' }
        : { ...rules[index], action: rules[index].action || 'route' };
    open(
      initial,
      tr(index === undefined ? 'newRule' : 'editRule'),
      (c) => dnsRuleSections(c, resolvers),
      (current, c) => {
        const list = objects(current.dns.rules);
        return {
          ...current,
          dns: {
            ...current.dns,
            rules: index === undefined ? [...list, c] : list.map((r, i) => (i === index ? c : r)),
          },
        };
      },
      {
        hint: tr('ruleHint'),
        variant: {
          path: 'action',
          seed: (action) => ({
            action,
            ...(['route', 'evaluate'].includes(action) ? { server: resolvers[0] || '' } : {}),
          }),
          shared: dnsRuleShared,
        },
      },
    );
  }
  function ruleSet(index?: number) {
    open(
      index === undefined ? ruleSetSeed('remote') : { ...sets[index], type: sets[index].type || 'inline' },
      tr(index === undefined ? 'newSet' : 'editSet'),
      (c) => ruleSetSections(c, outbounds),
      (current, c) => saveRuleSet(current, index, c),
      {
        hint: tr('setHint'),
        variant: { path: 'type', seed: ruleSetSeed, shared: (c) => ({ tag: c.tag }) },
      },
    );
  }
  function editContents(index: number) {
    const set = sets[index];
    void run(async () => {
      let rules = Object.prototype.hasOwnProperty.call(set, 'rules') ? set.rules : [];
      if (set.type === 'geodata') {
        if (!isRequest('geodataCategory', set)) throw new Error('invalid_command_payload');
        rules = (await command('geodataCategory', set)).rules;
      }
      setContent({ index, name: tags(set.tag).join(', '), rules, source: structuredClone(set) });
    }, null);
  }
  function contentCandidate(name: string, rules: Config[]): RouteProfile {
    if (!content) throw Error('invalid_routing');
    // A downloaded category becomes a private inline copy. Editing an existing
    // inline set preserves every additional parameter on that set.
    const source = content.source.type === 'geodata' ? { type: 'inline' } : content.source;
    const tag =
      name === content.name
        ? content.source.tag
        : name
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
    return saveRuleSet(
      profile,
      content.index,
      { ...source, tag, rules },
      { preserveTag: name === content.name },
    );
  }
  useEffect(() => {
    if (!requested || kind !== 'dns') return;
    if (requested === 'json') {
      setView('json');
    } else if (requested === 'outbound') {
      outboundDns();
    } else if (requested === 'rules') {
      document.getElementById('dns-add-rule')?.focus();
    } else if (requested === 'servers') {
      document.getElementById('dns-add-server')?.focus();
    } else {
      open(
        profile.dns,
        tr('options'),
        () => dnsGeneralSections(resolvers),
        (current, c) => ({ ...current, dns: c }),
        { initialField: requested },
      );
    }
    navigated?.();
  }, [requested]);
  function outboundDns() {
    const value = profile.route.default_domain_resolver;
    open(
      typeof value === 'string' ? { server: value } : (value as Config) || {},
      translate(language, 'routing.server_address_dns_7c6314a'),
      () => [
        {
          id: 'main',
          label: 'routing.resolution_5c17f1a',
          fields: [
            { path: 'server', label: 'routing.dns_server_175f9f1', kind: 'select', options: resolvers },
            {
              path: 'strategy',
              label: 'routing.address_strategy_ec86ed2',
              kind: 'select',
              options: strategyOptions,
            },
          ],
        },
      ],
      (current, c) => ({ ...current, route: { ...current.route, default_domain_resolver: c } }),
    );
  }
  function reorder(index: number, delta: number) {
    const list = [...rules];
    [list[index], list[index + delta]] = [list[index + delta], list[index]];
    void run(() => update({ ...profile, dns: { ...profile.dns, rules: list } }));
  }
  const name = (entry: Entry) =>
    entry.kind === 'rule'
      ? String(entry.index + 1)
      : tags((entry.kind === 'server' ? servers : sets)[entry.index]?.tag).join(', ') || '—';
  async function remove() {
    if (!deleting) return;
    const { kind: type, index } = deleting;
    const candidate =
      type === 'server'
        ? removeServer(profile, index)
        : type === 'set'
          ? removeRuleSet(profile, index)
          : { ...profile, dns: { ...profile.dns, rules: rules.filter((_, i) => i !== index) } };
    await update(candidate);
    setDeleting(null);
  }
  function changeView(next: string) {
    if (next === view) return;
    if (next === 'fields' && dirty) {
      setDiscard(true);
      return;
    }
    setView(next);
    if (next === 'fields') setRaw(null);
    setNotice('');
    setError('');
  }
  async function jsonAction(save: boolean) {
    const value: unknown = JSON.parse(raw ?? encoded);
    if (kind === 'dns' ? !value || typeof value !== 'object' || Array.isArray(value) : !Array.isArray(value))
      throw Error('invalid_routing');
    const candidate =
      kind === 'dns'
        ? { ...profile, dns: value as Config }
        : { ...profile, route: { ...profile.route, rule_set: value } };
    if (save) {
      await update(candidate);
      setRaw(null);
    } else await check(candidate);
  }
  return {
    kind,
    profile,
    profiles,
    language,
    update,
    translateError,
    tr,
    view,
    setView,
    raw,
    setRaw,
    error,
    setError,
    notice,
    discard,
    setDiscard,
    editor,
    setEditor,
    deleting,
    setDeleting,
    content,
    setContent,
    disabled,
    servers,
    rules,
    sets,
    resolvers,
    optionLabels,
    check,
    encoded,
    dirty,
    run,
    open,
    server,
    rule,
    ruleSet,
    editContents,
    contentCandidate,
    outboundDns,
    reorder,
    name,
    remove,
    changeView,
    jsonAction,
    setNotice,
  };
}

export type ResourcesController = ReturnType<typeof useResourcesPanel>;
