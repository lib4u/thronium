import { useMessageState } from '../shared/i18n/react';
import { messageRef, LocalizedError } from '../shared/i18n/message';
import { translate, type MessageKey } from '../shared/i18n/index.ts';
import { ApiError, errorCode } from '../shared/api/errors.ts';
import { useEffect, useRef, useState } from 'react';
import { command, type Snapshot } from '../api';
import { settingsValues, type WarpConfig } from '../warp/config';
import { dnsGeneralSections } from '../routing/resources';
import { usesTestUrl } from '../probes/messages';
import aliases from './aliases.json';
import {
  Values,
  Conflict,
  Field,
  fields,
  messageSearch,
  sections,
  inputId,
  groups,
  runtimeSections,
  sectionGroups as groupsOf,
  encode,
  decode,
} from './SettingsCatalog';
// The control a navigation request wants focused: an explicit input id, else
// the entry point of the two sections other pages link to.
const requestedFocus = (requested?: string, focus?: string) =>
  focus ??
  (requested === 'inbound' ? 'connection-mode' : requested === 'testing' ? 'setting-ping_method' : undefined);
export function useSettingsController({
  snapshot,
  changed,
  translateError,
  requested,
  focus,
  navigated,
}: {
  snapshot: Snapshot;
  changed(): Promise<void>;
  translateError(e: unknown): string;
  requested?: string;
  focus?: string;
  navigated(): void;
}) {
  const [active, setActive] = useState(requested || 'appearance'),
    [search, setSearch] = useState('');
  const [saved, setSaved] = useState<Record<string, Values>>({}),
    [drafts, setDrafts] = useState<Record<string, Values>>({});
  const [error, setError] = useMessageState(snapshot.preferences.language, translateError),
    [fieldErrors, setFieldErrors] = useState<Set<string>>(new Set()),
    [busy, setBusy] = useState(false),
    [notice, setNotice] = useMessageState(snapshot.preferences.language, () => '');
  const [conflict, setConflict] = useState<Conflict>();
  // Listener and TUN settings belong to the running connection: disconnect first.
  const runtimeLocked = !!snapshot.running && runtimeSections.includes(active);
  // The latency method this form shows: the draft, else the saved value, else the catalog default.
  const pingMethod = String(
    drafts.testing?.ping_method ??
      saved.testing?.ping_method ??
      fields.find((f) => f.id === 'ping_method')?.default,
  );
  const [dnsTarget, setDnsTarget] = useState<string>();
  const [subscription, setSubscription] = useState<string>(),
    [jobs, setJobs] = useState(false);
  const [group, setGroup] = useState<string>(),
    [dnsVisited, setDnsVisited] = useState(active === 'dns');
  const lock = useRef(false),
    pendingFocus = useRef<string | undefined>(requestedFocus(requested, focus));
  function load(section?: string) {
    return command('settings').then((next) =>
      setSaved((old) => (section ? { ...old, [section]: next[section] } : next)),
    );
  }
  useEffect(() => {
    void load().catch((e) => setError(errorCode(e)));
  }, []);
  useEffect(() => {
    if (requested) {
      pendingFocus.current = requestedFocus(requested, focus);
      setActive(requested);
      setSearch('');
      navigated();
    }
  }, [requested, focus]);
  useEffect(() => {
    if (active === 'dns') setDnsVisited(true);
  }, [active]);
  function liveValue(f: Field): unknown {
    if (f.preference)
      return f.preference
        .split('/')
        .slice(1)
        .reduce<unknown>(
          (v, k) => (v && typeof v === 'object' ? (v as Values)[k] : undefined),
          snapshot.preferences,
        );
    return f.section === 'appearance' ? snapshot.appearance?.[f.id] : undefined;
  }
  // Refresh untouched controls when the header or another UI changes a setting.
  // Edited controls retain the baseline needed to detect a real field conflict.
  const liveSettingsKey = JSON.stringify([snapshot.preferences, snapshot.appearance]);
  useEffect(() => {
    setSaved((old) => {
      let next = old;
      for (const f of fields) {
        const value = liveValue(f);
        if (
          !old[f.section] ||
          value === undefined ||
          drafts[f.section]?.[f.id] !== undefined ||
          JSON.stringify(old[f.section][f.id]) === JSON.stringify(value)
        )
          continue;
        if (next === old) next = { ...old };
        next[f.section] = { ...next[f.section], [f.id]: value };
      }
      return next;
    });
  }, [liveSettingsKey]);

  useEffect(() => {
    if (!pendingFocus.current || search || !saved[active]) return;
    const target = document.getElementById(pendingFocus.current);
    if (target) {
      const card = target.closest('details');
      if (card) card.open = true;
      let focus = target;
      if (target.matches(':disabled')) {
        const field = fields.find((f) => inputId(f) === target.id),
          controller = field?.dependsOn || field?.disabledWhen?.field;
        focus =
          (controller ? document.getElementById('setting-' + controller) : null) ||
          card?.querySelector('summary') ||
          target;
      }
      focus.scrollIntoView({ block: 'center' });
      focus.focus({ preventScroll: true });
      pendingFocus.current = undefined;
    }
  }, [active, search, saved, error, busy, conflict]);
  const [assetBusy, setAssetBusy] = useState(false);
  const [geoSourcesVersion, setGeoSourcesVersion] = useState(0);
  const sec = sections.find((s) => s[0] === active)!;
  const sectionFields = fields.filter((f) => f.section === active),
    base = saved[active];
  const sectionGroups = groupsOf(active);
  const fieldValue = (f: Field) => drafts[active]?.[f.id] ?? encode(f, base?.[f.id] ?? f.default);
  const dirty = sectionFields.some(
    (f) =>
      drafts[active]?.[f.id] !== undefined && drafts[active][f.id] !== encode(f, base?.[f.id] ?? f.default),
  );
  function edit(f: Field, value: unknown) {
    let reference = base?.[f.id] ?? f.default;
    const live = liveValue(f);
    if (
      live !== undefined &&
      value === encode(f, reference) &&
      JSON.stringify(live) !== JSON.stringify(reference)
    ) {
      reference = live;
      setSaved((old) => ({ ...old, [active]: { ...old[active], [f.id]: live } }));
    }
    setDrafts((d) => {
      const section = { ...d[active] };
      if (value === encode(f, reference)) delete section[f.id];
      else section[f.id] = value;
      return { ...d, [active]: section };
    });
    setConflict(undefined);
    setError('');
    setNotice('');
    setFieldErrors((old) => {
      const next = new Set(old);
      next.delete(f.id);
      return next;
    });
  }
  function useWarp(config: WarpConfig) {
    const values = settingsValues(config);
    setDrafts((old) => {
      const section = { ...old.intercept };
      for (const [id, value] of Object.entries(values)) {
        const field = fields.find((f) => f.id === id)!;
        const encoded = encode(field, value);
        if (encoded === encode(field, saved.intercept?.[id] ?? field.default)) delete section[id];
        else section[id] = encoded;
      }
      return { ...old, intercept: section };
    });
    setConflict(undefined);
    setError('');
    setFieldErrors(
      (old) => new Set([...old].filter((id) => !Object.prototype.hasOwnProperty.call(values, id))),
    );
    setNotice(
      translate(
        snapshot.preferences.language,
        'settings.warp_parameters_filled_save_settings_to_keep_the_fe23e72',
      ),
    );
  }
  function errorText(e: unknown) {
    const message = errorCode(e);
    if (message === 'settings_shortcut_unavailable')
      return messageRef('settings.this_shortcut_is_invalid_or_already_registered_b_b99188f');
    if (message === 'settings_invalid') {
      // The boundary names the rejected setting as `$.<id>`.
      const id = e instanceof ApiError ? e.field?.slice(2) || '' : '';
      setFieldErrors(new Set([id]));
      const field = fields.find((f) => f.id === id);
      if (field) {
        pendingFocus.current =
          id === 'test_url' && !usesTestUrl(pingMethod) ? 'setting-ping_method' : inputId(field);
        setActive(field.section);
        setSearch('');
      }
      return messageRef('settings.check_the_highlighted_field_35bb2b1');
    }
    if (message === 'settings_conflict')
      return messageRef('settings.a_setting_changed_while_you_were_editing_your_in_e2d6a25');
    const known: Record<string, MessageKey> = {
      settings_autostart_failed: 'settings.could_not_change_startup_registration_530861f',
      settings_deeplink_failed: 'settings.could_not_register_links_with_the_operating_syst_4c8447e',
      settings_deeplink_bundled_only: 'settings.on_macos_link_registration_is_provided_by_the_in_84dc6bd',
      settings_system_proxy_incompatible: 'settings.system_proxy_requires_a_local_mixed_listener_wit_b200868',
      settings_tray_failed: 'settings.could_not_change_the_tray_icon_b7a7be9',
      settings_rollback_failed: 'settings.could_not_restore_the_previous_settings_reload_t_5a16219',
    };
    return known[message] ? messageRef(known[message]) : e;
  }
  async function applyValues(sectionId: string, previous: Values, values: Values) {
    try {
      const updated = await command('saveSettings', { section: sectionId, previous, values });
      await changed();
      setSaved((s) => ({ ...s, [sectionId]: updated }));
      setDrafts((d) => {
        const next = { ...d };
        delete next[sectionId];
        return next;
      });
      setConflict(undefined);
      setFieldErrors(new Set());
      setNotice(messageRef('settings.saved_c2b7708'));
    } catch (e) {
      const message = errorCode(e);
      if (message === 'settings_conflict') {
        const ids = (e instanceof ApiError ? e.safeParams?.fields || '' : '')
          .split(',')
          .filter((id) => fields.some((f) => f.id === id && f.section === sectionId));
        if (ids.length) {
          setConflict({ section: sectionId, previous, values, fields: ids });
          setFieldErrors(new Set());
          pendingFocus.current = 'settings-conflict-current';
          setActive(sectionId);
          setSearch('');
          return;
        }
      }
      throw e;
    }
  }
  async function save() {
    if (lock.current || !base) return;
    lock.current = true;
    setBusy(true);
    setError('');
    setNotice('');
    setConflict(undefined);
    try {
      const values: Values = {},
        invalid = new Set<string>();
      for (const f of sectionFields) {
        try {
          const value = decode(f, fieldValue(f));
          if (
            f.kind === 'number' &&
            (!Number.isFinite(value) ||
              (f.min !== undefined && Number(value) < f.min) ||
              (f.max !== undefined && Number(value) > f.max))
          )
            throw Error();
          values[f.id] = value;
        } catch {
          invalid.add(f.id);
        }
      }
      if (invalid.size) {
        setFieldErrors(invalid);
        const first = sectionFields.find((f) => invalid.has(f.id))!;
        pendingFocus.current = inputId(first);
        throw new LocalizedError('settings.check_the_highlighted_fields_9ad6790');
      }
      // A hidden HTTP URL draft must not prevent saving TCP/ICMP settings.
      if (active === 'testing' && !usesTestUrl(String(values.ping_method))) values.test_url = base.test_url;
      await applyValues(active, base, values);
    } catch (e) {
      setError(errorText(e));
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  async function resolveConflict(keepMine: boolean) {
    if (lock.current || !conflict) return;
    const pending = conflict;
    lock.current = true;
    setBusy(true);
    setError('');
    try {
      const latest = (await command('settings'))[pending.section];
      const resolved = Object.fromEntries(pending.fields.map((id) => [id, latest[id]]));
      if (keepMine) {
        await applyValues(pending.section, { ...pending.previous, ...resolved }, pending.values);
      } else {
        setSaved((s) => ({ ...s, [pending.section]: { ...s[pending.section], ...resolved } }));
        setDrafts((d) => {
          const next = { ...d[pending.section] };
          for (const id of pending.fields) delete next[id];
          return { ...d, [pending.section]: next };
        });
        setConflict(undefined);
        setFieldErrors(new Set());
        setNotice(
          translate(
            snapshot.preferences.language,
            'settings.saved_values_loaded_other_edits_remain_in_the_fo_0c4525c',
          ),
        );
      }
    } catch (e) {
      setError(errorText(e));
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  const query = search.trim().toLocaleLowerCase();
  const found = fields.filter((f) =>
    (
      messageSearch(f.label) +
      ' ' +
      f.id +
      ' ' +
      (messageSearch(groups[f.group]) || '') +
      ' ' +
      (messageSearch(groups[f.subgroup || '']) || '') +
      ' ' +
      aliases
        .filter((a) => a.section === f.section && a.field === f.id)
        .map((a) => a.key)
        .join(' ') +
      ' ' +
      sections
        .find((s) => s[0] === f.section)
        ?.slice(2)
        .map(messageSearch)
        .join(' ')
    )
      .toLocaleLowerCase()
      .includes(query),
  );
  const dnsMatches = dnsGeneralSections([])
    .flatMap((s) => s.fields)
    .filter((f) =>
      (
        messageSearch(f.label) +
        ' dns_' +
        f.path +
        ' ' +
        aliases
          .filter((a) => a.section === 'dns' && a.field === f.path)
          .map((a) => a.key)
          .join(' ')
      )
        .toLocaleLowerCase()
        .includes(query),
    );
  const specialMatches = (
    [
      ['dns', 'servers', 'settings.dns_servers_hosts_fakeip_remote_and_direct_dns_6c0daf6'],
      ['dns', 'rules', 'settings.dns_routing_and_predefined_responses_5a398b1'],
      ['dns', 'json', 'settings.custom_dns_json_dns_object_use_dns_object_8bf21a8'],
      ['dns', 'outbound', 'settings.server_address_dns_outbound_domain_strategy_798db78'],
      ['backup', 'backup', 'settings.backup_and_restore_722793b'],
    ] as const
  ).filter((s) =>
    (
      s.slice(2).map(messageSearch).join(' ') +
      ' ' +
      aliases
        .filter((a) => a.section === s[0] && a.field === s[1])
        .map((a) => a.key)
        .join(' ')
    )
      .toLocaleLowerCase()
      .includes(query),
  );
  /** Opens a section from the section list; a search and old messages end. */
  function openSection(id: string) {
    setActive(id);
    setSearch('');
    setError('');
    setNotice('');
  }
  /** Opens the section of a setting (or `input` there) and focuses it. */
  function openSetting(section: string, input?: string) {
    if (input) pendingFocus.current = input;
    openSection(section);
  }
  /** Opens a DNS object (a server, rule or special entry) found by the search. */
  function openDnsObject(section: string, target: string) {
    setActive(section);
    setDnsTarget(target);
    setSearch('');
  }
  /** Drops the drafts of the shown section and reloads it. */
  function discardDrafts() {
    setDrafts((d) => {
      const next = { ...d };
      delete next[active];
      return next;
    });
    setFieldErrors(new Set());
    setError('');
    setConflict(undefined);
    void load(active).catch((e) => setError(errorText(e)));
  }
  /** A restored backup replaces every section, including unsaved drafts. */
  async function backupRestored() {
    setDrafts({});
    await load();
    await changed();
  }
  const dialogs = {
    editGroup: (id: string) => setGroup(id),
    addGroup: () => setGroup(''),
    closeGroups: () => setGroup(undefined),
    updateSubscription(id: string) {
      setGroup(undefined);
      setJobs(false);
      setSubscription(id);
    },
    closeSubscription: () => setSubscription(undefined),
    showJobs() {
      setGroup(undefined);
      setJobs(true);
    },
    closeJobs: () => setJobs(false),
  };
  return {
    active,
    assetBusy,
    assetBusyChanged: setAssetBusy,
    backupRestored,
    base,
    busy,
    changed,
    changeSearch: setSearch,
    conflict,
    dialogs,
    dirty,
    discardDrafts,
    dnsMatches,
    dnsNavigated: () => setDnsTarget(undefined),
    dnsTarget,
    dnsVisited,
    drafts,
    edit,
    error,
    fieldErrors,
    fieldValue,
    found,
    geoSourcesChanged: () => setGeoSourcesVersion((version) => version + 1),
    geoSourcesVersion,
    group,
    jobs,
    notice,
    openDnsObject,
    openSection,
    openSetting,
    pingMethod,
    query,
    resolveConflict,
    runtimeLocked,
    save,
    saved,
    search,
    sec,
    sectionFields,
    sectionGroups,
    snapshot,
    specialMatches,
    subscription,
    translateError,
    useWarp,
  };
}
