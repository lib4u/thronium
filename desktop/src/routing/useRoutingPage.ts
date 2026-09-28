import { messageRef } from '../shared/i18n/message';
import { routingProfileName, targetLabel as routeTargetLabel } from './model';
import { errorCode } from '../shared/api/errors.ts';
import { useMessageState } from '../shared/i18n/react';
import { useEffect, useState } from 'react';
import type { RoutingImportRequest } from './catalog';
import { command, type Snapshot } from '../api';
import { label } from '../profiles/schema';
import {
  actions,
  ruleTarget,
  replaceSimple,
  coreRoute,
  fromCoreRoute,
  type RouteRule,
  type RouteProfile,
  type Routing,
} from './model';
import { messageKeys, type Tr } from './RuleEditor';

export type RoutingPageProps = {
  snapshot: Snapshot;
  refresh(): Promise<void>;
  translateError(e: unknown): string;
  requestedImport?: RoutingImportRequest;
  importOpened?(): void;
};

/** Routing page state: the saved routing, open editors, text buffers and the actions that save them. */
export function useRoutingPage({
  snapshot,
  refresh,
  translateError,
  requestedImport,
  importOpened,
}: RoutingPageProps) {
  const language = snapshot.preferences.language;
  const tr: Tr = (key) => label(messageKeys[key], language);
  const [data, setData] = useState<Routing | null>(null);
  const [error, setError] = useMessageState(language, translateError);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useMessageState(language, () => '');
  const [tab, setTab] = useState('rules');
  const [query, setQuery] = useState('');
  const [simpleTarget, setSimpleTarget] = useState('direct');
  const [buffers, setBuffers] = useState<Record<string, string>>({});
  const [modal, setModal] = useState<'rule' | 'profiles' | 'delete-rule' | 'import' | null>(null);
  const [editing, setEditing] = useState<RouteRule | undefined>();
  const [profileName, setProfileName] = useState('');
  const [profileEditing, setProfileEditing] = useState('');
  const [deleting, setDeleting] = useState('');
  const [importRequest, setImportRequest] = useState<RoutingImportRequest>();
  // Saved routing is re-read whenever its revision changes, also while an
  // editor or a text buffer is open: drafts live in their own state, and a
  // stale base would make every later save fail with routing_changed.
  useEffect(() => {
    if (busy) return;
    let live = true;
    command('routing')
      .then((r) => {
        if (live) setData(r);
      })
      .catch((e) => {
        if (live) setError(e);
      });
    return () => {
      live = false;
    };
  }, [snapshot.routing.revision, busy]);
  useEffect(() => {
    if (!requestedImport || !data) return;
    importOpened?.();
    if (busy || modal || document.querySelector('dialog[open]')) return;
    setImportRequest(requestedImport);
    setModal('import');
  }, [requestedImport, data, busy, modal, importOpened]);
  const current = data?.profiles.find((p) => p.id === data.active);
  async function persist(next: Routing, check?: RouteProfile | RouteProfile[]) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      for (const profile of [check ?? []].flat()) await command('checkRouting', profile);
      const saved = await command('saveRouting', next);
      setData(saved);
      setNotice(messageRef(messageKeys.saved));
      // The save already succeeded; a failed snapshot refresh must not make the
      // editor retry it and add the rule twice. The periodic snapshot catches up.
      await refresh().catch(() => {});
    } catch (e) {
      setError(e);
      // Another window or the tray saved first: load that version so the
      // kept draft can be saved again on top of it.
      if (errorCode(e) === 'routing_changed') void command('routing').then(setData, () => {});
      throw e;
    } finally {
      setBusy(false);
    }
  }
  async function update(profile: RouteProfile) {
    await persist(
      { ...data!, profiles: data!.profiles.map((p) => (p.id === profile.id ? profile : p)) },
      profile,
    );
  }
  function run(action: () => Promise<unknown>) {
    void action().catch(() => {});
  }
  async function apply() {
    setBusy(true);
    setError('');
    try {
      await command('applyRouting');
      await refresh();
      setNotice(messageRef(messageKeys.saved));
    } catch (e) {
      setError(e);
      await refresh().catch(() => {});
    } finally {
      setBusy(false);
    }
  }
  const targetLabel = (value: string) => routeTargetLabel(value, snapshot.profiles, language);
  const actionLabel = (rule: RouteRule) =>
    !rule.config.action || rule.config.action === 'route' || rule.config.action === 'reject'
      ? targetLabel(ruleTarget(rule))
      : actions.find((a) => a.id === rule.config.action)
        ? label(actions.find((a) => a.id === rule.config.action)!.label, language)
        : String(rule.config.action);
  const nameOf = (p: RouteProfile) => routingProfileName(p, language);
  const bufferKey = current?.id + ':' + tab + (tab === 'simple' ? ':' + simpleTarget : '');
  const source = current
    ? tab === 'simple'
      ? current.rules
          .filter((r) => r.simple !== undefined && ruleTarget(r) === simpleTarget)
          .map((r) => r.simple)
          .join('\n')
      : JSON.stringify(
          tab === 'dns' ? current.dns : tab === 'sets' ? current.route.rule_set || [] : coreRoute(current),
          null,
          2,
        )
    : '';
  const text = buffers[bufferKey] ?? source;
  async function jsonAction(save: boolean) {
    if (!current) return;
    setError('');
    setNotice('');
    try {
      let changed: RouteProfile;
      if (tab === 'simple') changed = replaceSimple(current, simpleTarget, text);
      else {
        const value = JSON.parse(text);
        if (tab === 'sets') {
          if (!Array.isArray(value)) throw Error('invalid_routing');
          changed = { ...current, route: { ...current.route, rule_set: value } };
        } else {
          if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('invalid_routing');
          changed = tab === 'dns' ? { ...current, dns: value } : fromCoreRoute(current, value);
        }
      }
      if (save) {
        await update(changed);
        setBuffers((old) => {
          const next = { ...old };
          delete next[bufferKey];
          return next;
        });
      } else {
        setBusy(true);
        await command('checkRouting', changed);
        setNotice(messageRef(messageKeys.checked));
      }
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  function reorder(rule: RouteRule, delta: number) {
    const rules = [...current!.rules];
    const i = rules.findIndex((r) => r.id === rule.id);
    [rules[i], rules[i + delta]] = [rules[i + delta], rules[i]];
    run(() => update({ ...current!, rules }));
  }
  async function exportProfile() {
    setBusy(true);
    setError('');
    try {
      const profile = await command('exportRoutingProfile', { id: current!.id });
      const result = await command('exportSharedText', {
        text: JSON.stringify(profile, null, 2),
        format: 'routing-profile',
        destination: 'file',
      });
      if (result.status === 'saved') setNotice(messageRef(messageKeys.saved));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  return {
    snapshot,
    refresh,
    translateError,
    language,
    tr,
    data,
    setData,
    error,
    setError,
    busy,
    notice,
    setNotice,
    tab,
    setTab,
    query,
    setQuery,
    simpleTarget,
    setSimpleTarget,
    buffers,
    setBuffers,
    modal,
    setModal,
    editing,
    setEditing,
    profileName,
    setProfileName,
    profileEditing,
    setProfileEditing,
    deleting,
    setDeleting,
    importRequest,
    setImportRequest,
    current,
    persist,
    update,
    run,
    apply,
    targetLabel,
    actionLabel,
    nameOf,
    bufferKey,
    text,
    jsonAction,
    reorder,
    exportProfile,
  };
}

export type RoutingPageController = ReturnType<typeof useRoutingPage>;
