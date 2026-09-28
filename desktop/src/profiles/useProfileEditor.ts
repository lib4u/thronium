import { useMessageState } from '../shared/i18n/react';
import { messageRef, LocalizedError } from '../shared/i18n/message';
import { errorCode } from '../shared/api/errors.ts';
import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { command, type Draft, type Snapshot, type VlessCore } from '../api';
import { type Key } from '../i18n';
import { Modal } from '../ui';
import { editWsEarlyData, wsPath, wsBuffer, httpUpgradePath } from './wsEarlyData';
import type { EmbeddedEditorProps } from './DialogPane';
import {
  definitions,
  sections,
  identify,
  get,
  set,
  parse,
  label,
  type Field,
  type Config,
  type Label,
} from './schema';
import { messageKeys, Working, working } from './EditorModel';
import { jsonKind, maxImportBytes } from './import';
import type { Language } from '../shared/i18n/index.ts';
import { policyDraft, tailscaleNodeDraft } from './vpnPolicy';
import { personalGroupId } from '../groups/groupModel';
export function useProfileEditor({
  libraryRevision = 0,
  draft: initialDraft,
  initialGroup,
  groups,
  profiles,
  runningId,
  language,
  t,
  translateError,
  close,
  changed,
  Frame = Modal,
  onActivity,
  completed = close,
  targetGroup,
  groupChanged,
}: {
  libraryRevision?: number;
  draft?: Draft;
  initialGroup?: string;
  runningId?: string | null;
  groups: Snapshot['groups'];
  profiles: Snapshot['profiles'];
  language: Language;
  t(key: Key): string;
  translateError(e: unknown): string;
  close(): void;
  changed(): Promise<void>;
} & EmbeddedEditorProps) {
  const [draft, setDraft] = useState(initialDraft);
  const [conflict, setConflict] = useState(false);
  const [confirmReload, setConfirmReload] = useState(false);
  const submitting = useRef(false);
  const tr = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const inUse = !!draft?.id && runningId === draft.id;
  const initialType = identify(draft);
  const [type, setType] = useState(initialType);
  const def = definitions.find((d) => d.id === type)!;
  const [drafts, setDrafts] = useState<Record<string, Working>>({
    [initialType]: working(draft?.config || def.seed),
  });
  const current = drafts[type] || working(def.seed);
  const [vlessCore, setVlessCore] = useState<VlessCore | 'default'>(draft?.vlessCore || 'default');
  const [vpnPolicy, setVpnPolicy] = useState<Draft['vpnPolicy']>(draft?.vpnPolicy);
  const [name, setName] = useState(draft?.name || '');
  const [localGroup, setLocalGroup] = useState(
    draft?.groupId || initialGroup || groups[0]?.id || personalGroupId,
  );
  const groupId = targetGroup ?? localGroup;
  const setGroup = (id: string) => {
    setLocalGroup(id);
    groupChanged?.(id);
  };
  const [tab, setTab] = useState(type.startsWith('custom') ? 'json' : 'main');
  const [error, setError] = useMessageState(language, translateError);
  const [status, setStatus] = useMessageState(language, translateError);
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const [confirmKey, setConfirmKey] = useState(false);
  useLayoutEffect(() => {
    onActivity?.(busy, dirty);
  }, [busy, dirty, onActivity]);
  const [publicKey, setPublicKey] = useState('');
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const parsed = useMemo(() => {
    try {
      const value = JSON.parse(current.text);
      return value && typeof value === 'object' && !Array.isArray(value) ? (value as Config) : null;
    } catch {
      return null;
    }
  }, [current.text]);
  const isVless = parsed?.type === 'vless' || parsed?.protocol === 'vless';
  const network = get(parsed, 'streamSettings.network');
  const earlyTransport: 'ws' | 'httpupgrade' | null =
    def.kind === 'xray-outbound' && (network === 'ws' || network === 'httpupgrade') ? network : null;
  const earlyPath = earlyTransport === 'httpupgrade' ? httpUpgradePath : wsPath;
  const draftShape = { kind: def.kind, config: parsed || {} };
  const tailscaleNode = tailscaleNodeDraft(draftShape);
  const supportsVpnPolicy = policyDraft(draftShape);
  const tabs = [
    ...sections(def, parsed || {}),
    ...(supportsVpnPolicy
      ? [
          {
            id: 'vpn-policy',
            label: (tailscaleNode
              ? 'profiles.tailscale_dns_tab'
              : 'profiles.vpn_routes_and_dns_1c6eaa7') as Label,
            fields: [] as Field[],
          },
        ]
      : []),
    { id: 'json', label: messageKeys.json, fields: [] },
  ];
  function changeVpnPolicy(value: Draft['vpnPolicy']) {
    setVpnPolicy(value);
    setDirty(true);
    setError('');
    setStatus('');
  }
  const active = tabs.find((s) => s.id === tab) || tabs[0];
  function update(next: Working) {
    setDrafts((old) => ({ ...old, [type]: next }));
    setDirty(true);
    setStatus('');
    setError('');
  }
  /** Edited JSON text replaces the configuration, so typed field buffers no longer apply. */
  function raw(text: string) {
    update({ ...current, text, buffers: {}, invalid: {} });
  }
  /**
   * A structured control (pool members, filters) changed the configuration;
   * values typed in other fields and their errors stay, so an invalid value is
   * still reported instead of being saved.
   */
  function changeConfig(config: Config) {
    update({ ...current, text: JSON.stringify(config, null, 2) });
  }
  function changeEarlyData(text: string) {
    if (!parsed || busy || !earlyTransport) return;
    const buffers: Record<string, string> = { ...current.buffers, [wsBuffer]: text };
    const invalid = { ...current.invalid };
    try {
      const before = get(parsed, earlyPath),
        path = editWsEarlyData(before, text);
      const config = path === before ? parsed : set(parsed, earlyPath, path);
      delete buffers[earlyPath];
      delete invalid[wsBuffer];
      update({ ...current, text: JSON.stringify(config, null, 2), buffers, invalid });
    } catch {
      invalid[wsBuffer] = true;
      update({ ...current, buffers, invalid });
    }
  }
  function change(field: Field, text: string) {
    const buffers = { ...current.buffers, [field.path]: text };
    const invalid = { ...current.invalid };
    try {
      const value = parse(field, text);
      let config = set(parsed || {}, field.path, value);
      const variants = { ...current.variants };
      if (field.path === 'transport.type' || field.path === 'obfs.type') {
        const path = field.path.split('.')[0];
        const previous = get(parsed, path);
        const previousType = get(parsed, field.path);
        if (previous && typeof previous === 'object')
          variants[path + ':' + previousType] = {
            config: previous as Config,
            buffers: Object.fromEntries(
              Object.entries(current.buffers).filter(([key]) => key.startsWith(path + '.')),
            ),
            invalid: Object.fromEntries(
              Object.entries(current.invalid).filter(([key]) => key.startsWith(path + '.')),
            ),
          };
        const restored = value ? variants[path + ':' + value] : undefined;
        config = set(parsed || {}, path, value ? restored?.config || { type: value } : undefined);
        if (field.path === 'transport.type' && value === 'quic') config = set(config, 'tls.enabled', true);
        for (const key of Object.keys(buffers))
          if (key.startsWith(path + '.')) {
            delete buffers[key];
            delete invalid[key];
          }
        if (restored) {
          Object.assign(buffers, restored.buffers);
          Object.assign(invalid, restored.invalid);
        }
        delete buffers[field.path];
      }
      delete invalid[field.path];
      // The helper and the raw Path field describe the same stored value.
      if (
        field.path === wsPath ||
        field.path === httpUpgradePath ||
        field.path === 'streamSettings.network'
      ) {
        delete buffers[wsBuffer];
        delete invalid[wsBuffer];
      }
      update({ text: JSON.stringify(config, null, 2), buffers, invalid, variants });
    } catch {
      invalid[field.path] = true;
      update({ ...current, buffers, invalid });
    }
  }
  function switchType(value: string) {
    setDrafts((old) => ({ ...old, [type]: current }));
    setType(value);
    setTab(value.startsWith('custom') ? 'json' : 'main');
    setError('');
    setStatus('');
    setPublicKey('');
    setConfirmKey(false);
    setDirty(true);
  }
  function chooseTab(next: string) {
    if (tab === 'json' && next !== 'json' && parsed) {
      const actualType = identify({ kind: def.kind, config: parsed });
      if (actualType !== type) {
        setDrafts((old) => ({ ...old, [type]: current, [actualType]: current }));
        setType(actualType);
      }
    }
    setTab(next);
  }
  function editPeers(next: unknown[], removed?: number) {
    const remap = <T>(source: Record<string, T>) =>
      Object.fromEntries(
        Object.entries(source).flatMap(([key, value]) => {
          const match = /^peers\.(\d+)\.(.*)$/.exec(key);
          if (!match || removed === undefined) return [[key, value]];
          const index = Number(match[1]);
          return index === removed
            ? []
            : [[`peers.${index > removed ? index - 1 : index}.${match[2]}`, value]];
        }),
      );
    update({
      ...current,
      text: JSON.stringify(set(parsed || {}, 'peers', next), null, 2),
      buffers: remap(current.buffers),
      invalid: remap(current.invalid),
    });
  }
  function value(): Draft {
    if (!parsed) throw new LocalizedError('common.jsonInvalid');
    if (Object.values(current.invalid).some(Boolean)) throw new LocalizedError(messageKeys.invalidFields);
    if (vpnPolicy && !supportsVpnPolicy)
      throw new LocalizedError('profiles.remove_the_vpn_policy_before_saving_this_protoco_0dd304d');
    return {
      id: draft?.id,
      expectedRevision: draft?.expectedRevision,
      name,
      groupId,
      kind: def.kind,
      config: parsed,
      vpnPolicy,
    };
  }
  async function submit(check: boolean) {
    if (busy || submitting.current) return;
    submitting.current = true;
    setError('');
    setStatus('');
    setBusy(true);
    try {
      const v = value();
      if (!v.name.trim()) {
        setTab('main');
        throw Error('invalid_profile');
      }
      await command(check ? 'checkProfile' : 'saveProfile', { ...v, ...(isVless ? { vlessCore } : {}) });
      if (check)
        setStatus(
          def.kind === 'external-core'
            ? messageRef(messageKeys.externalChecked)
            : messageRef('common.checked'),
        );
      else {
        await changed();
        completed();
      }
    } catch (e) {
      if (errorCode(e) === 'profile_configuration_changed') setConflict(true);
      setError(e);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  async function reload() {
    if (busy || submitting.current || !draft?.id) return;
    submitting.current = true;
    setBusy(true);
    try {
      const latest = await command('profile', { id: draft.id });
      const nextType = identify(latest);
      setDraft(latest);
      setType(nextType);
      setDrafts({ [nextType]: working(latest.config) });
      setName(latest.name);
      setGroup(latest.groupId);
      setVlessCore(latest.vlessCore || 'default');
      setVpnPolicy(latest.vpnPolicy);
      setTab(nextType.startsWith('custom') ? 'json' : 'main');
      setPublicKey('');
      setRevealed({});
      setConfirmKey(false);
      setDirty(false);
      setConflict(false);
      setConfirmReload(false);
      setError('');
      setStatus('');
    } catch (e) {
      setError(e);
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  }
  async function importFile(file?: File) {
    if (!file || busy) return;
    setBusy(true);
    try {
      if (file.size > maxImportBytes) throw new LocalizedError('common.importFailed');
      const config = JSON.parse(await file.text());
      if (!config || typeof config !== 'object' || Array.isArray(config))
        throw new LocalizedError('common.jsonInvalid');
      const kind = jsonKind(config);
      if (!kind) throw new LocalizedError('common.jsonInvalid');
      const nextType = identify({ config, kind });
      setDrafts((old) => ({ ...old, [type]: current, [nextType]: working(config) }));
      setType(nextType);
      setTab(nextType.startsWith('custom') ? 'json' : 'main');
      if (!name) setName(typeof config.tag === 'string' ? config.tag : file.name.replace(/\.[^.]+$/, ''));
      setDirty(true);
      setError('');
      setStatus('');
      setPublicKey('');
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function chooseExternalCore() {
    if (busy || !parsed) return;
    setBusy(true);
    setError('');
    try {
      const path = await command('chooseExternalCorePath', {});
      if (path !== null) raw(JSON.stringify({ ...parsed, extra_core_path: path }, null, 2));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  /** Stops the connection that uses this profile so its changes can be saved. */
  async function disconnect() {
    setBusy(true);
    setError('');
    try {
      await command('disconnect');
      await changed();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  async function generateKey() {
    setBusy(true);
    setError('');
    try {
      const pair = await command('generateWgKeys');
      change({ path: 'private_key', kind: 'secret', label: 'profiles.private_key_0b13591' }, pair.privateKey);
      setPublicKey(pair.publicKey);
      setConfirmKey(false);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  function removeCustomFragment() {
    if (!parsed) return;
    const buffers = { ...current.buffers },
      invalid = { ...current.invalid };
    for (const key of Object.keys(buffers))
      if (key.startsWith('tls_fragment.')) {
        delete buffers[key];
        delete invalid[key];
      }
    update({
      ...current,
      text: JSON.stringify(set(parsed, 'tls_fragment', undefined), null, 2),
      buffers,
      invalid,
    });
  }
  const peers = Array.isArray(parsed?.peers) ? parsed.peers : [];
  const requestClose = () => {
    if (!busy) {
      if (Frame === Modal && dirty) setConfirmClose(true);
      else close();
    }
  };
  return {
    Frame,
    active,
    busy,
    change,
    changeEarlyData,
    changeVpnPolicy,
    changed,
    chooseExternalCore,
    chooseTab,
    close,
    confirmClose,
    confirmKey,
    confirmReload,
    conflict,
    current,
    def,
    disconnect,
    draft,
    earlyPath,
    earlyTransport,
    editPeers,
    error,
    generateKey,
    groupId,
    groups,
    importFile,
    inUse,
    isVless,
    language,
    libraryRevision,
    name,
    parsed,
    peers,
    profiles,
    publicKey,
    raw,
    changeConfig,
    reload,
    removeCustomFragment,
    requestClose,
    revealed,
    setBusy,
    setConfirmClose,
    setConfirmKey,
    setConfirmReload,
    setDirty,
    setError,
    setGroup,
    setName,
    setPublicKey,
    setRevealed,
    setStatus,
    setVlessCore,
    status,
    submit,
    supportsVpnPolicy,
    tailscaleNode,
    switchType,
    t,
    tabs,
    tr,
    translateError,
    type,
    update,
    vlessCore,
    vpnPolicy,
  };
}
