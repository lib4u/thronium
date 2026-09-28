import { messageRef } from '../shared/i18n/message';
import { useMessageState } from '../shared/i18n/react';
import { useRoutingDownload } from './useRoutingDownload';
import type { Language } from '../shared/i18n/index.ts';
import { useEffect, useRef, useState } from 'react';
import { command, type Profile } from '../api';
import type { Config } from '../profiles/schema';
import type { RouteProfile } from './model';
import {
  addCategories,
  geoProviders,
  geoUrl,
  type GeoKind,
  type GeoSource,
  type GeoSummary,
} from './catalog';
import { defaultTarget, targetAction } from './model';
import { limits } from '../shared/limits.ts';
import { encodeBytes } from '../shared/base64.ts';

export type GeoPanelProps = {
  profile: RouteProfile;
  profiles: Profile[];
  language: Language;
  busy: boolean;
  update(p: RouteProfile): Promise<void>;
  refresh(): Promise<void>;
  translateError(e: unknown): string;
};

/** Geodata categories: the loaded database, the selection and adding categories or private copies as rules. */
export function useGeoPanel({
  profile,
  profiles,
  language,
  busy: parentBusy,
  update,
  refresh,
  translateError,
}: GeoPanelProps) {
  const [kind, setKind] = useState<GeoKind>('geosite');
  const [url, setUrl] = useState(geoUrl('geosite'));
  const [sources, setSources] = useState<GeoSummary[]>([]);
  const [source, setSource] = useState<GeoSource | null>(null);
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string[]>([]);
  const [target, setTarget] = useState<string>(defaultTarget);
  const [first, setFirst] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useMessageState(language, translateError);
  const [notice, setNotice] = useMessageState(language, () => '');
  const [preview, setPreview] = useState<{ code: string; rules: Config[] } | null>(null);
  const [attribute, setAttribute] = useState('');
  const [editor, setEditor] = useState<{ name: string; rules: Config[] } | null>(null);
  const file = useRef<HTMLInputElement>(null);
  const request = useRoutingDownload(profile.id);
  const disabled = busy || request.pending || parentBusy;
  const choices: { url: string; name: string }[] = geoProviders.map((p) => ({ url: p[kind], name: p.name }));
  for (const s of sources.filter((s) => s.kind === kind))
    if (!choices.some((p) => p.url === s.url)) choices.push({ url: s.url, name: s.name });
  useEffect(() => {
    let live = true;
    command('geodataSources')
      .then((s) => {
        if (live) setSources(s);
      })
      .catch((e) => {
        if (live) setError(e);
      });
    return () => {
      live = false;
    };
  }, []);
  async function run(action: () => Promise<void>) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await action();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }
  function changeSource(next: string, k = kind) {
    setKind(k);
    setUrl(next);
    setSource(null);
    setSelected([]);
    setQuery('');
    setPage(0);
    setError('');
    setNotice('');
  }
  async function load(force = false, data?: string, name?: string) {
    await run(async () => {
      const result = await request.download((requestId) =>
        command('loadGeodata', {
          requestId,
          kind,
          url,
          force,
          data,
          name: name || choices.find((c) => c.url === url)?.name || url,
        }),
      );
      if (!result) return;
      setSource(result);
      setUrl(result.url);
      setSelected([]);
      setPage(0);
      setSources(await command('geodataSources'));
      await refresh();
      setNotice(messageRef('routing.database_ready_choose_categories_and_where_their_4426e61'));
    });
  }
  async function readFile(f?: File) {
    if (!f) return;
    await run(async () => {
      if (f.size > limits.maxCategoryDatabaseBytes) throw Error('routing_geodata_too_large');
      const data = encodeBytes(new Uint8Array(await f.arrayBuffer()));
      const result = await request.download((requestId) =>
        command('loadGeodata', { requestId, kind, data, name: f.name }),
      );
      if (!result) return;
      setSource(result);
      setUrl(result.url);
      setSelected([]);
      setPage(0);
      setSources(await command('geodataSources'));
    });
  }
  async function inspect(code: string) {
    if (!source) return;
    await run(async () => {
      const result = await command('geodataCategory', {
        kind: source.kind,
        url: source.url,
        category: code,
      });
      setPreview({ code, rules: result.rules });
      setAttribute('');
    });
  }
  async function add(codes = selected) {
    if (!source || !codes.length) return;
    await run(async () => {
      await update(addCategories(profile, source, codes, target, first));
      setSelected([]);
      setPreview(null);
      setNotice(messageRef('routing.categories_added_to_routing_rules_7336a1c'));
    });
  }
  async function copy(name: string, rules: Config[]) {
    const tag = `custom-${crypto.randomUUID().slice(0, 8)}`;
    const set = { type: 'inline', tag, rules };
    const rule = {
      id: crypto.randomUUID(),
      name,
      enabled: true,
      config: {
        rule_set: [tag],
        ...targetAction(target),
      },
    };
    await update({
      ...profile,
      route: { ...profile.route, rule_set: [...((profile.route.rule_set as Config[]) || []), set] },
      rules: first ? [rule, ...profile.rules] : [...profile.rules, rule],
    });
    setPreview(null);
    setNotice(messageRef('routing.your_copy_has_been_added_dad36f6'));
  }
  const found = (source?.categories || []).filter((c) => c.code.includes(query.trim().toLowerCase()));
  const pageSize = 60;
  const shown = found.slice(page * pageSize, (page + 1) * pageSize);
  const used = ((profile.route.rule_set as Config[]) || []).filter((s) => s.type === 'geodata');
  const attrs = source?.categories.find((c) => c.code === preview?.code)?.attributes || [];
  return {
    profile,
    profiles,
    language,
    translateError,
    kind,
    url,
    source,
    query,
    setQuery,
    page,
    setPage,
    selected,
    setSelected,
    target,
    setTarget,
    first,
    setFirst,
    busy,
    error,
    notice,
    preview,
    setPreview,
    attribute,
    setAttribute,
    editor,
    setEditor,
    file,
    request,
    disabled,
    choices,
    run,
    changeSource,
    load,
    readFile,
    inspect,
    add,
    copy,
    found,
    pageSize,
    shown,
    used,
    attrs,
  };
}

export type GeoController = ReturnType<typeof useGeoPanel>;
