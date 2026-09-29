import type * as Wire from '../shared/api/generated/commands';
import type { Config } from '../profiles/schema';
import {
  newProfile,
  simpleLines,
  simplePrefixes,
  targetAction,
  type RouteProfile,
  type RouteRule,
} from './model.ts';
import { defaults } from '../shared/api/generated/defaults.ts';
import { decodeBytes } from '../shared/base64.ts';
import { limits } from '../shared/api/generated/limits.ts';

export type GeoKind = Wire.GeoKind;
export type GeoCategory = Wire.GeoCategory;
export type GeoSource = Wire.GeoSource;
export type GeoSummary = Wire.GeoSummary;
/** Geodata publishers; the same list the Xray asset settings offer. */
export const geoProviders = defaults.geodataProviders;
export const profileCatalogs = [
  {
    id: 'Russia',
    label: 'routing.russia_ed6c98e',
    url: 'https://raw.githubusercontent.com/throneproj/routeprofiles/profile/Profile_Russia',
  },
  {
    id: 'China',
    label: 'routing.china_b2aa98d',
    url: 'https://raw.githubusercontent.com/throneproj/routeprofiles/profile/Profile_China',
  },
  {
    id: 'Iran',
    label: 'routing.iran_0aec67d',
    url: 'https://raw.githubusercontent.com/throneproj/routeprofiles/profile/Profile_Iran',
  },
] as const;
export type ProfileCatalogId = (typeof profileCatalogs)[number]['id'];
/** The routing profile loader opened on a country catalog or on received text. */
export type RoutingImportRequest = { country?: ProfileCatalogId; text?: string };
/** A source of `provider`; by default the pair shipped with the application. */
export const geoUrl = (kind: GeoKind, provider = 'v2fly'): string =>
  (geoProviders.find((p) => p.id === provider) || geoProviders[0])[kind];
const config = (value: unknown): Config => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('routing_import_invalid');
  return value as Config;
};
function decode(value: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(decodeBytes(value));
  } catch {
    throw Error('routing_import_invalid');
  }
}
export type RemoteRoute = { name: string; url: string };
/**
 * A `throne://remoteroute/` link: base64 lines of profile URLs named by their
 * fragment. Like Qt, lines that are not web URLs are skipped; a link without
 * any is invalid.
 */
export function remoteRouteIndex(text: string): RemoteRoute[] | null {
  const prefix = 'throne://remoteroute/';
  if (!text.trim().toLowerCase().startsWith(prefix)) return null;
  const lines = decode(text.trim().slice(prefix.length)).split(/\r?\n/);
  if (lines.length > 100) throw Error('routing_import_invalid');
  const routes = lines.flatMap((line) => {
    try {
      const url = new URL(line.trim());
      const name = decodeURIComponent(url.hash.slice(1)) || url.hostname;
      url.hash = '';
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return [];
      return [{ name, url: url.href }];
    } catch {
      return [];
    }
  });
  if (!routes.length) throw Error('routing_import_invalid');
  return routes;
}
/** Text the engine converts: a Throne route link or a `throne-route-profile` document. */
export function isThroneRoute(text: string): boolean {
  const raw = text.trim();
  if (/^throne:\/\/route\//i.test(raw)) return true;
  try {
    const value: unknown = JSON.parse(raw);
    return !!value && typeof value === 'object' && (value as Config).kind === 'throne-route-profile';
  } catch {
    return false;
  }
}
export function importRoutingProfile(text: string, name = 'Imported routing', url?: string): RouteProfile {
  if (new TextEncoder().encode(text).length > limits.maxRoutingProfileBytes)
    throw Error('routing_import_too_large');
  const raw = text.trim();
  let data: Config;
  try {
    data = config(JSON.parse(raw));
  } catch {
    throw Error('routing_import_invalid');
  }
  let profile = newProfile(name);
  if (data.format === 'thronium-routing-profile') {
    if (data.version !== 1) throw Error('routing_import_version');
    const p = config(data.profile);
    if (
      p.source !== undefined &&
      (typeof config(p.source).url !== 'string' || !Number.isSafeInteger(config(p.source).importedAt))
    )
      throw Error('routing_import_invalid');
    profile = { ...p, id: profile.id, route: config(p.route), dns: config(p.dns) } as RouteProfile;
    if (!['rules', 'direct', 'all'].includes(profile.mode) || !Array.isArray(profile.rules))
      throw Error('routing_import_invalid');
    profile.rules = profile.rules.map((r) => ({ ...r, id: crypto.randomUUID(), config: config(r.config) }));
  } else {
    if (data.outbounds || data.inbounds || data.protocol || data.format || data.kind)
      throw Error('routing_import_unsupported');
    if (data.route && Object.keys(data).some((k) => !['route', 'dns', 'name'].includes(k)))
      throw Error('routing_import_unsupported');
    const { rules, ...route } = config(data.route || data);
    if (!Array.isArray(rules)) throw Error('routing_import_invalid');
    profile.route = { ...profile.route, ...route };
    profile.rules = rules.map((r, i) => ({
      id: crypto.randomUUID(),
      name: String(i + 1),
      enabled: true,
      config: config(r),
    }));
    if (data.dns) profile.dns = config(data.dns);
    if (data.route && typeof data.name === 'string') profile.name = data.name;
  }
  if (
    typeof profile.name !== 'string' ||
    !profile.name.trim() ||
    new TextEncoder().encode(profile.name).length > limits.maxNameBytes ||
    profile.rules.length > limits.maxRoutingRules ||
    profile.rules.some((r) => typeof r.name !== 'string' || !r.name.trim() || typeof r.enabled !== 'boolean')
  )
    throw Error('routing_import_invalid');
  if (url) profile.source = { url, importedAt: Math.floor(Date.now() / 1000) };
  return profile;
}
export function addCategories(
  profile: RouteProfile,
  source: Pick<GeoSource, 'url' | 'kind'>,
  categories: string[],
  target: string,
  first: boolean,
): RouteProfile {
  const sets: Config[] = [...((profile.route.rule_set as Config[]) || [])];
  const rules: RouteRule[] = [];
  for (const category of [...new Set(categories)]) {
    let set = sets.find(
      (s) =>
        s.type === 'geodata' && s.kind === source.kind && s.url === source.url && s.category === category,
    );
    if (!set) {
      set = {
        type: 'geodata',
        tag: `${source.kind}-${category.replace(/[^a-zA-Z0-9_-]/g, '-')}-${crypto.randomUUID().slice(0, 8)}`,
        kind: source.kind,
        url: source.url,
        category,
      };
      sets.push(set);
    }
    const tag = Array.isArray(set.tag) ? set.tag[0] : set.tag;
    const config = {
      rule_set: [tag],
      ...targetAction(target),
    };
    if (!profile.rules.some((r) => r.enabled && JSON.stringify(r.config) === JSON.stringify(config)))
      rules.push({ id: crypto.randomUUID(), name: `${source.kind}:${category}`, enabled: true, config });
  }
  return {
    ...profile,
    route: { ...profile.route, rule_set: sets },
    rules: first ? [...rules, ...profile.rules] : [...profile.rules, ...rules],
  };
}
// A category database holds addresses only: no process or rule-set matches.
const prefixes = Object.fromEntries(
  ['domain', 'suffix', 'keyword', 'regex', 'ip'].map((prefix) => [prefix, simplePrefixes[prefix]]),
);
export function categoryText(value: unknown): string | null {
  if (!Array.isArray(value) || value.some((r) => !r || typeof r !== 'object' || Array.isArray(r)))
    return null;
  const rules = value as Config[];
  if (
    rules.some((r) =>
      Object.keys(r).some((k) => !Object.values(prefixes).includes(k) && !(k === 'invert' && r[k] === false)),
    )
  )
    return null;
  if (
    rules.some((r) =>
      Object.values(prefixes).some(
        (key) =>
          r[key] !== undefined &&
          (Array.isArray(r[key]) ? r[key] : [r[key]]).some(
            (v: unknown) => typeof v !== 'string' || !v || v.trim() !== v || /[\r\n]/.test(v),
          ),
      ),
    )
  )
    return null;
  return rules
    .flatMap((r) =>
      Object.entries(prefixes).flatMap(([prefix, key]) => {
        const values = r[key];
        if (values === undefined) return [];
        return (Array.isArray(values) ? values : [values]).map((v) => `${prefix}:${v}`);
      }),
    )
    .join('\n');
}
export function parseCategoryText(text: string): Config[] {
  const grouped: Record<string, string[]> = {};
  for (const { key, value } of simpleLines(text, prefixes)) (grouped[key] ||= []).push(value);
  const result = Object.entries(grouped).map(([key, values]) => ({ [key]: [...new Set(values)] }));
  if (!result.length) throw Error('geodata_category_empty');
  return result;
}
