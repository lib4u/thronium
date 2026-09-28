// Saving and removing DNS servers and rule sets while keeping every reference to their tags consistent.
import type { Config } from '../profiles/schema.ts';
import type { RouteProfile } from './model.ts';
import { objects, tags } from './resources.ts';

// Only visit configuration reference positions. Host records, headers and unknown
// extension objects may contain the same words and must remain untouched.
function mapped(value: unknown, mapping: Record<string, string>): unknown {
  const one = (s: string) => (Object.prototype.hasOwnProperty.call(mapping, s) ? mapping[s] : s);
  return typeof value === 'string'
    ? one(value)
    : Array.isArray(value)
      ? value.map((v) => (typeof v === 'string' ? one(v) : v))
      : value;
}
function mapRules(value: unknown, keys: string[], mapping: Record<string, string>): unknown {
  if (Array.isArray(value)) return value.map((v) => mapRules(v, keys, mapping));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, v]) => [
      key,
      keys.includes(key) ? mapped(v, mapping) : key === 'rules' ? mapRules(v, keys, mapping) : v,
    ]),
  );
}
const resolver = (value: unknown, mapping: Record<string, string>): unknown =>
  typeof value === 'string'
    ? mapped(value, mapping)
    : value && typeof value === 'object' && !Array.isArray(value)
      ? { ...value, server: mapped((value as Config).server, mapping) }
      : value;
function dnsReferences(p: RouteProfile, mapping: Record<string, string>): RouteProfile {
  const dns = {
    ...p.dns,
    ...(p.dns.final !== undefined ? { final: mapped(p.dns.final, mapping) } : {}),
    ...(p.dns.rules !== undefined
      ? { rules: mapRules(p.dns.rules, ['server', 'preferred_by'], mapping) }
      : {}),
    servers: objects(p.dns.servers).map((s) =>
      s.domain_resolver !== undefined ? { ...s, domain_resolver: resolver(s.domain_resolver, mapping) } : s,
    ),
  };
  const route: Config = {
    ...p.route,
    ...(p.route.default_domain_resolver !== undefined
      ? { default_domain_resolver: resolver(p.route.default_domain_resolver, mapping) }
      : {}),
  };
  if (Array.isArray(route.rule_set))
    route.rule_set = objects(route.rule_set).map((s) => {
      const client = s.http_client as Config | undefined;
      return client?.domain_resolver !== undefined
        ? { ...s, http_client: { ...client, domain_resolver: resolver(client.domain_resolver, mapping) } }
        : s;
    });
  const rules = p.rules.map((r) => ({ ...r, config: mapRules(r.config, ['server'], mapping) as Config }));
  return { ...p, dns, route, rules };
}
export function saveServer(p: RouteProfile, index: number | undefined, server: Config): RouteProfile {
  const tag = typeof server.tag === 'string' ? server.tag.trim() : '';
  if (!tag) throw Error('resource_tag_required');
  const servers = objects(p.dns.servers);
  if (servers.some((s, i) => i !== index && s.tag === tag)) throw Error('resource_duplicate_tag');
  const old = index === undefined ? '' : String(servers[index].tag || '');
  const mapping = old && old !== tag ? { [old]: tag } : {};
  const result = dnsReferences(structuredClone(p), mapping);
  const list = objects(result.dns.servers);
  const next = {
    ...server,
    tag,
    ...(server.domain_resolver !== undefined
      ? { domain_resolver: resolver(server.domain_resolver, mapping) }
      : {}),
  };
  if (index === undefined) list.push(next);
  else list[index] = next;
  result.dns.servers = list;
  if (index === undefined && ['hosts', 'fakeip'].includes(String(server.type))) {
    const rule = {
      query_type: ['A', 'AAAA'],
      action: 'route',
      server: tag,
      ...(server.type === 'hosts' ? { preferred_by: [tag], disable_cache: true } : {}),
    };
    const rules = objects(result.dns.rules);
    if (server.type === 'hosts') rules.unshift(rule);
    else rules.push(rule);
    result.dns.rules = rules;
  }
  return result;
}
export function removeServer(p: RouteProfile, index: number): RouteProfile {
  const tag = String(objects(p.dns.servers)[index].tag || '');
  if (
    tag &&
    JSON.stringify(dnsReferences(p, { [tag]: tag + '-removed' })) !== JSON.stringify(dnsReferences(p, {}))
  )
    throw Error('resource_in_use');
  return { ...p, dns: { ...p.dns, servers: objects(p.dns.servers).filter((_, i) => i !== index) } };
}
function setReferences(p: RouteProfile, mapping: Record<string, string>): RouteProfile {
  return {
    ...p,
    rules: p.rules.map((r) => {
      const simple = r.simple?.startsWith('ruleset:')
        ? 'ruleset:' + mapped(r.simple.slice(8), mapping)
        : r.simple;
      return {
        ...r,
        config: mapRules(r.config, ['rule_set'], mapping) as Config,
        ...(simple ? { simple, name: r.name === r.simple ? simple : r.name } : {}),
      };
    }),
    dns: {
      ...p.dns,
      ...(p.dns.rules !== undefined ? { rules: mapRules(p.dns.rules, ['rule_set'], mapping) } : {}),
    },
  };
}
export function saveRuleSet(
  p: RouteProfile,
  index: number | undefined,
  value: Config,
  options: { preserveTag?: boolean } = {},
): RouteProfile {
  const list = objects(p.route.rule_set),
    names = tags(value.tag).map((t) => (options.preserveTag ? t : t.trim()));
  if (!names.length || names.some((t) => !t.trim())) throw Error('resource_tag_required');
  if (
    new Set(names).size !== names.length ||
    list.some((s, i) => i !== index && tags(s.tag).some((t) => names.includes(t)))
  )
    throw Error('resource_duplicate_tag');
  const old = index === undefined ? [] : tags(list[index].tag);
  const removed = old.filter((t) => !names.includes(t)),
    added = names.filter((t) => !old.includes(t));
  const mapping = Object.fromEntries(removed.slice(0, added.length).map((tag, i) => [tag, added[i]]));
  const result = setReferences(structuredClone(p), mapping);
  if (removed.slice(added.length).some((t) => referencesRuleSet(result, t))) throw Error('resource_in_use');
  const next = { ...value, tag: options.preserveTag ? value.tag : names.length === 1 ? names[0] : names };
  if (index === undefined) list.push(next);
  else list[index] = next;
  result.route.rule_set = list;
  return result;
}
function referencesRuleSet(p: RouteProfile, tag: string): boolean {
  return (
    JSON.stringify(setReferences(p, { [tag]: tag + '-removed' })) !== JSON.stringify(setReferences(p, {}))
  );
}
export function removeRuleSet(p: RouteProfile, index: number): RouteProfile {
  const list = objects(p.route.rule_set);
  if (tags(list[index].tag).some((t) => referencesRuleSet(p, t))) throw Error('resource_in_use');
  return { ...p, route: { ...p.route, rule_set: list.filter((_, i) => i !== index) } };
}
