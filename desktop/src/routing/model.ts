import { appliesHere } from '../shared/platform.ts';
import type * as Wire from '../shared/api/generated/commands';
import type { Config, Label } from '../profiles/schema';
import type { Profile } from '../api';
import { translate } from '../shared/i18n/index.ts';
import { defaults } from '../shared/api/generated/defaults.ts';
export type RouteRule = Wire.RouteRule;

/** Built-in targets a rule can send traffic to, in the order editors offer them. */
export const builtInTargets = ['proxy', 'direct', 'warp', 'warp-bypass', 'block'] as const;
export type BuiltInTarget = (typeof builtInTargets)[number];
/** Where traffic no rule matches goes, and the target a new rule starts with. */
export const defaultTarget: BuiltInTarget = defaults.routingProfile.route.final;
const targetLabels: Record<BuiltInTarget, Label> = {
  proxy: 'routing.selected_server_1797ac9',
  direct: 'routing.direct_cc7ab89',
  warp: 'routing.through_warp',
  'warp-bypass': 'routing.vpn_without_warp',
  block: 'routing.block_59fb954',
};
const isBuiltIn = (value: string): value is BuiltInTarget =>
  (builtInTargets as readonly string[]).includes(value);
/** Profiles a rule or resolver can send traffic through, as `profile:<id>` targets. */
export const outboundProfiles = (profiles: Profile[]) =>
  profiles.filter((p) => p.kind.endsWith('outbound') || p.kind === 'chain' || p.kind === 'auto-selector');
/** The rule action that sends traffic to `target`; `block` rejects it. */
export const targetAction = (target: string): Config =>
  target === 'block' ? { action: 'reject' } : { action: 'route', outbound: target };
/** The name of a target value: a built-in target, a profile or the value itself. */
export function targetLabel(value: string, profiles: Profile[], language: string): string {
  if (isBuiltIn(value)) return translate(language, targetLabels[value] as Parameters<typeof translate>[1]);
  if (value.startsWith('profile:')) return profiles.find((p) => p.id === value.slice(8))?.name || value;
  return value;
}
export type RouteProfile = Wire.RouteProfile;
export type Routing = Wire.Routing;
export type MatchField = {
  key: string;
  label: Label;
  kind: 'list' | 'numbers' | 'text' | 'number' | 'bool' | 'json';
};
const field = (key: string, message: Label, kind: MatchField['kind'] = 'list'): MatchField => ({
  key,
  label: message,
  kind,
});
export const matches: MatchField[] = [
  field('domain', 'routing.domain_381e975'),
  field('domain_suffix', 'routing.domain_suffix_c8634ef'),
  field('domain_keyword', 'routing.domain_keyword_b0ecba3'),
  field('domain_regex', 'routing.domain_expression_bab7097'),
  field('ip_cidr', 'routing.destination_ip_cidr_f03f18c'),
  field('ip_is_private', 'routing.private_destination_ip_e2447b1', 'bool'),
  field('port', 'routing.destination_port_a66ec87', 'numbers'),
  field('port_range', 'routing.destination_port_range_80_90_8d914ae'),
  field('process_name', 'routing.process_name_87ce9cf'),
  field('process_path', 'routing.process_path_eb8aa32'),
  field('process_path_regex', 'routing.process_path_expression_34a9dd2'),
  field('network', 'routing.network_tcp_udp_icmp_69a8909'),
  field('protocol', 'routing.detected_protocol_baed476'),
  field('ip_version', 'routing.ip_version_4_6_49aba2a', 'number'),
  field('source_ip_cidr', 'routing.source_ip_cidr_3d32b18'),
  field('source_ip_is_private', 'routing.private_source_ip_489934c', 'bool'),
  field('source_port', 'routing.source_port_474ca84', 'numbers'),
  field('source_port_range', 'routing.source_port_range_cd681bf'),
  field('inbound', 'routing.inbound_tag_d789d59'),
  field('auth_user', 'routing.authenticated_user_8b09816'),
  field('client', 'routing.client_19d3ddb'),
  field('rule_set', 'routing.rule_set_tag_d65c7ab'),
  field('rule_set_ip_cidr_match_source', 'routing.match_source_ip_in_rule_set_5dbbaee', 'bool'),
  field('wifi_ssid', 'routing.wi_fi_ssid_3cf354f'),
  field('wifi_bssid', 'routing.wi_fi_bssid_ef0bdec'),
  field('network_type', 'routing.interface_type_00ef6c1'),
  field('network_is_expensive', 'routing.metered_network_0d7a114', 'bool'),
  field('network_is_constrained', 'routing.constrained_network_d92baae', 'bool'),
  field('user', 'routing.system_user_3475816'),
  field('user_id', 'routing.system_user_id_eeb9180', 'numbers'),
  field('package_name', 'routing.package_name_100b1bf'),
  field('package_name_regex', 'routing.package_name_expression_201e220'),
  field('clash_mode', 'routing.clash_mode_3b5620f', 'text'),
  field('interface_address', 'routing.interface_addresses_c5667ee', 'json'),
  field('network_interface_address', 'routing.network_interface_addresses_7125ad6', 'json'),
  field('default_interface_address', 'routing.default_interface_address_111609a'),
  field('source_mac_address', 'routing.source_mac_c94390c'),
  field('source_hostname', 'routing.source_hostname_cb9714a'),
  field('preferred_by', 'routing.preferred_by_endpoint_9963ec4'),
];
/** Ports a route, DNS or rule-set rule matches or overrides. Port 0 matches no traffic
 * and turns an override off; an imported rule set that has it stays opaque JSON. */
export const portRange = { min: 1, max: 65535 } as const;
export const portKeys: readonly string[] = ['port', 'source_port', 'override_port'];
export const validPort = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value >= portRange.min && value <= portRange.max;
/** The condition a new rule or condition group starts with. */
export const defaultCondition = 'domain_suffix';
/** Match fields a rule configuration sets, in editor order. */
export const presentConditions = (config: Config) =>
  matches.filter((f) => Object.prototype.hasOwnProperty.call(config, f.key)).map((f) => f.key);
const allActions: { id: string; label: Label; platforms?: string[] }[] = [
  { id: 'route', label: 'routing.route_fbb8660' },
  { id: 'reject', label: 'routing.block_59fb954' },
  { id: 'hijack-dns', label: 'routing.intercept_dns_3ccbe43' },
  { id: 'sniff', label: 'routing.detect_protocol_44403ad' },
  { id: 'resolve', label: 'routing.resolve_domain_235775f' },
  { id: 'route-options', label: 'routing.set_route_options_f866253' },
  { id: 'direct', label: 'routing.direct_with_options_4be274a' },
  // sing-box bypass works through Linux auto-redirect only.
  { id: 'bypass', label: 'routing.bypass_d3fa7f9', platforms: ['linux'] },
];
/** Rule actions offered on this system. */
export const actions = allActions.filter((action) => appliesHere(action.platforms));
const options = [
  field('override_address', 'routing.override_destination_b252cfd', 'text'),
  field('override_port', 'routing.override_port_2b7def5', 'number'),
  field('network_strategy', 'routing.network_strategy_9cba00b', 'text'),
  field('fallback_delay', 'routing.fallback_delay_ms_76578f3', 'number'),
  field('udp_disable_domain_unmapping', 'routing.disable_udp_domain_unmapping_a30f4f9', 'bool'),
  field('udp_connect', 'routing.udp_connect_36d9596', 'bool'),
  field('udp_timeout', 'routing.udp_timeout_846623f', 'text'),
  field('tls_fragment', 'routing.tls_fragmentation_4626abb', 'bool'),
  field('tls_fragment_fallback_delay', 'routing.tls_fragment_fallback_delay_f6d98f9', 'text'),
  field('tls_record_fragment', 'routing.tls_record_fragmentation_37593b8', 'bool'),
  field('tls_spoof', 'routing.tls_spoof_host_8cbcb6f', 'text'),
  field('tls_spoof_method', 'routing.tls_spoof_method_652b15a', 'text'),
];
const dial = [
  field('bind_interface', 'routing.bind_interface_7dd22a0', 'text'),
  field('inet4_bind_address', 'routing.ipv4_bind_address_9b62a46', 'text'),
  field('inet6_bind_address', 'routing.ipv6_bind_address_8f7682e', 'text'),
  field('routing_mark', 'routing.routing_mark_df7031d', 'text'),
  field('connect_timeout', 'routing.connect_timeout_e6e6de4', 'text'),
  field('tcp_fast_open', 'routing.tcp_fast_open_9653922', 'bool'),
  field('tcp_multi_path', 'routing.multipath_tcp_463ed7d', 'bool'),
  field('udp_fragment', 'routing.udp_fragmentation_e7f0487', 'bool'),
];
export function actionFields(action: string): MatchField[] {
  if (action === 'route' || action === 'route-options' || action === 'bypass') return options;
  if (action === 'reject')
    return [
      field('method', 'routing.method_default_drop_reply_ee7933b', 'text'),
      field('no_drop', 'routing.never_drop_54ec7ae', 'bool'),
    ];
  if (action === 'sniff')
    return [
      field('sniffer', 'routing.sniffers_tls_http_quic_dns_bbfbcac'),
      field('timeout', 'routing.timeout_1963af1', 'text'),
      field('override_destination', 'routing.override_destination_b252cfd', 'bool'),
    ];
  if (action === 'resolve')
    return [
      field('server', 'routing.dns_server_tag_c44366a', 'text'),
      field('strategy', 'routing.strategy_prefer_ipv4_prefer_ipv6_ipv4_only_ipv6__ec97e62', 'text'),
      field('timeout', 'routing.timeout_1963af1', 'text'),
      field('disable_cache', 'routing.disable_cache_553c398', 'bool'),
      field('rewrite_ttl', 'routing.override_ttl_c1238a3', 'number'),
      field('client_subnet', 'routing.client_subnet_3329cf9', 'text'),
    ];
  if (action === 'direct') return dial;
  return [];
}
export function parseValue(field: MatchField, value: string): unknown {
  if (!value.trim()) return undefined;
  if (field.kind === 'text') return value;
  if (field.kind === 'json') return JSON.parse(value);
  if (field.kind === 'bool') {
    if (!['true', 'false'].includes(value)) throw Error('invalid_condition');
    return value === 'true';
  }
  const values =
    field.kind === 'numbers'
      ? value.split(/[\s,]+/).filter(Boolean)
      : field.kind === 'number'
        ? [value]
        : value
            .split('\n')
            .map((v) => v.trim())
            .filter(Boolean);
  if (field.kind === 'numbers' || field.kind === 'number') {
    const numbers = values.map((v) => {
      const n = Number(v);
      if (!/^\d+$/.test(v) || !Number.isSafeInteger(n)) throw Error('invalid_condition');
      return n;
    });
    if (field.key === 'ip_version' && ![4, 6].includes(numbers[0])) throw Error('invalid_condition');
    if (portKeys.includes(field.key) && !numbers.every(validPort)) throw Error('invalid_condition');
    return field.kind === 'number' ? numbers[0] : numbers;
  }
  return values;
}
export function formatValue(field: MatchField, value: unknown): string {
  return value === undefined
    ? ''
    : field.kind === 'json'
      ? JSON.stringify(value, null, 2)
      : Array.isArray(value)
        ? value.join('\n')
        : String(value);
}
/** A new routing profile with the engine's default rules, route and DNS. */
export function newProfile(name: string): RouteProfile {
  return {
    ...(structuredClone(defaults.routingProfile) as unknown as RouteProfile),
    id: crypto.randomUUID(),
    name,
  };
}
/** JSON values compared as the engine compares them: object key order aside. */
const sameJson = (a: unknown, b: unknown): boolean =>
  a === b ||
  (typeof a === 'object' &&
    typeof b === 'object' &&
    a !== null &&
    b !== null &&
    Array.isArray(a) === Array.isArray(b) &&
    Object.keys(a).length === Object.keys(b).length &&
    Object.entries(a).every(([k, v]) => sameJson(v, (b as Record<string, unknown>)[k])));
/** The untouched Default profile (the engine's `RoutingProfile::baseline`): no
 * client policy of its own, so a subscription's routing applies instead. */
export const isBaselineProfile = (profile: RouteProfile) => {
  const baseline = defaults.routingProfile as unknown as RouteProfile;
  return (
    profile.id === baseline.id &&
    profile.mode === baseline.mode &&
    !profile.rules.some((r) => r.enabled) &&
    sameJson(profile.route, baseline.route) &&
    sameJson(profile.dns, baseline.dns)
  );
};
/** The built-in profile every library starts with, still under its original name. */
export const isDefaultRoutingProfile = (profile: { id?: string; active?: string; name: string }) =>
  (profile.id ?? profile.active) === defaults.routingProfile.id &&
  profile.name === defaults.routingProfile.name;
/** A routing profile's name; the untouched built-in profile is named in the interface language. */
export const routingProfileName = (profile: { id: string; name: string }, language: string) =>
  isDefaultRoutingProfile(profile) ? translate(language, 'routing.default_4d4d367') : profile.name;
/** Prefixes of the simple `prefix:value` rule lines and the sing-box match fields they fill. */
export const simplePrefixes: Record<string, string> = {
  domain: 'domain',
  suffix: 'domain_suffix',
  keyword: 'domain_keyword',
  regex: 'domain_regex',
  ip: 'ip_cidr',
  processName: 'process_name',
  processPath: 'process_path',
  ruleset: 'rule_set',
};
/** The non-empty, non-comment lines of a simple rule text, each with its match field and value. */
export function simpleLines(text: string, prefixes: Record<string, string> = simplePrefixes) {
  return text
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('#'))
    .map((line) => {
      const i = line.indexOf(':');
      const prefix = line.slice(0, i);
      const value = line.slice(i + 1).trim();
      if (i < 0 || !Object.prototype.hasOwnProperty.call(prefixes, prefix) || !value)
        throw Error('invalid_simple_rule');
      return { line, key: prefixes[prefix], value };
    });
}
export function simpleRules(text: string, target: string): RouteRule[] {
  return simpleLines(text).map(({ line, key, value }) => ({
    id: crypto.randomUUID(),
    name: line,
    enabled: true,
    config: { [key]: [value], ...targetAction(target) },
    simple: line,
  }));
}
export const ruleTarget = (r: RouteRule) =>
  r.config.action === 'reject' ? 'block' : String(r.config.outbound || defaultTarget);
export function replaceSimple(profile: RouteProfile, target: string, text: string): RouteProfile {
  const next = simpleRules(text, target);
  const first = profile.rules.findIndex((r) => r.simple !== undefined && ruleTarget(r) === target);
  const kept = profile.rules.filter((r) => !(r.simple !== undefined && ruleTarget(r) === target));
  const at =
    first < 0
      ? kept.length
      : profile.rules.slice(0, first).filter((r) => !(r.simple !== undefined && ruleTarget(r) === target))
          .length;
  kept.splice(at, 0, ...next);
  return { ...profile, rules: kept };
}
export function fromCoreRoute(profile: RouteProfile, raw: Config): RouteProfile {
  if (
    raw.rules !== undefined &&
    (!Array.isArray(raw.rules) || raw.rules.some((r) => !r || typeof r !== 'object' || Array.isArray(r)))
  )
    throw Error('invalid_routing');
  const { rules = [], ...route } = raw;
  const configs = rules as Config[];
  const encoded = configs.map((c) => JSON.stringify(c));
  const used = new Set<string>();
  const exact = configs.map((config) => {
    const found = profile.rules.find(
      (r) => !used.has(r.id) && JSON.stringify(r.config) === JSON.stringify(config),
    );
    if (found) used.add(found.id);
    return found;
  });
  return {
    ...profile,
    route,
    rules: configs.map((config, i) => {
      const atPosition = profile.rules[i];
      const old =
        exact[i] ||
        (atPosition && !used.has(atPosition.id) && !encoded.includes(JSON.stringify(atPosition.config))
          ? atPosition
          : undefined);
      if (old) {
        used.add(old.id);
        return {
          ...old,
          config,
          ...(JSON.stringify(old.config) !== JSON.stringify(config) ? { simple: undefined } : {}),
        };
      }
      return { id: crypto.randomUUID(), name: String(i + 1), enabled: true, config };
    }),
  };
}
export const coreRoute = (p: RouteProfile): Config => ({ ...p.route, rules: p.rules.map((r) => r.config) });
