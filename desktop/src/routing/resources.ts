import type { Label } from '../profiles/schema.ts';
import { type Config, type Field, type Section, parse, format } from '../profiles/schema.ts';
import { type RouteProfile, matches, portKeys, portRange } from './model.ts';
import { dnsStrategies } from './ruleInput.ts';
import { geoUrl } from './catalog.ts';
export type ResourceField = Omit<Field, 'kind'> & { kind: Field['kind'] | 'hosts' | 'integers' };
export type ResourceSection = Omit<Section, 'fields'> & { fields: ResourceField[] };
const f = (
  path: string,
  message: Label,
  kind: ResourceField['kind'] = 'text',
  options?: string[],
): ResourceField => ({ path, label: message, kind, options });
const b = (path: string, message: Label) => f(path, message, 'bool');
const n = (path: string, message: Label, max = 4294967295) => ({ ...f(path, message, 'number'), max });
const list = (path: string, message: Label) => f(path, message, 'list');
const json = (path: string, message: Label) => ({ ...f(path, message, 'json'), wide: true });
const section = (id: string, message: Label, fields: ResourceField[]): ResourceSection => ({
  id,
  label: message,
  fields,
});
const dnsTypes = [
  'local',
  'udp',
  'tcp',
  'tls',
  'https',
  'h3',
  'quic',
  'hosts',
  'fakeip',
  'dhcp',
  'mdns',
  'resolved',
  'tailscale',
  'openvpn',
  'openconnect',
];
/** A strategy choice where empty keeps the core default. */
export const strategyOptions = ['', ...dnsStrategies];
export const objects = (value: unknown): Config[] =>
  Array.isArray(value)
    ? (value.filter((v) => v && typeof v === 'object' && !Array.isArray(v)) as Config[])
    : [];
export const tags = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((v) => typeof v === 'string')
    : typeof value === 'string'
      ? [value]
      : [];
export const dnsTags = (p: RouteProfile) => objects(p.dns.servers).flatMap((s) => tags(s.tag));
export function parseResource(field: ResourceField, text: string): unknown {
  if (field.kind === 'hosts') {
    const result: Record<string, string[]> = Object.create(null);
    for (const line of text
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith('#'))) {
      const [name, ...addresses] = line.split(/[\s,]+/);
      if (!name || !addresses.length || Object.prototype.hasOwnProperty.call(result, name))
        throw Error('invalid_hosts');
      result[name] = addresses;
    }
    return Object.keys(result).length ? result : undefined;
  }
  if (field.kind === 'integers') {
    if (!text.trim()) return undefined;
    const values = text
      .trim()
      .split(/[\s,]+/)
      .map((v) => {
        if (!/^\d+$/.test(v)) throw Error('invalid_number');
        return Number(v);
      });
    if (values.some((n) => !Number.isSafeInteger(n) || n < (field.min ?? 0) || n > (field.max ?? 2147483647)))
      throw Error('invalid_number');
    return values;
  }
  return parse(field as Field, text);
}
export function formatResource(field: ResourceField, value: unknown): string {
  if (field.kind === 'hosts')
    return value && typeof value === 'object'
      ? Object.entries(value)
          .map(([domain, ip]) => domain + ' ' + tags(ip).join(' '))
          .join('\n')
      : '';
  if (field.kind === 'integers')
    return tags(value).length
      ? tags(value).join('\n')
      : Array.isArray(value)
        ? value.join('\n')
        : value === undefined
          ? ''
          : String(value);
  return format(field as Field, value);
}
export function dnsSeed(type: string): Config {
  if (['udp', 'tcp', 'tls', 'https', 'h3', 'quic'].includes(type))
    return {
      type,
      tag: '',
      server: '',
      ...(['tls', 'https', 'h3', 'quic'].includes(type) ? { tls: { enabled: true } } : {}),
      ...(['https', 'h3'].includes(type) ? { path: '/dns-query' } : {}),
    };
  return {
    type,
    tag: '',
    ...(type === 'fakeip' ? { inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' } : {}),
  };
}
export function dnsServerSections(
  c: Config,
  resolvers: string[],
  outbounds: string[],
  endpoints: string[] = [],
): ResourceSection[] {
  const type = String(c.type || 'local');
  const main = [f('type', 'routing.type_756c9a6', 'select', dnsTypes), f('tag', 'routing.name_tag_963c609')];
  if (['udp', 'tcp', 'tls', 'https', 'h3', 'quic'].includes(type))
    main.push(f('server', 'routing.server_address_57ff2f5'), {
      ...n('server_port', 'routing.port_651531e', 65535),
      min: 1,
    });
  if (['https', 'h3'].includes(type))
    main.push(
      f('path', 'routing.query_path_d531d78'),
      f('method', 'routing.method_4d78f09', 'select', ['', 'GET', 'POST']),
    );
  if (type === 'hosts')
    main.push(
      {
        ...f('predefined', 'routing.local_answers_domain_ip_ip_c390a79', 'hosts'),
        wide: true,
        hint: 'routing.one_domain_per_line_followed_by_its_ipv4_ipv6_ad_758ddbc',
      },
      list('path', 'routing.hosts_file_paths_621f934'),
    );
  if (type === 'fakeip')
    main.push(
      f('inet4_range', 'routing.fake_ipv4_range_83f917f'),
      f('inet6_range', 'routing.fake_ipv6_range_486ca49'),
    );
  if (type === 'local' || type === 'dhcp' || type === 'mdns')
    main.push(
      b('prefer_go', 'routing.use_go_resolver_f521e87'),
      list('neighbor_domain', 'routing.neighbor_domains_2bb188c'),
    );
  if (type === 'dhcp') main.push(f('interface', 'routing.interface_0196774'));
  if (type === 'mdns') main.push(list('interface', 'routing.interfaces_1f1c434'));
  if (['tailscale', 'openvpn', 'openconnect'].includes(type))
    main.push(
      f('endpoint', 'routing.vpn_endpoint_50c3619', 'select', endpoints),
      b('accept_default_resolvers', 'routing.accept_default_resolvers_9770416'),
      b('accept_search_domain', 'routing.accept_search_domains_70547ea'),
    );
  if (type === 'resolved')
    main.push(
      f('service', 'routing.resolved_service_tag_5e1aa70'),
      b('accept_default_resolvers', 'routing.accept_default_resolvers_9770416'),
    );
  const result = [section('main', 'routing.general_012bafa', main)];
  if (['local', 'udp', 'tcp', 'tls', 'https', 'h3', 'quic', 'dhcp', 'mdns'].includes(type))
    result.push(
      section('dial', 'routing.connection_6b4c264', [
        f('detour', 'routing.connect_through_cbc0fcc', 'select', ['', ...outbounds]),
        f('domain_resolver', 'routing.bootstrap_resolver_a5d5808', 'select', ['', ...resolvers]),
        f('bind_interface', 'routing.bind_interface_7dd22a0'),
        f('inet4_bind_address', 'routing.ipv4_bind_address_9b62a46'),
        f('inet6_bind_address', 'routing.ipv6_bind_address_8f7682e'),
        f('routing_mark', 'routing.routing_mark_df7031d', 'mark'),
        f('connect_timeout', 'routing.connect_timeout_e6e6de4'),
        b('tcp_fast_open', 'routing.tcp_fast_open_9653922'),
        b('tcp_multi_path', 'routing.multipath_tcp_463ed7d'),
        b('udp_fragment', 'routing.udp_fragmentation_e7f0487'),
      ]),
    );
  if (['tls', 'https', 'h3', 'quic'].includes(type))
    result.push(
      section('tls', 'routing.tls_http_9b67e97', [
        b('tls.enabled', 'routing.enable_tls_8f09d9a'),
        f('tls.server_name', 'routing.server_name_sni_f265323'),
        b('tls.insecure', 'routing.skip_certificate_verification_a559e43'),
        list('tls.alpn', 'routing.alpn_b0dc97a'),
        list('tls.certificate', 'routing.ca_certificates_pem_82aaddd'),
        f('tls.certificate_path', 'routing.ca_certificate_path_2b57d7f'),
        list('tls.certificate_public_key_sha256', 'routing.pinned_key_sha_256_9dee972'),
        ...(['https', 'h3'].includes(type) ? [json('headers', 'routing.http_headers_14c57f4')] : []),
      ]),
    );
  return result;
}
export function dnsGeneralSections(resolvers: string[]): ResourceSection[] {
  return [
    section('main', 'routing.resolution_5c17f1a', [
      f('final', 'routing.default_dns_server_e9651e0', 'select', resolvers),
      f('strategy', 'routing.address_strategy_ec86ed2', 'select', strategyOptions),
      f('timeout', 'routing.query_timeout_69231e6'),
      f('client_subnet', 'routing.client_subnet_ecs_24d844d'),
      b('reverse_mapping', 'routing.reverse_mapping_3a2c2ea'),
    ]),
    section('cache', 'routing.cache_a8abda5', [
      n('cache_capacity', 'routing.cache_capacity_08130b7'),
      b('disable_cache', 'routing.disable_cache_553c398'),
      {
        ...b('disable_expire', 'routing.keep_expired_entries_4452463'),
        hint: 'routing.cannot_be_combined_with_optimistic_cache_cab2d22',
      },
      b('optimistic.enabled', 'routing.optimistic_cache_9a85e3c'),
      f('optimistic.timeout', 'routing.optimistic_cache_timeout_4559721'),
    ]),
  ];
}
const dnsActions = ['route', 'reject', 'predefined', 'route-options', 'evaluate', 'respond'];
export function dnsRuleSections(c: Config, resolvers: string[]): ResourceSection[] {
  const base = matches
    .filter((f) => !['ip_cidr', 'ip_is_private', 'client'].includes(f.key))
    .map(
      (m) =>
        ({
          path: m.key,
          label: m.label,
          kind: m.kind === 'numbers' ? 'integers' : m.kind,
          ...(portKeys.includes(m.key) ? portRange : {}),
        }) as ResourceField,
    );
  base.push(
    list('query_type', 'routing.query_type_a_aaaa_https_5a606ff'),
    list('query_client_subnet', 'routing.query_client_subnet_035b7ca'),
    b('query_dnssec', 'routing.query_dnssec_6ca1524'),
    b('invert', 'routing.invert_match_cd0993c'),
  );
  base.push(
    json('match_response', 'routing.match_response_true_or_response_tag_4c272d3'),
    list('ip_cidr', 'routing.response_ip_cidr_43949f3'),
    b('ip_is_private', 'routing.private_response_ip_2789b24'),
    b('ip_accept_any', 'routing.accept_any_response_ip_8ecb3b5'),
    f('response_rcode', 'routing.response_code_condition_a78c31b'),
    list('response_answer', 'routing.response_answer_conditions_12b28ab'),
    list('response_ns', 'routing.response_authority_conditions_281bd36'),
    list('response_extra', 'routing.response_additional_conditions_8199b67'),
  );
  const common = [
    'domain',
    'domain_suffix',
    'domain_keyword',
    'domain_regex',
    'query_type',
    'rule_set',
    'invert',
  ];
  const action = String(c.action || 'route');
  const fields = [
    f('action', 'routing.action_6b117e2', 'select', dnsActions),
    b('race', 'routing.race_queries_f9f8cad'),
  ];
  if (action === 'route' || action === 'evaluate')
    fields.push(
      f('server', 'routing.dns_server_175f9f1', 'select', resolvers),
      b('speculative', 'routing.speculative_query_b947716'),
    );
  if (action === 'evaluate') fields.push(f('tag', 'routing.response_tag_ff6cc00'));
  if (['route', 'evaluate', 'route-options'].includes(action))
    fields.push(
      f('strategy', 'routing.address_strategy_ec86ed2', 'select', strategyOptions),
      f('timeout', 'routing.query_timeout_69231e6'),
      b('disable_cache', 'routing.disable_cache_553c398'),
      b('disable_optimistic_cache', 'routing.disable_optimistic_cache_7c479c0'),
      n('rewrite_ttl', 'routing.override_ttl_c1238a3'),
      f('client_subnet', 'routing.client_subnet_3329cf9'),
      b('remove_client_subnet', 'routing.remove_client_subnet_7bffa69'),
    );
  if (action === 'reject')
    fields.push(
      f('method', 'routing.reject_method_b7cffff', 'select', ['', 'default', 'drop']),
      b('no_drop', 'routing.never_drop_54ec7ae'),
    );
  if (action === 'predefined')
    fields.push(
      f('rcode', 'routing.response_code_eb5ed71', 'select', [
        '',
        'NOERROR',
        'NXDOMAIN',
        'REFUSED',
        'SERVFAIL',
      ]),
      list('answer', 'routing.answers_example_test_60_in_a_127_0_0_1_9c1522f'),
      list('ns', 'routing.authority_records_6dd9e84'),
      list('extra', 'routing.additional_records_4707a40'),
    );
  if (c.type === 'logical')
    return [
      section('main', 'routing.conditions_16b104c', [
        f('mode', 'routing.logical_operator_8f863b9', 'select', ['and', 'or']),
        json('rules', 'routing.nested_conditions_3c70b63'),
        b('invert', 'routing.invert_match_cd0993c'),
      ]),
      section('action', 'routing.action_6b117e2', fields),
    ];
  return [
    section(
      'main',
      'routing.conditions_16b104c',
      base.filter((f) => common.includes(f.path)),
    ),
    section('action', 'routing.action_6b117e2', fields),
    section(
      'advanced',
      'routing.more_conditions_8213974',
      base.filter((f) => !common.includes(f.path)),
    ),
  ];
}
export function dnsRuleShared(c: Config): Config {
  const keys = new Set(
    dnsActions.flatMap((action) =>
      dnsRuleSections({ action }, [])
        .find((s) => s.id === 'action')!
        .fields.map((f) => f.path),
    ),
  );
  return Object.fromEntries(Object.entries(c).filter(([key]) => !keys.has(key)));
}
export function ruleSetSeed(type: string): Config {
  return {
    type,
    tag: '',
    ...(type === 'geodata'
      ? {
          kind: 'geosite',
          url: geoUrl('geosite'),
          category: '',
        }
      : type === 'inline'
        ? { rules: [] }
        : { format: 'binary', ...(type === 'remote' ? { url: '', update_interval: '1d' } : { path: '' }) }),
  };
}
export function ruleSetSections(c: Config, outbounds: string[]): ResourceSection[] {
  const type = String(c.type || 'inline');
  const main = [
    f('type', 'routing.source_64835b1', 'select', ['remote', 'local', 'inline', 'geodata']),
    list('tag', 'routing.names_tags_5307928'),
  ];
  if (type === 'geodata')
    return [
      section('main', 'routing.geo_category_6976750', [
        ...main,
        f('kind', 'routing.database_811e5b0', 'select', ['geosite', 'geoip']),
        f('url', 'routing.source_dat_url_3aa0002'),
        f('category', 'routing.category_optional_attribute_cfee0f7'),
      ]),
    ];
  if (type === 'inline') main.push(json('rules', 'routing.inline_rules_23f298e'));
  else
    main.push(
      f('format', 'routing.format_e00adff', 'select', ['binary', 'source']),
      f(
        type === 'remote' ? 'url' : 'path',
        type === 'remote' ? 'routing.url_1c7bc44' : 'routing.file_path_2a0c193',
      ),
    );
  if (type === 'remote')
    main.push(
      f('download_detour', 'routing.download_through_a5717e9', 'select', ['', ...outbounds]),
      f('update_interval', 'routing.update_interval_5014de3'),
      f('initial_path', 'routing.initial_file_path_bad1850'),
      json('http_client', 'routing.http_client_options_2e2d139'),
    );
  return [section('main', 'routing.rule_set_3eb00ae', main)];
}
