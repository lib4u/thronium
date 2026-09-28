// Pass values through the same serializer as the routing form before core validation.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { set } from '../src/profiles/schema.ts';
import {
  dnsSeed,
  dnsServerSections,
  dnsGeneralSections,
  dnsRuleSections,
  ruleSetSeed,
  ruleSetSections,
  parseResource,
} from '../src/routing/resources.ts';
import { saveServer, saveRuleSet } from '../src/routing/resourceReferences.ts';
import { matches, actions, actionFields, newProfile, parseValue } from '../src/routing/model.ts';
const values = {
  domain: 'example.test',
  domain_suffix: 'example.test',
  domain_keyword: 'example',
  domain_regex: '\\.test$',
  ip_cidr: '127.0.0.0/8',
  ip_is_private: 'true',
  port: '80,443',
  port_range: '8000:8080',
  process_name: 'firefox',
  process_path: '/usr/bin/firefox',
  process_path_regex: '/usr/bin/.*',
  network: 'tcp\nudp',
  protocol: 'tls\nhttp',
  ip_version: '4',
  source_ip_cidr: '127.0.0.0/8',
  source_ip_is_private: 'true',
  source_port: '50000',
  source_port_range: '49000:51000',
  inbound: 'mixed-in',
  auth_user: 'test',
  client: 'chromium',
  rule_set: 'test-set',
  rule_set_ip_cidr_match_source: 'true',
  wifi_ssid: 'test-network',
  wifi_bssid: '02:00:00:00:00:01',
  network_type: 'wifi',
  network_is_expensive: 'true',
  network_is_constrained: 'true',
  user: 'test',
  user_id: '1000',
  package_name: 'org.example.app',
  package_name_regex: 'org\\.example\\..*',
  clash_mode: 'rule',
  interface_address: '{"lo":["127.0.0.0/8"]}',
  network_interface_address: '{"wifi":["192.0.2.0/24"]}',
  default_interface_address: '192.0.2.0/24',
  source_mac_address: '02:00:00:00:00:01',
  source_hostname: 'test-machine',
  preferred_by: 'test-endpoint',
};
function fixture(name, config) {
  const profile = newProfile(name);
  profile.route.rule_set = [{ type: 'inline', tag: 'test-set', rules: [{ ip_cidr: ['127.0.0.0/8'] }] }];
  profile.rules = [{ id: 'test-rule', name, enabled: true, config }];
  return profile;
}
const fixtures = matches.map((field) => {
  if (!Object.hasOwn(values, field.key)) throw Error('Missing fixture: ' + field.key);
  return fixture('condition: ' + field.key, {
    [field.key]: parseValue(field, values[field.key]),
    action: 'route',
    outbound: 'direct',
  });
});
const options = {
  route: {
    override_address: '127.0.0.1',
    override_port: '443',
    network_strategy: 'default',
    fallback_delay: '250',
    udp_disable_domain_unmapping: 'true',
    udp_connect: 'true',
    udp_timeout: '30s',
    tls_fragment: 'true',
    tls_fragment_fallback_delay: '10ms',
    tls_spoof: 'example.test',
    tls_spoof_method: 'wrong-checksum',
  },
  reject: { method: 'reply', no_drop: 'true' },
  sniff: { sniffer: 'http\ntls', timeout: '300ms', override_destination: 'true' },
  resolve: {
    server: 'dns-direct',
    strategy: 'prefer_ipv4',
    timeout: '2s',
    disable_cache: 'true',
    rewrite_ttl: '60',
    client_subnet: '192.0.2.0/24',
  },
  'route-options': { override_port: '443', tls_record_fragment: 'true' },
  direct: {
    inet4_bind_address: '127.0.0.1',
    inet6_bind_address: '::1',
    routing_mark: '0xff',
    connect_timeout: '2s',
    tcp_fast_open: 'true',
    tcp_multi_path: 'true',
    udp_fragment: 'false',
  },
  bypass: { override_port: '443', udp_timeout: '30s' },
};
for (const action of actions) {
  const config = { action: action.id, ...(action.id === 'route' ? { outbound: 'direct' } : {}) };
  for (const [key, value] of Object.entries(options[action.id] || {})) {
    const field = actionFields(action.id).find((f) => f.key === key);
    if (!field) throw Error('Missing action field: ' + key);
    config[key] = parseValue(field, value);
  }
  fixtures.push(fixture('action: ' + action.id, config));
}
fixtures.push(
  fixture('nested logical conditions', {
    type: 'logical',
    mode: 'and',
    rules: [
      { domain_suffix: ['example.test'] },
      { type: 'logical', mode: 'or', rules: [{ network: 'tcp' }, { port: [53] }], invert: true },
    ],
    action: 'route',
    outbound: 'direct',
  }),
);
// These values pass through the resource form's exact parsers and setters.
function form(seed, sections, values) {
  let c = structuredClone(seed);
  for (const [path, text] of Object.entries(values)) {
    const field = sections.flatMap((s) => s.fields).find((f) => f.path === path);
    if (!field) throw Error('Missing resource field: ' + path);
    c = set(c, path, parseResource(field, text));
  }
  return c;
}
for (const type of [
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
]) {
  const seed = dnsSeed(type);
  const values = {
    tag: 'test-dns',
    ...(['udp', 'tcp', 'tls', 'https', 'h3', 'quic'].includes(type)
      ? { server: '127.0.0.1', server_port: '5353', connect_timeout: '2s' }
      : {}),
  };
  if (type === 'hosts') values.predefined = 'resource.test 127.0.0.1 ::1';
  if (['tls', 'https', 'h3', 'quic'].includes(type)) values['tls.server_name'] = 'dns.example.test';
  if (['https', 'h3'].includes(type))
    Object.assign(values, { method: 'POST', headers: '{"X-Test":["test"]}' });
  if (['tailscale', 'openvpn', 'openconnect'].includes(type)) values.endpoint = 'test-endpoint';
  const server = form(seed, dnsServerSections(seed, ['dns-direct'], ['direct']), values);
  fixtures.push(saveServer(newProfile('DNS server: ' + type), undefined, server));
}
{
  const p = newProfile('DNS resolution and optimistic cache');
  p.dns = form(p.dns, dnsGeneralSections(['dns-direct']), {
    final: 'dns-direct',
    strategy: 'prefer_ipv4',
    timeout: '3s',
    client_subnet: '192.0.2.0/24',
    reverse_mapping: 'true',
    cache_capacity: '512',
    disable_cache: 'false',
    disable_expire: 'false',
    'optimistic.enabled': 'true',
    'optimistic.timeout': '30s',
  });
  fixtures.push(p);
}
for (const action of ['route', 'reject', 'predefined', 'route-options', 'evaluate', 'respond']) {
  const p = newProfile('DNS action: ' + action);
  const values = { domain_suffix: 'example.test', query_type: 'A\nAAAA' };
  if (['route', 'evaluate'].includes(action))
    Object.assign(values, {
      server: 'dns-direct',
      timeout: '2s',
      disable_cache: 'true',
      rewrite_ttl: '60',
      client_subnet: '192.0.2.0/24',
    });
  if (action === 'evaluate') values.tag = 'response';
  if (action === 'reject') values.method = 'default';
  if (action === 'predefined')
    Object.assign(values, { rcode: 'NOERROR', answer: 'resource.test. 60 IN A 127.0.0.1' });
  if (action === 'route-options') values.disable_cache = 'true';
  if (action === 'respond') values.match_response = 'true';
  const rule = form({ action }, dnsRuleSections({ action }, ['dns-direct']), values);
  p.dns.rules = action === 'respond' ? [{ action: 'evaluate', server: 'dns-direct' }, rule] : [rule];
  fixtures.push(p);
}
const resourceFile = join(dirname(process.argv[2]), 'resource-rules.json');
writeFileSync(resourceFile, JSON.stringify({ version: 3, rules: [{ domain_suffix: ['example.test'] }] }));
for (const type of ['inline', 'local', 'remote']) {
  const p = newProfile('Rule-set source: ' + type),
    seed = ruleSetSeed(type);
  const values = {
    tag: 'test-set',
    ...(type === 'inline'
      ? { rules: '[{"domain_suffix":["example.test"]}]' }
      : {
          format: 'source',
          ...(type === 'local'
            ? { path: resourceFile }
            : {
                url: 'http://127.0.0.1:1/rules.json',
                initial_path: resourceFile,
                update_interval: '1d',
                download_detour: 'direct',
              }),
        }),
  };
  const resource = form(seed, ruleSetSections(seed, ['direct']), values);
  p.rules = [
    {
      id: 'reference',
      name: 'Use resource',
      enabled: true,
      config: { rule_set: ['test-set'], action: 'route', outbound: 'direct' },
    },
  ];
  fixtures.push(saveRuleSet(p, undefined, resource));
}
writeFileSync(process.argv[2], JSON.stringify(fixtures, null, 2));
