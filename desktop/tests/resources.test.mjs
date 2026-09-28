import { translate } from '../src/shared/i18n/index.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { newProfile, simpleRules } from '../src/routing/model.ts';
import { set } from '../src/profiles/schema.ts';
import {
  parseResource,
  formatResource,
  dnsSeed,
  dnsServerSections,
  dnsGeneralSections,
  dnsRuleSections,
  dnsRuleShared,
  ruleSetSections,
} from '../src/routing/resources.ts';
import { saveServer, removeServer, saveRuleSet, removeRuleSet } from '../src/routing/resourceReferences.ts';

test('renaming a DNS server repairs nested references and keeps host records and unknown fields intact', () => {
  const p = newProfile('DNS');
  p.dns.servers.push({
    type: 'hosts',
    tag: 'hosts',
    predefined: { server: '192.0.2.1', preferred_by: '192.0.2.2' },
    future: { server: 'dns-direct' },
  });
  p.dns.servers.push({
    type: 'https',
    tag: 'secure',
    server: 'dns-direct',
    domain_resolver: { server: 'dns-direct', strategy: 'ipv4_only' },
    headers: { server: ['dns-direct'] },
  });
  p.dns.rules = [
    { type: 'logical', rules: [{ preferred_by: ['dns-direct'] }], action: 'route', server: 'dns-direct' },
  ];
  p.route.default_domain_resolver = { server: 'dns-direct', timeout: '3s' };
  p.route.rule_set = [
    {
      type: 'remote',
      tag: 'rules',
      url: 'https://example.test/rules.srs',
      http_client: {
        domain_resolver: { server: 'dns-direct', strategy: 'ipv4_only' },
        headers: { server: ['dns-direct'] },
      },
    },
  ];
  p.rules = [
    { id: 'off', name: 'Resolve', enabled: false, config: { action: 'resolve', server: 'dns-direct' } },
  ];
  const snapshot = structuredClone(p);
  const changed = saveServer(p, 0, { ...p.dns.servers[0], tag: 'renamed' });
  assert.equal(changed.dns.final, 'renamed');
  assert.deepEqual(changed.route.default_domain_resolver, { server: 'renamed', timeout: '3s' });
  assert.equal(changed.route.rule_set[0].http_client.domain_resolver.server, 'renamed');
  assert.deepEqual(changed.route.rule_set[0].http_client.headers, { server: ['dns-direct'] });
  assert.equal(changed.dns.rules[0].rules[0].preferred_by[0], 'renamed');
  assert.equal(changed.rules[0].config.server, 'renamed');
  assert.equal(changed.rules[0].enabled, false);
  assert.deepEqual(changed.dns.servers[1], p.dns.servers[1]);
  assert.deepEqual(changed.dns.servers[2].domain_resolver, { server: 'renamed', strategy: 'ipv4_only' });
  assert.equal(changed.dns.servers[2].server, 'dns-direct');
  assert.deepEqual(changed.dns.servers[2].headers, { server: ['dns-direct'] });
  assert.deepEqual(p, snapshot);
});
test('DNS deletion blocks live references, allows unused entries, and rejects duplicate tags', () => {
  let p = newProfile('DNS');
  assert.throws(() => removeServer(p, 0), /resource_in_use/);
  assert.throws(() => saveServer(p, undefined, { type: 'udp', tag: 'dns-direct' }), /resource_duplicate_tag/);
  assert.throws(() => saveServer(p, undefined, { type: 'udp', tag: [] }), /resource_tag_required/);
  p = saveServer(p, undefined, { type: 'udp', tag: 'unused', server: '127.0.0.1' });
  assert.equal(removeServer(p, 1).dns.servers.length, 1);
  p = saveServer(p, undefined, {
    type: 'hosts',
    tag: 'local-hosts',
    predefined: { 'example.test': '127.0.0.1' },
  });
  assert.deepEqual(p.dns.rules[0], {
    query_type: ['A', 'AAAA'],
    action: 'route',
    server: 'local-hosts',
    preferred_by: ['local-hosts'],
    disable_cache: true,
  });
  assert.throws(() => removeServer(p, 2), /resource_in_use/);
  p = saveServer(p, undefined, { ...dnsSeed('fakeip'), tag: 'fake' });
  assert.equal(p.dns.rules.at(-1).server, 'fake');
});
test('renaming rule-set aliases updates nested DNS/routing and simple lists without mutating inputs', () => {
  let p = newProfile('Sets');
  p = saveRuleSet(p, undefined, {
    type: 'remote',
    tag: ['keep', 'old'],
    url: 'https://example.test/{tag}.srs',
  });
  p.rules = [
    ...simpleRules('ruleset:old', 'direct'),
    {
      id: 'nested',
      name: 'Nested',
      enabled: false,
      config: { type: 'logical', rules: [{ rule_set: ['keep', 'old'] }], action: 'reject' },
    },
  ];
  p.dns.rules = [{ rule_set: ['old'], action: 'route', server: 'dns-direct' }];
  p.dns.future = { rule_set: ['old'] };
  const before = structuredClone(p);
  const changed = saveRuleSet(p, 0, { ...p.route.rule_set[0], tag: ['new', 'keep'] });
  assert.equal(changed.rules[0].simple, 'ruleset:new');
  assert.equal(changed.rules[0].name, 'ruleset:new');
  assert.deepEqual(changed.rules[1].config.rules[0].rule_set, ['keep', 'new']);
  assert.deepEqual(changed.dns.rules[0].rule_set, ['new']);
  assert.deepEqual(changed.dns.future, p.dns.future);
  assert.deepEqual(p, before);
  const reorder = saveRuleSet(p, 0, { ...p.route.rule_set[0], tag: ['old', 'keep'] });
  assert.deepEqual(reorder.rules, p.rules);
  assert.throws(() => saveRuleSet(p, 0, { ...p.route.rule_set[0], tag: ['keep'] }), /resource_in_use/);
  assert.throws(() => removeRuleSet(p, 0), /resource_in_use/);
  assert.throws(
    () => saveRuleSet(p, undefined, { type: 'inline', tag: 'old', rules: [] }),
    /resource_duplicate_tag/,
  );
});
test('a tag named like an object property does not rewrite unrelated references', () => {
  const p = newProfile('Unusual tags');
  p.rules = simpleRules('ruleset:constructor', 'direct');
  const changed = saveRuleSet(p, undefined, { type: 'inline', tag: 'new', rules: [] });
  assert.deepEqual(changed.rules, p.rules);
});
test('editing only inline contents preserves opaque tags, alias spelling and references', () => {
  for (const tag of ['set, one', ' padded tag ', ['set, one'], ['set, one', 'alias']]) {
    const p = newProfile('Inline contents'),
      reference = Array.isArray(tag) ? tag[0] : tag;
    p.route.rule_set = [{ type: 'inline', tag, rules: [{ domain: 'old.test' }], future: { keep: true } }];
    p.rules = [
      {
        id: 'ref',
        name: 'Reference',
        enabled: true,
        config: { rule_set: reference, action: 'route', outbound: 'direct' },
      },
    ];
    p.dns.rules = [{ rule_set: reference, action: 'route', server: 'dns-direct' }];
    const before = structuredClone(p),
      rules = [{ network: ['tcp'] }];
    const next = saveRuleSet(p, 0, { ...p.route.rule_set[0], rules }, { preserveTag: true });
    assert.deepEqual(next.route.rule_set[0], { ...p.route.rule_set[0], rules });
    assert.deepEqual(next.rules, p.rules);
    assert.deepEqual(next.dns, p.dns);
    assert.deepEqual(p, before);
  }
});
test('host and numeric fields preserve valid values and reject lossy input', () => {
  const field = dnsServerSections({ type: 'hosts' }, [], [])[0].fields.find((f) => f.path === 'predefined');
  const value = parseResource(field, '# local\nexample.test 127.0.0.1 ::1\n__proto__ 192.0.2.1');
  assert.deepEqual(value['example.test'], ['127.0.0.1', '::1']);
  assert.deepEqual(value.__proto__, ['192.0.2.1']);
  assert.deepEqual(parseResource(field, formatResource(field, value)), value);
  assert.throws(() => parseResource(field, 'example.test'));
  assert.throws(() => parseResource(field, 'x 127.0.0.1\nx ::1'));
  const ports = dnsRuleSections({}, [])[2].fields.find((f) => f.path === 'port');
  assert.deepEqual(parseResource(ports, '53,443\n5353'), [53, 443, 5353]);
  assert.throws(() => parseResource(ports, '0'));
  assert.throws(() => parseResource(ports, '65536'));
});
test('resource fields use unique bilingual paths and keep unknown configuration values when edited', () => {
  for (const sections of [
    ...[
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
    ].map((type) => dnsServerSections({ type }, [], [])),
    dnsGeneralSections([]),
    ...['route', 'reject', 'predefined', 'evaluate', 'respond', 'route-options'].map((action) =>
      dnsRuleSections({ action }, []),
    ),
    ...['inline', 'local', 'remote'].map((type) => ruleSetSections({ type }, [])),
  ]) {
    const fields = sections.flatMap((s) => s.fields);
    assert.equal(fields.length, new Set(fields.map((f) => f.path)).size);
    for (const field of fields)
      assert(['en', 'ru'].every((language) => Boolean(translate(language, field.label))));
  }
  const c = {
    type: 'https',
    tag: 'test',
    tls: { future: { keep: true }, server_name: 'old' },
    unknown: [1, 2, 3],
  };
  const changed = set(c, 'tls.server_name', 'new');
  assert.deepEqual(changed.tls.future, c.tls.future);
  assert.deepEqual(changed.unknown, c.unknown);
  assert.deepEqual(
    dnsRuleShared({ domain: ['example.test'], action: 'predefined', answer: ['x'], future: { keep: true } }),
    { domain: ['example.test'], future: { keep: true } },
  );
});
