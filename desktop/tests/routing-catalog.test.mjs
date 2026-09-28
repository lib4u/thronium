import test from 'node:test';
import assert from 'node:assert/strict';
import {
  importRoutingProfile,
  isThroneRoute,
  remoteRouteIndex,
  geoProviders,
  geoUrl,
  addCategories,
  categoryText,
  parseCategoryText,
} from '../src/routing/catalog.ts';
import { newProfile } from '../src/routing/model.ts';
const link = (p) => 'throne://route/' + Buffer.from(JSON.stringify(p)).toString('base64url');
test('Throne route formats go to the engine converter and providers come from the engine catalog', () => {
  assert.equal(isThroneRoute(link({ kind: 'throne-route-profile', v: 1, rules: [] })), true);
  assert.equal(isThroneRoute(JSON.stringify({ kind: 'throne-route-profile', v: 1, rules: [] })), true);
  assert.equal(isThroneRoute(JSON.stringify({ format: 'thronium-routing-profile', version: 1 })), false);
  assert.equal(isThroneRoute('{"route":{"rules":[]}}'), false);
  assert.equal(isThroneRoute('not json'), false);
  assert(geoProviders.some((p) => p.id === 'ru' && p.geosite.includes('runetfreedom')));
  assert.equal(geoUrl('geoip', 'ir'), geoProviders.find((p) => p.id === 'ir').geoip);
  assert.equal(geoUrl('geosite', 'missing'), geoProviders[0].geosite);
});
test('remote index decodes UTF-8 names and does not auto-import or execute sources', () => {
  const list = remoteRouteIndex(
    'throne://remoteroute/' +
      Buffer.from('https://example.test/ru#Россия\nhttps://example.test/cn#China').toString('base64url'),
  );
  assert.deepEqual(list, [
    { name: 'Россия', url: 'https://example.test/ru' },
    { name: 'China', url: 'https://example.test/cn' },
  ]);
  assert.deepEqual(
    remoteRouteIndex(
      'throne://RemoteRoute/' +
        Buffer.from(
          'file:///etc/passwd\n http://route.test/p \nnot a url\nhttps://user:pw@route.test/x',
        ).toString('base64url'),
    ),
    [{ name: 'route.test', url: 'http://route.test/p' }],
  );
  assert.throws(() =>
    remoteRouteIndex('throne://remoteroute/' + Buffer.from('file:///etc/passwd').toString('base64url')),
  );
  assert.equal(remoteRouteIndex('{}'), null);
});
test('native round trip preserves disabled rules, custom JSON and independent profile identity', () => {
  const p = newProfile('Owned');
  p.rules = [
    {
      id: 'old',
      name: 'Nested',
      enabled: false,
      config: {
        type: 'logical',
        mode: 'or',
        rules: [{ domain: ['x.test'] }],
        action: 'route',
        outbound: 'direct',
        future: { keep: true },
      },
    },
  ];
  p.route.future = { keep: true };
  p.dns.future = { keep: true };
  const next = importRoutingProfile(
    JSON.stringify({ format: 'thronium-routing-profile', version: 1, profile: p }),
  );
  assert.notEqual(next.id, p.id);
  assert.notEqual(next.rules[0].id, 'old');
  assert.equal(next.rules[0].enabled, false);
  assert.deepEqual(next.rules[0].config, p.rules[0].config);
  assert.deepEqual(next.route, p.route);
  assert.deepEqual(next.dns, p.dns);
});
test('categories preserve existing rules and sources, reuse sets and honour requested priority', () => {
  const p = newProfile('Manual');
  p.rules = [
    { id: 'manual', name: 'Manual', enabled: true, config: { domain: ['custom.test'], outbound: 'direct' } },
  ];
  const source = { kind: 'geosite', url: 'https://example.test/a.dat' };
  const next = addCategories(p, source, ['ru', 'ru', 'openai'], 'proxy', true);
  assert.equal(next.rules.length, 3);
  assert.equal(next.rules[2].id, 'manual');
  assert.equal(p.rules.length, 1);
  assert.equal(p.route.rule_set, undefined);
  assert.equal(addCategories(next, source, ['ru'], 'proxy', true).rules.length, 3);
  const other = addCategories(next, { ...source, url: 'https://example.test/b.dat' }, ['ru'], 'block', false);
  assert.equal(other.rules.at(-1).config.action, 'reject');
  assert.equal(other.route.rule_set.length, 3);
});
test('content editor preserves OR across kinds, IPv6 and commas in expressions', () => {
  const rules = [
    { domain_suffix: ['one.test'] },
    { domain: ['exact.test'] },
    { domain_regex: ['a{1,3}\\.test'] },
    { ip_cidr: ['2001:db8::/32'] },
  ];
  const text = categoryText(rules);
  const copy = parseCategoryText(text);
  assert(copy.some((r) => r.domain_regex?.[0] === 'a{1,3}\\.test'));
  assert(copy.some((r) => r.ip_cidr?.[0] === '2001:db8::/32'));
  assert.equal(copy.length, 4);
  assert.equal(categoryText([{ ip_cidr: ['192.0.2.0/24'], invert: true }]), null);
  assert.throws(() => parseCategoryText('constructor:bad'));
});
test('a simple category view leaves malformed and nonrepresentable contents in JSON', () => {
  const cases = [
    null,
    {},
    [null],
    [false],
    [[]],
    [{ domain: { future: true } }],
    [{ domain: [42] }],
    [{ domain: ['one.test\ntwo.test'] }],
    [{ domain: [' padded.test'] }],
    [{ domain: [''] }],
    [{ domain: ['ok.test'], future: { keep: true } }],
    [{ domain: ['ok.test'] }, null],
  ];
  for (const input of cases) {
    const before = structuredClone(input);
    assert.equal(categoryText(input), null);
    assert.deepEqual(input, before);
  }
  assert.equal(
    categoryText([{ domain: 'one.test', invert: false }, { domain: ['one.test', 'two.test'] }]),
    'domain:one.test\ndomain:one.test\ndomain:two.test',
  );
});
test('unsupported JSON fails without a partial imported profile', () => {
  assert.throws(
    () => importRoutingProfile(JSON.stringify({ outbounds: [], route: { rules: [] } })),
    /unsupported/,
  );
  assert.throws(
    () =>
      importRoutingProfile(JSON.stringify({ format: 'thronium-routing-profile', version: 2, profile: {} })),
    /version/,
  );
});
