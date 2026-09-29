import { translate } from '../src/shared/i18n/index.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { matches, actions, actionFields, newProfile, parseValue, simpleRules, replaceSimple, fromCoreRoute, coreRoute, isBaselineProfile } from '../src/routing/model.ts';
import { defaults } from '../src/shared/api/generated/defaults.ts';
import { parseRuleValue, formatRuleValue } from '../src/routing/ruleInput.ts';

test('simple lists preserve IPv6 and process paths, and reject unknown selectors', () => {
  const rules = simpleRules('ip:2001:db8::/32\nprocessPath:C:\\Apps\\browser.exe\nsuffix:example.test\n# comment', 'direct');
  assert.deepEqual(rules[0].config.ip_cidr, ['2001:db8::/32']); assert.deepEqual(rules[1].config.process_path, ['C:\\Apps\\browser.exe']); assert.equal(rules.length, 3);
  assert.equal(simpleRules('domain:example.test', 'block')[0].config.action, 'reject');
  assert.throws(() => simpleRules('geosite:unknown', 'proxy')); assert.throws(() => simpleRules('domain: ', 'proxy'));
});
test('replacing a simple list keeps its priority and leaves custom and other target rules intact', () => {
  const profile = newProfile('Work'); const custom = { id:'custom', name:'Block', enabled:true, config:{ action:'reject', port:[25] } };
  profile.rules = [custom, ...simpleRules('suffix:old.example', 'direct'), ...simpleRules('domain:proxy.example', 'proxy')];
  const changed = replaceSimple(profile, 'direct', 'ip:127.0.0.0/8\nprocessName:firefox');
  assert.equal(changed.rules[0], custom); assert.deepEqual(changed.rules[1].config.ip_cidr, ['127.0.0.0/8']); assert.equal(changed.rules[3], profile.rules[2]); assert.equal(profile.rules.length, 3);
});
test('editing or reordering raw routing keeps disabled status, names and unknown fields', () => {
  const profile = newProfile('Work'); profile.route.future_option = { preserve: true };
  profile.rules = [{ id:'first', name:'Disabled rule', enabled:false, config:{ domain:['one.test'], action:'route', outbound:'proxy' } }, { id:'second', name:'Second', enabled:true, config:{ action:'reject', port:[25] } }];
  const raw = coreRoute(profile); raw.rules = [{ ...profile.rules[0].config, domain:['changed.test'] }, profile.rules[1].config];
  const changed = fromCoreRoute(profile, raw);
  assert.equal(changed.rules[0].id, 'first'); assert.equal(changed.rules[0].enabled, false); assert.equal(changed.rules[0].name, 'Disabled rule'); assert.deepEqual(changed.route.future_option, {preserve:true});
  const reordered = fromCoreRoute(profile, { ...profile.route, rules:[profile.rules[1].config, profile.rules[0].config] }); assert.equal(reordered.rules[1].enabled, false); assert.equal(reordered.rules[0].id, 'second');
  assert.throws(() => fromCoreRoute(profile, { rules:[null] }));
});
test('condition types match core JSON: ports are numbers, flags are booleans, and expressions remain opaque', () => {
  const field = key => matches.find(f => f.key === key);
  assert.deepEqual(parseValue(field('port'), '80, 443\n8443'), [80,443,8443]);
  assert.throws(() => parseValue(field('port'), '65536')); assert.throws(() => parseValue(field('port'), '0'));
  assert.equal(parseValue(field('ip_is_private'), 'false'), false); assert.equal(parseValue(field('ip_version'), '6'), 6); assert.throws(() => parseValue(field('ip_version'), '5'));
  assert.deepEqual(parseValue(field('domain_regex'), 'a\\.test$'), ['a\\.test$']);
  assert.deepEqual(parseValue(field('interface_address'), '{"eth0":["192.0.2.0/24"]}'), {eth0:['192.0.2.0/24']});
});
test('routing fields and actions have bilingual labels and unique keys', () => {
  assert.equal(new Set(matches.map(f => f.key)).size, matches.length);
  for (const action of actions) { assert(['en', 'ru'].every(language => Boolean(translate(language, action.label)))); const fields = actionFields(action.id); assert.equal(new Set(fields.map(f => f.key)).size, fields.length); for (const field of fields) assert(['en', 'ru'].every(language => Boolean(translate(language, field.label)))); }
  for (const field of matches) assert(['en', 'ru'].every(language => Boolean(translate(language, field.label))));
});
test('compact rule inputs accept comma-separated addresses without splitting expressions, names or paths', () => {
  const field = key => matches.find(f => f.key === key);
  for (const [key, text, expected] of [
    ['domain_suffix', 'example.test, other.test\nthird.test', ['example.test', 'other.test', 'third.test']],
    ['source_ip_cidr', '192.0.2.0/24, 2001:db8::/32', ['192.0.2.0/24', '2001:db8::/32']],
    ['port', '80,443\n8443', [80, 443, 8443]],
    ['domain_regex', '[a-z]{1,3}\\.test$\nother', ['[a-z]{1,3}\\.test$', 'other']],
    ['process_path', '/opt/Browser, Inc/browser\n/usr/bin/browser', ['/opt/Browser, Inc/browser', '/usr/bin/browser']],
    ['wifi_ssid', 'Office, West', ['Office, West']],
  ]) {
    assert.deepEqual(parseRuleValue(field(key), text), expected);
    assert.deepEqual(parseRuleValue(field(key), formatRuleValue(field(key), expected)), expected);
  }
});

test('WARP targets round-trip through simple lists and raw routing with independent destinations', () => {
  const profile = newProfile('Split WARP');
  profile.route.final = 'warp-bypass';
  profile.rules = [...simpleRules('domain:warp.test', 'warp'), ...simpleRules('processName:browser', 'warp-bypass')];
  const result = fromCoreRoute(profile, coreRoute(profile));
  assert.equal(result.route.final, 'warp-bypass');
  assert.deepEqual(result.rules.map(rule => rule.config.outbound), ['warp', 'warp-bypass']);
  const replaced = replaceSimple(result, 'warp', 'domain:other.test');
  assert.equal(replaced.rules[1].config.outbound, 'warp-bypass');
  assert.deepEqual(replaced.rules[1].config.process_name, ['browser']);
});
test('an untouched Default leaves routing to a subscription, as the engine decides', () => {
  const baseline = structuredClone(defaults.routingProfile);
  assert.ok(isBaselineProfile(baseline));
  // Key order and a renamed Default do not count; disabled rules neither.
  assert.ok(isBaselineProfile({ ...baseline, name: 'Renamed', route: Object.fromEntries(Object.entries(baseline.route).reverse()), rules: [{ id: 'r', name: 'Off', enabled: false, config: {} }] }));
  assert.ok(!isBaselineProfile({ ...baseline, mode: 'direct' }));
  assert.ok(!isBaselineProfile({ ...baseline, rules: [{ id: 'r', name: 'On', enabled: true, config: {} }] }));
  assert.ok(!isBaselineProfile({ ...baseline, dns: { ...baseline.dns, final: 'custom' } }));
  assert.ok(!isBaselineProfile({ ...baseline, id: 'explicit' }));
});
