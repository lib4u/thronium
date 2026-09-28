// Public URI parser/export integration; all credentials/endpoints are synthetic.
import { readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { parseLink } from '../src/profiles/import.ts';
import { nativeLink } from '../src/profiles/share.ts';
const fixture = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const cases = [];
for (const [name, value] of [['uri-absent', undefined], ['uri-true', true], ['uri-false', false]]) {
  const query = new URLSearchParams({sni: fixture.serverName, tls_spoof_enabled: 'false', tls_curve_preferences: 'X25519'});
  if (value !== undefined) query.set('tls_tricks', String(value));
  const uri = `https://fixture:synthetic@127.0.0.1:${fixture.proxyPort}?${query}#${name}`;
  const {draft, warnings} = parseLink(uri, 'personal');
  assert.equal(warnings.length, 0);
  assert.equal(draft.config.tls.tls_tricks?.mixedcase_sni, value);
  assert.equal(draft.config.tls.spoof_enabled, false);
  const original = structuredClone(draft);
  const exported = nativeLink(draft);
  assert.deepEqual(parseLink(exported, 'personal').draft.config, draft.config);
  assert.deepEqual(draft, original);
  cases.push({name, uri, exported, draft});
}
writeFileSync(process.argv[3], JSON.stringify(cases, null, 2) + '\n');
