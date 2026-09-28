import test from 'node:test';
import assert from 'node:assert/strict';
import { parseImport, splitConfigRows } from '../src/profiles/import.ts';

const rows = (text) => splitConfigRows(parseImport(text, 'sub'), 'sub');

test('a subscription configuration becomes one profile per server outbound', () => {
  const config = JSON.stringify({
    outbounds: [
      { type: 'selector', tag: 'select', outbounds: ['tokyo'] },
      { type: 'direct', tag: 'direct' },
      { type: 'trojan', tag: 'tokyo', server: '203.0.113.10', server_port: 443, password: 'x' },
      { type: 'shadowsocks', tag: 'oslo', server: '203.0.113.11', server_port: 8388, method: 'aes-256-gcm', password: 'y' },
    ],
    endpoints: [
      { type: 'wireguard', tag: 'wg', address: ['10.0.0.2/32'], private_key: 'k', peers: [] },
    ],
    route: { rules: [] },
    dns: { servers: [] },
  });
  const parsed = rows(config);
  assert.deepEqual(
    parsed.map((row) => [row.index, row.draft?.name, row.draft?.kind]),
    [
      [1, 'tokyo', 'sing-box-outbound'],
      [2, 'oslo', 'sing-box-outbound'],
      [3, 'wg', 'sing-box-outbound'],
    ],
  );
  assert.equal(parseImport(config, 'sub').length, 1, 'a direct import still keeps the whole configuration');
});

test('an Xray configuration splits by protocol outbounds and keeps their names', () => {
  const parsed = rows(
    JSON.stringify({
      outbounds: [
        { protocol: 'freedom', tag: 'direct' },
        { protocol: 'vless', tag: 'paris', settings: { vnext: [{ address: '203.0.113.12', port: 443, users: [{ id: 'u' }] }] } },
      ],
    }),
  );
  assert.deepEqual(
    parsed.map((row) => [row.draft?.name, row.draft?.kind]),
    [['paris', 'xray-outbound']],
  );
});

test('a configuration without a single server keeps its own row so routes and DNS survive', () => {
  const config = JSON.stringify({
    outbounds: [{ type: 'direct', tag: 'direct' }],
    route: { rules: [{ action: 'sniff' }] },
  });
  const parsed = rows(config);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].draft?.kind, 'sing-box-config');
  assert.deepEqual(parsed[0].draft?.config.route, { rules: [{ action: 'sniff' }] });
});

test('splitting leaves links, bundles and unparsable rows exactly as the parser reported them', () => {
  const parsed = rows(
    ['ss://YWVzLTI1Ni1nY206eA==@203.0.113.13:8388#ok', 'vless://broken', 'not-a-link://x'].join('\n'),
  );
  assert.equal(parsed.length, 3);
  assert.equal(parsed[0].draft?.name, 'ok');
  assert.ok(parsed[1].error, 'a broken link stays an error row for the caller to count');
  assert.ok(parsed[2].error);
});
