import test from 'node:test';
import assert from 'node:assert/strict';
import { parseImport, parseLink, parseWireGuard, subscriptionSource, maxImportBytes } from '../src/profiles/import.ts';
import { links, wgFile, uuid } from './import-fixtures.mjs';
import { importWarning } from '../src/profiles/ImportModel.ts';
const config = link => parseLink(link, 'work').draft.config;

test('Throne TLS switches preserve default, enabled and disabled with the core object shape', () => {
  const base = 'trojan://fixture@127.0.0.1:443?security=tls';
  assert.equal(config(base).tls.tls_tricks, undefined);
  assert.equal(config(base).tls.spoof_enabled, undefined);
  for (const value of [true, false]) {
    const parsed = config(base + '&tls_tricks=' + value + '&tls_spoof_enabled=' + value + '&tls_spoof=cover.example&tls_spoof_method=wrong-sequence');
    assert.deepEqual(parsed.tls.tls_tricks, { mixedcase_sni: value });
    assert.equal(parsed.tls.spoof_enabled, value);
    assert.equal(parsed.tls.spoof, 'cover.example');
    assert.equal(parsed.tls.spoof_method, 'wrong-sequence');
  }
  for (const value of ['', 'null', '{}', '2']) assert.throws(() => config(base + '&tls_tricks=' + value), /invalid_boolean/);
  const inherited = config(base + '&tls_spoof=&tls_spoof_method=');
  assert.equal(inherited.tls.spoof, undefined);
  assert.equal(inherited.tls.spoof_method, undefined);
  assert.equal(inherited.tls.spoof_enabled, undefined);
  for (const enabled of [true, false]) {
    const explicit = config(base + '&tls_spoof=&tls_spoof_method=&tls_spoof_enabled=' + enabled);
    assert.equal(explicit.tls.spoof_enabled, enabled);
    assert.equal(explicit.tls.spoof, '');
    assert.equal(explicit.tls.spoof_method, '');
  }
});

test('local external-core JSON and profile bundles retain original launch text and empty fields', () => {
  const configuration = { type: 'extracore', name: 'Original Qt name', socks_address: '127.0.0.1', socks_port: 1099, extra_core_path: '/tmp/fixture core', extra_core_args: '--config "%s" --literal "$HOME; $(ignored)"', extra_core_conf: '  [fixture]\r\nkey = "not JSON"\r\n\t', no_logs: false };
  for (const extra_core_args of [configuration.extra_core_args, '']) {
    const original = { ...configuration, extra_core_args };
    const raw = parseImport(JSON.stringify(original), 'work')[0];
    assert.equal(raw.draft.kind, 'external-core');
    assert.deepEqual(raw.draft.config, original);
    const profile = { name: 'Local executable', kind: 'external-core', config: original };
    const bundled = parseImport(JSON.stringify({ format: 'thronium-profiles', version: 1, profiles: [profile] }), 'work')[0];
    assert.deepEqual(bundled.draft, { ...profile, groupId: 'work' });
    assert.equal(bundled.error, undefined);
  }
});

test('meta profiles retain their explicit type, member aliases and preferred server', () => {
  for (const [kind, configuration] of [['chain', { type: 'chain', hops: ['p0'] }], ['auto-selector', { type: 'auto-selector', members: ['p0'], pinned_profile: 'p0', balance: true }]]) {
    assert.equal(parseImport(JSON.stringify(configuration), 'work')[0].draft.kind, kind);
    const profiles = [{ name: 'Member', reference: 'p0', kind: 'sing-box-outbound', config: { type: 'direct' } }, { name: 'Group', reference: 'p1', kind, config: configuration }];
    assert.deepEqual(parseImport(JSON.stringify({ format: 'thronium-profiles', version: 1, profiles }), 'work').map(r => r.draft), profiles.map(p => ({ ...p, groupId: 'work' })));
  }
});

test('portable chain aliases and nested references reach native import unchanged', () => {
  const profiles = [{ name: 'Leaf', reference: 'p0', kind: 'sing-box-outbound', config: { type: 'direct' } }, { name: 'Chain', reference: 'p1', kind: 'chain', config: { type: 'chain', hops: ['p0', 'p0'] } }];
  const bundle = profiles => JSON.stringify({ format: 'thronium-profiles', version: 1, profiles });
  assert.deepEqual(parseImport(bundle(profiles), 'work').map(r => r.draft), profiles.map(p => ({ ...p, groupId: 'work' })));
  for (const reference of ['', 'x y', 123, 'a'.repeat(65)]) {
    assert(parseImport(bundle([{ ...profiles[0], reference }]), 'work')[0].error);
  }
});

test('Thronium exports preserve explicit formats, names and complete unknown configuration fields', () => {
  const profiles = ['sing-box-outbound', 'sing-box-config', 'xray-outbound', 'xray-config'].map(kind => ({ name: 'Тест 🦊 ' + kind, kind, config: { future: { secret: 'fixture', note: '[Interface]' }, inbounds: [], outbounds: [] }, id: 'old', groupId: 'missing' }));
  const rows = parseImport(JSON.stringify({ format: 'thronium-profiles', version: 1, profiles }), 'work', 'unrelated-filename.json');
  assert.deepEqual(rows.map(r => r.draft), profiles.map(({ name, kind, config }) => ({ name, kind, config, groupId: 'work' })));
  assert(rows.every(r => !r.error && r.warnings.length === 0));
  const ordinary = { type: 'socks', server: 'localhost', server_port: 1, note: '[Interface]' };
  assert.deepEqual(parseImport(JSON.stringify(ordinary), 'work')[0].draft.config, ordinary);
});

test('malformed or future Thronium exports fail without exposing configuration credentials', () => {
  const bundle = profiles => JSON.stringify({ format: 'thronium-profiles', version: 1, profiles });
  for (const profiles of [[], null, [{ name: '', kind: 'sing-box-outbound', config: { password: 'hidden' } }], [{ name: 'a', kind: 'unknown', config: {} }], [{ name: 'a', kind: 'xray-config', config: [] }]]) {
    const rows = parseImport(bundle(profiles), 'work'); assert(rows[0].error); assert(!JSON.stringify(rows).includes('hidden'));
  }
  assert.equal(parseImport(JSON.stringify({ format: 'thronium-profiles', version: 3, profiles: [] }), 'work')[0].error, 'unsupported_bundle_version');
  assert.equal(parseImport(bundle(Array(1001).fill({})), 'work')[0].error, 'too_many_profiles');
});

test('subscription URLs select the subscription flow and preserve signed paths and query strings', () => {
  for (const url of ['https://provider.example/private-token', 'http://127.0.0.1:8000/sub?token=a+b%2Bc&x=%2f', 'https://provider.example/?token=private-token']) {
    assert.deepEqual(subscriptionSource(' \n' + url + '\n'), { url, automatic: true });
  }
  assert.equal(parseImport('https://provider.example/private-token', 'work')[0].error, 'subscription_link');
  assert(!JSON.stringify(parseImport('https://provider.example/private-token', 'work')).includes('private-token'));
  for (const value of ['https://provider.example/sub\n' + links.trojan, 'file:///tmp/sub', 'https://provider.example:99999/sub', 'https://user:secret@provider.example/sub', 'https://provider.example/sub#fragment', 'https://provider.example/sub#', 'https://provider.example/' + 'x'.repeat(8192), JSON.stringify({ type: 'direct' })]) assert.equal(subscriptionSource(value), null);
});

test('valid HTTP proxy links keep their profile flow while bare web addresses allow explicit subscription import', () => {
  assert.equal(subscriptionSource(links.http), null);
  for (const url of ['http://127.0.0.1:80', 'https://proxy.example:443', 'https://proxy.example:8443?path=%2Ftunnel', 'https://provider.example']) {
    assert.deepEqual(subscriptionSource(url), { url, automatic: false });
    assert.equal(parseImport(url, 'work')[0].draft.config.type, 'http');
  }
  assert.equal(config('http://127.0.0.1:80').server_port, 80);
});

test('all upstream URI families produce typed drafts without losing recognized query fields', () => {
  for (const [name, input] of Object.entries(links)) {
    const row = parseImport(input, 'work')[0];
    assert(!row.error, name + ': ' + row.error); assert(row.draft, name); assert.equal(row.draft.groupId, 'work'); assert.deepEqual(row.warnings, [], name);
  }
});
test('VLESS engine selection preserves XHTTP, raw HTTP headers, Reality and Unicode names', () => {
  const xhttp = parseLink(links['vless-xhttp'], 'work'); assert.equal(xhttp.draft.kind, 'xray-outbound');
  assert.equal(xhttp.draft.config.streamSettings.xhttpSettings.extra.xmux.maxConcurrency, '4-8');
  assert.equal(parseLink(links['vless-reality'], 'work').draft.kind, 'sing-box-outbound');
  assert.deepEqual(config(links['vless-raw-http']).streamSettings.rawSettings.header.request.headers, { Host: ['example.test'] });
  assert.equal(parseLink(links['vmess-base64'], 'work').draft.name, 'Русское имя');
  const ws = config(links['vless-ws-tls']); assert.equal(ws.transport.path, '/ws'); assert.equal(ws.transport.max_early_data, 2048); assert.equal(ws.transport.early_data_header_name, 'Sec-WebSocket-Protocol');
});
test('Reality spider paths select Xray and retain the encoded path', () => {
  const row = parseLink(links['vless-reality-spider'], 'work');
  assert.equal(row.draft.kind, 'xray-outbound'); assert.deepEqual(row.warnings, []);
  assert.equal(row.draft.config.streamSettings.realitySettings.spiderX, '/');
  const custom = parseLink(links['vless-reality-spider'].replace('spx=%2F', 'spx=%2Fnews%3Fa%3D1%2B2'), 'work');
  assert.equal(custom.draft.config.streamSettings.realitySettings.spiderX, '/news?a=1+2');
  const tls = parseLink(`vless://${uuid}@example.test:443?security=tls&spx=%2F`, 'work');
  assert.deepEqual(tls.warnings, ['query:spx']);
});
test('percent escapes and literal plus signs retain passwords, Base64 and IPv6', () => {
  const c = config(`vless://${uuid}@[2001:db8::1]:8443?type=ws&path=%2Ftest%3Fa%3Db%2Bc&security=tls#%D0%A2%D0%B5%D1%81%D1%82`);
  assert.equal(c.server, '2001:db8::1'); assert.equal(c.server_port, 8443); assert.equal(c.transport.path, '/test?a=b+c');
  assert.equal(config('trojan://p%40ss%3A%2F%23%25%2B@host:443').password, 'p@ss:/#%+');
  assert.equal(config('ssh://host:22?user=u&password=p+a%2Bb').password, 'p+a+b');
  for (const key of ['ss-sip002', 'ss-legacy']) assert.equal(config(links[key]).password, 'long:test/password+');
  assert.equal(config(links.http).server_port, 80);
  assert.deepEqual(config(links['hy2-hopping']).server_ports, ['443:443', '500:600']);
  assert.equal(config(links['hy2-hopping']).initial_packet_size, 1250);
  assert.equal(config(links.mierus).multiplexing, 'MULTIPLEXING_LOW');
});
test('explicit VLESS gRPC gun and multi modes use Xray and retain their semantics', () => {
  for (const mode of ['gun', 'multi']) {
    const row = parseLink(`vless://${uuid}@example.test:443?type=grpc&mode=${mode}&serviceName=tunnel&authority=example.test&security=tls&sni=example.test`, 'work');
    assert.equal(row.draft.kind, 'xray-outbound'); assert.deepEqual(row.warnings, []);
    assert.equal(row.draft.config.streamSettings.grpcSettings.multiMode, mode === 'multi');
    assert.equal(row.draft.config.streamSettings.grpcSettings.serviceName, 'tunnel');
    assert.equal(row.draft.config.streamSettings.grpcSettings.authority, 'example.test');
  }
  assert.equal(parseImport(`vless://${uuid}@example.test:443?type=grpc&mode=unknown`, 'work')[0].error, 'unsupported_transport');
  assert.deepEqual(parseLink('hysteria2://fixture@example.test:443?fm=%7B%22quicParams%22%3A%7B%22congestion%22%3A%22bbr%22%7D%7D', 'work').warnings, []);
});
test('Hysteria2 BBR FinalMask maps only the equivalent supported subset', () => {
  const link = (mask, query = '') => `hysteria2://fixture@example.test:443?fm=${encodeURIComponent(JSON.stringify(mask))}${query}`;
  const row = parseLink(link({ quicParams: { congestion: 'bbr', debug: false } }), 'work');
  assert.deepEqual(row.warnings, []); assert.equal(row.draft.config.bbr_profile, 'standard');
  assert.equal(row.draft.config.up_mbps, 0); assert.equal(row.draft.config.down_mbps, 0);
  for (const mask of [{ quicParams: { congestion: 'reno' } }, { quicParams: { congestion: 'bbr', debug: true } }, { quicParams: { congestion: 'bbr', future: 1 } }, { quicParams: { congestion: 'bbr' }, udp: [] }]) {
    const unknown = parseLink(link(mask), 'work'); assert.deepEqual(unknown.warnings, ['query:fm']); assert.equal(unknown.draft.config.bbr_profile, undefined);
  }
  const conflict = parseLink(link({ quicParams: { congestion: 'bbr' } }, '&upmbps=100'), 'work');
  assert.deepEqual(conflict.warnings, ['query:fm']); assert.equal(conflict.draft.config.up_mbps, 100);
});
test('WireGuard file preserves multiple peers, CIDRs, PSK, and AWG numeric types', () => {
  const parsed = parseWireGuard(wgFile.replace('PersistentKeepalive = 25', 'PersistentKeepalive = 25\nPresharedKey = a+/b='), 'work'); const c = parsed.draft.config;
  assert.equal(c.peers.length, 2); assert.equal(c.peers[0].address, '::1'); assert.equal(c.peers[0].port, 51820); assert.equal(c.peers[0].pre_shared_key, 'a+/b=');
  assert.deepEqual(c.peers[1].allowed_ips, ['::/0']); assert.equal(c.amnezia_wg.rekey_after_time, '100-110'); assert.equal(c.amnezia_wg.jc, 3); assert.equal(c.amnezia_wg.random_trailers, true); assert.equal(c.amnezia_wg.h1, '1-100');
  assert.deepEqual(c.address, ['10.44.0.2/32', 'fd00::2/128']); assert.deepEqual(parsed.warnings, []);
  const exported = { ...c, worker_count: 2, peers: [{ address: '::1', port: 51820, public_key: c.peers[0].public_key }] };
  const imported = config('throne://add/' + Buffer.from(JSON.stringify(exported)).toString('base64url'));
  assert.deepEqual(imported.peers[0].allowed_ips, ['0.0.0.0/0', '::/0']);
  assert.equal(imported.workers, 2); assert.equal(imported.worker_count, undefined);
  assert.deepEqual(parseImport(JSON.stringify(exported), 'work')[0].draft.config, exported);

});
test('unknown parameters and system directives are reported without executing or silently dropping them', () => {
  assert.deepEqual(parseLink('socks://host:1080?unknown=value', 'work').warnings, ['query:unknown']);
  const parsed = parseWireGuard(wgFile.replace('[Peer]', 'DNS = 1.1.1.1\nTable = off\nFwMark = 0x1\nPostUp = touch /tmp/must-not-exist\nPreDown = true\nSaveConfig = true\nUnknownKey = 1\n[Peer]'), 'work');
  assert.deepEqual(parsed.warnings, ['wg-setting:DNS', 'wg-setting:Table', 'wg-setting:FwMark', 'wg-action:PostUp', 'wg-action:PreDown', 'wg-action:SaveConfig', 'wg:UnknownKey']);
  assert.equal(parsed.draft.config.dns, undefined); assert(!JSON.stringify(parsed.draft.config).includes('must-not-exist'));
  assert.equal(importWarning('wg-action:PostUp', 'en'), 'Host command from the file is not executed: PostUp');
  assert.equal(importWarning('wg-setting:DNS', 'ru'), 'Настройка интерфейса не применяется приложением: DNS');
  assert.equal(importWarning('wg:UnknownKey', 'en'), 'File directives not applied: UnknownKey');
});
test('batch errors stay associated with source lines and do not reveal credentials', () => {
  const rows = parseImport('# comment\n' + links.trojan + '\ninvalid://secret@host\nvless://secret@host:99999\n', 'work');
  assert.deepEqual(rows.map(r => r.index), [2, 3, 4]); assert(rows[0].draft); assert.equal(rows[1].error, 'unsupported_link'); assert.equal(rows[2].error, 'invalid_link');
  assert(!JSON.stringify(rows.slice(1)).includes('secret'));
});
test('JSON full configurations and arrays preserve unknown data and are not split into broken fragments', () => {
  const full = { outbounds: [{ type: 'direct' }], route: { final: 'direct' }, unknown: { future: true } };
  const rows = parseImport(JSON.stringify([full, { protocol: 'freedom', settings: {} }]), 'work');
  assert.equal(rows[0].draft.kind, 'sing-box-config'); assert.deepEqual(rows[0].draft.config, full); assert.equal(rows[1].draft.kind, 'xray-outbound');
  const base64 = Buffer.from(links.trojan + '\n' + links.socks).toString('base64'); assert.equal(parseImport(base64, 'work').length, 2);
});
test('invalid data, unsupported formats and oversized imports produce explicit errors', () => {
  for (const input of ['vless://x@host?path=%GG', 'vmess://!!!', 'ss://!!@host:22', '[Interface]\nPrivateKey=a', 'vpn://not-supported', '[null]', '{bad']) assert(parseImport(input, 'work')[0].error, input);
  assert.equal(parseImport('x'.repeat(maxImportBytes + 1), 'work')[0].error, 'import_too_large');
  assert.equal(parseImport(Array(1001).fill(links.trojan).join('\n'), 'work')[0].error, 'too_many_profiles');
  assert.deepEqual(parseImport('  ', 'work'), []);
});

test('vmess JSON applies SNI, ALPN and fingerprint only to a TLS link, as Qt', async () => {
  const { parseLink } = await import('../src/profiles/import.ts');
  const link = (extra) =>
    'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'VMess', add: '192.0.2.10', port: '443', id: '00000000-0000-4000-8000-000000000001', aid: '0', net: 'tcp', sni: 'front.example', alpn: 'h2', fp: 'chrome', ...extra })).toString('base64');
  const plain = parseLink(link({ tls: '' }), 'target').draft.config;
  assert.equal(plain.tls, undefined);
  const secured = parseLink(link({ tls: 'tls' }), 'target').draft.config;
  assert.equal(secured.tls.enabled, true);
  assert.equal(secured.tls.server_name, 'front.example');
  assert.deepEqual(secured.tls.alpn, ['h2']);
});

test('a host on a gRPC link has no sing-box field and is reported', () => {
  const { draft, warnings } = parseLink('trojan://secret@192.0.2.10:443?security=tls&type=grpc&serviceName=svc&host=cdn.example#gRPC', 'target');
  assert.equal(draft.config.transport.service_name, 'svc');
  assert(warnings.includes('query:host'), warnings.join());
});

test('file warnings name relative paths and external credentials without English text', () => {
  const rows = parseImport('client\nremote 192.0.2.10 1194\nca ca.crt\nauth-user-pass creds.txt\n', 'target', 'client.ovpn');
  const warnings = rows[0].warnings;
  assert(warnings.includes('file-relative:ca'), warnings.join());
  assert(warnings.includes('file-external:auth-user-pass'), warnings.join());
  assert(!warnings.some((w) => /relative path|external credentials/.test(w)));
  for (const language of ['en', 'ru'])
    for (const warning of ['file-relative:ca', 'file-external:auth-user-pass'])
      assert(!importWarning(warning, language).startsWith('file'), importWarning(warning, language));
});
test('Xray early data from a link is bounded like the editor', async () => {
  const { maxXrayEarlyData } = await import('../src/profiles/wsEarlyData.ts');
  const link = (ed) => `vless://00000000-0000-4000-8000-000000000000@203.0.113.10:443?type=ws&security=tls&sni=example.test&path=%2Fws&ed=${ed}#fixture`;
  assert.match(parseLink(link(maxXrayEarlyData), 'work', true).draft.config.streamSettings.wsSettings.path, new RegExp(`ed=${maxXrayEarlyData}$`));
  assert.throws(() => parseLink(link(maxXrayEarlyData + 1), 'work', true), /invalid_number/);
});
test('the import preview finds the server like the engine descriptor', async () => {
  const { draftAddress } = await import('../src/profiles/draftAddress.ts');
  assert.equal(draftAddress({ server: 'a.example', settings: { address: 'b.example' } }), 'a.example');
  assert.equal(draftAddress({ settings: { vnext: [{ address: 'v.example', port: 443, users: [] }] } }), 'v.example');
  assert.equal(draftAddress({ settings: { servers: [{ address: 's.example' }] } }), 's.example');
  assert.equal(draftAddress({ peers: [{ endpoint: '[2001:db8::1]:51820' }] }), '2001:db8::1');
  assert.equal(draftAddress({ settings: { vnext: [{ address: 'a.example' }, { address: 'b.example' }] } }), '');
});
