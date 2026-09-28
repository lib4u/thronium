import { translate } from '../src/shared/i18n/index.ts';
import test from 'node:test';
import assert from 'node:assert/strict';
import { definitions, sections, get, set, parse, format, identify, awgFields } from '../src/profiles/schema.ts';

test('TLS form edits known switches without losing extensions and returns to inherited defaults', () => {
  const def = definitions.find(d => d.id === 'trojan');
  const fields = sections(def, def.seed).find(s => s.id === 'tls').fields;
  const field = fields.find(f => f.path === 'tls.tls_tricks.mixedcase_sni');
  const source = { ...def.seed, tls: { enabled: true, tls_tricks: { mixedcase_sni: false, future: [1, false] }, spoof_enabled: false, spoof: 'cover.example', extension: { keep: true } } };
  const before = structuredClone(source);
  const enabled = set(source, field.path, parse(field, 'true'));
  assert.deepEqual(enabled.tls.tls_tricks, { mixedcase_sni: true, future: [1, false] });
  const inherited = set(enabled, field.path, parse(field, ''));
  assert.deepEqual(inherited.tls.tls_tricks, { future: [1, false] });
  assert.deepEqual(inherited.tls.extension, source.tls.extension);
  assert.deepEqual(source, before);
  for (const value of [true, false]) {
    const old = { tls: { enabled: true, tls_tricks: value } };
    assert.equal(format(field, get(old, field.path)), String(value));
    assert.deepEqual(set(old, field.path, !value).tls.tls_tricks, { mixedcase_sni: !value });
    assert.deepEqual(set(old, field.path, undefined), { tls: { enabled: true } });
    assert.deepEqual(set({ tls: { tls_tricks: { mixedcase_sni: value } } }, field.path, undefined), { tls: {} });
  }
  const spoof = fields.find(f => f.path === 'tls.spoof_enabled');
  assert.equal(set(source, spoof.path, parse(spoof, '')).tls.spoof_enabled, undefined);
  assert.equal(set(source, spoof.path, parse(spoof, '')).tls.spoof, 'cover.example');
  const curves = fields.find(f => f.path === 'tls.curve_preferences');
  assert.deepEqual(parse(curves, 'X25519\nP256'), ['X25519', 'P256']);
  for (const malformed of [[], [false], 0, 'false']) {
    const original = { tls: { tls_tricks: malformed } };
    const snapshot = structuredClone(original);
    for (const value of [true, false, undefined]) assert.throws(() => set(original, field.path, value), /invalid_field_value/);
    assert.deepEqual(original, snapshot);
  }
  const oldOff = { tls: { enabled: true, spoof: '', spoof_method: '', future: 'keep' } };
  assert.equal(format(spoof, get(oldOff, spoof.path)), 'false');
  assert.equal(oldOff.tls.spoof_enabled, undefined);
  assert.deepEqual(set(oldOff, spoof.path, undefined), { tls: { enabled: true, future: 'keep' } });
  assert.deepEqual(oldOff, { tls: { enabled: true, spoof: '', spoof_method: '', future: 'keep' } });
  const own = { tls: { enabled: true, spoof_enabled: false, spoof: 'own.example', spoof_method: 'wrong-ack' } };
  assert.deepEqual(set(own, spoof.path, undefined), { tls: { enabled: true, spoof: 'own.example', spoof_method: 'wrong-ack' } });
});

test('external launch profiles use their own editor without unrelated network or TLS fields', () => {
  const def = definitions.find(d => d.id === 'extracore');
  assert.equal(identify({ kind: 'external-core', config: def.seed }), def.id);
  assert.equal(def.kind, 'external-core');
  assert.deepEqual(sections(def, def.seed).map(s => s.id), ['main']);
  assert.deepEqual(sections(def, def.seed)[0].fields, []);
  for (const key of ['extra_core_args', 'extra_core_conf', 'extra_core_path']) assert.equal(def.seed[key], '');
  assert.equal(def.seed.socks_address, '127.0.0.1');
});

test('changing one known field retains credentials, extensions and other peers', () => {
  const original = { type: 'wireguard', private_key: 'private', amnezia_wg: { future_option: 7 }, peers: [{ address: 'one', public_key: 'pub1', extension: { a: 1 } }, { address: 'two', public_key: 'pub2' }] };
  const changed = set(original, 'peers.0.address', 'new');
  assert.equal(changed.peers[0].address, 'new');
  assert.equal(original.peers[0].address, 'one');
  assert.equal(changed.private_key, 'private');
  assert.deepEqual(changed.amnezia_wg, original.amnezia_wg);
  assert.deepEqual(changed.peers[1], original.peers[1]);
  assert.deepEqual(changed.peers[0].extension, { a: 1 });
});
test('AWG ranges keep their JSON type and invalid input is rejected', () => {
  const range = awgFields.find(f => f.path.endsWith('rekey_after_time'));
  assert.equal(parse(range, '30'), 30);
  assert.equal(parse(range, '22-30'), '22-30');
  assert.throws(() => parse(range, '30-22'));
  assert.throws(() => parse(range, '4294967296'));
  const h1 = awgFields.find(f => f.path.endsWith('h1'));
  assert.equal(parse(h1, '22-30'), '22-30');
});
test('list editing preserves order, PEM lines and byte arrays', () => {
  const list = { kind: 'list' };
  const pem = '-----BEGIN PRIVATE KEY-----\nabc+/=\n-----END PRIVATE KEY-----';
  assert.equal(format(list, parse(list, pem)), pem);
  assert.deepEqual(parse({ kind: 'numbers' }, '1, 2\n255'), [1, 2, 255]);
  assert.throws(() => parse({ kind: 'numbers' }, '256'));
});
test('union values, numeric choices, false and zero survive', () => {
  assert.equal(get({ udp_over_tcp: true }, 'udp_over_tcp.enabled'), true);
  assert.deepEqual(set({ udp_over_tcp: { enabled: true, version: 1 } }, 'udp_over_tcp.enabled', false).udp_over_tcp, { enabled: false, version: 1 });
  assert.equal(parse({ kind: 'select', options: [0, 4, 6] }, '0'), 0);
  assert.equal(parse({ kind: 'bool' }, 'false'), false);
  assert.equal(parse({ kind: 'number' }, '0'), 0);
  const def = definitions.find(d => d.id === 'direct');
  const mark = sections(def, def.seed).flatMap(s => s.fields).find(f => f.path === 'routing_mark');
  assert.equal(parse(mark, '255'), 255);
  assert.equal(parse(mark, '0xff'), '0xff');
  assert.equal(parse(mark, '0xFFFFFFFF'), '0xFFFFFFFF');
  assert.throws(() => parse(mark, '22-30'));
  assert.throws(() => parse(mark, '0x100000000'));
  assert.throws(() => parse(mark, '-1'));
});
test('imported formats are identified without coercing opaque Xray configurations', () => {
  assert.equal(identify({ kind: 'sing-box-outbound', config: { type: 'openvpn-client' } }), 'openvpn');
  assert.equal(identify({ kind: 'sing-box-outbound', config: { type: 'wireguard', amnezia_wg: {} } }), 'amneziawg');
  assert.equal(identify({ kind: 'xray-outbound', config: { protocol: 'vless', settings: { vnext: [] } } }), 'customxray');
  assert.equal(identify({ kind: 'sing-box-config', config: {} }), 'customfull');
});
test('transport-specific fields are shown for their actual wire type', () => {
  const def = definitions.find(d => d.id === 'vless');
  const fields = type => sections(def, { transport: { type } }).find(s => s.id === 'transport').fields.map(f => f.path);
  assert(fields('ws').includes('transport.max_early_data'));
  assert(!fields('grpc').includes('transport.max_early_data'));
  assert(fields('grpc').includes('transport.service_name'));
  assert(!fields('').includes('transport.path'));
});
test('standard Xray VLESS uses structured fields without flattening or losing extensions', () => {
  const original = { protocol: 'vless', settings: { vnext: [{ address: 'old.example', port: 443, users: [{ id: 'private-fixture', flow: 'xtls-rprx-vision', encryption: 'none', email: 'retained' }], extra: 7 }] }, streamSettings: { network: 'xhttp', security: 'reality', xhttpSettings: { path: '/keep', extra: { noSSEHeader: true } } } };
  assert.equal(identify({ kind: 'xray-outbound', config: original }), 'xrayvless');
  const fields = sections(definitions.find(d => d.id === 'xrayvless'), original)[0].fields;
  assert(fields.some(f => f.path === 'settings.vnext.0.users.0.id' && f.kind === 'secret'));
  const changed = set(original, fields[0].path, 'new.example');
  assert.equal(changed.settings.vnext[0].address, 'new.example');
  assert.deepEqual(changed.settings.vnext[0].users, original.settings.vnext[0].users);
  assert.deepEqual(changed.streamSettings, original.streamSettings);
  assert.equal(changed.settings.vnext[0].extra, 7);
  assert.equal(changed.settings.address, undefined);
  assert.equal(original.settings.vnext[0].address, 'old.example');
});
test('ambiguous Xray destinations and user lists remain in the JSON editor', () => {
  for (const vnext of [[], [{ users: [] }], [{ users: [{}, {}] }], [{ users: [{}] }, { users: [{}] }]]) {
    assert.equal(identify({ kind: 'xray-outbound', config: { protocol: 'vless', settings: { vnext } } }), 'customxray');
  }
});
test('all editor tabs have bilingual labels and unique field paths', () => {
  for (const def of definitions) for (const config of [def.seed, { ...def.seed, streamSettings: { network: 'xhttp', security: 'reality' }, obfs: { type: 'gecko' } }]) {
    const tabs = sections(def, config);
    assert.equal(new Set(tabs.map(s => s.id)).size, tabs.length, def.id);
    for (const tab of tabs) {
      assert(['en', 'ru'].every(language => Boolean(translate(language, tab.label))));
      assert.equal(new Set(tab.fields.map(f => f.path)).size, tab.fields.length, `${def.id}: ${tab.id}`);
      for (const field of tab.fields) assert(['en', 'ru'].every(language => Boolean(translate(language, field.label))), field.path);
    }
  }
});
test('JSON path writes cannot mutate prototypes', () => {
  assert.throws(() => set({}, '__proto__.polluted', true));
  assert.equal(get({}, 'constructor'), undefined);
  assert.equal({}.polluted, undefined);
});
const paths = (id, tab, config) => {
  const def = definitions.find(d => d.id === id);
  return sections(def, config ?? def.seed).find(s => s.id === tab).fields.map(f => f.path);
};
const field = (id, tab, path) => {
  const def = definitions.find(d => d.id === id);
  return sections(def, def.seed).find(s => s.id === tab).fields.find(f => f.path === path);
};
test('endpoint UDP NAT behaviour is offered exactly where the pinned core accepts it', () => {
  const nat = ['udp_mapping', 'udp_filtering', 'udp_nat_max'];
  for (const [id, tab] of [['wireguard', 'main'], ['amneziawg', 'main'], ['openvpn', 'vpn'], ['openconnect', 'vpn']]) {
    for (const key of nat) assert(paths(id, tab).includes(key), `${id}: ${key}`);
  }
  for (const id of ['vless', 'trojan', 'hysteria2', 'tailscale', 'ssh']) {
    const all = sections(definitions.find(d => d.id === id), definitions.find(d => d.id === id).seed).flatMap(s => s.fields.map(f => f.path));
    for (const key of nat) assert(!all.includes(key), `${id}: ${key}`);
  }
  const mapping = field('wireguard', 'main', 'udp_mapping');
  assert.deepEqual(mapping.options, ['', 'endpoint_independent', 'address_dependent', 'address_and_port_dependent']);
  assert.equal(parse(mapping, 'address_dependent'), 'address_dependent');
  assert.equal(parse(mapping, ''), undefined);
  const limit = field('openvpn', 'vpn', 'udp_nat_max');
  assert.equal(parse(limit, '4294967295'), 4294967295);
  assert.throws(() => parse(limit, '4294967296'));
  const config = { type: 'wireguard', private_key: 'k', peers: [{ address: 'h' }], future: 1 };
  const changed = set(config, 'udp_filtering', parse(mapping, 'endpoint_independent'));
  assert.equal(changed.udp_filtering, 'endpoint_independent');
  assert.equal(changed.future, 1);
  assert.deepEqual(set(changed, 'udp_filtering', undefined), config);
});
test('ECH query server name and QUIC timers sit next to their existing fields', () => {
  const tls = paths('vless', 'tls');
  assert.equal(tls[tls.indexOf('tls.ech.config_path') + 1], 'tls.ech.query_server_name');
  assert(!paths('openvpn', 'tls').includes('tls.ech.query_server_name'));
  for (const id of ['hysteria', 'hysteria2', 'tuic']) {
    assert.deepEqual(paths(id, 'quic').slice(0, 2), ['idle_timeout', 'keep_alive_period'], id);
  }
  assert(!sections(definitions.find(d => d.id === 'vless'), { type: 'vless' }).some(s => s.id === 'quic'));
  const timer = field('tuic', 'quic', 'keep_alive_period');
  assert.equal(format(timer, get({ keep_alive_period: '10s' }, timer.path)), '10s');
  assert.equal(parse(timer, '10s'), '10s');
});
test('OpenVPN TLS extras and LZO compression are OpenVPN-only, OpenConnect MCA is OpenConnect-only', () => {
  const openvpn = paths('openvpn', 'tls');
  const extras = ['tls.crl_path', 'tls.remote_certificate_ku', 'tls.remote_certificate_eku', 'tls.certificate_profile', 'tls.ns_certificate_type', 'tls.version_min', 'tls.version_max', 'tls.cipher', 'tls.groups'];
  for (const key of extras) assert(openvpn.includes(key), key);
  const openconnect = paths('openconnect', 'tls');
  for (const key of extras) assert(!openconnect.includes(key), key);
  const mca = ['tls.mca_certificate', 'tls.mca_certificate_path', 'tls.mca_key', 'tls.mca_key_path', 'tls.mca_key_password'];
  for (const key of mca) assert(openconnect.includes(key), key);
  for (const key of mca) assert(!openvpn.includes(key), key);
  for (const key of [...extras, ...mca]) assert(!paths('trojan', 'tls').includes(key), key);
  const vpn = paths('openvpn', 'vpn');
  assert.equal(vpn[vpn.indexOf('compression') + 1], 'compression_lzo');
  assert(!paths('openconnect', 'vpn').includes('compression_lzo'));
  assert.deepEqual(field('openvpn', 'vpn', 'compression_lzo').options, ['none', 'no', 'yes', 'adaptive', 'asym', 'disabled', 'off']);
  assert.deepEqual(field('openvpn', 'tls', 'tls.certificate_profile').options, ['legacy', 'preferred', 'insecure', 'suiteb']);
  assert.deepEqual(field('openvpn', 'tls', 'tls.version_min').options, ['1.0', '1.1', '1.2', '1.3']);
  assert.equal(field('openvpn', 'tls', 'tls.remote_certificate_ku').kind, 'list');
  assert.deepEqual(parse(field('openvpn', 'tls', 'tls.remote_certificate_ku'), 'a0\n88'), ['a0', '88']);
  assert.equal(field('openconnect', 'tls', 'tls.mca_key').kind, 'list');
  assert.equal(field('openconnect', 'tls', 'tls.mca_key_password').kind, 'secret');
  const seed = definitions.find(d => d.id === 'openvpn').seed;
  const config = { ...seed, tls: { ...seed.tls, unknown: 'keep' } };
  const changed = set(set(config, 'tls.crl_path', '/etc/crl.pem'), 'compression_lzo', parse(field('openvpn', 'vpn', 'compression_lzo'), 'adaptive'));
  assert.deepEqual(changed.tls, { remote_certificate_tls: 'server', unknown: 'keep', crl_path: '/etc/crl.pem' });
  assert.equal(changed.compression_lzo, 'adaptive');
  assert.equal(config.compression_lzo, undefined);
});
