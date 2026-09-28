import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateSync } from 'node:zlib';
import { parseImport, subscriptionSource, maxImportBytes } from '../src/profiles/import.ts';
import { profileName } from '../src/library/profileName.ts';
const parse = (text, filename) => parseImport(text, 'test-group', filename);
const one = (text, filename) => { const rows = parse(text, filename); assert.equal(rows.length, 1); assert(!rows[0].error, rows[0].error); return rows[0]; };

test('leading emoji occupy the icon slot without changing interior emoji or ordinary prefixes', () => {
  for (const emoji of ['🇷🇺', '👩🏽‍💻', '👨‍👩‍👧‍👦', '1️⃣', '💫', '🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}']) assert.deepEqual(profileName('  ' + emoji + 'Server ⚡'), { emoji, text: 'Server ⚡' });
  for (const text of ['1Server', 'Server 🇷🇺', '123', '', '  Paris']) assert.deepEqual(profileName(text), { emoji: '', text });
  assert.deepEqual(profileName('🇯🇵'), { emoji: '🇯🇵', text: '' });
});
test('throne AddSub preserves signed URLs and reads the encoded group title', () => {
  const url = 'https://provider.test/sub?token=a+b%2Fc';
  assert.deepEqual(subscriptionSource('throne://AddSub/' + Buffer.from(url + '#Моя%20группа').toString('base64url')), { url, automatic: true, link: true, name: 'Моя группа' });
  assert.equal(subscriptionSource('throne://addsub/' + Buffer.from('file:///private').toString('base64')), null);
});
test('Clash imports YAML anchors, TLS/Reality, transport and reports unsupported options', () => {
  const rows = parse(`proxies:
  - &base
    name: 🇳🇱 Netherlands
    type: vless
    server: example.test
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    servername: public.test
    reality-opts: {public-key: fixture, short-id: aaaa}
  - {name: Socks, type: socks5, server: localhost, port: 1080}
  - *base
  - {name: bad, type: unsupported, server: localhost, port: 1}
`);
  assert.equal(rows.length, 4); assert(!rows[0].error); assert.equal(rows[0].draft.config.tls.reality.public_key, 'fixture'); assert.equal(rows[1].draft.config.version, '5'); assert.deepEqual(rows[2].draft, rows[0].draft); assert.equal(rows[3].error, 'invalid_yaml');
  const ws = one('proxies: [{name: WS, type: trojan, server: vpn.test, port: 443, password: secret, network: ws, ws-opts: {path: /tunnel, headers: {Host: www.test}}, future-flag: true}]');
  assert.equal(ws.draft.config.transport.path, '/tunnel'); assert.deepEqual(ws.warnings, ['file:future-flag']);
  assert(!JSON.stringify(ws.warnings).includes('secret'));
});
test('Clash bandwidth, port hopping and intervals become the types sing-box accepts', () => {
  const hy2 = one('proxies: [{name: H2, type: hysteria2, server: vpn.test, port: 443, password: secret, up: 30 Mbps, down: "12MBps", ports: "443,8000-9000/20000:20010", hop-interval: 30}]');
  assert.equal(hy2.draft.config.up_mbps, 30, 'a lowercase b is bits');
  assert.equal(hy2.draft.config.down_mbps, 96, 'an uppercase B is bytes');
  assert.deepEqual(hy2.draft.config.server_ports, ['443:443', '8000:9000', '20000:20010']);
  assert.equal(hy2.draft.config.server_port, undefined, 'hopping replaces the single port, as for hy2:// links');
  assert.equal(hy2.draft.config.hop_interval, '30s');
  assert.deepEqual(hy2.warnings, []);
  const hy1 = one('proxies: [{name: H1, type: hysteria, server: vpn.test, port: 443, auth-str: a, up: 100, down: "1 Gbps"}]');
  assert.equal(hy1.draft.config.up_mbps, 100);
  assert.equal(hy1.draft.config.down_mbps, 1000);
  const tuic = one('proxies: [{name: T, type: tuic, server: vpn.test, port: 443, uuid: 11111111-1111-4111-8111-111111111111, password: p, heartbeat-interval: 10000}]');
  assert.equal(tuic.draft.config.heartbeat, '10000ms');
  const any = one('proxies: [{name: A, type: anytls, server: vpn.test, port: 443, password: p, idle-session-check-interval: 30, idle-session-timeout: "45s"}]');
  assert.equal(any.draft.config.idle_session_check_interval, '30s');
  assert.equal(any.draft.config.idle_session_timeout, '45s');
  const bad = one('proxies: [{name: B, type: hysteria2, server: vpn.test, port: 443, password: p, up: fast, ports: "0-70000"}]');
  assert.equal(bad.draft.config.up_mbps, undefined);
  assert.equal(bad.draft.config.server_ports, undefined);
  assert.deepEqual(bad.warnings.sort(), ['file:ports', 'file:up'], 'an unconvertible value is reported, never copied raw');
});
test('Clash XHTTP selects the Xray engine and retains transport options', () => {
  const r = one('proxies: [{name: XHTTP, type: vless, uuid: 11111111-1111-4111-8111-111111111111, server: vpn.test, port: 443, tls: true, network: xhttp, xhttp-opts: {path: /x, mode: auto}}]');
  assert.equal(r.draft.kind, 'xray-outbound'); assert.equal(r.draft.config.streamSettings.xhttpSettings.path, '/x');
});
test('SIP008 and base64 YAML import individual profiles; typed JSON remains intact', () => {
  const sip = {version: 1, servers: [{server: 'vpn.test', server_port: 8388, method: 'aes-128-gcm', password: 'secret', remarks: 'SIP'}]};
  assert.equal(one(JSON.stringify(sip)).draft.name, 'SIP');
  const yaml = 'proxies: [{name: Base64, type: socks5, server: localhost, port: 1080}]';
  assert.equal(one(Buffer.from(yaml).toString('base64')).draft.name, 'Base64');
  const config = {type: 'openvpn-client', server: 'vpn.test', servers: [{server: 'backup.test', server_port: 1194}]};
  assert.deepEqual(one(JSON.stringify(config)).draft.config, config);
});
test('OpenVPN imports inline keys, alternative remotes and does not execute scripts', () => {
  const r = one('client\ndev tun\nproto udp\nremote vpn.test 1194\nremote backup.test 443 tcp-client\ncipher AES-256-GCM\nkey-direction 1\n<ca>\nCA\n</ca>\n<tls-auth>\nKEY\n</tls-auth>\n<auth-user-pass>\nuser\nsecret\n</auth-user-pass>\nup /private/script.sh\n', 'Work.ovpn');
  assert.equal(r.draft.name, 'Work'); assert(!r.draft.config.server); assert(!r.draft.config.server_port); assert.equal(r.draft.config.servers[1].network, 'tcp'); assert.deepEqual(r.draft.config.tls.certificate, ['CA']); assert.equal(r.draft.config.tls.control_wrap.direction, 'client'); assert.equal(r.draft.config.password, 'secret'); assert.deepEqual(r.warnings, ['file:up']);
  for (const text of ['client\ndev tap\nremote vpn.test 1', 'client\nremote vpn.test 1\npkcs12 secret.p12', 'client\nserver 10.0.0.0 255.255.255.0']) assert(parse(text, 'test.ovpn')[0].error);
  assert(one('client\nremote vpn.test 1194\nca relative.pem', 'test.ovpn').warnings.length);
});
test('OpenConnect reads config and CLI credentials, flags and quoted values', () => {
  const a = one('protocol = anyconnect\nserver = https://vpn.test/group\nuser = john\npassword = "a secret"\nno-dtls\nscript = private.sh', 'test.conf');
  assert.equal(a.draft.config.username, 'john'); assert.equal(a.draft.config.password, 'a secret'); assert.equal(a.draft.config.no_udp, true); assert.deepEqual(a.warnings, [], 'client-side script is ignored, as in Qt');
  const b = one('openconnect --protocol=gp --user john --no-dtls https://vpn.test/'); assert.equal(b.draft.config.flavor, 'gp'); assert.equal(b.draft.config.server, 'https://vpn.test/');
  // Qt vpnfiTokenize/vpnfiWalkOcArgs: `option value` lines, quotes inside a
  // token, short options and a comment character inside quotes.
  const c = one('protocol anyconnect\nserver vpn.test\nuser "john smith"\npassword pa#ss\nauthgroup=\'Ops #1\'', 'test.conf');
  assert.equal(c.draft.config.username, 'john smith'); assert.equal(c.draft.config.auth_group, 'Ops #1');
  assert.equal(c.draft.config.password, 'pa#ss');
  const d = one('openconnect -u john -gOps --user-agent="Any Connect" --servercert pin-sha256:AAAA vpn.test');
  assert.equal(d.draft.config.username, 'john'); assert.equal(d.draft.config.auth_group, 'Ops');
  assert.equal(d.draft.config.server, 'https://vpn.test/');
});
test('vpn links decode plain and Qt-compressed Amnezia containers with bounded expansion', () => {
  const value = JSON.stringify({containers: [{awg: {last_config: JSON.stringify({config: '{"type":"direct","tag":"Wrapped"}'})}}]});
  const header = Buffer.alloc(4); header.writeUInt32BE(Buffer.byteLength(value));
  for (const payload of [Buffer.from(value), Buffer.concat([header, deflateSync(value)]), deflateSync(value)]) assert.equal(one('vpn://' + payload.toString('base64url')).draft.name, 'Wrapped');
  header.writeUInt32BE(maxImportBytes + 1); assert.equal(parse('vpn://' + Buffer.concat([header, deflateSync(value)]).toString('base64url'))[0].error, 'import_too_large');
  assert(parse('vpn://not-valid')[0].error);
});
test('AmneziaWG 3.1 container retains obfuscation fields, keys and boolean switches', () => {
  const key = Buffer.alloc(32, 7).toString('base64');
  const config = `[Interface]
Address = 10.10.0.2/32
PrivateKey = ${key}
DNS = 1.1.1.1
Jc = 4
Jmin = 10
Jmax = 50
S1 = 20
S2 = 30
S3 = 40
S4 = 50
H1 = 100-200
H2 = 201-300
H3 = 301-400
H4 = 401-500
I1 = <b 0x01234567>
ContentPaddingAddition = 16-32
HeaderProtectionKey = ${key}
RandomTrailers = on
[Peer]
PublicKey = ${key}
PresharedKey = ${key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 20-30
`;
  const value = JSON.stringify({ containers: [{ container: 'amnezia-awg', awg: { protocol_version: '3.1', last_config: JSON.stringify({ config }) } }] });
  const header = Buffer.alloc(4); header.writeUInt32BE(Buffer.byteLength(value));
  const result = one('vpn://' + Buffer.concat([header, deflateSync(value)]).toString('base64url'));
  assert.equal(result.draft.name, 'AmneziaWG');
  assert.deepEqual(result.draft.config.amnezia_wg, { jc: 4, jmin: 10, jmax: 50, s1: 20, s2: 30, s3: 40, s4: 50, h1: '100-200', h2: '201-300', h3: '301-400', h4: '401-500', i1: '<b 0x01234567>', content_padding_addition: '16-32', header_protection_key: key, random_trailers: true });
  assert.equal(result.draft.config.private_key, key);
  assert.deepEqual(result.draft.config.peers, [{ public_key: key, pre_shared_key: key, allowed_ips: ['0.0.0.0/0', '::/0'], address: '127.0.0.1', port: 51820, persistent_keepalive_interval: '20-30' }]);
  assert.deepEqual(result.warnings, ['wg-setting:DNS']);
});
test('Amnezia location comes from the container description, including Unicode and a leading flag', () => {
  const inner = JSON.stringify({ config: { type: 'socks', server: '127.0.0.1', server_port: 1080 } });
  const containers = [{ awg: { last_config: inner } }, { wireguard: { last_config: { config: JSON.parse(inner).config } } }];
  for (const description of ['🇳🇱 Нидерланды', '  Локация № 2  ']) {
    const content = JSON.stringify({ description, containers });
    const header = Buffer.alloc(4); header.writeUInt32BE(Buffer.byteLength(content));
    const rows = parse('vpn://' + Buffer.concat([header, deflateSync(content)]).toString('base64url'), 'Imported.json');
    assert.deepEqual(rows.map(r => r.draft.name), [description.trim(), description.trim()]);
    assert(rows.every(r => r.draft.config.server === '127.0.0.1'));
  }
  for (const description of [undefined, '', '  ', 123, {}]) {
    const row = one(JSON.stringify({ description, containers: containers.slice(0, 1) }), 'Fallback.json');
    assert.equal(row.draft.name, 'Fallback');
  }
});
test('malformed YAML and duplicate keys fail without leaking secrets', () => {
  for (const value of ['proxies: [', 'proxies: [{type: socks5, server: secret, server: other, port: 1}]', 'proxies: []']) { const r = parse(value); assert(r[0].error); assert(!JSON.stringify(r).includes('secret')); }
});

test('expanded vpn containers keep unique selectable rows in a mixed import', () => {
  const bundle = JSON.stringify([{type: 'direct', tag: 'one'}, {type: 'direct', tag: 'two'}]);
  const rows = parse('vpn://' + Buffer.from(bundle).toString('base64url') + '\nsocks://127.0.0.1:1080#three');
  assert.deepEqual(rows.map(r => r.index), [1, 2, 3]);
  assert.deepEqual(rows.map(r => r.draft.name), ['one', 'two', 'three']);
});

test('Clash Shadowsocks plugins, UDP over TCP and SIP008 follow Qt conversion', () => {
  const obfs = one('proxies: [{name: O, type: ss, server: vpn.test, port: 8388, cipher: aes-128-gcm, password: p, plugin: obfs, plugin-opts: {mode: http, host: cover.test}, udp-over-tcp: true}]');
  assert.equal(obfs.draft.config.plugin, 'obfs-local');
  assert.equal(obfs.draft.config.plugin_opts, 'obfs=http;obfs-host=cover.test');
  assert.deepEqual(obfs.draft.config.udp_over_tcp, { enabled: true });
  const v2 = one('proxies: [{name: V, type: ss, server: vpn.test, port: 8388, cipher: aes-128-gcm, password: p, plugin: v2ray-plugin, plugin-opts: {mode: websocket, tls: true, host: cover.test, path: /ws, mux: true}}]');
  assert.equal(v2.draft.config.plugin, 'v2ray-plugin');
  assert.equal(v2.draft.config.plugin_opts, 'tls;host=cover.test;path=/ws;mode=websocket;mux');
  const other = one('proxies: [{name: X, type: ss, server: vpn.test, port: 8388, cipher: aes-128-gcm, password: p, plugin: shadow-tls, plugin-opts: {host: cover.test}}]');
  assert.equal(other.draft.config.plugin, undefined);
  assert(other.warnings.includes('file:plugin'));
  const sip = parse(JSON.stringify({ version: 1, servers: [{ server: '192.0.2.1', server_port: 8388, method: 'aes-128-gcm', password: 'p', plugin: 'simple-obfs', plugin_opts: 'obfs=http', uot: { enabled: true }, multiplex: { enabled: true, protocol: 'smux' } }] }));
  assert.equal(sip[0].draft.config.plugin, 'obfs-local');
  assert.deepEqual(sip[0].draft.config.udp_over_tcp, { enabled: true });
  assert.deepEqual(sip[0].draft.config.multiplex, { enabled: true, protocol: 'smux' });
});

test('Clash VLESS through Xray keeps ws and grpc options, maps XHTTP extras and refuses a missing UUID', () => {
  const ws = one('proxies: [{name: W, type: vless, uuid: 11111111-1111-4111-8111-111111111111, server: vpn.test, port: 443, tls: true, encryption: mlkem768x25519plus.native.0rtt.fixture, network: ws, ws-opts: {path: /tunnel, headers: {Host: cdn.test}}, smux: {enabled: true}}]');
  const stream = ws.draft.config.streamSettings;
  assert.equal(stream.network, 'ws');
  assert.equal(stream.wsSettings.path, '/tunnel');
  assert(ws.warnings.includes('file:smux'));
  const grpc = one('proxies: [{name: G, type: vless, uuid: 11111111-1111-4111-8111-111111111111, server: vpn.test, port: 443, tls: true, encryption: mlkem768x25519plus.native.0rtt.fixture, network: grpc, grpc-opts: {grpc-service-name: svc}}]');
  assert.equal(grpc.draft.config.streamSettings.grpcSettings.serviceName, 'svc');
  const x = one('proxies: [{name: X, type: vless, uuid: 11111111-1111-4111-8111-111111111111, server: vpn.test, port: 443, tls: true, network: xhttp, xhttp-opts: {path: /x, no-grpc-header: true, future-option: 1}}]');
  const extra = x.draft.config.streamSettings.xhttpSettings.extra;
  assert.equal(extra.noGRPCHeader, true);
  assert.equal(extra['no-grpc-header'], undefined);
  assert(x.warnings.includes('file:xhttp-opts.future-option'));
  const missing = parse('proxies: [{name: M, type: vless, server: vpn.test, port: 443, tls: true, network: xhttp}]');
  assert(missing[0].error);
});

test('Clash TLS details on a plain proxy are reported instead of silently dropped', () => {
  const plain = one('proxies: [{name: P, type: vmess, server: vpn.test, port: 443, uuid: 11111111-1111-4111-8111-111111111111, alterId: 0, cipher: auto, servername: front.test, skip-cert-verify: true}]');
  assert.equal(plain.draft.config.tls, undefined);
  assert(plain.warnings.includes('file:servername'));
  assert(plain.warnings.includes('file:skip-cert-verify'));
});

test('one JSON kind decision: Xray inbounds make a full Xray configuration, a typed object stays an outbound', async () => {
  const { jsonKind } = await import('../src/profiles/import.ts');
  assert.equal(jsonKind({ inbounds: [{ protocol: 'socks' }], outbounds: [] }), 'xray-config');
  assert.equal(jsonKind({ outbounds: [{ type: 'direct' }] }), 'sing-box-config');
  assert.equal(jsonKind({ type: 'chain', hops: [] }), 'chain');
  assert.equal(jsonKind({ type: 'socks', server: '192.0.2.1' }), 'sing-box-outbound');
  assert.equal(jsonKind({ protocol: 'vless' }), 'xray-outbound');
  assert.equal(jsonKind({ name: 'nothing' }), undefined);
});
