import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { parseImport } from '../src/profiles/import.ts';
const keys = generateKeyPairSync('x25519');
export const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64');
const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
export const uuid = 'bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1';
const b64 = value => Buffer.from(value).toString('base64');
const urlKey = Buffer.from(publicKey, 'base64').toString('base64url');
export const links = {
  'hy2-bbr-finalmask': 'hysteria2://fixture@127.0.0.1:443?sni=example.test&fm=' + encodeURIComponent(JSON.stringify({ quicParams: { congestion: 'bbr', debug: false } })),
  'vless-ws-tls': `vless://${uuid}@127.0.0.1:443?security=tls&sni=example.test&type=ws&host=example.test&path=%2Fws%3Fed%3D2048&fp=chrome#VLESS`,
  'vless-reality': `vless://${uuid}@127.0.0.1:443?security=reality&sni=example.test&pbk=${urlKey}&fp=chrome&sid=ab12&flow=xtls-rprx-vision#Reality`,
  'vless-reality-spider': `vless://${uuid}@127.0.0.1:443?security=reality&sni=example.test&pbk=${urlKey}&fp=chrome&sid=ab12&spx=%2F&flow=xtls-rprx-vision#Reality`,
  'vless-xhttp': `vless://${uuid}@127.0.0.1:443?security=reality&sni=example.test&pbk=${urlKey}&fp=chrome&sid=ab12&type=xhttp&mode=stream-one&path=%2Ftest&extra=${encodeURIComponent(JSON.stringify({ xmux: { maxConcurrency: '4-8' } }))}#XHTTP`,
  'vless-raw-http': `vless://${uuid}@127.0.0.1:443?type=tcp&headerType=http&host=example.test&path=%2F#Raw`,
  'vless-grpc-gun': `vless://${uuid}@127.0.0.1:443?type=grpc&mode=gun&serviceName=tunnel&security=reality&sni=example.test&pbk=${urlKey}&fp=chrome&sid=ab12`,
  'vless-grpc-multi': `vless://${uuid}@127.0.0.1:443?type=grpc&mode=multi&serviceName=tunnel&authority=example.test&security=tls&sni=example.test`,
  'vmess-uri': `vmess://${uuid}@127.0.0.1:443?encryption=auto&type=grpc&serviceName=hello&security=tls&sni=example.test`,
  'vmess-base64': 'vmess://' + b64(JSON.stringify({ v: '2', ps: 'Русское имя', add: '127.0.0.1', port: '443', id: uuid, aid: '0', net: 'ws', host: 'example.test', path: '/test', tls: 'tls', sni: 'example.test', scy: 'auto' })),
  trojan: 'trojan://test-pass@127.0.0.1:443?security=tls&sni=example.test',
  anytls: 'anytls://test-pass@127.0.0.1:443?sni=example.test&idle_session_timeout=30&min_idle_session=2',
  'ss-sip002': 'ss://' + b64('chacha20-ietf-poly1305:long:test/password+') + '@127.0.0.1:443#Shadowsocks',
  'ss-legacy': 'ss://' + b64('chacha20-ietf-poly1305:long:test/password+@127.0.0.1:443') + '#Legacy',
  socks: 'socks://user:password@127.0.0.1:1080?uot=true',
  socks4: 'socks4://127.0.0.1:1080', socks4a: 'socks4a://127.0.0.1:1080', socks5: 'socks5://' + b64('user:password') + '@127.0.0.1:1080',
  http: 'http://user:password@127.0.0.1:80', https: 'https://user:password@127.0.0.1:443?sni=example.test',
  hysteria: 'hysteria://127.0.0.1:443?auth=test&upmbps=10&downmbps=10&peer=example.test',
  hysteria2: 'hysteria2://user%3Apassword@127.0.0.1:443?sni=example.test&obfs=salamander&obfs-password=test',
  'hy2-hopping': 'hy2://password@127.0.0.1:443,500-600?sni=example.test&hop_interval=10&quic_initial_packet_size=1250',
  tuic: `tuic://${uuid}:password@127.0.0.1:443?sni=example.test&congestion_control=bbr&udp_relay_mode=native`,
  juicity: `juicity://${uuid}:password@127.0.0.1:443?sni=example.test`,
  tt: 'tt://user:password@127.0.0.1:443?sni=example.test&health_check=true',
  shadowtls: 'shadowtls://:password@127.0.0.1:443?version=3&sni=example.test',
  ssh: 'ssh://127.0.0.1:22?user=test&password=password',
  snell: 'snell://test-psk@127.0.0.1:443?version=4&obfs=http&obfs-host=example.test',
  'snell-v6': 'snell://test-psk@127.0.0.1:443?version=6&mode=default',
  mierus: 'mierus://user:password@127.0.0.1?port=443&protocol=TCP&port=500-600&protocol=TCP&multiplexing=LOW',
  'naive-https': 'naive+https://user:password@127.0.0.1:443?sni=example.test',
  'naive-quic': 'naive+quic://user:password@127.0.0.1:443?sni=example.test&congestion_control=bbr',
  wireguard: `wireguard://${encodeURIComponent(privateKey)}@127.0.0.1:51820?public_key=${encodeURIComponent(publicKey)}&address=10.44.0.2%2F32&reserved=1-2-3&keepalive=25`,
  awg: `wg://${encodeURIComponent(privateKey)}@[::1]:51820?public_key=${encodeURIComponent(publicKey)}&address=10.44.0.2%2F32&jc=3&jmin=40&jmax=70&h1=1-100&h2=101-200&h3=201-300&h4=301-400&rekey_after_time=100-110&random_trailers=true`,
  'json-link': 'json://#' + Buffer.from(JSON.stringify({ type: 'socks', tag: 'JSON link', server: '127.0.0.1', server_port: 1080 })).toString('base64url'),
  'throne-link': 'throne://add/' + Buffer.from(JSON.stringify({ type: 'vless', tag: 'Throne', server: '127.0.0.1', server_port: 443, uuid })).toString('base64url'),
};
export const wgFile = `[Interface]\nPrivateKey = ${privateKey}\nAddress = 10.44.0.2/32, fd00::2/128\nJc = 3\nJmin = 40\nJmax = 70\nH1 = 1-100\nH2 = 101-200\nH3 = 201-300\nH4 = 301-400\nRekeyAfterTime = 100-110\nRandomTrailers = true\n[Peer]\nPublicKey = ${publicKey}\nEndpoint = [::1]:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n[Peer]\nPublicKey = ${publicKey}\nEndpoint = 127.0.0.1:51821\nAllowedIPs = ::/0\n`;
// Clash YAML with units, port ranges and bare-number intervals must reach the
// core as the types sing-box accepts.
links['clash-hysteria2-units'] = 'proxies: [{name: H2, type: hysteria2, server: 127.0.0.1, port: 443, password: test, sni: example.test, up: 30 Mbps, down: "12MBps", ports: "443,8000-9000", hop-interval: 30}]';
links['clash-hysteria-units'] = 'proxies: [{name: H1, type: hysteria, server: 127.0.0.1, port: 443, auth-str: test, sni: example.test, up: 100, down: "1 Gbps"}]';
links['clash-tuic-heartbeat'] = `proxies: [{name: T, type: tuic, server: 127.0.0.1, port: 443, uuid: ${uuid}, password: test, sni: example.test, heartbeat-interval: 10000}]`;
links['clash-anytls-intervals'] = 'proxies: [{name: A, type: anytls, server: 127.0.0.1, port: 443, password: test, sni: example.test, idle-session-check-interval: 30, idle-session-timeout: 45}]';
links['clash-ss-obfs'] = 'proxies: [{name: O, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: test, plugin: obfs, plugin-opts: {mode: http, host: example.test}, udp-over-tcp: true}]';
links['clash-ss-v2ray-plugin'] = 'proxies: [{name: V, type: ss, server: 127.0.0.1, port: 8388, cipher: aes-128-gcm, password: test, plugin: v2ray-plugin, plugin-opts: {mode: websocket, host: example.test, path: /ws}}]';
links['clash-vless-encryption-ws'] = `proxies: [{name: W, type: vless, uuid: ${uuid}, server: 127.0.0.1, port: 443, tls: true, servername: example.test, encryption: none, network: ws, ws-opts: {path: /tunnel, headers: {Host: example.test}}}]`;
links['trojan-ech-query-server-name'] = 'trojan://test@127.0.0.1:443?security=tls&sni=example.test&ech_enabled=1&ech_server_name=query.example.test#ECH';
links['throne-wg-link'] = 'throne://add/' + Buffer.from(JSON.stringify({ type: 'wireguard', private_key: privateKey, address: ['10.44.0.2/32'], worker_count: 2, peers: [{ address: '127.0.0.1', port: 51820, public_key: publicKey }] })).toString('base64url');
export function fixtures() {
  return [...Object.entries(links), ['awg-file-multi-peer', wgFile]].map(([name, input]) => {
    const rows = parseImport(input, 'personal');
    if (rows.length !== 1 || !rows[0].draft || rows[0].warnings.length) throw new Error(name + ': ' + JSON.stringify(rows));
    return { name: 'import-' + name, kind: rows[0].draft.kind, config: rows[0].draft.config };
  });
}
if (process.argv[1]?.endsWith('import-fixtures.mjs') && process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(fixtures(), null, 2));
