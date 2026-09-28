// Non-secret, disposable fixtures built with the same field serializer as the UI.
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { definitions, sections, parse, set } from '../src/profiles/schema.ts';
const keys = generateKeyPairSync('x25519');
const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('base64');
const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
const uuid = 'bf422fe4-1a5c-4b64-bc33-43c18a1b9dd1';
const fixtures = [];
// External cores need a real executable path and are accepted by their own Core tests.
for (const def of definitions.filter(d => !d.id.startsWith('custom') && !['chain', 'auto-selector', 'external-core'].includes(d.kind))) {
  let config = structuredClone(def.seed);
  const values = { server: def.id === 'openconnect' ? 'https://127.0.0.1/' : '127.0.0.1', server_port: '443', 'settings.address': '127.0.0.1', 'settings.port': '443', 'settings.id': uuid, uuid, username: 'test', user: 'test', password: 'test-password', private_key: privateKey, address: '10.44.0.2/32', psk: privateKey, auth_str: 'test-auth', method: 'chacha20-ietf-poly1305' };
  if (def.id === 'direct') {
    const mark = sections(def, config).flatMap(s => s.fields).find(f => f.path === 'routing_mark');
    config = set(config, mark.path, parse(mark, '0xff'));
  }
  if (def.id === 'ssh') delete values.private_key;
  for (const field of sections(def, config)[0].fields) if (Object.hasOwn(values, field.path)) config = set(config, field.path, parse(field, values[field.path]));
  if (def.id === 'wireguard' || def.id === 'amneziawg') config.peers = [{ address: '127.0.0.1', port: 51820, public_key: publicKey, allowed_ips: ['0.0.0.0/0'] }];
  if (def.id === 'openvpn') config.tls.peer_fingerprint = ['ab'.repeat(32)];
  if (def.id === 'hysteria') { config.up_mbps = 10; config.down_mbps = 10; }
  if (def.id === 'amneziawg') config.amnezia_wg = { jc: 3, jmin: 40, jmax: 70, s1: 0, s2: 0, h1: '1-100', h2: '101-200', h3: '201-300', h4: '301-400', rekey_after_time: '100-110', random_trailers: true };
  fixtures.push({ name: def.id, kind: def.kind, config });
}
for (const type of ['http', 'ws', 'grpc', 'httpupgrade', 'quic']) {
  const def = definitions.find(d => d.id === 'vless');
  let config = { ...fixtures.find(f => f.name === 'vless').config, transport: { type } };
  const values = { 'transport.path': '/test', 'transport.host': 'example.test', 'transport.service_name': 'test' };
  for (const field of sections(def, config).find(s => s.id === 'transport').fields) if (Object.hasOwn(values, field.path)) config = set(config, field.path, parse(field, values[field.path]));
  if (type === 'quic') config.tls = { enabled: true };
  fixtures.push({ name: `vless-${type}`, kind: def.kind, config });
}
fixtures.push({ name: 'xray-xhttp-reality', kind: 'xray-outbound', config: { ...fixtures.find(f => f.name === 'xrayvless').config, streamSettings: { network: 'xhttp', security: 'reality', realitySettings: { serverName: 'example.test', fingerprint: 'chrome', password: Buffer.from(publicKey, 'base64').toString('base64url'), shortId: 'ab12' }, xhttpSettings: { path: '/test', mode: 'stream-one', extra: { xmux: { maxConcurrency: '4-8' } } } } } });
// Rare editor fields: endpoint UDP NAT, OpenVPN TLS extras and LZO, QUIC timers,
// written through the same field serializer so the core sees the form's own values.
const rare = (name, values, patch = {}) => {
  const def = definitions.find(d => d.id === name);
  let config = { ...structuredClone(fixtures.find(f => f.name === name).config), ...patch };
  for (const section of sections(def, config)) for (const field of section.fields) if (Object.hasOwn(values, field.path)) config = set(config, field.path, parse(field, values[field.path]));
  fixtures.push({ name: `${name}-rare-fields`, kind: def.kind, config });
};
rare('wireguard', { udp_mapping: 'address_dependent', udp_filtering: 'endpoint_independent', udp_nat_max: '1024' });
// The pinned core refuses remote_certificate_eku next to the seed's remote_certificate_tls.
rare('openvpn', { udp_mapping: 'address_and_port_dependent', udp_filtering: 'address_dependent', udp_nat_max: '512', compression_lzo: 'no', 'tls.certificate_profile': 'preferred', 'tls.ns_certificate_type': 'server', 'tls.version_min': '1.2', 'tls.version_max': '1.3' });
rare('openconnect', { udp_mapping: 'endpoint_independent', udp_filtering: 'address_and_port_dependent', udp_nat_max: '256' });
rare('hysteria2', { idle_timeout: '30s', keep_alive_period: '10s' });
rare('tuic', { idle_timeout: '45s', keep_alive_period: '15s' });
writeFileSync(process.argv[2], JSON.stringify(fixtures, null, 2));
