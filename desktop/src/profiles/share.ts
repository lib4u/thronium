import { linkTypes, parseLink, parseWireGuard, maxImportBytes } from './import.ts';
import {
  dialFields,
  echFields,
  multiplexFields,
  quicFields,
  tlsFields,
  transportFields,
  type UriField,
} from './uriFields.ts';
import { awgFields, type Config } from './schema.ts';
import { parseVpnPolicy } from './vpnPolicy.ts';
import { encodeText } from '../shared/base64.ts';
import { limits } from '../shared/api/generated/limits.ts';
import { allTraffic } from './wireguardDefaults.ts';
import { CodedError } from '../shared/api/errors.ts';
export type SharedProfile = import('../shared/api/generated/commands').ProfileExport;
export type ShareFormat = 'links' | 'throne-link' | 'thronium-link' | 'wireguard';
const enc = encodeURIComponent;
const fail = (code = 'share_unsupported'): never => {
  throw Error(code);
};
export const base64url = (text: string): string => encodeText(text, true);
function at(c: Config, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>((v, k) => (v && typeof v === 'object' ? (v as Config)[k] : undefined), c);
}
function host(value: unknown): string {
  if (typeof value !== 'string' || !value || /[\s/@?#[\]]/.test(value)) return fail('share_invalid_address');
  return value.includes(':') ? '[' + value + ']' : value;
}
function port(value: unknown): string {
  if (!Number.isInteger(value) || Number(value) < 1 || Number(value) > 65535)
    return fail('share_invalid_address');
  return String(value);
}
class Query {
  entries: string[] = [];
  add(key: string, value: unknown) {
    if (value !== undefined)
      this.entries.push(
        enc(key) + '=' + enc(typeof value === 'object' ? JSON.stringify(value) : String(value)),
      );
  }
  /** Writes the fields of `table` present in `c`, in table order. */
  fields(c: Config, table: readonly UriField[]) {
    for (const [path, key, kind] of table) {
      let v = at(c, path);
      if (kind === 'list' && Array.isArray(v)) v = v.join(',');
      this.add(key, v);
    }
  }
  map(c: Config, fields: Record<string, string>, lists = false) {
    for (const [path, key] of Object.entries(fields)) {
      let v = at(c, path);
      if (lists && Array.isArray(v)) v = v.join(',');
      this.add(key, v);
    }
  }
  toString() {
    return this.entries.length ? '?' + this.entries.join('&') : '';
  }
}
function differences(original: unknown, actual: unknown, prefix = ''): string[] {
  if (Array.isArray(original))
    return !Array.isArray(actual) || original.length !== actual.length
      ? [prefix]
      : original.flatMap((value, i) => differences(value, actual[i], `${prefix}[${i}]`));
  if (original && typeof original === 'object')
    return Object.entries(original).flatMap(([k, v]) =>
      !prefix && k === 'tag'
        ? []
        : differences(
            v,
            actual && typeof actual === 'object' ? (actual as Config)[k] : undefined,
            prefix ? prefix + '.' + k : k,
          ),
    );
  return JSON.stringify(original) === JSON.stringify(actual) ? [] : [prefix];
}
function requirePreserved(source: Config, imported: Config) {
  const missing = differences(source, imported);
  if (missing.length) throw new CodedError('share_fields', { fields: missing.slice(0, 8).join(', ') });
}
function tls(c: Config, q: Query) {
  const t = c.tls as Config | undefined;
  if (!t) return;
  q.add('security', t.enabled === false ? 'none' : at(t, 'reality.enabled') === true ? 'reality' : 'tls');
  q.map(t, { server_name: 'sni', insecure: 'allowInsecure' });
  q.fields(t, tlsFields);
  q.add('tls_tricks', typeof t.tls_tricks === 'boolean' ? t.tls_tricks : at(t, 'tls_tricks.mixedcase_sni'));
  // Preserve the explicit Off represented by old imported core JSON. The URI
  // needs a client switch because an empty URI value alone means Default.
  if (t.spoof_enabled === undefined && t.spoof === '') {
    // An active method without a spoof SNI is rejected by the core. Do not
    // silently turn that invalid source into a disabled, valid URI profile.
    if (t.spoof_method !== undefined && t.spoof_method !== '')
      throw new CodedError('share_fields', { fields: 'tls.spoof_method' });
    q.add('tls_spoof_enabled', false);
  }
  if (at(t, 'utls.enabled') === true) q.add('fp', at(t, 'utls.fingerprint'));
  if (at(t, 'reality.enabled') === true) q.map(t, { 'reality.public_key': 'pbk', 'reality.short_id': 'sid' });
  if (t.ech && typeof t.ech === 'object') q.fields(t.ech as Config, echFields);
}
function transport(c: Config, q: Query) {
  const t = c.transport as Config | undefined;
  if (!t) return;
  q.add('type', t.type);
  q.fields(t, transportFields);
  q.add('headers', t.headers);
  q.map(t, { host: 'host' }, true);
}
function common(c: Config, q: Query) {
  q.fields(c, dialFields);
  if (c.multiplex && typeof c.multiplex === 'object') q.fields(c.multiplex as Config, multiplexFields);
  q.fields(c, quicFields);
}
function xraySource(c: Config): Config {
  const result = structuredClone(c);
  const s = result.settings as Config;
  if (Array.isArray(s?.vnext)) {
    const next = s.vnext as Config[];
    const users = next[0]?.users as Config[];
    if (
      next.length !== 1 ||
      users?.length !== 1 ||
      Object.keys(s).some((k) => k !== 'vnext') ||
      Object.keys(next[0]).some((k) => !['address', 'port', 'users'].includes(k))
    )
      return fail('share_unsupported');
    result.settings = { address: next[0].address, port: next[0].port, ...users[0] };
  }
  if (at(result, 'streamSettings.network') === 'tcp') (result.streamSettings as Config).network = 'raw';
  return result;
}
function xrayLink(c: Config, q: Query): { address: unknown; port: unknown; user: string; source: Config } {
  const source = xraySource(c);
  const s = source.settings as Config,
    t = (source.streamSettings as Config) || {};
  if (c.protocol !== 'vless') return fail();
  q.add('encryption', s.encryption ?? 'none');
  q.add('flow', s.flow);
  q.add('type', t.network ?? 'raw');
  q.add('security', t.security ?? 'none');
  for (const key of ['tlsSettings', 'realitySettings']) {
    const secure = t[key] as Config | undefined;
    if (!secure) continue;
    q.map(secure, {
      serverName: 'sni',
      fingerprint: 'fp',
      allowInsecure: 'allowInsecure',
      pinnedPeerCertSha256: 'pcs',
      verifyPeerCertByName: 'vcn',
      password: 'pbk',
      publicKey: 'pbk',
      shortId: 'sid',
      spiderX: 'spx',
    });
    q.map(secure, { alpn: 'alpn' }, true);
    if (key === 'realitySettings' && secure.publicKey !== undefined && secure.password === undefined) {
      secure.password = secure.publicKey;
      delete secure.publicKey;
    }
  }
  const settings =
    (t[
      t.network === 'xhttp'
        ? 'xhttpSettings'
        : t.network === 'ws'
          ? 'wsSettings'
          : t.network === 'grpc'
            ? 'grpcSettings'
            : 'httpupgradeSettings'
    ] as Config) || {};
  q.map(settings, {
    host: 'host',
    path: 'path',
    mode: 'mode',
    extra: 'extra',
    serviceName: 'serviceName',
    authority: 'authority',
    headers: 'headers',
    maxEarlyData: 'ed',
    earlyDataHeaderName: 'eh',
  });
  if (t.network === 'grpc' && settings.multiMode !== undefined)
    q.add('mode', settings.multiMode ? 'multi' : 'gun');
  if (at(t, 'rawSettings.header.type') === 'http') {
    q.add('headerType', 'http');
    q.map(
      t,
      { 'rawSettings.header.request.path': 'path', 'rawSettings.header.request.headers.Host': 'host' },
      true,
    );
  }
  q.add('fm', t.finalmask);
  q.map(c, {
    'mux.enabled': 'mux',
    'mux.concurrency': 'mux_concurrency',
    'mux.xudpConcurrency': 'mux_xudp_concurrency',
  });
  q.add('heartbeat_period', settings.heartbeatPeriod);
  return { address: s.address, port: s.port, user: enc(String(s.id || '')), source };
}
export function nativeLink(profile: SharedProfile): string {
  if (profile.vpnPolicy != null) return fail('vpn_policy_export_requires_bundle');
  const c = profile.config,
    q = new Query();
  let source = c,
    scheme = String(c.type || ''),
    user = '',
    address = c.server,
    serverPort = c.server_port;
  if (profile.kind === 'xray-outbound') {
    const x = xrayLink(c, q);
    ({ source, address, user } = x);
    serverPort = x.port;
    scheme = 'vless';
  } else if (profile.kind !== 'sing-box-outbound') return fail();
  else if (c.type === 'wireguard') {
    const peers = c.peers as Config[];
    if (peers?.length !== 1) return fail('share_single_peer');
    const peer = peers[0];
    address = peer.address;
    serverPort = peer.port;
    scheme = 'wg';
    q.map(c, {
      private_key: 'private_key',
      mtu: 'mtu',
      workers: 'workers',
      system: 'use_system_interface',
      udp_timeout: 'udp_timeout',
    });
    q.map(c, { address: 'address' }, true);
    q.map(peer, {
      public_key: 'public_key',
      pre_shared_key: 'pre_shared_key',
      persistent_keepalive_interval: 'keepalive',
    });
    q.map(peer, { reserved: 'reserved', allowed_ips: 'allowed_ips' }, true);
    if (c.amnezia_wg) {
      q.add('enable_amnezia', true);
      for (const f of awgFields) q.add(f.path.split('.').slice(-1)[0], at(c, f.path));
    }
    common(c, q);
  } else {
    // A sing-box type exports as a link exactly when a link scheme imports it.
    if (!linkTypes.has(scheme)) return fail();
    tls(c, q);
    if (c.type !== 'mieru') transport(c, q);
    common(c, q);
    if (['vless', 'vmess'].includes(scheme)) {
      user = enc(String(c.uuid || ''));
      q.map(c, { flow: 'flow', packet_encoding: 'packetEncoding' });
      q.add('encryption', scheme === 'vless' ? 'none' : (c.security ?? 'auto'));
      q.map(c, {
        alter_id: 'alterId',
        global_padding: 'globalPadding',
        authenticated_length: 'authenticatedLength',
      });
    }
    if (['trojan', 'anytls'].includes(scheme)) user = enc(String(c.password || ''));
    if (['socks', 'http', 'tuic', 'juicity', 'trusttunnel', 'naive', 'mieru'].includes(scheme))
      user = enc(String(c.uuid ?? c.username ?? '')) + ':' + enc(String(c.password ?? ''));
    if (scheme === 'shadowsocks') {
      scheme = 'ss';
      user = String(c.method).startsWith('2022-')
        ? enc(String(c.method)) + ':' + enc(String(c.password))
        : base64url(String(c.method) + ':' + String(c.password));
      if (c.plugin) q.add('plugin', String(c.plugin) + (c.plugin_opts ? ';' + c.plugin_opts : ''));
    }
    if (scheme === 'hysteria2') {
      user = enc(String(c.password || ''));
      if (c.server_ports) {
        const ports = c.server_ports as string[];
        serverPort = Number(ports[0].split(':')[0]);
        q.add('mport', ports.map((p) => p.replace(':', '-')).join(','));
      }
      q.map(c, {
        'obfs.type': 'obfs',
        'obfs.password': 'obfs-password',
        up_mbps: 'upmbps',
        down_mbps: 'downmbps',
        hop_interval: 'hop_interval',
        hop_interval_max: 'hop_interval_max',
        bbr_profile: 'bbr_profile',
        disable_chrome_parrot: 'disable_chrome_parrot',
        'obfs.min_packet_size': 'min_packet_size',
        'obfs.max_packet_size': 'max_packet_size',
      });
      if (c.bbr_profile === 'standard' && c.up_mbps === 0 && c.down_mbps === 0)
        q.add('fm', { quicParams: { congestion: 'bbr' } });
    }
    if (scheme === 'hysteria')
      q.map(c, {
        auth_str: 'auth',
        up_mbps: 'upmbps',
        down_mbps: 'downmbps',
        obfs: 'obfsParam',
        recv_window_conn: 'recv_window_conn',
        recv_window: 'recv_window',
        disable_mtu_discovery: 'disable_mtu_discovery',
      });
    if (scheme === 'naive') scheme = at(c, 'quic') === true ? 'naive+quic' : 'naive+https';
    if (scheme === 'trusttunnel') {
      scheme = 'tt';
      // Qt's URI carries QUIC only through congestion_control; deep links select HTTP/3 alone.
      if (at(c, 'quic') === true) q.add('quic', true);
    }
    if (scheme === 'shadowtls') user = ':' + enc(String(c.password || ''));
    if (scheme === 'ssh') {
      q.map(c, {
        user: 'user',
        password: 'password',
        private_key_path: 'private_key_path',
        private_key_passphrase: 'private_key_passphrase',
        client_version: 'client_version',
      });
      if (Array.isArray(c.private_key)) q.add('private_key', base64url(c.private_key.join('\n')));
      for (const key of ['host_key', 'host_key_algorithms'])
        if (Array.isArray(c[key])) q.add(key, (c[key] as string[]).map((v) => encodeText(v)).join('-'));
    }
    q.map(c, {
      version: 'version',
      psk: 'psk',
      obfs_mode: 'obfs',
      obfs_host: 'obfs-host',
      mode: 'mode',
      reuse: 'reuse',
      path: 'path',
      headers: 'headers',
      idle_session_check_interval: 'idle_session_check_interval',
      idle_session_timeout: 'idle_session_timeout',
      min_idle_session: 'min_idle_session',
      congestion_control: 'congestion_control',
      udp_relay_mode: 'udp_relay_mode',
      zero_rtt_handshake: 'zero_rtt_handshake',
      heartbeat: 'heartbeat',
      health_check: 'health_check',
      quic_congestion_control: 'congestion_control',
      userkey: 'userkey',
      network: 'network',
      udp_over_stream: 'udp_over_stream',
    });
    if (c.udp_over_tcp !== undefined) {
      if (typeof c.udp_over_tcp === 'boolean') q.add('uot', c.udp_over_tcp);
      else {
        q.add('uot', at(c, 'udp_over_tcp.enabled'));
        q.add('uot_version', at(c, 'udp_over_tcp.version'));
      }
    }
    if (scheme === 'http' && at(c, 'tls.enabled') === true) scheme = 'https';
    if (scheme === 'mieru') {
      scheme = 'mierus';
      serverPort = c.server_port ?? 443;
      for (const value of [c.server_port, ...((c.server_ports as string[]) || [])])
        if (value !== undefined) {
          q.add('port', value);
          q.add('protocol', c.transport);
        }
      q.map(c, { traffic_pattern: 'traffic-pattern', multiplexing: 'multiplexing' });
    }
    if (scheme === 'snell') {
      user = enc(String(c.psk || ''));
      q.entries = q.entries.filter((v) => !v.startsWith('psk='));
    }
  }
  // Earlier Thronium URI imports stored this switch as a boolean. Export its
  // equivalent object form without changing the saved profile or other fields.
  if (profile.kind === 'sing-box-outbound' && typeof at(source, 'tls.tls_tricks') === 'boolean') {
    source = structuredClone(source);
    const tls = source.tls as Config;
    tls.tls_tricks = { mixedcase_sni: tls.tls_tricks };
  }
  const link = `${scheme}://${user ? user + '@' : ''}${host(address)}:${port(serverPort)}${scheme === 'ss' && c.plugin ? '/' : ''}${q}#${enc(profile.name)}`;
  let imported;
  try {
    imported = parseLink(link, 'share-check', profile.kind === 'xray-outbound');
  } catch {
    return fail();
  }
  if (imported.warnings.length)
    throw new CodedError('share_fields', { fields: imported.warnings.join(', ') });
  requirePreserved(source, imported.draft.config);
  return link;
}
export function wireguardFile(profile: SharedProfile): string {
  if (profile.vpnPolicy != null) return fail('vpn_policy_export_requires_bundle');
  const c = profile.config;
  if (profile.kind !== 'sing-box-outbound' || c.type !== 'wireguard') return fail('share_wireguard_only');
  const peers = c.peers as Config[];
  if (!peers?.length) return fail('share_single_peer');
  const lines = ['[Interface]'];
  function add(key: string, value: unknown) {
    if (value === undefined) return;
    const text = Array.isArray(value) ? value.join(', ') : String(value);
    if (!text || /[\r\n#;]/.test(text)) return fail('share_invalid_wireguard');
    lines.push(key + ' = ' + text);
  }
  add('PrivateKey', c.private_key);
  add('Address', c.address);
  add('ListenPort', c.listen_port);
  add('MTU', c.mtu);
  if (c.amnezia_wg)
    for (const f of awgFields) {
      const key = f.path.split('.').slice(-1)[0];
      add(
        key
          .split('_')
          .map((p) => p[0].toUpperCase() + p.slice(1))
          .join(''),
        at(c, f.path),
      );
    }
  for (const p of peers) {
    if (p.reserved !== undefined) throw new CodedError('share_fields', { fields: 'peers.reserved' });
    lines.push('', '[Peer]');
    add('PublicKey', p.public_key);
    add('PresharedKey', p.pre_shared_key);
    if (p.address !== undefined) add('Endpoint', host(p.address) + ':' + port(p.port));
    add('AllowedIPs', p.allowed_ips ?? allTraffic());
    add('PersistentKeepalive', p.persistent_keepalive_interval);
  }
  const text = lines.join('\n') + '\n';
  let restored;
  try {
    restored = parseWireGuard(text, 'share-check', profile.name);
  } catch {
    return fail('share_invalid_wireguard');
  }
  if (restored.warnings.length) return fail('share_unsupported');
  // A .conf file has no place for the sing-box interface options; a set one
  // is refused like any other field the format would lose.
  const expected = { ...c };
  for (const k of ['system', 'workers', 'udp_timeout']) {
    if (expected[k] !== undefined && expected[k] !== false && expected[k] !== 0 && expected[k] !== '')
      throw new CodedError('share_fields', { fields: k });
    delete expected[k];
  }
  requirePreserved(expected, restored.draft.config);
  return text;
}
/**
 * Qt's `ExportJsonLink`: the outbound as Throne itself shares it, named by its
 * tag. It carries the whole configuration, so it is the export for profiles no
 * protocol URI can describe.
 */
function throneLink(profile: SharedProfile): string {
  if (profile.vpnPolicy != null) return fail('vpn_policy_export_requires_bundle');
  if (profile.kind !== 'sing-box-outbound' && profile.kind !== 'xray-outbound') return fail();
  return 'throne://add/' + base64url(JSON.stringify({ ...profile.config, tag: profile.name }));
}
export function profileBundle(profiles: SharedProfile[]) {
  return {
    format: 'thronium-profiles',
    version: profiles.some((p) => p.vpnPolicy != null) ? 2 : 1,
    profiles: profiles.map(({ name, kind, config, reference, vlessCore, vpnPolicy }) => ({
      name,
      kind,
      config,
      ...(reference ? { reference } : {}),
      ...(vlessCore ? { vlessCore } : {}),
      ...(vpnPolicy != null ? { vpnPolicy: parseVpnPolicy(vpnPolicy, { kind, config }) } : {}),
    })),
  };
}
export function shareProfiles(profiles: SharedProfile[], format: ShareFormat): string {
  if (!profiles.length || profiles.length > limits.maxBatchProfiles) return fail('invalid_profile_selection');
  if (profiles.some((p) => p.kind === 'external-core')) return fail('external_export_format');
  let result: string;
  if (format === 'thronium-link')
    result = 'thronium://profiles/' + base64url(JSON.stringify(profileBundle(profiles)));
  else if (format === 'wireguard') {
    if (profiles.length !== 1) return fail('share_wireguard_only');
    result = wireguardFile(profiles[0]);
  } else if (format === 'throne-link') result = profiles.map(throneLink).join('\n');
  // Qt silently shares a JSON link for what its URI formats cannot carry; here
  // the URI format stays all or nothing and the JSON link is its own choice.
  else result = profiles.map(nativeLink).join('\n');
  if (new TextEncoder().encode(result).length > maxImportBytes) return fail('export_too_large');
  return result;
}
