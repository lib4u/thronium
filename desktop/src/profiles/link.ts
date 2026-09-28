// URI mappings follow upstream src/configs/outbounds and src/configs/common.
import type { Draft, Kind } from '../api';
import type { Config } from './schema.ts';
import { decodeTrustTunnelLink, isTrustTunnelDeepLink } from './trusttunnelLink.ts';
import { allTraffic } from './wireguardDefaults.ts';
import {
  fail,
  object,
  unescape,
  number,
  boolean,
  list,
  duration,
  pair,
  decodeBase64,
  Query,
  assign,
  headers,
  tls,
  transport,
  mux,
  dial,
  quic,
  draft,
} from './importValues.ts';
import { xray, wgQuery, vmessJson, hysteriaBBR } from './linkProtocols.ts';
import { jsonDraft } from './importJson.ts';

const schemes: Record<string, string> = {
  vless: 'vless',
  vmess: 'vmess',
  trojan: 'trojan',
  anytls: 'anytls',
  ss: 'shadowsocks',
  socks: 'socks',
  socks4: 'socks',
  socks4a: 'socks',
  socks5: 'socks',
  http: 'http',
  https: 'http',
  hysteria: 'hysteria',
  hysteria2: 'hysteria2',
  hy2: 'hysteria2',
  tuic: 'tuic',
  juicity: 'juicity',
  tt: 'trusttunnel',
  trusttunnel: 'trusttunnel',
  snell: 'snell',
  mieru: 'mieru',
  mierus: 'mieru',
  'naive+https': 'naive',
  'naive+quic': 'naive',
  shadowtls: 'shadowtls',
  ssh: 'ssh',
  wg: 'wireguard',
  wireguard: 'wireguard',
  awg: 'wireguard',
};
/** sing-box outbound types some link scheme imports. */
export const linkTypes: ReadonlySet<string> = new Set(Object.values(schemes));

export function parseLink(
  input: string,
  groupId: string,
  preferXray = false,
): { draft: Draft; warnings: string[] } {
  const scheme = input.split(':', 1)[0].toLowerCase();
  if (scheme === 'vmess' && !input.slice(8).split('#')[0].includes('@')) return vmessJson(input, groupId);
  if (scheme === 'tt' && isTrustTunnelDeepLink(input)) {
    const link = decodeTrustTunnelLink(input);
    return { draft: draft(link.config, groupId, link.name), warnings: link.warnings };
  }
  if (scheme === 'throne' || scheme === 'json') {
    const encoded =
      scheme === 'throne' ? input.match(/^throne:\/\/add\/([^?#]+)/i)?.[1] : input.split('#')[1];
    if (!encoded) return fail('unsupported_link');
    const config = object(JSON.parse(decodeBase64(unescape(encoded))));
    // Throne's WireGuard JSON links omit allowed_ips; Peer::Build adds these routes.
    if (config.type === 'wireguard' && Array.isArray(config.peers)) {
      config.peers = config.peers.map((p) => ({
        ...object(p),
        allowed_ips: object(p).allowed_ips ?? allTraffic(),
      }));
      if (config.worker_count !== undefined && config.workers === undefined) {
        config.workers = config.worker_count;
        delete config.worker_count;
      }
    }
    return { draft: jsonDraft(config, groupId), warnings: [] };
  }
  const type = Object.prototype.hasOwnProperty.call(schemes, scheme) ? schemes[scheme] : undefined;
  if (!type) return fail('unsupported_link');
  let text = input;
  if (type === 'shadowsocks' && !input.split('#')[0].includes('@')) {
    const [raw, fragment] = input.slice(5).split('#');
    const decoded = decodeBase64(raw);
    const at = decoded.lastIndexOf('@');
    if (at < 0) return fail('invalid_link');
    const [method, password] = pair(decoded.slice(0, at));
    text =
      'ss://' +
      encodeURIComponent(method) +
      ':' +
      encodeURIComponent(password) +
      decoded.slice(at) +
      (fragment ? '#' + fragment : '');
  }
  // Parse a neutral scheme so HTTP's default-port normalization cannot lose :80.
  const match = text.match(/^[^:]+:\/\/(.*?)(?:\?(.*?))?(?:#(.*))?$/s);
  if (!match) return fail('invalid_link');
  let authority = match[1].replace(/\/$/, '');
  const q = new Query(match[2] || '');
  const name = match[3] ? unescape(match[3]) : '';
  let portRanges: string | undefined;
  if (type.startsWith('hysteria')) {
    const m = authority.match(/:([\d,:-]+)$/);
    if (m && /[-,]/.test(m[1])) {
      portRanges = m[1];
      authority = authority.slice(0, -m[0].length);
    }
  }
  const userEnd = authority.lastIndexOf('@');
  if (userEnd >= 0) authority = authority.slice(0, userEnd).replace(/\//g, '%2F') + authority.slice(userEnd);
  let url: URL;
  try {
    url = new URL('proxy://' + authority);
  } catch {
    return fail('invalid_link');
  }
  if (!url.hostname) return fail('invalid_link');
  if (url.pathname && url.pathname !== '/')
    return fail(type === 'http' && !url.username && !url.password ? 'subscription_link' : 'invalid_link');
  const server = url.hostname.replace(/^\[|\]$/g, '');
  const port = url.port
    ? number(url.port, 65535, 1)
    : type === 'socks'
      ? 1080
      : type === 'ssh'
        ? 22
        : type === 'wireguard'
          ? 51820
          : 443;
  let username = unescape(url.username),
    password = unescape(url.password);
  if (['socks', 'http', 'shadowsocks'].includes(type) && !password && username) {
    try {
      const decoded = decodeBase64(username);
      if (decoded.includes(':')) [username, password] = pair(decoded);
    } catch {
      if (type === 'shadowsocks') return fail('invalid_base64');
    }
  }
  let config: Config = { type, server, server_port: port };
  let kind: Kind = 'sing-box-outbound';
  const needXray =
    type === 'vless' &&
    (preferXray ||
      ['pcs', 'vcn', 'heartbeat_period', 'mux_concurrency', 'mux_xudp_concurrency'].some((k) =>
        q.values.has(k),
      ) ||
      ['xhttp', 'splithttp'].includes(q.values.get('type')?.[0] || '') ||
      (q.values.get('type')?.[0] === 'grpc' && q.values.has('mode')) ||
      (q.values.get('security')?.[0] === 'reality' && q.values.has('spx')) ||
      q.values.has('fm') ||
      q.values.has('finalmask') ||
      q.values.has('extra') ||
      !['', 'none'].includes(q.values.get('encryption')?.[0] || '') ||
      q.values.get('headerType')?.[0] === 'http');
  if (needXray) {
    config = xray(q, server, port, username);
    kind = 'xray-outbound';
  } else if (type === 'wireguard') config = wgQuery(q, server, port, username);
  else {
    if (['vless', 'vmess', 'tuic', 'juicity'].includes(type)) {
      if (!username) return fail('missing_credentials');
      config.uuid = username;
    }
    if (['trojan', 'anytls'].includes(type)) config.password = username;
    if (['tuic', 'juicity', 'naive', 'trusttunnel', 'socks', 'http', 'mieru'].includes(type)) {
      config.password = password;
      if (!['tuic', 'juicity'].includes(type)) config.username = username;
    }
    if (type === 'http' && !username && password) config.username = password;
    if (type === 'socks')
      config.version = q.get('version') || (scheme === 'socks4a' ? '4a' : scheme === 'socks4' ? '4' : '5');
    if (type === 'shadowsocks') {
      if (!username || !password) return fail('missing_credentials');
      config.method = username;
      config.password = password;
      const plugin = q.get('plugin');
      if (plugin) {
        const i = plugin.indexOf(';');
        config.plugin = (i < 0 ? plugin : plugin.slice(0, i)).replace(/^simple-obfs$/, 'obfs-local');
        if (i >= 0) config.plugin_opts = plugin.slice(i + 1);
      }
      assign(config, q, { 'plugin-opts': 'plugin_opts' });
    }
    if (['http', 'socks', 'shadowsocks', 'naive'].includes(type)) {
      const uot = q.get('uot');
      if (uot !== undefined) config.udp_over_tcp = { enabled: /^(true|[1-9]\d*)$/.test(uot) };
      const version = q.get('uot_version');
      if (version !== undefined) {
        config.udp_over_tcp ||= {};
        (config.udp_over_tcp as Config).version = number(version, 2, 1);
      }
    }
    if (['vless', 'vmess'].includes(type)) {
      assign(config, q, { flow: 'flow', packetEncoding: 'packet_encoding' });
      if (type === 'vless') {
        q.get('encryption');
        config.packet_encoding ??= 'xudp';
      } else {
        config.security = q.get('encryption') || 'auto';
        assign(config, q, { alterId: 'alter_id' }, (s) => number(s));
        assign(
          config,
          q,
          { globalPadding: 'global_padding', authenticatedLength: 'authenticated_length' },
          boolean,
        );
      }
      if (config.packet_encoding === 'none') config.packet_encoding = '';
    }
    if (['vless', 'vmess', 'trojan'].includes(type)) {
      const trans = transport(q);
      if (trans) config.transport = trans;
    }
    if (['vless', 'vmess', 'trojan', 'shadowsocks'].includes(type)) {
      const multi = mux(q);
      if (multi) config.multiplex = multi;
    }
    if (
      [
        'vless',
        'vmess',
        'trojan',
        'anytls',
        'hysteria',
        'hysteria2',
        'tuic',
        'juicity',
        'naive',
        'trusttunnel',
        'shadowtls',
        'http',
      ].includes(type)
    ) {
      const secure = tls(q, !['vless', 'vmess', 'http'].includes(type) || scheme === 'https');
      if (secure) config.tls = secure;
    }
    if (type.startsWith('hysteria')) {
      const ports = q.get('mport') || portRanges;
      if (ports) {
        config.server_ports = list(ports).map((p) => (/[-:]/.test(p) ? p.replace(/-/g, ':') : p + ':' + p));
        delete config.server_port;
      }
      assign(config, q, { upmbps: 'up_mbps', downmbps: 'down_mbps' }, (s) => number(s));
      assign(config, q, { hop_interval: 'hop_interval', hop_interval_max: 'hop_interval_max' }, duration);
      if (type === 'hysteria') {
        assign(config, q, { auth: 'auth_str', obfsParam: 'obfs' });
        assign(config, q, { recv_window_conn: 'recv_window_conn', recv_window: 'recv_window' }, (s) =>
          number(s),
        );
        assign(config, q, { disable_mtu_discovery: 'disable_mtu_discovery' }, boolean);
      } else {
        config.password = username + (password ? ':' + password : '');
        const obfsPassword = q.get('obfs-password');
        const obfsType = q.get('obfs');
        if (obfsPassword || obfsType) {
          const obfs: Config = {
            type: obfsType || (q.values.has('min_packet_size') ? 'gecko' : 'salamander'),
            password: obfsPassword || '',
          };
          assign(obfs, q, { min_packet_size: 'min_packet_size', max_packet_size: 'max_packet_size' }, (s) =>
            number(s),
          );
          config.obfs = obfs;
        }
        assign(config, q, { bbr_profile: 'bbr_profile' });
        assign(config, q, { disable_chrome_parrot: 'disable_chrome_parrot' }, boolean);
        hysteriaBBR(config, q);
      }
    }
    if (['hysteria', 'hysteria2', 'tuic'].includes(type)) quic(config, q);
    if (type === 'tuic') {
      assign(config, q, {
        congestion_control: 'congestion_control',
        udp_relay_mode: 'udp_relay_mode',
        heartbeat: 'heartbeat',
      });
      assign(
        config,
        q,
        { udp_over_stream: 'udp_over_stream', zero_rtt_handshake: 'zero_rtt_handshake' },
        boolean,
      );
    }
    if (type === 'anytls') {
      assign(
        config,
        q,
        {
          idle_session_check_interval: 'idle_session_check_interval',
          idle_session_timeout: 'idle_session_timeout',
        },
        duration,
      );
      assign(config, q, { min_idle_session: 'min_idle_session' }, (s) => number(s));
    }
    if (['naive', 'trusttunnel'].includes(type)) {
      if (scheme === 'naive+quic') config.quic = true;
      assign(config, q, { quic: 'quic' }, boolean);
      const cc = q.get('congestion_control');
      if (cc) {
        config.quic = true;
        config.quic_congestion_control = cc;
      }
      assign(config, q, { health_check: 'health_check' }, boolean);
    }
    if (type === 'shadowtls') {
      config.password = password || username;
      config.version = number(q.get('version') || '3');
    }
    if (type === 'snell') {
      config.psk = q.get('psk') || username;
      config.version = number(q.get('version') || '4');
      if (![4, 6].includes(config.version as number)) return fail('unsupported_version');
      assign(config, q, {
        userkey: 'userkey',
        network: 'network',
        obfs: 'obfs_mode',
        'obfs-host': 'obfs_host',
        mode: 'mode',
      });
      const reuse = q.get('reuse');
      if (reuse !== undefined) config.reuse = reuse === '' || boolean(reuse);
    }
    if (type === 'http') {
      assign(config, q, { path: 'path' });
      const h = q.get('headers');
      if (h) config.headers = headers(h);
    }
    if (type === 'ssh') {
      config.user = q.get('user') || username;
      config.password = q.get('password') || password;
      assign(config, q, {
        private_key_path: 'private_key_path',
        private_key_passphrase: 'private_key_passphrase',
        client_version: 'client_version',
      });
      const key = q.get('private_key');
      if (key) config.private_key = decodeBase64(key).split('\n');
      for (const key of ['host_key', 'host_key_algorithms']) {
        const value = q.get(key);
        if (value) config[key] = list(value, '-').map(decodeBase64);
      }
    }
    if (type === 'mieru') {
      const protocols = q.all('protocol');
      const ports = q.all('port');
      if (!ports.length) return fail('missing_port');
      config.transport = (protocols[0] || 'TCP').toUpperCase();
      if (protocols.some((p) => p.toUpperCase() !== config.transport)) return fail('mixed_mieru_transports');
      delete config.server_port;
      const ranges: string[] = [];
      for (const value of ports)
        if (value.includes('-')) ranges.push(value);
        else if (config.server_port === undefined) config.server_port = number(value, 65535, 1);
        else ranges.push(value + '-' + value);
      if (ranges.length) config.server_ports = ranges;
      assign(config, q, { 'traffic-pattern': 'traffic_pattern' });
      const level = q.get('multiplexing');
      if (level)
        config.multiplexing = level.toUpperCase().startsWith('MULTIPLEXING_')
          ? level.toUpperCase()
          : 'MULTIPLEXING_' + level.toUpperCase();
    }
  }
  if (kind === 'sing-box-outbound') dial(config, q);
  return { draft: draft(config, groupId, name, kind), warnings: q.warnings() };
}
