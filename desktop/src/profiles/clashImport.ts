import type { Config } from './schema';
import { jsonDraft, parseLink } from './import.ts';
import { allTraffic } from './wireguardDefaults.ts';

const obj = (v: unknown): Config =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Config) : {};
const has = (v: Config, k: string) => Object.prototype.hasOwnProperty.call(v, k);
/**
 * Clash bandwidth ("30 Mbps", "100", "12MBps", "500 Kbps") as whole Mbit/s for
 * sing-box `up_mbps`/`down_mbps`. A bare number is already Mbit/s, as in Qt's
 * anyToMbps; unlike Qt, a lowercase "b" stays bits and only "B" means bytes.
 */
function clashMbps(value: unknown): number | undefined {
  const match = /^\s*(\d+(?:\.\d+)?)\s*(?:([kmgt])?(b)?(?:ps)?)?\s*$/i.exec(String(value ?? ''));
  if (!match) return undefined;
  // A bare number is Mbit/s; a unit without a prefix ("bps") is per second.
  const prefix = match[2]?.toLowerCase();
  const scale = prefix ? { k: 0.001, m: 1, g: 1000, t: 1_000_000 }[prefix]! : match[3] ? 0.000001 : 1;
  const mbps = Number(match[1]) * scale * (match[3] === 'B' ? 8 : 1);
  return mbps > 0 ? Math.max(1, Math.round(mbps)) : undefined;
}
/** Clash "443,8000-9000" (or "/"-separated) as sing-box ranges, as Qt portsToPorts. */
function clashPorts(value: unknown): string[] | undefined {
  const ranges = String(value ?? '')
    .split(/[,/]/)
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => part.split(/[:-]/));
  const valid = (port: string) => /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
  if (!ranges.length || ranges.some((range) => range.length > 2 || !range.every(valid))) return undefined;
  return ranges.map(([from, to = from]) => `${from}:${to}`);
}
/** Clash intervals are bare numbers in a fixed unit; sing-box needs a duration string. */
function clashDuration(value: unknown, unit: 'ms' | 's'): string | undefined {
  const text = String(value ?? '').trim();
  if (/^\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h)$/.test(text)) return text;
  const amount = Number(text);
  return text && Number.isFinite(amount) && amount > 0 ? `${amount}${unit}` : undefined;
}
/** Clash `xhttp-opts` keys and their Xray `extra` names. */
const XHTTP_EXTRA: Record<string, string> = {
  headers: 'headers',
  'no-grpc-header': 'noGRPCHeader',
  'x-padding-bytes': 'xPaddingBytes',
  'sc-max-each-post-bytes': 'scMaxEachPostBytes',
  'sc-min-posts-interval-ms': 'scMinPostsIntervalMs',
};
/**
 * Clash plugins and their options become sing-box plugin names and SIP003
 * option strings exactly as Qt's shadowsocks::ParseFromClash builds them.
 */
function shadowsocksPlugin(p: Config, c: Config, used: Set<string>, warnings: string[]) {
  for (const key of ['plugin', 'plugin-opts', 'udp-over-tcp']) used.add(key);
  if (p['udp-over-tcp'] === true) c.udp_over_tcp = { enabled: true };
  if (!p.plugin) return;
  const opts = obj(p['plugin-opts']);
  const parts: string[] = [];
  if (p.plugin === 'v2ray-plugin') {
    if (opts.tls === true) parts.push('tls');
    if (opts.host) parts.push(`host=${opts.host}`);
    if (opts.path) parts.push(`path=${opts.path}`);
    if (opts.mode) parts.push(`mode=${opts.mode}`);
    if (opts.mux === true) parts.push('mux');
    c.plugin = 'v2ray-plugin';
  } else if (p.plugin === 'obfs') {
    if (opts.mode) parts.push(`obfs=${opts.mode}`);
    if (opts.host) parts.push(`obfs-host=${opts.host}`);
    c.plugin = 'obfs-local';
  } else {
    warnings.push('file:plugin');
    return;
  }
  if (parts.length) c.plugin_opts = parts.join(';');
}
export function clashProfile(value: unknown, group: string) {
  const p = obj(value);
  const type = String(p.type);
  const supported: Record<string, string> = {
    ss: 'shadowsocks',
    socks5: 'socks',
    http: 'http',
    vmess: 'vmess',
    vless: 'vless',
    trojan: 'trojan',
    anytls: 'anytls',
    hysteria: 'hysteria',
    hysteria2: 'hysteria2',
    tuic: 'tuic',
    snell: 'snell',
    ssh: 'ssh',
    wireguard: 'wireguard',
  };
  if (
    !has(supported, type) ||
    typeof p.server !== 'string' ||
    !Number.isInteger(Number(p.port)) ||
    Number(p.port) < 1 ||
    Number(p.port) > 65535
  )
    throw new Error('invalid_yaml');
  const used = new Set(['type', 'name', 'server', 'port', 'udp']);
  const warnings: string[] = [];
  const c: Config = { type: supported[type], server: p.server, server_port: Number(p.port) };
  const take = (key: string, target: string, dst = c) => {
    used.add(key);
    if (has(p, key)) dst[target] = p[key];
  };
  // A value that cannot be expressed for sing-box is reported, never copied raw.
  const convert = (key: string, target: string, parse: (value: unknown) => unknown) => {
    used.add(key);
    if (!has(p, key)) return;
    const value = parse(p[key]);
    if (value === undefined) warnings.push('file:' + key);
    else c[target] = value;
  };
  const fields: Record<string, Record<string, string>> = {
    ss: { cipher: 'method', password: 'password' },
    socks5: { username: 'username', password: 'password' },
    http: { username: 'username', password: 'password' },
    vmess: { uuid: 'uuid', alterId: 'alter_id', cipher: 'security', 'packet-encoding': 'packet_encoding' },
    vless: { uuid: 'uuid', flow: 'flow', 'packet-encoding': 'packet_encoding' },
    trojan: { password: 'password' },
    anytls: {
      password: 'password',
      'min-idle-session': 'min_idle_session',
    },
    snell: { psk: 'psk', version: 'version' },
    hysteria: {
      'auth-str': 'auth_str',
      auth: 'auth',
      obfs: 'obfs',
      'recv-window-conn': 'recv_window_conn',
      'recv-window': 'recv_window',
      'disable-mtu-discovery': 'disable_mtu_discovery',
    },
    hysteria2: {
      password: 'password',
    },
    tuic: {
      uuid: 'uuid',
      password: 'password',
      'congestion-controller': 'congestion_control',
      'udp-relay-mode': 'udp_relay_mode',
      'reduce-rtt': 'zero_rtt_handshake',
    },
    ssh: {
      username: 'user',
      password: 'password',
      'private-key': 'private_key',
      'private-key-passphrase': 'private_key_passphrase',
    },
  };
  for (const [key, target] of Object.entries(fields[type] || {})) take(key, target);
  if (type === 'hysteria' || type === 'hysteria2') {
    convert('up', 'up_mbps', clashMbps);
    convert('down', 'down_mbps', clashMbps);
    convert('ports', 'server_ports', clashPorts);
    // Port hopping replaces the single port, as in the link importer, so the
    // profile has one shape whether it came from Clash or a hy2:// link.
    if (c.server_ports) delete c.server_port;
  }
  if (type === 'hysteria2') convert('hop-interval', 'hop_interval', (v) => clashDuration(v, 's'));
  if (type === 'tuic') convert('heartbeat-interval', 'heartbeat', (v) => clashDuration(v, 'ms'));
  if (type === 'anytls') {
    convert('idle-session-check-interval', 'idle_session_check_interval', (v) => clashDuration(v, 's'));
    convert('idle-session-timeout', 'idle_session_timeout', (v) => clashDuration(v, 's'));
  }
  if (type === 'ss') shadowsocksPlugin(p, c, used, warnings);
  if (type === 'hysteria2' && has(p, 'obfs')) {
    used.add('obfs');
    used.add('obfs-password');
    c.obfs = { type: p.obfs, password: p['obfs-password'] };
  }
  if (type === 'socks5') c.version = '5';
  if (type === 'wireguard') {
    for (const k of ['private-key', 'public-key', 'pre-shared-key', 'ip', 'ipv6', 'mtu', 'reserved'])
      used.add(k);
    delete c.server;
    delete c.server_port;
    c.private_key = p['private-key'];
    c.address = [p.ip, p.ipv6]
      .filter(Boolean)
      .map((v) => (String(v).includes('/') ? v : String(v) + (String(v).includes(':') ? '/128' : '/32')));
    if (p.mtu) c.mtu = p.mtu;
    c.peers = [
      {
        address: p.server,
        port: Number(p.port),
        public_key: p['public-key'],
        allowed_ips: allTraffic(),
        ...(p['pre-shared-key'] ? { pre_shared_key: p['pre-shared-key'] } : {}),
        ...(p.reserved ? { reserved: p.reserved } : {}),
      },
    ];
  }
  const tls: Config = {};
  used.add('tls');
  // TLS details count as imported only with a TLS block; on a plain proxy
  // they are reported like any other field that has no effect.
  if (p.tls || p['reality-opts'] || ['trojan', 'anytls', 'hysteria', 'hysteria2', 'tuic'].includes(type)) {
    for (const k of ['servername', 'sni', 'skip-cert-verify', 'alpn', 'client-fingerprint', 'reality-opts'])
      used.add(k);
    tls.enabled = true;
    if (p.servername || p.sni) tls.server_name = p.servername || p.sni;
    if (has(p, 'skip-cert-verify')) tls.insecure = p['skip-cert-verify'];
    if (p.alpn) tls.alpn = p.alpn;
    if (p['client-fingerprint']) tls.utls = { enabled: true, fingerprint: p['client-fingerprint'] };
    if (p['reality-opts']) {
      const reality = obj(p['reality-opts']);
      tls.reality = { enabled: true, public_key: reality['public-key'], short_id: reality['short-id'] };
    }
    c.tls = tls;
  }
  const nested = (source: string, mapping: Record<string, string>, target: Config) => {
    used.add(source);
    const options = obj(p[source]);
    for (const [k, v] of Object.entries(options))
      if (has(mapping, k)) target[mapping[k]] = v;
      else warnings.push('file:' + source + '.' + k);
  };
  used.add('network');
  const net = p.network || 'tcp';
  if (net !== 'tcp' && net !== 'xhttp') {
    const transport: Config = {};
    if (net === 'ws') {
      transport.type = 'ws';
      nested(
        'ws-opts',
        {
          path: 'path',
          headers: 'headers',
          'max-early-data': 'max_early_data',
          'early-data-header-name': 'early_data_header_name',
        },
        transport,
      );
    } else if (net === 'grpc') {
      transport.type = 'grpc';
      nested('grpc-opts', { 'grpc-service-name': 'service_name' }, transport);
    } else if (net === 'h2' || net === 'http') {
      transport.type = 'http';
      nested(
        net === 'h2' ? 'h2-opts' : 'http-opts',
        { host: 'host', path: 'path', headers: 'headers', method: 'method' },
        transport,
      );
      if (Array.isArray(transport.path)) {
        if (transport.path.length > 1) warnings.push('file:http-opts.path');
        transport.path = transport.path[0];
      }
    } else if (net === 'httpupgrade') {
      transport.type = 'httpupgrade';
      nested('http-upgrade-opts', { host: 'host', path: 'path' }, transport);
    } else throw new Error('unsupported_transport');
    c.transport = transport;
  }
  if (p.smux) {
    const multiplex: Config = {};
    nested(
      'smux',
      {
        enabled: 'enabled',
        protocol: 'protocol',
        'max-connections': 'max_connections',
        'min-streams': 'min_streams',
        'max-streams': 'max_streams',
        padding: 'padding',
      },
      multiplex,
    );
    c.multiplex = multiplex;
  }
  let draft = jsonDraft(c, group, String(p.name || p.server));
  if (type === 'vless' && (net === 'xhttp' || (p.encryption && p.encryption !== 'none'))) {
    used.add('encryption');
    used.add('xhttp-opts');
    if (typeof p.uuid !== 'string' || !p.uuid) throw new Error('invalid_yaml');
    const x = obj(p['xhttp-opts']);
    const r = obj(p['reality-opts']);
    // The link keeps the transport chosen above; sing-box-only multiplex has
    // no Xray equivalent here and is reported.
    const ws = obj(p['ws-opts']);
    const grpc = obj(p['grpc-opts']);
    if (p.smux) warnings.push('file:smux');
    const params: Record<string, unknown> = {
      encryption: p.encryption || 'none',
      type: net,
      flow: p.flow,
      security: p['reality-opts'] ? 'reality' : p.tls ? 'tls' : 'none',
      sni: p.servername || p.sni,
      fp: p['client-fingerprint'],
      allowInsecure: p['skip-cert-verify'],
      alpn: Array.isArray(p.alpn) ? p.alpn.join(',') : p.alpn,
      pbk: r['public-key'],
      sid: r['short-id'],
      path: net === 'ws' ? ws.path : x.path,
      host: net === 'ws' ? obj(ws.headers).Host : x.host,
      mode: x.mode,
      serviceName: net === 'grpc' ? grpc['grpc-service-name'] : undefined,
    };
    // Xray names XHTTP extras in camelCase; an option without a known name is
    // reported instead of being passed under the Clash spelling.
    const extra: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(x)) {
      if (['path', 'host', 'mode'].includes(key)) continue;
      if (has(XHTTP_EXTRA, key)) extra[XHTTP_EXTRA[key]] = value;
      else warnings.push('file:xhttp-opts.' + key);
    }
    if (Object.keys(extra).length) params.extra = JSON.stringify(extra);
    const host = String(p.server).includes(':') ? `[${p.server}]` : p.server;
    const query = Object.entries(params)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join('&');
    const parsed = parseLink(
      `vless://${encodeURIComponent(String(p.uuid))}@${host}:${p.port}?${query}#${encodeURIComponent(String(p.name || p.server))}`,
      group,
    );
    draft = parsed.draft;
    warnings.push(...parsed.warnings);
  } else if (has(p, 'encryption')) {
    used.add('encryption');
    if (p.encryption !== 'none') warnings.push('file:encryption');
  }
  for (const key of Object.keys(p)) if (!used.has(key)) warnings.push('file:' + key);
  return { draft, warnings: [...new Set(warnings)] };
}
